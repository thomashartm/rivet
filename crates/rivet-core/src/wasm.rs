//! The WASM component runtime (ARCHITECTURE.md §4.3, ADR-0002).
//!
//! An extension is a WASM component that implements the world `extension` of
//! the WIT package `rivet:extension@0.1.0` (`crates/rivet-sdk/wit`). This
//! module loads a component, makes instances of it and calls its lifecycle
//! functions.
//!
//! | Item | Pinned version |
//! | --- | --- |
//! | Wasmtime | 51.0.0 |
//! | WASI | none: the host gives no WASI interface |
//!
//! # Extension host
//!
//! [`WasmRuntime`] is an [`ExtensionRuntime`]: the extension host
//! ([`crate::host`]) loads the file [`COMPONENT_FILE`] of a package directory
//! into a [`WasmInstance`], calls its lifecycle functions, and drops it to
//! unload it. An error of a call puts the extension in the state `Failed`
//! (ARCHITECTURE.md §4.4): a trap, a limit violation, or an error that the
//! component returns.
//!
//! - A WASM extension cannot register a service, a command handler or a job
//!   yet. The imports for this come with the first extension point that has
//!   a WIT interface (ADR-0013).
//! - A package with a missing or invalid component file fails with a `user`
//!   error. The host restarts it with backoff until it is `Disabled`
//!   (ADR-0021), although a restart cannot repair the file.
//! - The component file must be a regular file. A symbolic link is refused,
//!   so a package cannot make the host read a file outside its directory.
//! - The code that builds the runtime and the host makes the limits with
//!   [`Limits::for_host`] from the [`HostConfig`] that it gives to the host.
//!   Then the time limit of the host and [`Limits::call_timeout`] are one
//!   value. For `activate` and `deactivate`, guest code stops not later
//!   than the overshoot of "Limits" after the host gave up the call. For a
//!   `load` the two limits do not start together (ADR-0018): the host counts
//!   from the start of the load, before the file read and the compilation.
//!   The runtime counts from the instantiation, when guest code starts. So
//!   after the host gave up a load, the start function of a component can
//!   run for the full limit of the runtime plus the overshoot, counted from
//!   the end of the compilation. Only the size limit of the file bounds the
//!   time of the compilation. With a longer limit in the runtime, the guest
//!   code of a failed call runs on a blocking thread until that limit.
//!
//! # Sandbox
//!
//! A component can use only what the host gives it as an import. The host
//! gives one import: `rivet:extension/logging`. It gives no WASI interface,
//! so a component has no filesystem, network, environment, process, clock or
//! random access. A component that imports one of these does not load.
//!
//! # Limits
//!
//! - Memory: each instance has a limit for its linear memories and tables
//!   together ([`Limits::memory_bytes`]).
//! - Objects: each instance can have [`MAX_CORE_INSTANCES`] core instances,
//!   [`MAX_MEMORIES`] memories and [`MAX_TABLES`] tables at most (ADR-0018).
//!   A memory of zero pages costs no bytes, but it reserves address space.
//! - CPU: each call has a fuel budget ([`Limits::fuel_per_call`]). Fuel
//!   gives the same result on each run. Fuel counts WASM instructions. It
//!   does not count the work of the host in an import.
//! - Time: each call has a time limit ([`Limits::call_timeout`]). It is the
//!   backstop for the work that fuel does not count. One thread for each
//!   runtime advances the epoch of Wasmtime; guest code stops when its
//!   deadline has passed. The limit does not stop host code: each host
//!   import must do a bounded quantity of work. The limit is a backstop,
//!   not an exact timer. A call does not end before its limit. It can end
//!   later: by two ticks of 100 ms at most, plus the time that the thread
//!   sleeps too long at each tick. Measured on macOS: a limit of 3000 ms
//!   ended a call after 3.30 s.
//! - Data to the host: one call of an import, and one result of an export,
//!   can pass [`MAX_GUEST_CALL_BYTES`] at most. Wasmtime checks this before
//!   it copies the data. More is a trap: one log message past this size
//!   ends the instance.
//! - Log: the messages of one call have a budget of [`LOG_LINES_PER_CALL`]
//!   lines and [`LOG_BYTES_PER_CALL`] bytes. The host drops the messages
//!   past the budget and writes one line with their number. A message below
//!   the log level of the host is not written: it uses no budget and is not
//!   in that number. Fuel limits the number of such messages.
//! - File: a component file can have [`Limits::component_bytes`] at most.
//!   The compilation has no time limit and cannot be stopped: this size
//!   limit is its only bound.
//!
//! # Errors
//!
//! | Failure | Category |
//! | --- | --- |
//! | Invalid file, wrong world, import that the host does not give | `user` |
//! | Component file past the size limit | `user` |
//! | Trap, CPU limit, time limit, memory limit, data limit | `internal` |
//! | Instantiation fails without a trap, for example past an object limit | `internal` |
//! | A call breaks the rules of the component model | `internal` |
//! | The component returns an error | the category that the component gives |
//!
//! The message of an error that the component returns starts with a fixed
//! text of the host that names the extension. So the text of the component
//! cannot imitate a message of the host.
//!
//! Wasmtime quotes names from the component in the cause of a load error.
//! So the source of a load error is that cause as one text, with the rules
//! of the guest text: redacted, cleaned and cut. The source of a trap error
//! has no backtrace: a backtrace has the function names of the component.
//!
//! After a trap, a limit violation or a panic of the host in an import
//! (ARCHITECTURE.md §5.6) the instance cannot be used: each later call gives
//! an `internal` error. Other instances are not affected.
//!
//! # Threads
//!
//! Compilation and each call into a component run on the blocking pool of
//! Tokio, not on an async worker thread (ARCHITECTURE.md §5.1). A call that
//! the caller drops continues until it returns or reaches a limit: the fuel
//! or the time limit.

use crate::host::{ExtensionContext, ExtensionInstance, ExtensionRuntime, HostConfig};
use crate::logging::Redactor;
use rivet_sdk::error::{Error, Result};
use rivet_sdk::extension::BoxFuture;
use rivet_sdk::manifest::{ExtensionId, Manifest};
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Config, Engine, ResourceLimiter, Store, Trap};

mod bindings {
    wasmtime::component::bindgen!({ path: "../rivet-sdk/wit", world: "extension" });
}

use bindings::rivet::extension::logging::{self, LogLevel};
use bindings::rivet::extension::types::{self, ErrorCategory as GuestCategory};
use bindings::{Extension, ExtensionPre};

/// The name of the component file in an extension directory, next to the
/// manifest ([`MANIFEST_FILE`](crate::host::MANIFEST_FILE)).
pub const COMPONENT_FILE: &str = "extension.wasm";

/// The default of [`Limits::memory_bytes`]: 64 MiB.
pub const DEFAULT_MEMORY_BYTES: usize = 64 << 20;

/// The default of [`Limits::fuel_per_call`].
pub const DEFAULT_FUEL_PER_CALL: u64 = 1_000_000_000;

/// The default of [`Limits::component_bytes`]: 4 MiB (ADR-0018).
///
/// A debug build of the host compiles a component of this size for longer
/// than the default call time limit (ADR-0018: 35 to 64 s), so that load
/// fails.
pub const DEFAULT_COMPONENT_BYTES: usize = 4 << 20;

/// The most core instances that one instance of a component can have.
pub const MAX_CORE_INSTANCES: usize = 64;

/// The most linear memories that one instance of a component can have.
pub const MAX_MEMORIES: usize = 8;

/// The most tables that one instance of a component can have.
pub const MAX_TABLES: usize = 64;

/// The most bytes that a component can pass to the host in one call of an
/// import or in one result of an export. More is a trap.
pub const MAX_GUEST_CALL_BYTES: usize = 64 * 1024;

/// The most log lines that the host writes for one call into a component.
pub const LOG_LINES_PER_CALL: u32 = 100;

/// The most bytes of log messages that the host writes for one call into a
/// component.
pub const LOG_BYTES_PER_CALL: usize = 64 * 1024;

/// Log or error text from a component is cut to this number of bytes.
const MAX_GUEST_TEXT_BYTES: usize = 8 * 1024;

/// A path in an error text is cut to this number of bytes.
const MAX_PATH_TEXT_BYTES: usize = 256;

/// The shortest time between two epoch ticks of an engine. A call can run
/// two ticks longer than [`Limits::call_timeout`], plus the time that the
/// timer thread sleeps too long at each tick.
const EPOCH_TICK: Duration = Duration::from_millis(100);

/// The resource limits of an extension instance (ARCHITECTURE.md §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most bytes that the linear memories and the tables of one instance
    /// can have together.
    pub memory_bytes: usize,
    /// The fuel for one call into a component. The instantiation is also one
    /// call. Wasmtime uses approximately one unit of fuel for each WASM
    /// instruction.
    pub fuel_per_call: u64,
    /// The longest time of one call into a component. The instantiation is
    /// also one call. The call does not end before this time. It can end
    /// later: see "Limits" in the module documentation.
    ///
    /// The value has one owner,
    /// [`HostConfig::call_timeout`](crate::host::HostConfig::call_timeout)
    /// (ADR-0018): [`for_host`](Self::for_host) copies it. This module reads
    /// no settings.
    pub call_timeout: Duration,
    /// The most bytes that a component file can have.
    pub component_bytes: usize,
}

impl Default for Limits {
    /// [`for_host`](Self::for_host) with the default [`HostConfig`]: the
    /// call time limit has one default, that of the host (ADR-0018).
    fn default() -> Self {
        Self::for_host(&HostConfig::default())
    }
}

impl Limits {
    /// The limits for a runtime whose extensions run in a host with
    /// `config`: [`DEFAULT_MEMORY_BYTES`], [`DEFAULT_FUEL_PER_CALL`],
    /// [`DEFAULT_COMPONENT_BYTES`], and the call time limit of the host.
    ///
    /// The code that builds the runtime and the host must use this function
    /// and give the same `config` to the host. With a longer time limit in
    /// the runtime, the guest code of a call that the host gave up continues
    /// until the limit of the runtime.
    ///
    /// With the same limit, the guest code of `activate` and `deactivate`
    /// stops not later than the overshoot after the host gave up the call.
    /// For `load`, the timer of the host starts before the compilation and
    /// the limit of the runtime starts when guest code starts: after the
    /// host gave up a load, guest code can run for the full limit of the
    /// runtime plus the overshoot, counted from the end of the compilation
    /// (ADR-0018).
    #[must_use]
    pub fn for_host(config: &HostConfig) -> Self {
        Self {
            memory_bytes: DEFAULT_MEMORY_BYTES,
            fuel_per_call: DEFAULT_FUEL_PER_CALL,
            call_timeout: config.call_timeout,
            component_bytes: DEFAULT_COMPONENT_BYTES,
        }
    }

    /// The epoch ticks after which a call has run for `call_timeout` at
    /// least. The quotient is rounded up. One more: the first tick can come
    /// at once.
    fn epoch_ticks(&self) -> u64 {
        let ticks = self.call_timeout.as_nanos().div_ceil(EPOCH_TICK.as_nanos());
        // The cap keeps the sum with the current epoch in a `u64`.
        u64::try_from(ticks).map_or(u64::from(u32::MAX), |ticks| {
            ticks.min(u64::from(u32::MAX)) + 1
        })
    }
}

/// A component asked for more memory than [`Limits::memory_bytes`].
#[derive(Debug)]
struct MemoryLimitExceeded;

impl std::fmt::Display for MemoryLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("memory limit exceeded")
    }
}

impl std::error::Error for MemoryLimitExceeded {}

/// The host data of one instance.
struct State {
    id: ExtensionId,
    memory_limit: usize,
    /// The bytes that the instance was given. A growth that Wasmtime refuses
    /// afterwards is not given back: the count can only be too high.
    memory_used: usize,
    redactor: Redactor,
    /// The log lines that the current call can still write.
    log_lines: u32,
    /// The log message bytes that the current call can still write.
    log_bytes: usize,
    /// The log lines of the current call that were dropped.
    log_dropped: u64,
}

impl State {
    fn charge(&mut self, bytes: usize) -> wasmtime::Result<bool> {
        match self.memory_used.checked_add(bytes) {
            Some(total) if total <= self.memory_limit => {
                self.memory_used = total;
                Ok(true)
            }
            // An error, not `false`: the component traps and cannot continue.
            _ => Err(MemoryLimitExceeded.into()),
        }
    }
}

impl ResourceLimiter for State {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.charge(desired.saturating_sub(current))
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // Wasmtime uses one pointer for each table element.
        self.charge(
            desired
                .saturating_sub(current)
                .saturating_mul(size_of::<usize>()),
        )
    }

    // The counts: an object of size zero is not seen by `charge`.
    fn instances(&self) -> usize {
        MAX_CORE_INSTANCES
    }

    fn tables(&self) -> usize {
        MAX_TABLES
    }

    fn memories(&self) -> usize {
        MAX_MEMORIES
    }
}

impl logging::Host for State {
    fn log(&mut self, level: LogLevel, message: String) {
        // Before the budget: a message that the host does not write costs
        // nothing and is not a dropped line.
        let written = match level {
            LogLevel::Trace => tracing::enabled!(tracing::Level::TRACE),
            LogLevel::Debug => tracing::enabled!(tracing::Level::DEBUG),
            LogLevel::Info => tracing::enabled!(tracing::Level::INFO),
            LogLevel::Warn => tracing::enabled!(tracing::Level::WARN),
            LogLevel::Error => tracing::enabled!(tracing::Level::ERROR),
        };
        if !written {
            return;
        }
        // Before the work on the text: a dropped message must be cheap.
        let bytes = message.len().min(MAX_GUEST_TEXT_BYTES);
        if self.log_lines == 0 || bytes > self.log_bytes {
            self.log_dropped += 1;
            return;
        }
        self.log_lines -= 1;
        self.log_bytes -= bytes;
        let message = guest_text(&self.redactor, &message);
        let extension = self.id.as_str();
        // A field, not the message: in the log each character of the
        // component is inside `guest_message`, apart from the host fields.
        let guest_message = message.as_str();
        match level {
            LogLevel::Trace => tracing::trace!(extension, guest_message, "extension log"),
            LogLevel::Debug => tracing::debug!(extension, guest_message, "extension log"),
            LogLevel::Info => tracing::info!(extension, guest_message, "extension log"),
            LogLevel::Warn => tracing::warn!(extension, guest_message, "extension log"),
            LogLevel::Error => tracing::error!(extension, guest_message, "extension log"),
        }
    }
}

impl types::Host for State {}

/// Turns an error that a component returned from `action` into the error of
/// the SDK. The category stays. The message starts with a fixed text of the
/// host, so the text of the component cannot imitate a message of the host.
fn guest_error(state: &State, action: &str, error: &types::Error) -> Error {
    let message = format!(
        "extension `{}`: {action} failed: the component returned an error: {}",
        state.id,
        guest_text(&state.redactor, &error.message)
    );
    match error.category {
        GuestCategory::User => Error::user(message),
        GuestCategory::Auth => Error::auth(message),
        GuestCategory::Connectivity => Error::connectivity(message),
        GuestCategory::Database => Error::database(message),
        GuestCategory::Policy => Error::policy(message),
        GuestCategory::Cancelled => Error::cancelled(message),
        GuestCategory::Retryable => Error::retryable(message),
        GuestCategory::Internal => Error::internal(message),
    }
}

/// Makes text from a component safe for a log line or an error message.
///
/// 1. Secrets are redacted. This is before the cut, so the cut cannot leave
///    a part of a secret that the redacting log writer does not find.
/// 2. Each character that can start a line or hide text becomes a space
///    ([`is_unsafe`]), and `"` becomes `'`. The human log format writes a host
///    field as `name="value"`, so the text cannot imitate one.
/// 3. The text is cut to [`MAX_GUEST_TEXT_BYTES`].
pub(crate) fn guest_text(redactor: &Redactor, text: &str) -> String {
    let mut text: String = redactor
        .redact(text)
        .chars()
        .map(|c| match c {
            '"' => '\'',
            c if is_unsafe(c) => ' ',
            c => c,
        })
        .collect();
    text.truncate(text.floor_char_boundary(MAX_GUEST_TEXT_BYTES));
    text
}

/// The reason that Wasmtime gives for a component that it refuses, with its
/// causes, as one text. Wasmtime quotes names from the component in it, so
/// it has the rules of [`guest_text`].
fn refusal_text(redactor: &Redactor, error: &wasmtime::Error) -> String {
    guest_text(redactor, &format!("{error:#}"))
}

/// Makes a path safe for an error message: the rules of [`guest_text`], and a
/// cut to the last [`MAX_PATH_TEXT_BYTES`]: the end of a path names the file.
/// The name of a directory is untrusted.
fn path_text(redactor: &Redactor, path: &Path) -> String {
    // shortcut: `guest_text` keeps the first 8 KiB, so a longer path still
    // loses its end; cut here before `guest_text` cuts when a caller can
    // give such a path (the path limit of Linux is 4096 bytes).
    let text = guest_text(redactor, &path.display().to_string());
    match text.len().checked_sub(MAX_PATH_TEXT_BYTES) {
        None | Some(0) => text,
        Some(cut) => format!("…{}", &text[text.ceil_char_boundary(cut)..]),
    }
}

/// The format characters of Unicode 16.0 (general category Cf), the line
/// separator (Zl) and the paragraph separator (Zp). `std` has no API for the
/// general category. A range can include code points that are not assigned.
const FORMAT_AND_SEPARATOR_RANGES: [(char, char); 20] = [
    ('\u{ad}', '\u{ad}'),
    ('\u{600}', '\u{605}'),
    ('\u{61c}', '\u{61c}'),
    ('\u{6dd}', '\u{6dd}'),
    ('\u{70f}', '\u{70f}'),
    ('\u{890}', '\u{891}'),
    ('\u{8e2}', '\u{8e2}'),
    ('\u{180e}', '\u{180e}'),
    ('\u{200b}', '\u{200f}'),
    ('\u{2028}', '\u{202e}'),
    ('\u{2060}', '\u{206f}'),
    ('\u{feff}', '\u{feff}'),
    ('\u{fff9}', '\u{fffb}'),
    ('\u{110bd}', '\u{110bd}'),
    ('\u{110cd}', '\u{110cd}'),
    ('\u{13430}', '\u{1343f}'),
    ('\u{1bca0}', '\u{1bca3}'),
    ('\u{1d173}', '\u{1d17a}'),
    ('\u{e0001}', '\u{e0001}'),
    ('\u{e0020}', '\u{e007f}'),
];

/// Returns `true` for a control character (Cc), a format character (Cf), the
/// line separator (Zl) and the paragraph separator (Zp).
fn is_unsafe(c: char) -> bool {
    c.is_control()
        || FORMAT_AND_SEPARATOR_RANGES
            .iter()
            .any(|&(first, last)| (first..=last).contains(&c))
}

/// Runs `work` on the blocking pool, with the log subscriber and the span of
/// the caller.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&dispatch, || span.in_scope(work))
    })
    .await
    .map_err(|error| Error::internal("the WASM runtime task failed").with_source(error))?
}

/// The `action` of [`failure`] for the instantiation.
const INSTANTIATE: &str = "instantiate";

/// Turns a failure of Wasmtime in guest code into an `internal` error.
fn failure(id: &ExtensionId, action: &str, error: wasmtime::Error) -> Error {
    let reason = if error.is::<MemoryLimitExceeded>() {
        "the memory limit was exceeded"
    } else {
        match error.downcast_ref::<Trap>() {
            Some(Trap::OutOfFuel) => "the CPU limit was exceeded",
            Some(Trap::Interrupt) => "the call time limit was exceeded",
            Some(Trap::HostcallFuelExhausted) => "the component passed too much data to the host",
            Some(_) => "the component trapped",
            // Not a trap: Wasmtime gives no type for the cause, only text.
            None if action == INSTANTIATE => "the component could not be instantiated",
            None => "the call broke the rules of the component model",
        }
    };
    Error::internal(format!("extension `{id}`: {action} failed: {reason}")).with_source(error)
}

/// Runs one call into a component with a new fuel budget, a new time limit
/// and a new log budget. Writes the number of dropped log lines afterwards.
fn limited<T>(
    store: &mut Store<State>,
    limits: &Limits,
    call: impl FnOnce(&mut Store<State>) -> wasmtime::Result<T>,
) -> wasmtime::Result<T> {
    let state = store.data_mut();
    state.log_lines = LOG_LINES_PER_CALL;
    state.log_bytes = LOG_BYTES_PER_CALL;
    state.log_dropped = 0;
    store.set_fuel(limits.fuel_per_call)?;
    store.set_epoch_deadline(limits.epoch_ticks());
    let result = call(store);
    let state = store.data();
    if state.log_dropped > 0 {
        tracing::warn!(
            extension = state.id.as_str(),
            "{} log lines dropped",
            state.log_dropped
        );
    }
    result
}

/// The WASM runtime: one Wasmtime engine and the limits for its instances.
///
/// A clone uses the same engine.
#[derive(Clone)]
pub struct WasmRuntime {
    engine: Engine,
    linker: Arc<Linker<State>>,
    limits: Limits,
    redactor: Redactor,
}

impl WasmRuntime {
    /// Makes a runtime. Each instance gets `limits`. Text from a component
    /// goes through `redactor` before it is cut for the log or for an error.
    ///
    /// The runtime starts one thread that counts the time for
    /// [`Limits::call_timeout`]. The thread ends when the runtime, its
    /// components and its instances are dropped.
    ///
    /// # Errors
    ///
    /// Returns an `internal` error if Wasmtime or the thread cannot start on
    /// this machine.
    pub fn new(limits: Limits, redactor: Redactor) -> Result<Self> {
        let unusable =
            |error: wasmtime::Error| Error::internal("cannot start Wasmtime").with_source(error);
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        // A backtrace has the function names that the component chose: it
        // must not be in the source of a trap error.
        config.wasm_backtrace_max_frames(None);
        let engine = Engine::new(&config).map_err(unusable)?;
        let weak = engine.weak();
        std::thread::Builder::new()
            .name("rivet-wasm-epoch".to_owned())
            .spawn(move || {
                while let Some(engine) = weak.upgrade() {
                    engine.increment_epoch();
                    drop(engine);
                    std::thread::sleep(EPOCH_TICK);
                }
            })
            .map_err(|error| {
                Error::internal("cannot start the WASM timer thread").with_source(error)
            })?;
        let mut linker = Linker::new(&engine);
        // The only import of a component. There is no WASI on purpose.
        Extension::add_to_linker::<_, HasSelf<State>>(&mut linker, |state| state)
            .map_err(unusable)?;
        Ok(Self {
            engine,
            linker: Arc::new(linker),
            limits,
            redactor,
        })
    }

    /// Compiles a component from the bytes of a binary `.wasm` file.
    ///
    /// # Errors
    ///
    /// Returns a `user` error if `bytes` is longer than
    /// [`Limits::component_bytes`], if `bytes` is not a valid component, if
    /// the component does not export the world `extension`, or if it imports
    /// something that the host does not give, for example a WASI interface.
    pub async fn load(&self, bytes: Vec<u8>) -> Result<WasmComponent> {
        let limit = self.limits.component_bytes;
        if bytes.len() > limit {
            return Err(Error::user(format!(
                "the WASM component is larger than the limit of {limit} bytes"
            )));
        }
        let engine = self.engine.clone();
        let linker = Arc::clone(&self.linker);
        let redactor = self.redactor.clone();
        blocking(move || {
            // shortcut: no time limit for the compilation, it is bounded by the
            // size limit only (4 MiB, ADR-0018: 16 MiB compiled for 43 s on one
            // thread); add a compile cache or parallel compilation when a
            // component of the allowed size compiles for too long.
            let component = Component::new(&engine, &bytes).map_err(|error| {
                Error::user("the file is not a valid WASM component")
                    .with_source(refusal_text(&redactor, &error))
            })?;
            linker
                .instantiate_pre(&component)
                .and_then(ExtensionPre::new)
                .map(WasmComponent)
                .map_err(|error| {
                    let kind = component.component_type();
                    let message = match kind
                        .imports(&engine)
                        .find(|(name, _)| name.starts_with("wasi:"))
                    {
                        Some((name, _)) => format!(
                            "the WASM component imports `{}`, but the host gives no WASI interface",
                            guest_text(&redactor, name)
                        ),
                        None => {
                            "the WASM component does not fit the world `rivet:extension`".to_owned()
                        }
                    };
                    Error::user(message).with_source(refusal_text(&redactor, &error))
                })
        })
        .await
    }

    /// Reads the file at `path` and compiles it with [`load`](Self::load).
    ///
    /// # Errors
    ///
    /// Returns a `user` error if the file cannot be read or is not a regular
    /// file (a symbolic link is refused), and the errors of
    /// [`load`](Self::load).
    pub async fn load_file(&self, path: &Path) -> Result<WasmComponent> {
        let path = path.to_owned();
        // One byte more than the limit: `load` then refuses the file, and a
        // file of any size costs this much memory at most.
        let most =
            u64::try_from(self.limits.component_bytes).map_or(u64::MAX, |n| n.saturating_add(1));
        let redactor = self.redactor.clone();
        let bytes = blocking(move || {
            let shown = path_text(&redactor, &path);
            let unreadable = |error| {
                Error::user(format!("cannot read the WASM component {shown}")).with_source(error)
            };
            // Not `metadata`: that follows a symbolic link.
            // shortcut: the file can be replaced between this check and the
            // open; open with `O_NOFOLLOW` (needs a new crate or `unsafe`)
            // when the package directory can change while the host loads it.
            if !std::fs::symlink_metadata(&path)
                .map_err(unreadable)?
                .is_file()
            {
                return Err(Error::user(format!(
                    "the WASM component {shown} is not a regular file"
                )));
            }
            let mut bytes = Vec::new();
            std::fs::File::open(&path)
                .and_then(|file| file.take(most).read_to_end(&mut bytes))
                .map_err(unreadable)?;
            Ok(bytes)
        })
        .await?;
        self.load(bytes).await
    }

    /// Makes an instance of `component` for the extension `id`. The instance
    /// has its own memory and its own limits.
    ///
    /// # Errors
    ///
    /// Returns an `internal` error if the component traps or exceeds a limit
    /// while it starts.
    pub async fn instantiate(
        &self,
        component: &WasmComponent,
        id: ExtensionId,
    ) -> Result<WasmInstance> {
        let engine = self.engine.clone();
        let component = component.0.clone();
        let limits = self.limits;
        let redactor = self.redactor.clone();
        blocking(move || {
            let state = State {
                id: id.clone(),
                memory_limit: limits.memory_bytes,
                memory_used: 0,
                redactor,
                log_lines: 0,
                log_bytes: 0,
                log_dropped: 0,
            };
            let mut store = Store::new(&engine, state);
            store.limiter(|state| state);
            store.set_hostcall_fuel(MAX_GUEST_CALL_BYTES);
            let extension = limited(&mut store, &limits, |store| component.instantiate(store))
                .map_err(|error| failure(&id, INSTANTIATE, error))?;
            Ok(WasmInstance {
                inner: Arc::new(Mutex::new(Inner {
                    store,
                    extension,
                    failed: false,
                })),
                limits,
            })
        })
        .await
    }
}

impl WasmRuntime {
    /// Loads [`COMPONENT_FILE`] of the package in `directory` and makes the
    /// instance of the extension of `manifest`.
    async fn load_package(&self, manifest: &Manifest, directory: &Path) -> Result<WasmInstance> {
        let component = self.load_file(&directory.join(COMPONENT_FILE)).await?;
        self.instantiate(&component, manifest.id.clone()).await
    }
}

impl ExtensionRuntime for WasmRuntime {
    /// Loads the file [`COMPONENT_FILE`] in `directory`.
    ///
    /// Gives the errors of [`load_file`](Self::load_file) and
    /// [`instantiate`](Self::instantiate).
    fn load<'a>(
        &'a self,
        manifest: &'a Manifest,
        directory: &'a Path,
    ) -> BoxFuture<'a, Result<Box<dyn ExtensionInstance>>> {
        Box::pin(async move {
            let instance = self.load_package(manifest, directory).await?;
            Ok(Box::new(instance) as Box<dyn ExtensionInstance>)
        })
    }
}

/// A compiled component. One component can have many instances.
#[derive(Clone)]
pub struct WasmComponent(ExtensionPre<State>);

/// A lifecycle export of the world `extension`.
type Lifecycle = fn(&Extension, &mut Store<State>) -> wasmtime::Result<Result<(), types::Error>>;

/// One running instance of a component. To drop it frees its memory.
///
/// Calls into one instance run one after the other.
pub struct WasmInstance {
    inner: Arc<Mutex<Inner>>,
    limits: Limits,
}

struct Inner {
    store: Store<State>,
    extension: Extension,
    /// A call ended with a trap or a limit violation.
    failed: bool,
}

impl WasmInstance {
    /// Calls `activate` of the component.
    ///
    /// # Errors
    ///
    /// Returns the error that the component returns, with its category.
    /// Returns an `internal` error if the component traps or exceeds a limit.
    pub async fn activate(&self) -> Result<()> {
        self.call("activate", |extension, store| {
            extension.call_activate(store)
        })
        .await
    }

    /// Calls `deactivate` of the component.
    ///
    /// # Errors
    ///
    /// Returns the error that the component returns, with its category.
    /// Returns an `internal` error if the component traps or exceeds a limit.
    pub async fn deactivate(&self) -> Result<()> {
        self.call("deactivate", |extension, store| {
            extension.call_deactivate(store)
        })
        .await
    }

    async fn call(&self, action: &'static str, export: Lifecycle) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        let limits = self.limits;
        blocking(move || {
            // The lock is poisoned if the host panicked in an import.
            let (mut inner, poisoned) = match inner.lock() {
                Ok(inner) => (inner, false),
                Err(poison) => (poison.into_inner(), true),
            };
            let Inner {
                store,
                extension,
                failed,
            } = &mut *inner;
            if poisoned || *failed {
                return Err(Error::internal(format!(
                    "extension `{}`: {action} failed: the instance failed in an earlier call",
                    store.data().id
                )));
            }
            match limited(store, &limits, |store| export(extension, store)) {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(guest_error(store.data(), action, &error)),
                Err(error) => {
                    *failed = true;
                    Err(failure(&store.data().id, action, error))
                }
            }
        })
        .await
    }
}

impl ExtensionInstance for WasmInstance {
    /// Calls `activate` of the component. The component cannot register a
    /// service, a command handler or a job yet (see the module
    /// documentation), so `_context` is not used.
    // shortcut: the context is dropped; give it to the instance when the
    // first registration import is added to the world `extension`.
    fn activate(&self, _context: ExtensionContext) -> BoxFuture<'_, Result<()>> {
        Box::pin(WasmInstance::activate(self))
    }

    fn deactivate(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(WasmInstance::deactivate(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::{CommandBus, EventBus};
    use crate::host::{
        ActivationReport, ExtensionHost, ExtensionState, ExtensionStatus, HostConfig,
        MANIFEST_FILE, Services,
    };
    use crate::jobs::JobScheduler;
    use crate::logging::{Capture, Level, LogConfig, LogFormat, Redactor, capture_logs, dispatch};
    use crate::registry::ServiceRegistry;
    use crate::resolve::ActivationTrigger;
    use rivet_sdk::error::ErrorCategory;
    use rivet_sdk::manifest::Version;
    use rivet_sdk::secret::Secret;
    use std::future::Future;
    use std::num::{NonZeroU16, NonZeroUsize};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, ThreadId};

    const SMALL: Limits = Limits {
        memory_bytes: 2 * 65536,
        fuel_per_call: 100_000,
        call_timeout: Duration::from_secs(30),
        component_bytes: DEFAULT_COMPONENT_BYTES,
    };

    /// Builds a component of the `extension` world from WAT text.
    /// `data` is put in its memory of one page. `activate` is the body of the
    /// core function: it returns the address of a `result<_, error>`.
    /// Address 0 holds zeros, which is `ok`.
    fn guest_with(imports: &str, data: &str, activate: &str) -> Vec<u8> {
        component(imports, data, activate, "(i32.const 0)")
    }

    /// As [`guest_with`]. `deactivate` is the body of the core function.
    fn component(imports: &str, data: &str, activate: &str, deactivate: &str) -> Vec<u8> {
        let text = format!(
            r#"(component
  {imports}
  (import "rivet:extension/types@0.1.0" (instance $types
    (type $category (enum "user" "auth" "connectivity" "database" "policy"
      "cancelled" "retryable" "internal"))
    (export "error-category" (type $error-category (eq $category)))
    (type $record (record (field "category" $error-category) (field "message" string)))
    (export "error" (type (eq $record)))))
  (alias export $types "error" (type $error))
  (import "rivet:extension/logging@0.1.0" (instance $logging
    (type $level (enum "trace" "debug" "info" "warn" "error"))
    (export "log-level" (type $log-level (eq $level)))
    (export "log" (func (param "level" $log-level) (param "message" string)))))
  (core module $memory (memory (export "memory") 1))
  (core instance $memory (instantiate $memory))
  (alias core export $memory "memory" (core memory $mem))
  (core func $log (canon lower (func $logging "log") (memory $mem)))
  (core module $guest
    (import "host" "log" (func $log (param i32 i32 i32)))
    (import "host" "memory" (memory 1))
    {data}
    (func (export "activate") (result i32) {activate})
    (func (export "deactivate") (result i32) {deactivate}))
  (core instance $guest (instantiate $guest (with "host" (instance
    (export "log" (func $log))
    (export "memory" (memory $mem))))))
  (type $result (result (error $error)))
  (func (export "activate") (result $result)
    (canon lift (core func $guest "activate") (memory $mem)))
  (func (export "deactivate") (result $result)
    (canon lift (core func $guest "deactivate") (memory $mem))))"#
        );
        wat::parse_str(text).unwrap()
    }

    fn guest(data: &str, activate: &str) -> Vec<u8> {
        guest_with("", data, activate)
    }

    /// Logs `message` at the level `info`, then returns `ok`.
    fn logging_guest(message: &str) -> Vec<u8> {
        let data: String = message.bytes().map(|b| format!("\\{b:02x}")).collect();
        guest(
            &format!(r#"(data (i32.const 256) "{data}")"#),
            &format!(
                "(call $log (i32.const 2) (i32.const 256) (i32.const {})) (i32.const 0)",
                message.len()
            ),
        )
    }

    fn trapping_guest() -> Vec<u8> {
        guest("", "unreachable")
    }

    fn id(text: &str) -> ExtensionId {
        text.parse().unwrap()
    }

    async fn instance(runtime: &WasmRuntime, bytes: Vec<u8>, name: &str) -> WasmInstance {
        let component = runtime.load(bytes).await.unwrap();
        runtime.instantiate(&component, id(name)).await.unwrap()
    }

    fn runtime() -> WasmRuntime {
        runtime_with(SMALL, &Redactor::new())
    }

    fn runtime_with(limits: Limits, redactor: &Redactor) -> WasmRuntime {
        WasmRuntime::new(limits, redactor.clone()).unwrap()
    }

    #[test]
    fn api_types_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WasmRuntime>();
        assert_send_sync::<WasmComponent>();
        assert_send_sync::<WasmInstance>();
    }

    #[test]
    fn default_limits_are_the_documented_constants() {
        let limits = Limits::default();
        assert_eq!(limits.memory_bytes, DEFAULT_MEMORY_BYTES);
        assert_eq!(limits.fuel_per_call, DEFAULT_FUEL_PER_CALL);
        assert_eq!(limits.call_timeout, HostConfig::default().call_timeout);
        assert_eq!(limits.component_bytes, DEFAULT_COMPONENT_BYTES);
    }

    #[tokio::test]
    async fn a_component_file_is_loaded_and_its_lifecycle_is_called() {
        let capture = Capture::default();
        let _guard =
            capture_logs(&capture.dispatch(Level::INFO, LogFormat::Human, &Redactor::new()));
        // Each lifecycle function logs its own word of 7 bytes.
        let log = |address| {
            format!("(call $log (i32.const 2) (i32.const {address}) (i32.const 7)) (i32.const 0)")
        };
        let bytes = component(
            "",
            r#"(data (i32.const 256) "startedstopped")"#,
            &log(256),
            &log(263),
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("extension.wasm");
        std::fs::write(&path, bytes).unwrap();

        let runtime = runtime_with(Limits::default(), &Redactor::new());
        let component = runtime.load_file(&path).await.unwrap();
        let instance = runtime
            .instantiate(&component, id("acme.hello"))
            .await
            .unwrap();
        assert_eq!(capture.text(), "");
        instance.activate().await.unwrap();
        let text = capture.text();
        assert_eq!(text.matches("started").count(), 1, "{text}");
        assert!(!text.contains("stopped"), "{text}");
        instance.deactivate().await.unwrap();
        let text = capture.text();
        assert_eq!(text.matches("started").count(), 1, "{text}");
        assert_eq!(text.matches("stopped").count(), 1, "{text}");
    }

    #[tokio::test]
    async fn one_component_gives_independent_instances() {
        let runtime = runtime();
        let component = runtime.load(trapping_guest()).await.unwrap();
        let first = runtime
            .instantiate(&component, id("acme.first"))
            .await
            .unwrap();
        let second = runtime
            .instantiate(&component, id("acme.second"))
            .await
            .unwrap();
        first.activate().await.unwrap_err();
        second.deactivate().await.unwrap();
    }

    #[tokio::test]
    async fn an_error_result_of_the_component_keeps_its_category() {
        // A `result` at address 32: `err`, category 4 (`policy`), text at
        // 256, 4 bytes long.
        let bytes = guest(
            r#"(data (i32.const 32) "\01\00\00\00\04\00\00\00\00\01\00\00\04\00\00\00")
               (data (i32.const 256) "nope")"#,
            "(i32.const 32)",
        );
        let instance = instance(&runtime(), bytes, "acme.refuses").await;
        let error = instance.activate().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Policy);
        assert_eq!(
            error.message(),
            "extension `acme.refuses`: activate failed: the component returned an error: nope"
        );
        // It is not a trap: the instance still works.
        instance.deactivate().await.unwrap();
    }

    /// The names between `open` and the next `}` in `text`, one for each line
    /// of the form `name,`.
    fn cases<'a>(text: &'a str, open: &str) -> Vec<&'a str> {
        let (_, block) = text.split_once(open).unwrap();
        let (block, _) = block.split_once('}').unwrap();
        block
            .lines()
            .filter_map(|line| line.trim().strip_suffix(','))
            .collect()
    }

    const WIT: &str = include_str!("../../rivet-sdk/wit/extension.wit");

    #[test]
    fn the_wit_error_categories_are_the_sdk_error_categories() {
        let wit = cases(WIT, "enum error-category {");
        let sdk = cases(
            include_str!("../../rivet-sdk/src/error.rs"),
            "pub enum ErrorCategory {",
        );
        assert_eq!(wit.len(), 8);
        assert_eq!(
            wit,
            sdk.iter()
                .map(|name| name.to_lowercase())
                .collect::<Vec<_>>()
        );

        // Each WIT category becomes the SDK category with the same name.
        use GuestCategory::*;
        let all = [
            User,
            Auth,
            Connectivity,
            Database,
            Policy,
            Cancelled,
            Retryable,
            Internal,
        ];
        let state = State {
            id: id("acme.any"),
            memory_limit: 0,
            memory_used: 0,
            redactor: Redactor::new(),
            log_lines: 0,
            log_bytes: 0,
            log_dropped: 0,
        };
        for (category, name) in all.into_iter().zip(wit) {
            let error = types::Error {
                category,
                message: String::new(),
            };
            let error = guest_error(&state, "activate", &error);
            assert_eq!(error.category().to_string(), name);
        }
    }

    #[test]
    fn the_wit_package_version_is_the_sdk_crate_version() {
        // `rivet-sdk` and this crate take their version from the workspace.
        let manifest = include_str!("../../rivet-sdk/Cargo.toml");
        assert!(manifest.contains("version.workspace = true"));
        let package = format!("package rivet:extension@{};", env!("CARGO_PKG_VERSION"));
        assert!(WIT.contains(&package), "{package}");
    }

    #[test]
    fn the_wasmtime_version_is_exact_and_no_wasi_crate_is_a_dependency() {
        // ADR-0018: the pinned WASI version is "none". A WASI host
        // implementation would be a dependency of this crate.
        let manifest = include_str!("../Cargo.toml");
        let names: Vec<&str> = manifest
            .lines()
            .filter_map(|line| line.split_once(" = "))
            .map(|(name, _)| name)
            .collect();
        assert!(names.contains(&"wasmtime") && names.contains(&"wat"));
        assert!(!names.iter().any(|name| name.contains("wasi")), "{names:?}");
        // `wat` builds the test components: it is exact too.
        for name in ["wasmtime", "wat"] {
            let line = manifest
                .lines()
                .find(|line| line.starts_with(&format!("{name} = ")))
                .unwrap();
            let version = line.split('"').nth(1).unwrap();
            assert!(version.starts_with('='), "{line}");
        }
    }

    #[tokio::test]
    async fn an_invalid_file_is_a_user_error() {
        let runtime = runtime();
        let core_module = wat::parse_str("(module)").unwrap();
        for bytes in [Vec::new(), b"not wasm".to_vec(), core_module] {
            let error = runtime.load(bytes).await.err().unwrap();
            assert_eq!(error.category(), ErrorCategory::User, "{error}");
        }
        let missing = tempfile::tempdir().unwrap().path().join("missing.wasm");
        let error = runtime.load_file(&missing).await.err().unwrap();
        assert_eq!(error.category(), ErrorCategory::User, "{error}");
    }

    #[tokio::test]
    async fn a_component_that_does_not_implement_the_world_is_a_user_error() {
        let bytes = wat::parse_str("(component)").unwrap();
        let error = runtime().load(bytes).await.err().unwrap();
        assert_eq!(error.category(), ErrorCategory::User, "{error}");
    }

    #[tokio::test]
    async fn filesystem_network_environment_and_process_imports_are_refused() {
        // The imports have the names and the function types of WASI 0.2.6, so
        // a host that gives WASI would accept them.
        let resource = |interface: &str, name: &str| {
            format!(
                r#"(import "{interface}" (instance $i (export "{name}" (type (sub resource)))))
                   (alias export $i "{name}" (type $r))"#
            )
        };
        let function = |interface: &str, name: &str, signature: &str| {
            format!(r#"(import "{interface}" (instance (export "{name}" (func {signature}))))"#)
        };
        let cases = [
            (
                "wasi:filesystem/types@0.2.6",
                resource("wasi:filesystem/types@0.2.6", "descriptor")
                    + &function(
                        "wasi:filesystem/preopens@0.2.6",
                        "get-directories",
                        "(result (list (tuple (own $r) string)))",
                    ),
            ),
            (
                "wasi:sockets/network@0.2.6",
                resource("wasi:sockets/network@0.2.6", "network")
                    + &function(
                        "wasi:sockets/instance-network@0.2.6",
                        "instance-network",
                        "(result (own $r))",
                    ),
            ),
            (
                "wasi:cli/environment@0.2.6",
                function(
                    "wasi:cli/environment@0.2.6",
                    "get-environment",
                    "(result (list (tuple string string)))",
                ),
            ),
            (
                "wasi:cli/exit@0.2.6",
                function(
                    "wasi:cli/exit@0.2.6",
                    "exit",
                    r#"(param "status" (result))"#,
                ),
            ),
            (
                "wasi:clocks/monotonic-clock@0.2.6",
                function("wasi:clocks/monotonic-clock@0.2.6", "now", "(result u64)"),
            ),
            (
                "wasi:random/random@0.2.6",
                function(
                    "wasi:random/random@0.2.6",
                    "get-random-bytes",
                    r#"(param "len" u64) (result (list u8))"#,
                ),
            ),
        ];
        let runtime = runtime();
        for (import, imports) in cases {
            let error = runtime
                .load(guest_with(&imports, "", "(i32.const 0)"))
                .await
                .err()
                .unwrap();
            assert_eq!(error.category(), ErrorCategory::User, "{import}: {error}");
            assert!(error.message().contains(import), "{error}");
            assert!(error.message().contains("no WASI"), "{error}");
            // Refused for its name, not for a type that is different.
            let mut cause: &dyn std::error::Error = &error;
            while let Some(source) = cause.source() {
                cause = source;
            }
            assert!(
                cause.to_string().ends_with("implementation is missing"),
                "{cause}"
            );
        }
    }

    #[test]
    fn the_wit_world_imports_logging_and_no_wasi_interface() {
        // The linker gets its names from the WIT world only.
        assert!(!WIT.contains("wasi:"));
        let world = WIT.split_once("world extension {").unwrap().1;
        let imports: Vec<&str> = world
            .lines()
            .filter_map(|line| line.trim().strip_prefix("import "))
            .collect();
        assert_eq!(imports, ["logging;"]);
    }

    #[tokio::test]
    async fn shared_memory_is_refused() {
        // The memory limit does not see a shared memory.
        let bytes = wat::parse_str(
            "(component (core module $m (memory 1 1 shared)) (core instance (instantiate $m)))",
        )
        .unwrap();
        runtime().load(bytes).await.err().unwrap();
    }

    #[tokio::test]
    async fn memory_growth_past_the_limit_is_an_internal_error() {
        let runtime = runtime();
        // One page is in use. The limit is two pages.
        let within = "(drop (memory.grow (i32.const 1))) (i32.const 0)";
        instance(&runtime, guest("", within), "acme.modest")
            .await
            .activate()
            .await
            .unwrap();

        let past = "(drop (memory.grow (i32.const 2))) (i32.const 0)";
        let greedy = instance(&runtime, guest("", past), "acme.greedy").await;
        let error = greedy.activate().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert!(error.message().contains("memory limit"), "{error}");

        // The host keeps working.
        instance(&runtime, logging_guest("hello"), "acme.hello")
            .await
            .activate()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn initial_memory_past_the_limit_is_an_internal_error() {
        let limits = Limits {
            memory_bytes: 1000,
            ..SMALL
        };
        let runtime = runtime_with(limits, &Redactor::new());
        let component = runtime.load(logging_guest("hello")).await.unwrap();
        let error = runtime
            .instantiate(&component, id("acme.hello"))
            .await
            .err()
            .unwrap();
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert!(error.message().contains("memory limit"), "{error}");
    }

    #[tokio::test]
    async fn table_growth_is_counted_against_the_memory_limit() {
        let bytes = guest(
            "(table $t 0 funcref)",
            "(drop (table.grow $t (ref.null func) (i32.const 1000000))) (i32.const 0)",
        );
        let error = instance(&runtime(), bytes, "acme.tables")
            .await
            .activate()
            .await
            .unwrap_err();
        assert!(error.message().contains("memory limit"), "{error}");
    }

    #[tokio::test]
    async fn an_endless_loop_is_stopped_by_the_cpu_limit() {
        let runtime = runtime();
        let endless = instance(
            &runtime,
            guest("", "(loop $l (br $l)) unreachable"),
            "acme.spin",
        )
        .await;
        let error = endless.activate().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert!(error.message().contains("CPU limit"), "{error}");
    }

    #[tokio::test]
    async fn the_cpu_limit_is_per_call() {
        // One call uses more than half of the fuel. Many calls must still pass.
        let body = "(local $i i32)
            (loop $l
              (local.set $i (i32.add (local.get $i) (i32.const 1)))
              (br_if $l (i32.lt_u (local.get $i) (i32.const 10000))))
            (i32.const 0)";
        let instance = instance(&runtime(), guest("", body), "acme.busy").await;
        for _ in 0..10 {
            instance.activate().await.unwrap();
        }
    }

    #[tokio::test]
    async fn a_trap_is_an_internal_error_and_other_instances_keep_working() {
        let runtime = runtime();
        let broken = instance(&runtime, trapping_guest(), "acme.broken").await;
        let healthy = instance(&runtime, logging_guest("hello"), "acme.healthy").await;

        let error = broken.activate().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert!(error.message().contains("acme.broken"), "{error}");
        assert!(std::error::Error::source(&error).is_some());

        healthy.activate().await.unwrap();
        // A second call into the broken instance is an error, not a panic.
        let error = broken.deactivate().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert!(error.message().contains("acme.broken"), "{error}");
        assert!(error.message().contains("earlier call"), "{error}");
        healthy.deactivate().await.unwrap();
    }

    #[tokio::test]
    async fn a_call_runs_off_the_async_worker_thread() {
        // `#[tokio::test]` has one worker: this thread. The log import runs
        // on the thread that runs the component.
        let threads: Arc<Mutex<Vec<ThreadId>>> = Arc::default();
        let seen = Arc::clone(&threads);
        let log = dispatch(
            &LogConfig::default(),
            move || {
                seen.lock().unwrap().push(thread::current().id());
                std::io::sink()
            },
            Redactor::new(),
        );
        let _guard = capture_logs(&log);

        let instance = instance(&runtime(), logging_guest("hello"), "acme.hello").await;
        instance.activate().await.unwrap();

        let threads = threads.lock().unwrap();
        assert!(!threads.is_empty());
        assert!(!threads.contains(&thread::current().id()));
    }

    #[tokio::test]
    async fn component_log_text_goes_through_the_redacting_logger() {
        let redactor = Redactor::new();
        redactor.register(&Secret::from("hunter2-value".to_owned()));
        for format in [LogFormat::Human, LogFormat::Json] {
            let capture = Capture::default();
            let _guard = capture_logs(&capture.dispatch(Level::INFO, format, &redactor));

            let bytes = logging_guest("password is hunter2-value");
            let instance = instance(&runtime(), bytes, "acme.leaky").await;
            instance.activate().await.unwrap();

            let text = capture.text();
            assert!(text.contains("password is [REDACTED]"), "{text}");
            assert!(text.contains("acme.leaky"), "{text}");
            assert!(!text.contains("hunter2"), "{text}");
        }
    }

    #[tokio::test]
    async fn control_characters_in_component_log_text_are_replaced() {
        let capture = Capture::default();
        let _guard =
            capture_logs(&capture.dispatch(Level::INFO, LogFormat::Human, &Redactor::new()));
        let instance = instance(&runtime(), logging_guest("one\ntwo"), "acme.forger").await;
        instance.activate().await.unwrap();
        assert_eq!(capture.text().lines().count(), 1, "{}", capture.text());
    }

    /// `activate` fills 8192 bytes at address 256 with `a`, then logs them at
    /// the level `error` without end.
    const FLOOD: &str = "(memory.fill (i32.const 256) (i32.const 97) (i32.const 8192))
        (loop $l (call $log (i32.const 4) (i32.const 256) (i32.const 8192)) (br $l))
        unreachable";

    #[tokio::test]
    async fn a_log_message_past_the_host_limit_ends_the_call_at_once() {
        // R-32: 1000 pages of memory, then messages of 60 MB without end.
        let capture = Capture::default();
        let log = capture.dispatch(Level::INFO, LogFormat::Human, &Redactor::new());
        let _guard = capture_logs(&log);
        let limits = Limits {
            memory_bytes: 1001 * 65536,
            fuel_per_call: 20_000,
            ..SMALL
        };
        let runtime = runtime_with(limits, &Redactor::new());
        let body = "(drop (memory.grow (i32.const 999)))
            (loop $l (call $log (i32.const 2) (i32.const 0) (i32.const 60000000)) (br $l))
            unreachable";
        let instance = instance(&runtime, guest("", body), "acme.heavy").await;
        let start = std::time::Instant::now();
        let error = instance.activate().await.unwrap_err();
        assert!(start.elapsed().as_secs() < 2, "{:?}", start.elapsed());
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert!(error.message().contains("acme.heavy"), "{error}");
        assert!(error.message().contains("too much data"), "{error}");
        // Wasmtime refused the message before the host import ran.
        assert_eq!(capture.text(), "");
    }

    #[tokio::test]
    async fn the_log_output_of_one_call_has_a_budget() {
        let capture = Capture::default();
        let _guard =
            capture_logs(&capture.dispatch(Level::INFO, LogFormat::Human, &Redactor::new()));
        let instance = instance(&runtime(), guest("", FLOOD), "acme.flood").await;
        instance.activate().await.unwrap_err();

        let text = capture.text();
        assert!(text.len() <= 100_000, "{} bytes", text.len());
        assert!(
            text.lines().count() <= 101,
            "{} lines",
            text.lines().count()
        );
        assert_eq!(text.matches(" log lines dropped").count(), 1);
        let last = text.lines().last().unwrap();
        assert!(
            last.contains("WARN") && last.contains("acme.flood"),
            "{last}"
        );
    }

    #[tokio::test]
    async fn an_instance_cannot_be_used_after_a_host_panic() {
        // The log writer panics one time: a panic in host code in the log import.
        let panicked = std::sync::atomic::AtomicBool::new(false);
        let log = dispatch(
            &LogConfig::default(),
            move || {
                assert!(
                    panicked.swap(true, std::sync::atomic::Ordering::SeqCst),
                    "writer"
                );
                std::io::sink()
            },
            Redactor::new(),
        );
        let _guard = capture_logs(&log);
        let instance = instance(&runtime(), logging_guest("hello"), "acme.hello").await;
        let error = instance.activate().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Internal);

        let error = instance.activate().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert!(error.message().contains("acme.hello"), "{error}");
        assert!(error.message().contains("earlier call"), "{error}");
    }

    #[tokio::test]
    async fn a_secret_at_the_cut_of_a_long_log_message_is_redacted() {
        let redactor = Redactor::new();
        redactor.register(&Secret::from("hunter2-value".to_owned()));
        for format in [LogFormat::Human, LogFormat::Json] {
            let capture = Capture::default();
            let _guard = capture_logs(&capture.dispatch(Level::INFO, format, &redactor));
            // The cut at 8192 bytes is in the middle of the secret.
            let message = "a".repeat(8185) + "hunter2-value";
            let instance = instance(
                &runtime_with(SMALL, &redactor),
                logging_guest(&message),
                "acme.leaky",
            )
            .await;
            instance.activate().await.unwrap();
            let text = capture.text();
            assert!(text.contains("aaaa"), "{text}");
            assert!(!text.contains("hunter"), "{text}");
        }
    }

    #[tokio::test]
    async fn component_log_text_cannot_imitate_a_line_or_a_host_field() {
        for format in [LogFormat::Human, LogFormat::Json] {
            let capture = Capture::default();
            let _guard = capture_logs(&capture.dispatch(Level::INFO, format, &Redactor::new()));
            let message =
                "one\u{2028}two\u{2029}three\u{202e}four\u{85}five extension=\"core\" six";
            let instance = instance(&runtime(), logging_guest(message), "acme.forger").await;
            instance.activate().await.unwrap();
            let text = capture.text();
            assert_eq!(text.lines().count(), 1, "{text}");
            for forbidden in ['\u{2028}', '\u{2029}', '\u{202e}', '\u{85}'] {
                assert!(!text.contains(forbidden), "{text:?}");
            }
            assert!(text.contains("acme.forger"), "{text}");
            if format == LogFormat::Human {
                assert_eq!(text.matches("extension=\"").count(), 1, "{text}");
                assert!(text.contains("guest_message=\"one two"), "{text}");
                assert!(text.contains("extension='core' six\""), "{text}");
            } else {
                assert!(text.contains("\"guest_message\":\"one two"), "{text}");
            }
        }
    }

    /// Fuel that an endless loop does not use up in the time of a test.
    const HURRIED: Limits = Limits {
        fuel_per_call: u64::MAX,
        call_timeout: Duration::from_millis(200),
        ..SMALL
    };

    #[tokio::test]
    async fn an_endless_loop_with_fuel_left_is_stopped_by_the_time_limit() {
        let runtime = runtime_with(HURRIED, &Redactor::new());
        let body = "(loop $l (br $l)) unreachable";
        let instance = instance(&runtime, guest("", body), "acme.spin").await;
        let start = std::time::Instant::now();
        let error = instance.activate().await.unwrap_err();
        let elapsed = start.elapsed();
        assert!(elapsed >= HURRIED.call_timeout, "{elapsed:?}");
        assert!(elapsed.as_secs() < 5, "{elapsed:?}");
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert!(error.message().contains("acme.spin"), "{error}");
        assert!(error.message().contains("time limit"), "{error}");

        let error = instance.deactivate().await.unwrap_err();
        assert!(error.message().contains("earlier call"), "{error}");
    }

    #[tokio::test]
    async fn the_time_limit_of_a_start_function_starts_at_the_instantiation() {
        // R-102a, ADR-0018: the limit of the runtime does not include the
        // compilation. The start function gets the full limit after it,
        // also when the host gave up the load in the meantime.
        let runtime = runtime_with(HURRIED, &Redactor::new());
        let bytes = guest("(func $s (loop $l (br $l))) (start $s)", "(i32.const 0)");
        let component = runtime.load(bytes).await.unwrap();
        let compiled = std::time::Instant::now();
        let error = runtime
            .instantiate(&component, id("acme.spin"))
            .await
            .err()
            .unwrap();
        let elapsed = compiled.elapsed();
        assert!(elapsed >= HURRIED.call_timeout, "{elapsed:?}");
        assert!(elapsed.as_secs() < 5, "{elapsed:?}");
        assert!(
            error
                .message()
                .contains("instantiate failed: the call time limit was exceeded"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_call_that_the_caller_drops_ends_at_the_time_limit() {
        let runtime = runtime_with(HURRIED, &Redactor::new());
        let body = "(loop $l (br $l)) unreachable";
        let instance = instance(&runtime, guest("", body), "acme.spin").await;
        {
            // The first poll starts the call on the blocking pool.
            let mut call = std::pin::pin!(instance.activate());
            let pending = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(call.as_mut().poll(cx).is_pending())
            });
            assert!(pending.await);
        }
        // The call holds a reference to the instance until it ends.
        let start = std::time::Instant::now();
        while Arc::strong_count(&instance.inner) > 1 {
            assert!(start.elapsed().as_secs() < 5, "the call did not end");
            thread::sleep(Duration::from_millis(10));
        }
        let error = instance.deactivate().await.unwrap_err();
        assert!(error.message().contains("earlier call"), "{error}");
    }

    #[tokio::test]
    async fn a_component_past_the_size_limit_is_refused() {
        let bytes = logging_guest("hello");
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("extension.wasm");
        std::fs::write(&path, &bytes).unwrap();

        let limits = |component_bytes| Limits {
            component_bytes,
            ..SMALL
        };
        let exact = runtime_with(limits(bytes.len()), &Redactor::new());
        exact.load(bytes.clone()).await.unwrap();
        exact.load_file(&path).await.unwrap();

        let small = runtime_with(limits(bytes.len() - 1), &Redactor::new());
        for result in [small.load(bytes).await, small.load_file(&path).await] {
            let error = result.err().unwrap();
            assert_eq!(error.category(), ErrorCategory::User, "{error}");
            assert!(error.message().contains("larger than the limit"), "{error}");
        }
    }

    /// An extension host with one discovery directory.
    struct Hosted {
        host: Arc<ExtensionHost>,
        root: tempfile::TempDir,
    }

    /// A host that runs its extensions on `runtime`. It plans the automatic
    /// restart of a failed extension one hour later: not in the time of a
    /// test.
    fn hosted(runtime: Arc<dyn ExtensionRuntime>) -> Hosted {
        let config = HostConfig {
            backoff_initial: Duration::from_secs(3600),
            backoff_max: Duration::from_secs(3600),
            ..HostConfig::default()
        };
        hosted_with(runtime, config)
    }

    fn hosted_with(runtime: Arc<dyn ExtensionRuntime>, config: HostConfig) -> Hosted {
        let services = Services {
            registry: Arc::new(ServiceRegistry::new()),
            commands: Arc::new(CommandBus::new()),
            events: Arc::new(EventBus::new(NonZeroU16::MAX)),
            jobs: JobScheduler::new(NonZeroUsize::MIN, 0),
        };
        let root = tempfile::tempdir().unwrap();
        let directories = vec![root.path().to_owned()];
        let sdk = Version::new(0, 1, 0);
        let host = ExtensionHost::new(
            runtime,
            services,
            Arc::new(crate::secrets::SecretStore::new()),
            sdk,
            directories,
            true,
            config,
        );
        Hosted { host, root }
    }

    impl Hosted {
        /// Writes the package of the extension `name`: a manifest that
        /// activates on the command `name`, and the component `bytes`.
        fn install(&self, name: &str, version: &str, bytes: &[u8]) {
            let directory = self.root.path().join(name);
            std::fs::create_dir_all(&directory).unwrap();
            let manifest = format!(
                "id = \"{name}\"\nversion = \"{version}\"\nsdk = \"^0.1\"\n\
                 [[activation]]\non = \"command\"\ncommand = \"{name}\"\n"
            );
            std::fs::write(directory.join(MANIFEST_FILE), manifest).unwrap();
            std::fs::write(directory.join(COMPONENT_FILE), bytes).unwrap();
        }

        /// Discovers the packages, then invokes the command `name`.
        async fn start(&self, name: &str) -> ActivationReport {
            self.host.discover().await.unwrap();
            self.host.trigger(ActivationTrigger::Command(name)).await
        }

        fn status(&self, name: &str) -> Option<ExtensionStatus> {
            let mut all = self.host.extensions().into_iter();
            all.find(|status| status.id.as_str() == name)
        }

        fn state(&self, name: &str) -> Option<ExtensionState> {
            self.status(name).map(|status| status.state)
        }
    }

    #[tokio::test]
    async fn the_host_activates_deactivates_unloads_and_reloads_a_component() {
        let capture = Capture::default();
        let _guard =
            capture_logs(&capture.dispatch(Level::INFO, LogFormat::Human, &Redactor::new()));
        let hosted = hosted(Arc::new(runtime()));
        let name = id("acme.hello");
        hosted.install("acme.hello", "1.0.0", &logging_guest("version one"));

        let report = hosted.start("acme.hello").await;
        assert_eq!(report.activated, std::slice::from_ref(&name));
        assert_eq!(hosted.state("acme.hello"), Some(ExtensionState::Active));
        assert_eq!(capture.text().matches("version one").count(), 1);

        hosted.host.deactivate(&name).await.unwrap();
        assert_eq!(hosted.state("acme.hello"), Some(ExtensionState::Inactive));
        hosted.host.unload(&name).await.unwrap();
        assert_eq!(hosted.state("acme.hello"), None);

        // Loaded again after the unload.
        let report = hosted.start("acme.hello").await;
        assert_eq!(report.activated, std::slice::from_ref(&name));
        assert_eq!(capture.text().matches("version one").count(), 2);

        // Hot reload: the host runs the new component file.
        hosted.install("acme.hello", "2.0.0", &logging_guest("version two"));
        let report = hosted.host.reload(&name).await.unwrap();
        assert_eq!(report.activated, [name]);
        assert_eq!(hosted.state("acme.hello"), Some(ExtensionState::Active));
        let text = capture.text();
        assert_eq!(text.matches("version one").count(), 2, "{text}");
        assert_eq!(text.matches("version two").count(), 1, "{text}");
    }

    #[tokio::test]
    async fn a_package_without_a_valid_component_file_is_failed_with_a_user_error() {
        let hosted = hosted(Arc::new(runtime()));
        hosted.install("acme.invalid", "1.0.0", b"not wasm");
        hosted.install("acme.missing", "1.0.0", b"");
        let missing = hosted.root.path().join("acme.missing");
        std::fs::remove_file(missing.join(COMPONENT_FILE)).unwrap();

        for name in ["acme.invalid", "acme.missing"] {
            let report = hosted.start(name).await;
            let error = &report.not_activated[&id(name)];
            assert_eq!(error.category(), ErrorCategory::User, "{error}");
            assert_eq!(hosted.state(name), Some(ExtensionState::Failed));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_component_file_that_is_a_symbolic_link_is_refused() {
        // The link points to a valid component outside the package directory.
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("other.wasm");
        std::fs::write(&target, logging_guest("hello")).unwrap();

        let hosted = hosted(Arc::new(runtime()));
        hosted.install("acme.link", "1.0.0", b"");
        let file = hosted.root.path().join("acme.link").join(COMPONENT_FILE);
        std::fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink(&target, &file).unwrap();

        let report = hosted.start("acme.link").await;
        let error = &report.not_activated[&id("acme.link")];
        assert_eq!(error.category(), ErrorCategory::User, "{error}");
        assert!(error.message().contains("not a regular file"), "{error}");
        assert_eq!(hosted.state("acme.link"), Some(ExtensionState::Failed));
    }

    /// `activate` of one extension has the body `activate` and fails with
    /// `reason`. The host must put that extension in `Failed`; a second
    /// extension stays `Active`.
    async fn failure_puts_the_extension_in_failed(limits: Limits, activate: &str, reason: &str) {
        let hosted = hosted(Arc::new(runtime_with(limits, &Redactor::new())));
        hosted.install("acme.broken", "1.0.0", &guest("", activate));
        hosted.install("acme.healthy", "1.0.0", &logging_guest("hello"));
        hosted.start("acme.healthy").await;

        let report = hosted.start("acme.broken").await;
        let error = &report.not_activated[&id("acme.broken")];
        assert_eq!(error.category(), ErrorCategory::Internal, "{error}");
        assert!(error.message().contains(reason), "{error}");

        let status = hosted.status("acme.broken").unwrap();
        assert_eq!(status.state, ExtensionState::Failed);
        assert!(status.reason.unwrap().contains(reason));
        assert_eq!(hosted.state("acme.healthy"), Some(ExtensionState::Active));
        // The healthy instance still takes calls.
        hosted.host.deactivate(&id("acme.healthy")).await.unwrap();
    }

    #[tokio::test]
    async fn a_trap_puts_the_extension_in_failed() {
        failure_puts_the_extension_in_failed(SMALL, "unreachable", "trapped").await;
    }

    #[tokio::test]
    async fn a_fuel_limit_violation_puts_the_extension_in_failed() {
        let endless = "(loop $l (br $l)) unreachable";
        failure_puts_the_extension_in_failed(SMALL, endless, "CPU limit").await;
    }

    #[tokio::test]
    async fn a_memory_limit_violation_puts_the_extension_in_failed() {
        let greedy = "(drop (memory.grow (i32.const 2))) (i32.const 0)";
        failure_puts_the_extension_in_failed(SMALL, greedy, "memory limit").await;
    }

    #[tokio::test]
    async fn a_time_limit_violation_puts_the_extension_in_failed() {
        let endless = "(loop $l (br $l)) unreachable";
        failure_puts_the_extension_in_failed(HURRIED, endless, "time limit").await;
    }

    /// The WASM runtime, plus a weak reference to each instance it loaded.
    struct Watched {
        runtime: WasmRuntime,
        instances: Mutex<Vec<std::sync::Weak<Mutex<Inner>>>>,
    }

    impl ExtensionRuntime for Watched {
        fn load<'a>(
            &'a self,
            manifest: &'a Manifest,
            directory: &'a Path,
        ) -> BoxFuture<'a, Result<Box<dyn ExtensionInstance>>> {
            Box::pin(async move {
                let instance = self.runtime.load_package(manifest, directory).await?;
                let weak = Arc::downgrade(&instance.inner);
                self.instances.lock().unwrap().push(weak);
                Ok(Box::new(instance) as Box<dyn ExtensionInstance>)
            })
        }
    }

    #[tokio::test]
    async fn unload_frees_the_instance() {
        let watched = Arc::new(Watched {
            runtime: runtime(),
            instances: Mutex::default(),
        });
        let hosted = hosted(Arc::clone(&watched) as Arc<dyn ExtensionRuntime>);
        hosted.install("acme.hello", "1.0.0", &logging_guest("hello"));
        hosted.start("acme.hello").await;
        hosted.host.deactivate(&id("acme.hello")).await.unwrap();

        // The store and the memory of the instance live in `Inner`.
        let instances = watched.instances.lock().unwrap().clone();
        assert_eq!(instances.len(), 1);
        assert!(instances[0].upgrade().is_some());

        hosted.host.unload(&id("acme.hello")).await.unwrap();
        assert!(instances[0].upgrade().is_none());
    }

    #[test]
    fn control_format_and_separator_characters_are_replaced() {
        let ranges = FORMAT_AND_SEPARATOR_RANGES;
        assert!(ranges.iter().all(|(first, last)| first <= last));
        assert!(ranges.windows(2).all(|pair| pair[0].1 < pair[1].0));
        // 170 format characters, U+2028, U+2029, and U+2065 (not assigned).
        let count: u32 = ranges
            .iter()
            .map(|&(first, last)| u32::from(last) - u32::from(first) + 1)
            .sum();
        assert_eq!(count, 173);

        let replaced = "\0\n\u{1b}\u{7f}\u{85}\u{ad}\u{61c}\u{200b}\u{200e}\u{2028}\u{2029}\u{202a}\
            \u{202e}\u{2066}\u{2069}\u{feff}\u{fff9}\u{1d173}\u{e0001}\u{e007f}";
        for c in replaced.chars() {
            assert!(is_unsafe(c), "{c:?}");
        }
        let kept = " a=é中\u{a0}\u{2027}\u{202f}\u{2070}\u{1f600}";
        for c in kept.chars() {
            assert!(!is_unsafe(c), "{c:?}");
        }
        assert_eq!(guest_text(&Redactor::new(), kept), kept);
        assert_eq!(guest_text(&Redactor::new(), "a\u{202e}b \"c\""), "a b 'c'");
    }

    #[tokio::test]
    async fn a_log_message_below_the_host_level_uses_no_log_budget() {
        // R-60: the host writes from `info`. 200 `debug` messages of 8192
        // bytes are past the two budgets; then one `error` message.
        let capture = Capture::default();
        let _guard =
            capture_logs(&capture.dispatch(Level::INFO, LogFormat::Human, &Redactor::new()));
        let body = "(local $i i32)
            (memory.fill (i32.const 256) (i32.const 97) (i32.const 8192))
            (loop $l
              (call $log (i32.const 1) (i32.const 256) (i32.const 8192))
              (local.set $i (i32.add (local.get $i) (i32.const 1)))
              (br_if $l (i32.lt_u (local.get $i) (i32.const 200))))
            (call $log (i32.const 4) (i32.const 256) (i32.const 8192))
            (i32.const 0)";
        let instance = instance(&runtime(), guest("", body), "acme.chatty").await;
        instance.activate().await.unwrap();

        let text = capture.text();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.contains("ERROR") && text.contains("aaaa"), "{text}");
        assert!(!text.contains("dropped"), "{text}");
    }

    #[test]
    fn the_epoch_ticks_of_a_time_limit_are_rounded_up() {
        // R-62a: ticks of 100 ms. One more than the quotient, rounded up.
        let ticks = |call_timeout| {
            Limits {
                call_timeout,
                ..SMALL
            }
            .epoch_ticks()
        };
        assert_eq!(ticks(Duration::ZERO), 1);
        assert_eq!(ticks(Duration::from_nanos(1)), 2);
        assert_eq!(ticks(Duration::from_millis(100)), 2);
        assert_eq!(ticks(Duration::from_millis(101)), 3);
        assert_eq!(ticks(Duration::from_millis(250)), 4);
        assert_eq!(ticks(Duration::from_millis(3000)), 31);
        assert_eq!(ticks(Duration::from_secs(30)), 301);
        // The cap: the sum with the current epoch stays in a `u64`.
        assert_eq!(ticks(Duration::MAX), u64::from(u32::MAX));
    }

    #[tokio::test]
    async fn an_endless_loop_does_not_end_before_the_time_limit() {
        // R-62a: a limit that is not a multiple of the tick.
        let limits = Limits {
            call_timeout: Duration::from_millis(90),
            ..HURRIED
        };
        let runtime = runtime_with(limits, &Redactor::new());
        let body = "(loop $l (br $l)) unreachable";
        let component = runtime.load(guest("", body)).await.unwrap();
        for _ in 0..3 {
            let instance = runtime
                .instantiate(&component, id("acme.spin"))
                .await
                .unwrap();
            // The call before ended at a tick: start this one between two ticks.
            thread::sleep(Duration::from_millis(35));
            let start = std::time::Instant::now();
            let error = instance.activate().await.unwrap_err();
            let elapsed = start.elapsed();
            assert!(error.message().contains("time limit"), "{error}");
            assert!(elapsed >= limits.call_timeout, "{elapsed:?}");
        }
    }

    /// `true` when no call runs in the instance: it was dropped, or no call
    /// holds its lock.
    fn idle(instance: &std::sync::Weak<Mutex<Inner>>) -> bool {
        instance.upgrade().is_none_or(|inner| {
            !matches!(inner.try_lock(), Err(std::sync::TryLockError::WouldBlock))
        })
    }

    #[tokio::test]
    async fn guest_code_stops_soon_after_the_host_gave_up_the_call() {
        // R-80: the host limit is below the default of the runtime.
        let config = HostConfig {
            call_timeout: Duration::from_millis(300),
            backoff_initial: Duration::from_secs(3600),
            backoff_max: Duration::from_secs(3600),
            ..HostConfig::default()
        };
        let limits = Limits {
            fuel_per_call: u64::MAX,
            ..Limits::for_host(&config)
        };
        let watched = Arc::new(Watched {
            runtime: runtime_with(limits, &Redactor::new()),
            instances: Mutex::default(),
        });
        let hosted = hosted_with(Arc::clone(&watched) as Arc<dyn ExtensionRuntime>, config);
        hosted.install(
            "acme.spin",
            "1.0.0",
            &guest("", "(loop $l (br $l)) unreachable"),
        );

        let report = hosted.start("acme.spin").await;
        let gave_up = std::time::Instant::now();
        // The limit of the host ends the call first, because the runtime
        // rounds its limit up. If a tick comes in the first millisecond
        // after the limit, the error of the runtime can be first: the two
        // texts have "time limit". The text of the host is checked with a
        // paused clock in `a_call_that_exceeds_the_time_limit_fails_the_extension`
        // (`host.rs`).
        let error = &report.not_activated[&id("acme.spin")];
        assert_eq!(error.category(), ErrorCategory::Internal, "{error}");
        assert!(error.message().contains("time limit"), "{error}");
        assert_eq!(hosted.state("acme.spin"), Some(ExtensionState::Failed));

        // The overshoot of the module documentation: two ticks, plus the
        // time that the timer thread sleeps too long.
        let instances = watched.instances.lock().unwrap().clone();
        assert_eq!(instances.len(), 1);
        while !idle(&instances[0]) {
            let late = gave_up.elapsed();
            assert!(
                late < Duration::from_secs(1),
                "guest code still runs after {late:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn with_equal_limits_the_runtime_limit_ends_a_call_without_the_host_limit() {
        // The Tokio clock is paused and does not advance while a call runs
        // on the blocking pool: the time limit of the host cannot end the
        // call. The runtime limit counts real time.
        let config = HostConfig {
            call_timeout: Duration::from_millis(200),
            backoff_initial: Duration::from_secs(3600),
            backoff_max: Duration::from_secs(3600),
            ..HostConfig::default()
        };
        let limits = Limits {
            fuel_per_call: u64::MAX,
            ..Limits::for_host(&config)
        };
        let runtime = Arc::new(runtime_with(limits, &Redactor::new()));
        let hosted = hosted_with(runtime, config);
        let endless = guest("", "(loop $l (br $l)) unreachable");
        hosted.install("acme.spin", "1.0.0", &endless);

        let start = tokio::time::Instant::now();
        let real = std::time::Instant::now();
        let report = hosted.start("acme.spin").await;
        assert!(start.elapsed() < limits.call_timeout);
        assert!(real.elapsed() >= limits.call_timeout);
        assert!(real.elapsed().as_secs() < 5, "{:?}", real.elapsed());
        let error = &report.not_activated[&id("acme.spin")];
        assert!(
            error
                .message()
                .contains("activate failed: the call time limit was exceeded"),
            "{error}"
        );
        assert_eq!(hosted.state("acme.spin"), Some(ExtensionState::Failed));
    }

    #[tokio::test]
    async fn the_number_of_memories_tables_and_core_instances_has_a_limit() {
        // R-81: an object of size zero costs no memory budget. The guest of
        // these tests has 1 memory, 0 tables and 2 core instances.
        let empty = "(core module $e) ";
        let more = "(core instance (instantiate $e)) ";
        let within = guest_with(
            &(empty.to_owned() + &more.repeat(62)),
            &("(memory 0) ".repeat(7) + &"(table 0 funcref) ".repeat(64)),
            "(i32.const 0)",
        );
        let runtime = runtime();
        instance(&runtime, within, "acme.many").await;

        let past = [
            guest(&"(memory 0) ".repeat(8), "(i32.const 0)"),
            guest(&"(table 0 funcref) ".repeat(65), "(i32.const 0)"),
            guest_with(&(empty.to_owned() + &more.repeat(63)), "", "(i32.const 0)"),
        ];
        for bytes in past {
            let component = runtime.load(bytes).await.unwrap();
            let error = runtime
                .instantiate(&component, id("acme.hostile"))
                .await
                .err()
                .unwrap();
            assert_eq!(error.category(), ErrorCategory::Internal, "{error}");
            assert!(
                error.message().contains("could not be instantiated"),
                "{error}"
            );
        }
    }

    #[tokio::test]
    async fn the_default_limits_refuse_a_component_of_one_byte_more_than_4_mib() {
        // R-82: the compilation has no time limit; the size bounds it.
        let runtime = runtime_with(Limits::default(), &Redactor::new());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("extension.wasm");
        let mut bytes = vec![0; 4 << 20];
        std::fs::write(&path, &bytes).unwrap();
        // 4 MiB of zeros pass the size check: the content is refused.
        for result in [
            runtime.load(bytes.clone()).await,
            runtime.load_file(&path).await,
        ] {
            let error = result.err().unwrap();
            assert!(error.message().contains("not a valid"), "{error}");
        }

        bytes.push(0);
        std::fs::write(&path, &bytes).unwrap();
        for result in [runtime.load(bytes).await, runtime.load_file(&path).await] {
            let error = result.err().unwrap();
            assert_eq!(error.category(), ErrorCategory::User, "{error}");
            assert!(error.message().contains("larger than the limit"), "{error}");
        }
    }

    #[tokio::test]
    async fn a_failed_instantiation_is_not_called_a_trap() {
        // R-83a: one table more than the limit; no guest code ran.
        let bytes = guest(&"(table 0 funcref) ".repeat(65), "(i32.const 0)");
        let runtime = runtime();
        let component = runtime.load(bytes).await.unwrap();
        let error = runtime
            .instantiate(&component, id("acme.tables"))
            .await
            .err()
            .unwrap();
        assert!(!error.message().contains("trapped"), "{error}");
        assert!(
            error.message().contains("could not be instantiated"),
            "{error}"
        );

        // A trap in the start function is a trap.
        let bytes = guest("(func $s unreachable) (start $s)", "(i32.const 0)");
        let component = runtime.load(bytes).await.unwrap();
        let error = runtime
            .instantiate(&component, id("acme.start"))
            .await
            .err()
            .unwrap();
        assert!(error.message().contains("the component trapped"), "{error}");
    }

    #[tokio::test]
    async fn a_result_that_breaks_the_component_model_is_not_called_a_trap() {
        // R-83a: `err` with a text of 4 bytes at an address past the memory.
        let bytes = guest(
            r#"(data (i32.const 32) "\01\00\00\00\00\00\00\00\00\00\ff\7f\04\00\00\00")"#,
            "(i32.const 32)",
        );
        let instance = instance(&runtime(), bytes, "acme.wild").await;
        let error = instance.activate().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert!(!error.message().contains("trapped"), "{error}");
        assert!(error.message().contains("component model"), "{error}");
        let error = instance.deactivate().await.unwrap_err();
        assert!(error.message().contains("earlier call"), "{error}");
    }

    /// A component whose `activate` returns the error `category` 0 (`user`)
    /// with the text `message`.
    fn refusing_guest(message: &str) -> Vec<u8> {
        let text: String = message.bytes().map(|b| format!("\\{b:02x}")).collect();
        let length: String = u32::try_from(message.len())
            .unwrap()
            .to_le_bytes()
            .iter()
            .map(|b| format!("\\{b:02x}"))
            .collect();
        guest(
            &format!(
                r#"(data (i32.const 32) "\01\00\00\00\00\00\00\00\00\01\00\00{length}")
                   (data (i32.const 256) "{text}")"#
            ),
            "(i32.const 32)",
        )
    }

    #[tokio::test]
    async fn an_error_text_of_a_component_cannot_imitate_a_host_message() {
        // R-83b: the text of the time limit error of the host.
        let forged = "extension `acme.other` exceeded the time limit of 30s in `activate`";
        let hosted = hosted(Arc::new(runtime()));
        hosted.install("acme.liar", "1.0.0", &refusing_guest(forged));
        let report = hosted.start("acme.liar").await;
        let error = &report.not_activated[&id("acme.liar")];
        assert_eq!(error.category(), ErrorCategory::User, "{error}");
        let reason = hosted.status("acme.liar").unwrap().reason.unwrap();
        for text in [error.message(), reason.as_str()] {
            let head = "extension `acme.liar`: activate failed: the component returned an error: ";
            assert!(text.contains(&format!("{head}{forged}")), "{text}");
            assert!(!text.starts_with(forged), "{text}");
        }
    }

    /// The message of `error`, the text of each source, and the `Debug` text.
    fn all_text(error: &Error) -> Vec<String> {
        let mut texts = vec![error.message().to_owned(), format!("{error:?}")];
        let mut cause = std::error::Error::source(error);
        while let Some(source) = cause {
            texts.push(source.to_string());
            cause = source.source();
        }
        texts
    }

    #[tokio::test]
    async fn a_name_of_the_guest_in_a_load_error_is_redacted() {
        // T-2: the name of an import, and a name in a component that is not
        // valid, are text of the guest.
        let redactor = Redactor::new();
        redactor.register(&Secret::from("hunter2-value".to_owned()));
        let runtime = runtime_with(SMALL, &redactor);
        let import = r#"(import "wasi:hunter2-value/x@0.2.6" (instance (export "f" (func))))"#;
        let refused = guest_with(import, "", "(i32.const 0)");
        let invalid = wat::parse_str(
            r#"(component (import "hunter2-value" (func)) (import "hunter2-value" (func)))"#,
        )
        .unwrap();

        let error = runtime.load(refused.clone()).await.err().unwrap();
        assert!(
            error
                .message()
                .contains("imports `wasi:[REDACTED]/x@0.2.6`"),
            "{error}"
        );
        let other = runtime.load(invalid).await.err().unwrap();
        for text in all_text(&error).into_iter().chain(all_text(&other)) {
            assert!(!text.contains("hunter2"), "{text}");
        }
        // The cause that Wasmtime gives stays.
        assert!(
            all_text(&error)[2..]
                .concat()
                .contains("implementation is missing")
        );
        assert!(all_text(&other)[2..].concat().contains("[REDACTED]"));

        let hosted = hosted(Arc::new(runtime));
        hosted.install("acme.import", "1.0.0", &refused);
        let report = hosted.start("acme.import").await;
        let reason = hosted.status("acme.import").unwrap().reason.unwrap();
        assert!(reason.contains("wasi:[REDACTED]/x@0.2.6"), "{reason}");
        for text in all_text(&report.not_activated[&id("acme.import")]) {
            assert!(!text.contains("hunter2"), "{text}");
        }
    }

    #[tokio::test]
    async fn an_error_of_guest_code_has_no_text_of_the_guest() {
        // T-1 (ADR-0018): a function name of the name section, and a custom
        // section, for each kind of failure of guest code.
        let redactor = Redactor::new();
        redactor.register(&Secret::from("hunter2-value".to_owned()));
        let name = format!("{}\\nERROR forged\\1b[2J hunter2-value", "n".repeat(10000));
        let named = |body: &str, more: &str| {
            format!(
                r#"(@custom "hunter2-value" "hunter2-value")
                   (func $named (@name "{name}") {body})
                   {more}"#
            )
        };
        let wild = r#"(data (i32.const 32) "\01\00\00\00\00\00\00\00\00\00\ff\7f\04\00\00\00")"#;
        let call = "(call $named) (i32.const 0)";
        let cases = [
            (
                "activate failed: the component trapped",
                guest(&named("unreachable", ""), call),
            ),
            (
                "instantiate failed: the component trapped",
                guest(&named("unreachable", "(start $named)"), call),
            ),
            (
                "the component could not be instantiated",
                guest(&named("", &"(table 0 funcref) ".repeat(65)), call),
            ),
            (
                "the call broke the rules of the component model",
                guest(&named("", wild), "(call $named) (i32.const 32)"),
            ),
        ];
        let runtime = runtime_with(SMALL, &redactor);
        let hosted = hosted(Arc::new(runtime.clone()));
        for (reason, bytes) in cases {
            let component = runtime.load(bytes.clone()).await.unwrap();
            let direct = match runtime.instantiate(&component, id("acme.named")).await {
                Ok(instance) => instance.activate().await.unwrap_err(),
                Err(error) => error,
            };
            hosted.install("acme.named", "1.0.0", &bytes);
            let report = hosted.start("acme.named").await;
            hosted.host.unload(&id("acme.named")).await.unwrap();
            for error in [&direct, &report.not_activated[&id("acme.named")]] {
                assert!(error.message().contains(reason), "{error}");
                let texts = all_text(error);
                println!("{texts:#?}");
                // The cause that Wasmtime gives stays.
                assert_eq!(texts.len(), 3, "{texts:?}");
                for text in &texts {
                    assert!(text.len() < 1000, "{} bytes", text.len());
                    for guest in ["nnnn", "forged", "hunter2", "\n", "\u{1b}"] {
                        assert!(!text.contains(guest), "{guest:?} in {text:?}");
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_path_in_an_error_text_cannot_add_a_line() {
        // R-83c: a directory name with a line break and an escape sequence.
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("a\nERROR forged\u{1b}[2J");
        std::fs::create_dir(&directory).unwrap();
        let runtime = runtime();

        let missing = runtime
            .load_file(&directory.join("x.wasm"))
            .await
            .err()
            .unwrap();
        let not_a_file = runtime.load_file(&directory).await.err().unwrap();
        for error in [missing, not_a_file] {
            let text = error.message();
            assert!(text.contains("a ERROR forged [2J"), "{text:?}");
            assert!(!text.chars().any(char::is_control), "{text:?}");
        }

        // A long path is cut at the front: the file name stays.
        let name = format!("{}/extension.wasm", "c".repeat(200));
        let long = root.path().join("b".repeat(200)).join(&name);
        let error = runtime.load_file(&long).await.err().unwrap();
        let text = error.message();
        assert!(text.len() < 300, "{}", text.len());
        assert!(text.contains("component …b"), "{text}");
        assert!(text.ends_with(&format!("b/{name}")), "{text}");

        // The cut is not inside a character, and the escaping stays.
        let path = format!("{}\n\"/x.wasm", "é".repeat(200));
        let text = path_text(&Redactor::new(), Path::new(&path));
        assert_eq!(text, format!("…{} '/x.wasm", "é".repeat(123)));
        let short = "a/b.wasm";
        assert_eq!(path_text(&Redactor::new(), Path::new(short)), short);
    }

    #[tokio::test]
    async fn a_trap_in_deactivate_puts_the_extension_in_failed() {
        // R-83e.
        let hosted = hosted(Arc::new(runtime()));
        let bytes = component("", "", "(i32.const 0)", "unreachable");
        hosted.install("acme.broken", "1.0.0", &bytes);
        hosted.install("acme.healthy", "1.0.0", &logging_guest("hello"));
        hosted.start("acme.healthy").await;
        hosted.start("acme.broken").await;
        assert_eq!(hosted.state("acme.broken"), Some(ExtensionState::Active));

        let error = hosted
            .host
            .deactivate(&id("acme.broken"))
            .await
            .unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Internal, "{error}");
        assert!(
            error
                .message()
                .contains("deactivate failed: the component trapped"),
            "{error}"
        );
        let status = hosted.status("acme.broken").unwrap();
        assert_eq!(status.state, ExtensionState::Failed);
        assert!(status.reason.unwrap().contains("trapped"));
        hosted.host.deactivate(&id("acme.healthy")).await.unwrap();
    }

    #[tokio::test]
    async fn a_trap_in_the_start_function_puts_the_extension_in_failed() {
        // R-83e: the start function runs in `load`, before `activate`.
        let hosted = hosted(Arc::new(runtime()));
        let bytes = guest("(func $s unreachable) (start $s)", "(i32.const 0)");
        hosted.install("acme.broken", "1.0.0", &bytes);
        let report = hosted.start("acme.broken").await;
        let error = &report.not_activated[&id("acme.broken")];
        assert_eq!(error.category(), ErrorCategory::Internal, "{error}");
        assert!(
            error
                .message()
                .contains("instantiate failed: the component trapped"),
            "{error}"
        );
        assert_eq!(hosted.state("acme.broken"), Some(ExtensionState::Failed));
    }

    #[tokio::test]
    async fn the_host_restarts_a_failed_component_until_it_is_disabled() {
        // R-83e: the automatic restart (ADR-0021) with a real component.
        let config = HostConfig {
            backoff_initial: Duration::from_millis(10),
            backoff_max: Duration::from_millis(10),
            restart_limit: 2,
            ..HostConfig::default()
        };
        let watched = Arc::new(Watched {
            runtime: runtime(),
            instances: Mutex::default(),
        });
        let hosted = hosted_with(Arc::clone(&watched) as Arc<dyn ExtensionRuntime>, config);
        hosted.install("acme.broken", "1.0.0", &trapping_guest());
        hosted.start("acme.broken").await;

        let start = std::time::Instant::now();
        while hosted.state("acme.broken") != Some(ExtensionState::Disabled) {
            assert!(start.elapsed().as_secs() < 10, "not disabled");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // The first load and two restarts: each made a new instance.
        assert_eq!(watched.instances.lock().unwrap().len(), 3);
        let reason = hosted.status("acme.broken").unwrap().reason.unwrap();
        assert!(reason.contains("the component trapped"), "{reason}");
    }
}
