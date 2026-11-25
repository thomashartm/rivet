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
//! - CPU: each call has a fuel budget ([`Limits::fuel_per_call`]). Fuel was
//!   chosen and not epoch interruption because it gives the same result on
//!   each run and needs no timer thread. Its cost is slower guest code.
//!   Fuel counts WASM instructions. It does not limit the time in a host
//!   import that blocks; a time limit comes with issue #11.
//!
//! # Errors
//!
//! | Failure | Category |
//! | --- | --- |
//! | Invalid file, wrong world, import that the host does not give | `user` |
//! | Trap, CPU limit, memory limit | `internal` |
//! | The component returns an error | the category that the component gives |
//!
//! After a trap or a limit violation (ARCHITECTURE.md §5.6) the instance
//! cannot be used: each later call gives an error. Other instances are not affected.
//!
//! # Threads
//!
//! Compilation and each call into a component run on the blocking pool of
//! Tokio, not on an async worker thread (ARCHITECTURE.md §5.1). A call that
//! the caller drops continues until it returns or its fuel is used.

use rivet_sdk::error::{Error, Result};
use rivet_sdk::manifest::ExtensionId;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Config, Engine, ResourceLimiter, Store, Trap};

mod bindings {
    wasmtime::component::bindgen!({ path: "../rivet-sdk/wit", world: "extension" });
}

use bindings::rivet::extension::logging::{self, LogLevel};
use bindings::rivet::extension::types::{self, ErrorCategory as GuestCategory};
use bindings::{Extension, ExtensionPre};

/// The default of [`Limits::memory_bytes`]: 64 MiB.
pub const DEFAULT_MEMORY_BYTES: usize = 64 << 20;

/// The default of [`Limits::fuel_per_call`].
pub const DEFAULT_FUEL_PER_CALL: u64 = 1_000_000_000;

/// Log or error text from a component is cut to this number of bytes.
const MAX_GUEST_TEXT_BYTES: usize = 8 * 1024;

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
}

impl Default for Limits {
    /// [`DEFAULT_MEMORY_BYTES`] and [`DEFAULT_FUEL_PER_CALL`].
    fn default() -> Self {
        Self {
            memory_bytes: DEFAULT_MEMORY_BYTES,
            fuel_per_call: DEFAULT_FUEL_PER_CALL,
        }
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
}

impl logging::Host for State {
    fn log(&mut self, level: LogLevel, message: String) {
        let extension = self.id.as_str();
        let message = guest_text(&message);
        match level {
            LogLevel::Trace => tracing::trace!(extension, "{message}"),
            LogLevel::Debug => tracing::debug!(extension, "{message}"),
            LogLevel::Info => tracing::info!(extension, "{message}"),
            LogLevel::Warn => tracing::warn!(extension, "{message}"),
            LogLevel::Error => tracing::error!(extension, "{message}"),
        }
    }
}

impl types::Host for State {}

/// Turns an error that a component returned into the error of the SDK. The
/// category stays.
fn guest_error(error: &types::Error) -> Error {
    let message = guest_text(&error.message);
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

/// Makes text from a component safe for a log line or an error message: it
/// is cut to [`MAX_GUEST_TEXT_BYTES`] and has no control characters, so a
/// component cannot write a false log line.
fn guest_text(text: &str) -> String {
    text[..text.floor_char_boundary(MAX_GUEST_TEXT_BYTES)]
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
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

/// Turns a failure of Wasmtime in guest code into an `internal` error.
fn failure(id: &ExtensionId, action: &str, error: wasmtime::Error) -> Error {
    let reason = if error.is::<MemoryLimitExceeded>() {
        "the memory limit was exceeded"
    } else if error.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel) {
        "the CPU limit was exceeded"
    } else {
        "the component trapped"
    };
    Error::internal(format!("extension `{id}`: {action} failed: {reason}")).with_source(error)
}

/// The WASM runtime: one Wasmtime engine and the limits for its instances.
///
/// A clone uses the same engine.
#[derive(Clone)]
pub struct WasmRuntime {
    engine: Engine,
    linker: Arc<Linker<State>>,
    limits: Limits,
}

impl WasmRuntime {
    /// Makes a runtime. Each instance gets `limits`.
    ///
    /// # Errors
    ///
    /// Returns an `internal` error if Wasmtime cannot start on this machine.
    pub fn new(limits: Limits) -> Result<Self> {
        let unusable =
            |error: wasmtime::Error| Error::internal("cannot start Wasmtime").with_source(error);
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).map_err(unusable)?;
        let mut linker = Linker::new(&engine);
        // The only import of a component. There is no WASI on purpose.
        Extension::add_to_linker::<_, HasSelf<State>>(&mut linker, |state| state)
            .map_err(unusable)?;
        Ok(Self {
            engine,
            linker: Arc::new(linker),
            limits,
        })
    }

    /// Compiles a component from the bytes of a binary `.wasm` file.
    ///
    /// # Errors
    ///
    /// Returns a `user` error if `bytes` is not a valid component, if the
    /// component does not export the world `extension`, or if it imports
    /// something that the host does not give, for example a WASI interface.
    pub async fn load(&self, bytes: Vec<u8>) -> Result<WasmComponent> {
        let engine = self.engine.clone();
        let linker = Arc::clone(&self.linker);
        blocking(move || {
            let component = Component::new(&engine, &bytes).map_err(|error| {
                Error::user("the file is not a valid WASM component").with_source(error)
            })?;
            linker
                .instantiate_pre(&component)
                .and_then(ExtensionPre::new)
                .map(WasmComponent)
                .map_err(|error| {
                    let kind = component.component_type();
                    let message = match kind.imports(&engine).find(|(name, _)| name.starts_with("wasi:")) {
                        Some((name, _)) => format!(
                            "the WASM component imports `{name}`, but the host gives no WASI interface"
                        ),
                        None => "the WASM component does not fit the world `rivet:extension`".to_owned(),
                    };
                    Error::user(message).with_source(error)
                })
        })
        .await
    }

    /// Reads the file at `path` and compiles it with [`load`](Self::load).
    ///
    /// # Errors
    ///
    /// Returns a `user` error if the file cannot be read, and the errors of
    /// [`load`](Self::load).
    pub async fn load_file(&self, path: &Path) -> Result<WasmComponent> {
        let path = path.to_owned();
        let bytes = blocking(move || {
            std::fs::read(&path).map_err(|error| {
                Error::user(format!("cannot read the WASM component {}", path.display()))
                    .with_source(error)
            })
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
        blocking(move || {
            let state = State {
                id: id.clone(),
                memory_limit: limits.memory_bytes,
                memory_used: 0,
            };
            let mut store = Store::new(&engine, state);
            store.limiter(|state| state);
            let extension = store
                .set_fuel(limits.fuel_per_call)
                .and_then(|()| component.instantiate(&mut store))
                .map_err(|error| failure(&id, "instantiate", error))?;
            Ok(WasmInstance {
                inner: Arc::new(Mutex::new((store, extension))),
                fuel_per_call: limits.fuel_per_call,
            })
        })
        .await
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
    inner: Arc<Mutex<(Store<State>, Extension)>>,
    fuel_per_call: u64,
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
        let fuel = self.fuel_per_call;
        blocking(move || {
            // A poisoned lock is safe to use: Wasmtime refuses calls into an
            // instance that failed.
            let mut inner = inner.lock().unwrap_or_else(PoisonError::into_inner);
            let (store, extension) = &mut *inner;
            let result = store.set_fuel(fuel).and_then(|()| export(extension, store));
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(guest_error(&error)),
                Err(error) => Err(failure(&store.data().id, action, error)),
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{Capture, Level, LogConfig, LogFormat, Redactor, dispatch};
    use rivet_sdk::error::ErrorCategory;
    use rivet_sdk::secret::Secret;
    use std::sync::{Arc, Mutex};
    use std::thread::{self, ThreadId};

    const SMALL: Limits = Limits {
        memory_bytes: 2 * 65536,
        fuel_per_call: 100_000,
    };

    /// Builds a component of the `extension` world from WAT text.
    /// `data` is put in its memory of one page. `activate` is the body of the
    /// core function: it returns the address of a `result<_, error>`.
    /// Address 0 holds zeros, which is `ok`.
    fn guest_with(imports: &str, data: &str, activate: &str) -> Vec<u8> {
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
    (func (export "deactivate") (result i32) (i32.const 0)))
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
        guest(
            &format!(r#"(data (i32.const 256) "{message}")"#),
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
        WasmRuntime::new(SMALL).unwrap()
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
    }

    #[tokio::test]
    async fn a_component_file_is_loaded_and_its_lifecycle_is_called() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("extension.wasm");
        std::fs::write(&path, logging_guest("hello")).unwrap();

        let runtime = WasmRuntime::new(Limits::default()).unwrap();
        let component = runtime.load_file(&path).await.unwrap();
        let instance = runtime
            .instantiate(&component, id("acme.hello"))
            .await
            .unwrap();
        instance.activate().await.unwrap();
        instance.deactivate().await.unwrap();
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
        assert_eq!(error.message(), "nope");
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
        for (category, name) in all.into_iter().zip(wit) {
            let error = guest_error(&types::Error {
                category,
                message: String::new(),
            });
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
        let runtime = runtime();
        for import in [
            "wasi:filesystem/preopens@0.2.6",
            "wasi:sockets/tcp-create-socket@0.2.6",
            "wasi:sockets/ip-name-lookup@0.2.6",
            "wasi:cli/environment@0.2.6",
            "wasi:cli/exit@0.2.6",
            "wasi:cli/stdout@0.2.6",
            "wasi:clocks/wall-clock@0.2.6",
            "wasi:random/random@0.2.6",
        ] {
            let bytes = guest_with(
                &format!(r#"(import "{import}" (instance (export "f" (func))))"#),
                "",
                "(i32.const 0)",
            );
            let error = runtime.load(bytes).await.err().unwrap();
            assert_eq!(error.category(), ErrorCategory::User, "{import}: {error}");
            assert!(error.message().contains(import), "{error}");
            assert!(error.message().contains("no WASI"), "{error}");
        }
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
        let runtime = WasmRuntime::new(Limits {
            memory_bytes: 1000,
            ..SMALL
        })
        .unwrap();
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
        let _ = broken.deactivate().await;
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
        let _guard = tracing::dispatcher::set_default(&log);

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
            let _guard =
                tracing::dispatcher::set_default(&capture.dispatch(Level::INFO, format, &redactor));

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
        let _guard = tracing::dispatcher::set_default(&capture.dispatch(
            Level::INFO,
            LogFormat::Human,
            &Redactor::new(),
        ));
        let instance = instance(&runtime(), logging_guest("one\\ntwo"), "acme.forger").await;
        instance.activate().await.unwrap();
        assert_eq!(capture.text().lines().count(), 1, "{}", capture.text());
    }
}
