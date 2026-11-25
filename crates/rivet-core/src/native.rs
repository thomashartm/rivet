//! The process runtime for native extensions (ARCHITECTURE.md §4.3,
//! ADR-0003).
//!
//! A native extension runs in its own child process, so a crash or memory
//! corruption stays outside the engine. This module starts the process,
//! talks to it and ends it. It loads no library: the program that it starts
//! (the extension host program) does that.
//!
//! # Process
//!
//! [`ExtensionRuntime::load`] starts one process for each extension:
//! `<program> <arguments...> <package directory>`, with the package
//! directory as the working directory. [`NativeConfig::program`] must be an
//! absolute path: the runtime does not search in `PATH`.
//!
//! The process gets an empty environment plus the variables of
//! [`ENVIRONMENT`] that the engine has, so no secret of the engine
//! environment reaches it (§7.4).
//!
//! The instance owns the process. To drop the instance closes the standard
//! input of the process, waits [`NativeConfig::grace`] and then kills it. The
//! runtime always waits for the exit status, so no defunct process stays.
//! The drop does not block: a task does this work.
//!
//! The task that reads the error output ends with the process. If another
//! process holds the error output open, the runtime waits
//! [`NativeConfig::grace`] after the end of the process and then ends the
//! task.
//!
//! One extension has one process at a time (ADR-0024). The drop does not
//! wait for the end of the process, so a load of the same extension waits
//! for it: two times [`NativeConfig::grace`] at most after the drop. A load
//! while an instance of the same extension exists waits until that instance
//! is dropped.
//!
//! A limit: if the Tokio runtime ends while an instance exists, the process
//! is killed, but nothing reads its exit status. It stays defunct until the
//! engine exits.
//!
//! # Protocol
//!
//! Control messages go over the standard input and output of the process.
//! One message is one line of JSON of [`NativeConfig::max_message_bytes`] at
//! most. The engine sends one request and waits for one answer. An answer
//! that the process wrote before its exit counts: after an exit during a
//! call, the runtime waits [`NativeConfig::grace`] at most for the answer.
//!
//! | Request of the engine | Answer of the process |
//! | --- | --- |
//! | `{"type":"hello","protocol":1}` | `{"type":"hello","protocol":1}` |
//! | `{"type":"activate"}` | `{"type":"ok"}` |
//! | `{"type":"deactivate"}` | `{"type":"ok"}` |
//!
//! Each request can also have the answer
//! `{"type":"error","category":"<category>","message":"<text>"}`. The
//! category is a name of the SDK error model (§5.6), for example `user`.
//! The engine keeps the category. The message is untrusted text: see
//! [Untrusted text](#untrusted-text).
//!
//! `hello` is the first request. The answer must have the protocol version
//! [`PROTOCOL_VERSION`] and must arrive in
//! [`NativeConfig::handshake_timeout`]. `activate` and `deactivate` have no
//! time limit here: the host has one for each call
//! ([`HostConfig::call_timeout`](crate::host::HostConfig::call_timeout)).
//!
//! # Failures
//!
//! | Failure | Result |
//! | --- | --- |
//! | The program does not start | `internal` error of `load`, no process |
//! | Wrong protocol version, or no answer in time | `internal` error of `load`, no process |
//! | The process exits or closes a pipe before the handshake | `internal` error of `load`, no crash callback |
//! | The process exits or closes its output during a call, also in the middle of a line | `internal` error of the call |
//! | A malformed or too large answer | `internal` error of the call |
//! | The caller drops a call that runs | the process is killed |
//! | After the handshake, the process exits, closes its output or sends a byte while no call runs | the crash callback |
//!
//! After each of these failures the process is killed, and each later call
//! of the instance gives an `internal` error. The engine continues.
//!
//! The crash callback ([`CrashCallback`]) is for
//! [`ExtensionHost::report_crash`](crate::host::ExtensionHost::report_crash).
//! The runtime does not call it after an orderly drop of the instance.
//!
//! # Untrusted text
//!
//! The message of an error answer and the error output of the process are
//! text from extension code. The rules are those of the guest text of the
//! WASM runtime (ADR-0018): secrets are redacted, control characters are
//! replaced and the text is cut. Each line of the error output is one log
//! event of the level `info` with the text in the field `guest_message`, so
//! the text cannot imitate a field of the host.
//!
//! The error output has the log budget of the WASM runtime:
//! [`LOG_LINES_PER_CALL`] lines and [`LOG_BYTES_PER_CALL`] bytes. Each
//! request to the process (`hello`, `activate`, `deactivate`) starts a new
//! budget, which is also for the time until the next request. The runtime
//! reads the lines past the budget, so the process cannot block, and drops
//! them. It writes their number when the next budget starts and when the
//! error output ends.
//!
//! # Not in this module
//!
//! - The [`ExtensionContext`] does not cross the process boundary yet: the
//!   protocol has no message for a registration.
//! - Bulk data (Arrow IPC over a local socket, §6.6).
//! - Memory and CPU limits of the process, and OS sandboxing (§4.3).
//! - A process that the process of the extension starts itself. The runtime
//!   does not end it, and it does not wait for it: a pipe that such a
//!   process holds open delays a call by [`NativeConfig::grace`] at most
//!   (ADR-0024).

use crate::host::{ExtensionContext, ExtensionInstance, ExtensionRuntime};
use crate::logging::Redactor;
use crate::wasm::{LOG_BYTES_PER_CALL, LOG_LINES_PER_CALL, guest_text};
use rivet_sdk::error::{Error, Result};
use rivet_sdk::extension::BoxFuture;
use rivet_sdk::manifest::{ExtensionId, Manifest};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::instrument::WithSubscriber;

/// The version of the protocol between the engine and the process. The
/// handshake fails if the process has a different version.
pub const PROTOCOL_VERSION: u32 = 1;

/// The environment variables that the process gets from the engine, if the
/// engine has them. The process gets no other variable. On Windows the list
/// also has `SystemRoot`, `TEMP` and `TMP` (ADR-0024).
pub const ENVIRONMENT: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "TZ",
    #[cfg(windows)]
    "SystemRoot",
    #[cfg(windows)]
    "TEMP",
    #[cfg(windows)]
    "TMP",
];

/// The default of [`NativeConfig::handshake_timeout`]: 5 s.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// The default of [`NativeConfig::grace`]: 2 s.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(2);

/// The default of [`NativeConfig::max_message_bytes`]: 64 KiB.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// The most bytes that the runtime keeps of one line of the error output.
/// The rest of the line is read and dropped.
const ERROR_OUTPUT_LINE_BYTES: usize = 8 * 1024;

/// What the runtime calls when a process ends, closes its output or sends a
/// message while no call runs. The runtime calls it only for a process whose
/// handshake was successful. The arguments are the extension, the reason
/// and the time of the failure. The reason contains no text from the
/// process. With the time, the host ignores a report that is older than
/// the instance that it has now (ADR-0024).
///
/// The runtime calls it from a task of the Tokio runtime. It must not
/// block.
pub type CrashCallback = Arc<dyn Fn(ExtensionId, Error, Instant) + Send + Sync>;

/// How the runtime starts and limits a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeConfig {
    /// The extension host program, as an absolute path.
    pub program: PathBuf,
    /// The arguments before the package directory.
    pub arguments: Vec<OsString>,
    /// The longest time between the start of the process and its answer to
    /// `hello`. Not 0.
    pub handshake_timeout: Duration,
    /// The time that the process has to exit after its input was closed.
    /// Then the runtime kills it. Also the time that the error output has
    /// to end after the process has ended, and the time that an answer has
    /// to arrive from the pipe after the process has ended during a call.
    /// 0 is valid: the runtime kills the process at once, and the last
    /// lines of its error output and an answer directly before an exit can
    /// be lost.
    pub grace: Duration,
    /// The most bytes of one message of the process, without the line end.
    /// Not 0.
    pub max_message_bytes: usize,
}

impl NativeConfig {
    /// A configuration for `program` with no arguments,
    /// [`DEFAULT_HANDSHAKE_TIMEOUT`], [`DEFAULT_GRACE`] and
    /// [`DEFAULT_MAX_MESSAGE_BYTES`].
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            grace: DEFAULT_GRACE,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
        }
    }
}

/// The runtime that runs each extension in its own process.
pub struct NativeRuntime {
    config: NativeConfig,
    redactor: Redactor,
    on_crash: CrashCallback,
    slots: Arc<Slots>,
}

/// One permit for each extension that has a process or a load that waits.
/// See [`Slot`].
type Slots = Mutex<HashMap<ExtensionId, Arc<Semaphore>>>;

/// The right to run the one process of an extension (ADR-0024). The
/// supervisor task of the process keeps it to its end. The drop lets the
/// next load of the extension continue.
struct Slot {
    // Before `_user`: the permit is an owner of the semaphore, and the drop
    // of the user counts the owners without it.
    _permit: OwnedSemaphorePermit,
    _user: SlotUser,
}

/// One load that waits for the slot of an extension or has it.
struct SlotUser {
    id: ExtensionId,
    slots: Arc<Slots>,
    slot: Arc<Semaphore>,
}

impl Drop for SlotUser {
    /// Removes the entry of the extension if this is its last user, so the
    /// map does not grow. A load that is cancelled while it waits is a user
    /// also.
    fn drop(&mut self) {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        // The two owners are the map and this user: its permit or its wait
        // for the permit is dropped before it. Each other user is one or
        // two more, and it became a user with this lock held.
        if Arc::strong_count(&self.slot) == 2 {
            slots.remove(&self.id);
        }
    }
}

impl NativeRuntime {
    /// Creates a runtime.
    ///
    /// - `redactor` redacts the text that a process sends.
    /// - `on_crash` gets each crash that occurs while no call runs, one
    ///   time for each process at most. Connect it to
    ///   [`ExtensionHost::report_crash`](crate::host::ExtensionHost::report_crash).
    ///
    /// # Errors
    ///
    /// Returns a `user` error if [`NativeConfig::program`] is not an
    /// absolute path, or if [`NativeConfig::handshake_timeout`] or
    /// [`NativeConfig::max_message_bytes`] is 0.
    pub fn new(config: NativeConfig, redactor: Redactor, on_crash: CrashCallback) -> Result<Self> {
        if !config.program.is_absolute() {
            return Err(Error::user(format!(
                "the extension host program `{}` is not an absolute path",
                config.program.display()
            )));
        }
        // With 0 no handshake and no message can pass.
        if config.handshake_timeout.is_zero() {
            return Err(Error::user("`handshake_timeout` must not be 0"));
        }
        if config.max_message_bytes == 0 {
            return Err(Error::user("`max_message_bytes` must not be 0"));
        }
        Ok(Self {
            config,
            redactor,
            on_crash,
            slots: Arc::default(),
        })
    }

    /// Waits until no process of `id` runs. A load of a different
    /// extension does not wait, and no lock is held during the wait.
    async fn slot(&self, id: &ExtensionId) -> Result<Slot> {
        let user = {
            let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
            let slot = slots
                .entry(id.clone())
                .or_insert_with(|| Arc::new(Semaphore::new(1)));
            SlotUser {
                id: id.clone(),
                slots: Arc::clone(&self.slots),
                slot: Arc::clone(slot),
            }
        };
        // Nothing closes the semaphore.
        let permit = Arc::clone(&user.slot)
            .acquire_owned()
            .await
            .map_err(|error| failure(id, "the process slot is closed").with_source(error))?;
        Ok(Slot {
            _permit: permit,
            _user: user,
        })
    }
}

impl ExtensionRuntime for NativeRuntime {
    /// Starts the process of the extension and does the handshake.
    ///
    /// Returns the error answer of the process, or an `internal` error if
    /// the program does not start, the handshake fails or the process
    /// breaks the protocol. After an error no process is left.
    fn load<'a>(
        &'a self,
        manifest: &'a Manifest,
        directory: &'a Path,
    ) -> BoxFuture<'a, Result<Box<dyn ExtensionInstance>>> {
        Box::pin(async move {
            let id = manifest.id.clone();
            let slot = self.slot(&id).await?;
            let environment = ENVIRONMENT
                .iter()
                .filter_map(|name| std::env::var_os(name).map(|value| (name, value)));
            let mut child = Command::new(&self.config.program)
                .args(&self.config.arguments)
                .arg(directory)
                .current_dir(directory)
                .env_clear()
                .envs(environment)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                // The backstop when the Tokio runtime ends before the
                // supervisor task.
                .kill_on_drop(true)
                .spawn()
                .map_err(|error| {
                    failure(&id, "the extension host program did not start").with_source(error)
                })?;
            let pipes = (child.stdin.take(), child.stdout.take(), child.stderr.take());
            let (Some(input), Some(output), Some(errors)) = pipes else {
                let _ = child.kill().await;
                return Err(failure(&id, "the process has no pipes"));
            };
            let log = Arc::new(LogBudget::new(id.clone()));
            let error_output = tokio::spawn(
                log_error_output(errors, Arc::clone(&log), self.redactor.clone())
                    .with_current_subscriber(),
            );
            let process = Process {
                id: id.clone(),
                log,
                error_output,
                child,
                input,
                output: BufReader::new(output),
                config: self.config.clone(),
                redactor: self.redactor.clone(),
            };
            let (calls, requests) = mpsc::channel(1);
            let supervisor = tokio::spawn(
                supervise(process, requests, Arc::clone(&self.on_crash), slot)
                    .with_current_subscriber(),
            );
            if let Err(error) = call(&id, &calls, "hello").await {
                // The supervisor ends the process. Wait for it, so no
                // process is left when `load` returns.
                drop(calls);
                let _ = supervisor.await;
                return Err(error);
            }
            Ok(Box::new(NativeInstance { id, calls }) as Box<dyn ExtensionInstance>)
        })
    }
}

/// One request: its type and where the answer goes.
type Call = (&'static str, oneshot::Sender<Result<()>>);

/// One extension in its process. To drop it ends the process.
struct NativeInstance {
    id: ExtensionId,
    /// The requests for the supervisor task. The supervisor ends the
    /// process when this sender is dropped.
    calls: mpsc::Sender<Call>,
}

impl ExtensionInstance for NativeInstance {
    /// Sends `activate`. `context` stays in the engine (see the module
    /// documentation).
    fn activate(&self, _context: ExtensionContext) -> BoxFuture<'_, Result<()>> {
        Box::pin(call(&self.id, &self.calls, "activate"))
    }

    fn deactivate(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(call(&self.id, &self.calls, "deactivate"))
    }
}

/// Sends one request to the supervisor and waits for the answer. If the
/// caller drops this future, the supervisor kills the process.
async fn call(id: &ExtensionId, calls: &mpsc::Sender<Call>, request: &'static str) -> Result<()> {
    let ended = || failure(id, "the process has ended");
    let (answer, result) = oneshot::channel();
    calls.send((request, answer)).await.map_err(|_| ended())?;
    result.await.map_err(|_| ended())?
}

/// An `internal` error about the process of `id`. `reason` must not contain
/// text from the process.
fn failure(id: &ExtensionId, reason: &str) -> Error {
    Error::internal(format!("extension `{id}`: {reason}"))
}

/// The process of one extension and its control pipes.
struct Process {
    id: ExtensionId,
    log: Arc<LogBudget>,
    /// The task [`log_error_output`].
    error_output: JoinHandle<()>,
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    config: NativeConfig,
    redactor: Redactor,
}

/// Owns the process until it has ended. Does one request after the other.
async fn supervise(
    mut process: Process,
    mut requests: mpsc::Receiver<Call>,
    on_crash: CrashCallback,
    // Free at the end of this task: then the next process of the extension
    // can start.
    _slot: Slot,
) {
    // An end of the process is a crash only after the handshake. Before
    // it, the answer to `hello` gives the error (ADR-0024).
    let mut handshake_done = false;
    loop {
        tokio::select! {
            request = requests.recv() => {
                let Some((request, mut answer)) = request else {
                    // The instance was dropped.
                    break;
                };
                let result = tokio::select! {
                    result = process.exchange(request) => result,
                    () = answer.closed() => Err(failure(&process.id, "the call was dropped")),
                };
                match result {
                    Ok(result) => {
                        // `hello` is the first request.
                        handshake_done |= result.is_ok();
                        let _ = answer.send(result);
                    }
                    Err(error) => {
                        // The state of the process is not known.
                        let _ = process.child.kill().await;
                        let _ = answer.send(Err(error));
                        break;
                    }
                }
            }
            error = process.unexpected(), if handshake_done => {
                let failed_at = Instant::now();
                let _ = process.child.kill().await;
                on_crash(process.id.clone(), error, failed_at);
                break;
            }
        }
    }
    let Process {
        log,
        mut error_output,
        mut child,
        input,
        config,
        ..
    } = process;
    // The closed input tells the process to exit. A process that was killed
    // above has its exit status already.
    drop(input);
    if tokio::time::timeout(config.grace, child.wait())
        .await
        .is_err()
    {
        // Kills and reads the exit status. `kill_on_drop` kills also, but it
        // does not wait.
        let _ = child.kill().await;
    }
    // The error output ends with the process, and the task with it. The
    // wait ends only if another process holds the error output open.
    if tokio::time::timeout(config.grace, &mut error_output)
        .await
        .is_err()
    {
        error_output.abort();
        // After this the task counts no line.
        let _ = error_output.await;
        log.renew();
    }
}

impl Process {
    /// Sends `request` and reads one answer. The outer error is a failure
    /// of the process or of the protocol. The inner result is the answer.
    async fn exchange(&mut self, request: &'static str) -> Result<Result<()>> {
        self.log.renew();
        if request == "hello" {
            let limit = self.config.handshake_timeout;
            return tokio::time::timeout(limit, self.exchange_unlimited(request))
                .await
                .unwrap_or_else(|_| Err(failure(&self.id, "the process did not answer in time")));
        }
        self.exchange_unlimited(request).await
    }

    async fn exchange_unlimited(&mut self, request: &'static str) -> Result<Result<()>> {
        let mut line = match request {
            "hello" => json!({"type": request, "protocol": PROTOCOL_VERSION}),
            _ => json!({"type": request}),
        }
        .to_string();
        line.push('\n');
        let sent = async {
            self.input.write_all(line.as_bytes()).await?;
            self.input.flush().await
        };
        let when = if request == "hello" {
            "before the handshake"
        } else {
            "during the call"
        };
        sent.await.map_err(|error| {
            let reason = format!("the process ended or closed its input {when}");
            failure(&self.id, &reason).with_source(error)
        })?;

        let limit = self.config.max_message_bytes;
        let answer = {
            // One byte more than the limit, for the line end.
            let read = read_chunk(&mut self.output, limit.saturating_add(1));
            tokio::pin!(read);
            tokio::select! {
                // An answer that is in the pipe counts, also if the process
                // has ended after it.
                biased;
                answer = &mut read => answer,
                _ = self.child.wait() => {
                    // The exit can be known before Tokio says that the pipe
                    // has bytes, so one poll of the read is not sufficient.
                    // Another process can hold the output open, so the end
                    // of the output can stay away: the wait has a limit.
                    tokio::time::timeout(self.config.grace, &mut read)
                        .await
                        .unwrap_or_else(|_| Ok(Vec::new()))
                }
            }
        }
        .map_err(|error| {
            failure(&self.id, "the output of the process cannot be read").with_source(error)
        })?;
        let Some(answer) = answer.strip_suffix(b"\n") else {
            return Err(failure(
                &self.id,
                &if answer.len() > limit {
                    "the process sent a message that is too large".to_owned()
                } else {
                    // One message is one line: the output ended before the
                    // line end.
                    format!("the process ended or closed its output {when}")
                },
            ));
        };
        self.answer(request, answer)
    }

    /// Reads the answer `line` to `request`.
    fn answer(&self, request: &str, line: &[u8]) -> Result<Result<()>> {
        let malformed = || failure(&self.id, "the process sent a malformed message");
        // The cause is a kind and a position. It has no text of the line,
        // because the target type is `Value`: only a typed target gives
        // errors that quote the input.
        let message: Value =
            serde_json::from_slice(line).map_err(|error| malformed().with_source(error))?;
        match (message["type"].as_str(), request) {
            (Some("hello"), "hello") if message["protocol"] == PROTOCOL_VERSION => Ok(Ok(())),
            (Some("hello"), "hello") => Err(failure(
                &self.id,
                &format!("the process does not have the protocol version {PROTOCOL_VERSION}"),
            )),
            (Some("ok"), "activate" | "deactivate") => Ok(Ok(())),
            (Some("error"), _) => {
                let text = message["message"].as_str().ok_or_else(malformed)?;
                let text = guest_text(&self.redactor, text);
                let error = match message["category"].as_str() {
                    Some("user") => Error::user(text),
                    Some("auth") => Error::auth(text),
                    Some("connectivity") => Error::connectivity(text),
                    Some("database") => Error::database(text),
                    Some("policy") => Error::policy(text),
                    Some("cancelled") => Error::cancelled(text),
                    Some("retryable") => Error::retryable(text),
                    Some("internal") => Error::internal(text),
                    _ => return Err(malformed()),
                };
                Ok(Err(error))
            }
            _ => Err(malformed()),
        }
    }

    /// Completes when the process does something that is a crash while no
    /// call runs. Returns the reason.
    async fn unexpected(&mut self) -> Error {
        let id = &self.id;
        tokio::select! {
            status = self.child.wait() => match status {
                Ok(status) => failure(id, &format!("the process ended ({status})")),
                Err(error) => {
                    failure(id, "the state of the process cannot be read").with_source(error)
                }
            },
            // Does not take the bytes, so each byte counts, also without a
            // line end.
            bytes = self.output.fill_buf() => match bytes {
                Ok([]) => failure(id, "the process ended or closed its output"),
                Ok(_) => failure(id, "the process sent a message that answers no request"),
                Err(error) => {
                    failure(id, "the output of the process cannot be read").with_source(error)
                }
            },
        }
    }
}

/// Reads to the end of the line, but `most` bytes at most. The result is
/// empty at the end of the input.
async fn read_chunk<R>(reader: &mut R, most: usize) -> std::io::Result<Vec<u8>>
where
    R: AsyncBufRead + Unpin,
{
    let mut chunk = Vec::new();
    let most = u64::try_from(most).unwrap_or(u64::MAX);
    reader.take(most).read_until(b'\n', &mut chunk).await?;
    Ok(chunk)
}

/// The log budget of the error output of one process (see the module
/// documentation).
struct LogBudget {
    id: ExtensionId,
    /// The lines and the bytes that are left, and the dropped lines.
    left: Mutex<(u32, usize, u64)>,
}

impl LogBudget {
    fn new(id: ExtensionId) -> Self {
        Self {
            id,
            left: Mutex::new((LOG_LINES_PER_CALL, LOG_BYTES_PER_CALL, 0)),
        }
    }

    fn left(&self) -> MutexGuard<'_, (u32, usize, u64)> {
        self.left.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts a new budget. Writes the number of the lines that the last
    /// budget dropped.
    fn renew(&self) {
        let new = (LOG_LINES_PER_CALL, LOG_BYTES_PER_CALL, 0);
        let (_, _, dropped) = std::mem::replace(&mut *self.left(), new);
        if dropped > 0 {
            // The message of `wasm.rs`.
            tracing::warn!(extension = self.id.as_str(), "{dropped} log lines dropped");
        }
    }

    /// Takes one line of `bytes` from the budget. Returns `false`, and
    /// counts the line as dropped, if the budget does not have it.
    fn take(&self, bytes: usize) -> bool {
        let mut left = self.left();
        let (lines, left_bytes, dropped) = &mut *left;
        if *lines == 0 || bytes > *left_bytes {
            *dropped += 1;
            return false;
        }
        *lines -= 1;
        *left_bytes -= bytes;
        true
    }
}

/// Writes the error output of the process to the log, as untrusted text.
/// Ends when the error output ends. The supervisor ends this task if another
/// process holds the error output open.
async fn log_error_output(errors: ChildStderr, log: Arc<LogBudget>, redactor: Redactor) {
    let mut errors = BufReader::new(errors);
    let extension = log.id.as_str();
    // `true` while the start of the current line is already read.
    let mut rest_of_line = false;
    loop {
        let chunk = match read_chunk(&mut errors, ERROR_OUTPUT_LINE_BYTES).await {
            Ok(chunk) if chunk.is_empty() => break,
            Ok(chunk) => chunk,
            Err(error) => {
                tracing::warn!(extension, %error, "the error output of the process cannot be read");
                break;
            }
        };
        let dropped = std::mem::replace(&mut rest_of_line, !chunk.ends_with(b"\n"));
        // Before the work on the text: a dropped line must be cheap.
        if dropped || !log.take(chunk.len()) {
            continue;
        }
        let text = String::from_utf8_lossy(&chunk);
        let text = guest_text(&redactor, text.trim_end_matches(['\r', '\n']));
        // A field, not the message: see `wasm.rs`.
        let guest_message = text.as_str();
        tracing::info!(extension, guest_message, "extension error output");
    }
    log.renew();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> NativeRuntime {
        // No test here starts the program.
        let program = std::env::current_exe().unwrap();
        NativeRuntime::new(
            NativeConfig::new(program),
            Redactor::new(),
            Arc::new(|_, _, _| {}),
        )
        .unwrap()
    }

    fn entries(runtime: &NativeRuntime) -> usize {
        runtime.slots.lock().unwrap().len()
    }

    #[tokio::test]
    async fn the_end_of_a_slot_removes_its_entry() {
        let runtime = runtime();
        let ids: Vec<ExtensionId> = (0..8)
            .map(|n| format!("acme.e{n}").parse().unwrap())
            .collect();
        let mut slots = Vec::new();
        for id in &ids {
            slots.push(runtime.slot(id).await.unwrap());
        }
        assert_eq!(entries(&runtime), ids.len());
        drop(slots);
        assert_eq!(entries(&runtime), 0);
    }

    #[tokio::test]
    async fn a_load_that_waits_keeps_the_entry_and_gets_the_slot() {
        let runtime = runtime();
        let id: ExtensionId = "acme.native".parse().unwrap();
        let old = runtime.slot(&id).await.unwrap();
        let waiter = runtime.slot(&id);
        tokio::pin!(waiter);
        // One poll: the waiter is in the queue of the slot.
        tokio::select! {
            biased;
            _ = &mut waiter => panic!("two slots for one extension"),
            () = std::future::ready(()) => {}
        }
        drop(old);
        assert_eq!(entries(&runtime), 1);
        let new = waiter.await.unwrap();
        assert_eq!(entries(&runtime), 1);
        drop(new);
        assert_eq!(entries(&runtime), 0);
    }

    #[tokio::test]
    async fn a_cancelled_load_that_waited_leaves_no_entry() {
        let runtime = runtime();
        let id: ExtensionId = "acme.native".parse().unwrap();
        let old = runtime.slot(&id).await.unwrap();
        {
            let waiter = runtime.slot(&id);
            tokio::pin!(waiter);
            tokio::select! {
                biased;
                _ = &mut waiter => panic!("two slots for one extension"),
                () = std::future::ready(()) => {}
            }
            // The old slot ends while the load waits, then the load is
            // cancelled.
            drop(old);
        }
        assert_eq!(entries(&runtime), 0);
        // The next load does not wait.
        let _slot = runtime.slot(&id).await.unwrap();
    }
}
