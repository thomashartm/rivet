//! Tests of the process runtime for native extensions (`rivet_core::native`).
//!
//! This target has no test harness (`harness = false`), because the test
//! program is also the child process: the runtime starts
//! `<this program> --child <package directory>`. The file `behaviour` in the
//! package directory tells the child what to do. No library is loaded.
//!
//! The tests run one after the other. An argument that does not start with
//! `-` is a filter on the test name.
//!
//! Only on Unix can a test check that a process is gone (`kill -0`). On
//! other systems each test that makes this check does not run, and the
//! runner says so.

#[cfg(unix)]
use rivet_core::bus::Received;
use rivet_core::bus::{CommandBus, EventBus};
use rivet_core::host::{
    ExtensionContext, ExtensionInstance, ExtensionRuntime, MANIFEST_FILE, Services,
};
#[cfg(unix)]
use rivet_core::host::{ExtensionHost, ExtensionState, ExtensionStateChanged, HostConfig};
use rivet_core::jobs::JobScheduler;
use rivet_core::logging::{LogConfig, Redactor, dispatch};
use rivet_core::native::{
    CrashCallback, DEFAULT_MAX_MESSAGE_BYTES, ENVIRONMENT, NativeConfig, NativeRuntime,
    PROTOCOL_VERSION,
};
use rivet_core::registry::ServiceRegistry;
#[cfg(unix)]
use rivet_core::resolve::ActivationTrigger;
use rivet_sdk::error::{Error, ErrorCategory, Result};
use rivet_sdk::extension::BoxFuture;
#[cfg(unix)]
use rivet_sdk::manifest::Version;
use rivet_sdk::manifest::{ExtensionId, Manifest};
use rivet_sdk::secret::Secret;
use serde_json::{Value, json};
use std::future::Future;
use std::io::Write;
use std::num::{NonZeroU16, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::sync::{OnceLock, Weak};
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;

const ID: &str = "acme.native";
const SECRET: &str = "hunter2-value";

/// The limit of each wait in a test. No test passes because of a wait.
const PATIENCE: Duration = Duration::from_secs(20);

// ---------------------------------------------------------------- child

/// The child process: speaks the protocol on its standard input and output.
fn child(directory: &Path) -> ! {
    let behaviour = std::fs::read_to_string(directory.join("behaviour")).unwrap();
    // One extension has one process at a time: the file `overlap` says that
    // an older process of this package directory exists.
    #[cfg(unix)]
    {
        let older = std::fs::read_to_string(directory.join("pids")).unwrap_or_default();
        if let Some(older) = older.lines().last()
            && alive(older.parse().unwrap())
        {
            std::fs::write(directory.join("overlap"), older).unwrap();
        }
    }
    let mut pids = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("pids"))
        .unwrap();
    writeln!(pids, "{}", std::process::id()).unwrap();
    drop(pids);

    match behaviour.as_str() {
        "env" => {
            let names: Vec<String> = std::env::vars_os()
                .map(|(name, _)| name.to_string_lossy().into_owned())
                .collect();
            std::fs::write(directory.join("env"), names.join("\n")).unwrap();
        }
        "stderr" => {
            eprintln!("token {SECRET} \u{1b}[2J\" level=\"ERROR");
            eprintln!("{}end-of-long-line", "x".repeat(20 * 1024));
            eprintln!("after the long line");
        }
        "crash" => {
            // Aborts when the test makes the file `crash`.
            let trigger = directory.join("crash");
            std::thread::spawn(move || {
                while std::fs::remove_file(&trigger).is_err() {
                    std::thread::sleep(Duration::from_millis(5));
                }
                std::process::abort();
            });
        }
        "gone" => std::process::exit(1),
        _ => {}
    }

    let reply = |message: Value| println!("{message}");
    let forever = || -> ! {
        loop {
            std::thread::park();
        }
    };
    for line in std::io::stdin().lines() {
        let request: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let kind = request["type"].as_str().unwrap();
        if kind == "hello" {
            assert_eq!(
                request,
                json!({"type": "hello", "protocol": PROTOCOL_VERSION})
            );
        } else {
            assert_eq!(request, json!({"type": kind}));
        }
        match (kind, behaviour.as_str()) {
            ("hello", "silent") => forever(),
            ("hello", "wrong-version") => {
                reply(json!({"type": "hello", "protocol": PROTOCOL_VERSION + 1}));
            }
            ("hello", "refuse") => {
                reply(json!({"type": "error", "category": "user", "message": "no library"}));
            }
            ("hello", _) => reply(json!({"type": "hello", "protocol": PROTOCOL_VERSION})),
            ("activate", "abort") => std::process::abort(),
            ("activate", "exit") => std::process::exit(3),
            ("activate", "exit-held") => {
                second(directory, true);
                std::process::exit(3);
            }
            ("activate", "answer-exit" | "answer-exit-held") => {
                if behaviour == "answer-exit-held" {
                    second(directory, true);
                }
                reply(json!({"type": "ok"}));
                std::process::exit(0);
            }
            ("activate", "answer-exit-late") => {
                // Answers when the test makes the file `go`.
                std::fs::write(directory.join("asked"), "").unwrap();
                let go = directory.join("go");
                while !go.exists() {
                    std::thread::sleep(Duration::from_millis(5));
                }
                reply(json!({"type": "ok"}));
                std::process::exit(0);
            }
            ("activate", "half-exit" | "half-exit-held") => {
                if behaviour == "half-exit-held" {
                    second(directory, true);
                }
                print!("{{\"type\":");
                std::io::stdout().flush().unwrap();
                std::process::exit(0);
            }
            ("activate", other) if other.starts_with("raw:") => {
                println!("{}", &other["raw:".len()..]);
            }
            ("activate", "malformed") => println!("{{\"token\":\"{SECRET}\",\"type\":"),
            ("activate", "not-an-answer") => reply(json!({"type": "hello", "protocol": 1})),
            ("activate", "unknown-category") => {
                reply(json!({"type": "error", "category": "fatal", "message": "x"}));
            }
            ("activate", "message-number") => {
                reply(json!({"type": "error", "category": "user", "message": 5}));
            }
            ("activate", "largest" | "too-large") => {
                // `{"type":"ok","pad":""}` has 22 bytes.
                let extra = usize::from(behaviour == "too-large");
                let pad = "x".repeat(DEFAULT_MAX_MESSAGE_BYTES - 22 + extra);
                reply(json!({"type": "ok", "pad": pad}));
            }
            ("activate", "flood" | "flood-held") => {
                if behaviour == "flood-held" {
                    second(directory, false);
                }
                for number in 0..300 {
                    eprintln!("flood {number}");
                }
                reply(json!({"type": "ok"}));
            }
            ("activate", "flood-bytes") => {
                // With the line end, 16 of these lines are the byte budget.
                for _ in 0..20 {
                    eprintln!("{}", "b".repeat(4095));
                }
                reply(json!({"type": "ok"}));
            }
            ("activate", "hang") => {
                std::fs::write(directory.join("hanging"), "").unwrap();
                forever();
            }
            ("activate", "talk") => {
                reply(json!({"type": "ok"}));
                reply(json!({"type": "ok"}));
            }
            ("activate", "talk-no-line-end") => {
                reply(json!({"type": "ok"}));
                print!("x");
                std::io::stdout().flush().unwrap();
            }
            ("activate", other) if other.starts_with("error:") => reply(json!({
                "type": "error",
                "category": &other["error:".len()..],
                "message": format!("bad \u{1b}licence {SECRET}"),
            })),
            ("activate" | "deactivate", _) => reply(json!({"type": "ok"})),
            (other, _) => panic!("unknown request {other}"),
        }
    }
    if behaviour == "stubborn" {
        forever();
    }
    std::process::exit(0)
}

/// Starts a second process that lives 30 s. It has the output of the child
/// (`output`) or its error output, and it does not end with the child. The
/// file `second` gets its process id: [`Package`] ends it.
#[expect(
    clippy::zombie_processes,
    reason = "the second process must live longer than the child"
)]
fn second(directory: &Path, output: bool) {
    use std::process::Stdio;
    let (stdout, stderr) = if output {
        (Stdio::inherit(), Stdio::null())
    } else {
        (Stdio::null(), Stdio::inherit())
    };
    let second = std::process::Command::new("/bin/sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .unwrap();
    std::fs::write(directory.join("second"), second.id().to_string()).unwrap();
}

// ------------------------------------------------------------- fixtures

/// A package directory `<root>/acme.native` with a manifest and the
/// behaviour of the child.
struct Package {
    root: TempDir,
    directory: PathBuf,
    manifest: Manifest,
}

fn package(behaviour: &str) -> Package {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join(ID);
    let text = format!(
        "id = \"{ID}\"\nversion = \"1.0.0\"\nsdk = \"^0.1\"\n\n\
         [[activation]]\non = \"command\"\ncommand = \"{ID}\"\n"
    );
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join(MANIFEST_FILE), &text).unwrap();
    std::fs::write(directory.join("behaviour"), behaviour).unwrap();
    Package {
        root,
        directory,
        manifest: Manifest::parse(&text).unwrap(),
    }
}

impl Drop for Package {
    /// Ends the process that the child started with `second`.
    fn drop(&mut self) {
        if let Ok(pid) = std::fs::read_to_string(self.directory.join("second")) {
            let _ = std::process::Command::new("kill").arg(pid).status();
        }
    }
}

impl Package {
    /// The process ids of the children that started, oldest first.
    fn pids(&self) -> Vec<u32> {
        std::fs::read_to_string(self.directory.join("pids"))
            .unwrap_or_default()
            .lines()
            .map(|line| line.parse().unwrap())
            .collect()
    }

    #[cfg(unix)]
    fn pid(&self) -> u32 {
        let pids = self.pids();
        assert_eq!(pids.len(), 1, "one process for one extension");
        pids[0]
    }
}

fn config() -> NativeConfig {
    let mut config = NativeConfig::new(std::env::current_exe().unwrap());
    config.arguments = vec!["--child".into()];
    config
}

fn redactor() -> Redactor {
    let redactor = Redactor::new();
    redactor.register(&Secret::from(SECRET.to_owned()));
    redactor
}

/// A runtime whose crash callback sends each report to the receiver.
fn runtime(config: NativeConfig) -> (NativeRuntime, mpsc::UnboundedReceiver<(ExtensionId, Error)>) {
    let (sender, crashes) = mpsc::unbounded_channel();
    let on_crash: CrashCallback = Arc::new(move |id, error| {
        let _ = sender.send((id, error));
    });
    let runtime = NativeRuntime::new(config, redactor(), on_crash).unwrap();
    (runtime, crashes)
}

async fn load(runtime: &NativeRuntime, package: &Package) -> Result<Box<dyn ExtensionInstance>> {
    within(runtime.load(&package.manifest, &package.directory)).await
}

/// Loads `package` in a runtime with the test configuration.
async fn loaded(package: &Package) -> Box<dyn ExtensionInstance> {
    let (runtime, _crashes) = runtime(config());
    load(&runtime, package).await.unwrap()
}

fn services() -> Services {
    Services {
        registry: Arc::new(ServiceRegistry::new()),
        commands: Arc::new(CommandBus::new()),
        events: Arc::new(EventBus::new(NonZeroU16::new(64).unwrap())),
        jobs: JobScheduler::new(NonZeroUsize::new(4).unwrap(), 4),
    }
}

fn context() -> ExtensionContext {
    ExtensionContext {
        owner: ID.parse().unwrap(),
        services: services(),
    }
}

/// A real host with the native runtime. The crash callback of the runtime
/// calls `report_crash` of the host.
#[cfg(unix)]
fn host(package: &Package, services: Services) -> Arc<ExtensionHost> {
    let slot: Arc<OnceLock<Weak<ExtensionHost>>> = Arc::default();
    let on_crash: CrashCallback = Arc::new({
        let slot = Arc::clone(&slot);
        move |id, error| {
            if let Some(host) = slot.get().and_then(Weak::upgrade) {
                tokio::spawn(async move { host.report_crash(&id, error).await });
            }
        }
    });
    let host = ExtensionHost::new(
        Arc::new(NativeRuntime::new(config(), redactor(), on_crash).unwrap()),
        services,
        Arc::new(rivet_core::secrets::SecretStore::new()),
        Version::new(0, 1, 0),
        vec![package.root.path().to_owned()],
        true,
        HostConfig::default(),
    );
    slot.set(Arc::downgrade(&host)).unwrap();
    host
}

#[cfg(unix)]
fn state(host: &ExtensionHost) -> ExtensionState {
    host.extensions()[0].state
}

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(PATIENCE, future)
        .await
        .expect("the test waited too long")
}

/// Waits until `done` is true. Polls, with [`PATIENCE`] as the limit.
async fn until(mut done: impl FnMut() -> bool) {
    within(async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
}

/// `true` while the process exists. A process that ended and whose exit
/// status nobody read (a defunct process) exists.
#[cfg(unix)]
fn alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
        .success()
}

/// `true` if the process has ended and nobody has read its exit status.
#[cfg(unix)]
fn defunct(pid: u32) -> bool {
    let state = std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    state.stdout.trim_ascii_start().starts_with(b"Z")
}

/// Blocks the thread until `done` is true, with [`PATIENCE`] as the limit.
#[cfg(unix)]
fn block_until(mut done: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while !done() {
        assert!(start.elapsed() < PATIENCE, "the test waited too long");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn internal(error: &Error) {
    assert_eq!(error.category(), ErrorCategory::Internal, "{error}");
    assert!(error.message().contains(ID), "{error}");
    assert!(!error.message().contains(SECRET), "{error}");
}

// ---------------------------------------------------------------- tests

/// Criteria 1, 2 and 3: the runtime works behind the contract of the host.
#[cfg(unix)]
async fn a_host_runs_an_extension_in_one_process() {
    let package = package("ok");
    let host = host(&package, services());
    let id: ExtensionId = ID.parse().unwrap();
    host.discover().await.unwrap();

    let report = within(host.trigger(ActivationTrigger::Command(ID))).await;
    assert_eq!(
        report.activated,
        std::slice::from_ref(&id),
        "{:?}",
        report.not_activated
    );
    assert_eq!(state(&host), ExtensionState::Active);
    let pid = package.pid();
    assert!(alive(pid));

    within(host.deactivate(&id)).await.unwrap();
    assert_eq!(state(&host), ExtensionState::Inactive);
    assert!(alive(pid));

    within(host.unload(&id)).await.unwrap();
    until(|| !alive(pid)).await;
    assert_eq!(package.pids(), [pid]);
}

/// Criterion 2.
#[cfg(unix)]
async fn a_failed_handshake_is_an_error_and_leaves_no_process() {
    let mut short = config();
    short.handshake_timeout = Duration::from_millis(200);
    for (behaviour, reason) in [
        ("wrong-version", "protocol version"),
        ("silent", "did not answer in time"),
    ] {
        let package = package(behaviour);
        let (runtime, mut crashes) = runtime(short.clone());
        let error = load(&runtime, &package).await.err().expect(behaviour);
        internal(&error);
        assert!(error.message().contains(reason), "{error}");
        assert!(!alive(package.pid()), "{behaviour}");
        assert!(crashes.try_recv().is_err(), "{behaviour}");
    }
}

/// Criterion 2.
async fn a_program_that_cannot_start_is_an_error() {
    let package = package("ok");
    let (runtime, _crashes) = runtime(NativeConfig::new(package.directory.join("missing")));
    let error = load(&runtime, &package).await.err().unwrap();
    internal(&error);
    assert!(error.message().contains("did not start"), "{error}");
    assert!(package.pids().is_empty());
}

/// A limit of 0 lets no handshake and no message pass.
async fn a_limit_of_zero_is_refused() {
    let on_crash: CrashCallback = Arc::new(|_, _| {});
    let mut no_time = config();
    no_time.handshake_timeout = Duration::ZERO;
    let mut no_bytes = config();
    no_bytes.max_message_bytes = 0;
    for (config, name) in [
        (no_time, "handshake_timeout"),
        (no_bytes, "max_message_bytes"),
    ] {
        let error = NativeRuntime::new(config, redactor(), Arc::clone(&on_crash))
            .err()
            .expect(name);
        assert_eq!(error.category(), ErrorCategory::User);
        assert!(error.message().contains(name), "{error}");
    }
    // A grace time of 0 is valid: the process is killed at once.
    let mut no_grace = config();
    no_grace.grace = Duration::ZERO;
    assert!(NativeRuntime::new(no_grace, redactor(), on_crash).is_ok());
}

/// Criterion 2 (ADR-0024): no search in `PATH`.
async fn a_relative_program_path_is_refused() {
    let on_crash: CrashCallback = Arc::new(|_, _| {});
    let config = NativeConfig::new("sh");
    let error = NativeRuntime::new(config, redactor(), on_crash)
        .err()
        .unwrap();
    assert_eq!(error.category(), ErrorCategory::User);
    assert!(
        error.message().contains("`sh` is not an absolute path"),
        "{error}"
    );
}

/// Criteria 2 and 3: the process can refuse the handshake with its own
/// error.
#[cfg(unix)]
async fn an_error_answer_to_the_handshake_is_kept_and_leaves_no_process() {
    let package = package("refuse");
    let (runtime, _crashes) = runtime(config());
    let error = load(&runtime, &package).await.err().unwrap();
    assert_eq!(error.category(), ErrorCategory::User);
    assert_eq!(error.message(), "no library");
    assert!(!alive(package.pid()));
}

/// Criterion 3.
async fn an_error_answer_keeps_its_category_and_its_message() {
    let categories = [
        Error::user(""),
        Error::auth(""),
        Error::connectivity(""),
        Error::database(""),
        Error::policy(""),
        Error::cancelled(""),
        Error::retryable(""),
        Error::internal(""),
    ]
    .map(|error| error.category());
    for category in categories {
        let package = package(&format!("error:{category}"));
        let instance = loaded(&package).await;
        let error = within(instance.activate(context())).await.unwrap_err();
        assert_eq!(error.category(), category);
        // Untrusted text: the control character and the secret are gone.
        assert_eq!(error.message(), "bad  licence [REDACTED]");
        // An error answer is no failure of the process.
        within(instance.deactivate()).await.unwrap();
        assert_eq!(package.pids().len(), 1);
    }
}

/// Criterion 4.
#[cfg(unix)]
async fn a_failure_of_the_process_during_a_call_is_an_internal_error() {
    for (behaviour, reason) in [
        ("abort", "ended or closed its output"),
        ("exit", "ended or closed its output"),
        ("malformed", "malformed message"),
        ("not-an-answer", "malformed message"),
        ("unknown-category", "malformed message"),
        ("message-number", "malformed message"),
        ("too-large", "too large"),
    ] {
        let package = package(behaviour);
        let (runtime, mut crashes) = runtime(config());
        let instance = load(&runtime, &package).await.unwrap();
        let error = within(instance.activate(context())).await.unwrap_err();
        internal(&error);
        assert!(error.message().contains(reason), "{behaviour}: {error}");
        // The runtime ended the process before the call returned.
        assert!(!alive(package.pid()), "{behaviour}");
        // The instance cannot be used again, and the failure of a call is
        // not reported a second time as a crash.
        let error = within(instance.deactivate()).await.unwrap_err();
        internal(&error);
        assert!(
            error.message().contains("has ended"),
            "{behaviour}: {error}"
        );
        assert!(crashes.try_recv().is_err(), "{behaviour}");
    }
    // The engine continues: the next extension works.
    let package = package("largest");
    let instance = loaded(&package).await;
    within(instance.activate(context())).await.unwrap();
}

/// Criterion 4 (§5.6): the error keeps its cause, and the cause has no text
/// of the process.
async fn a_malformed_message_keeps_its_cause_without_text_of_the_process() {
    // The cause of each kind of malformed text is a kind and a position.
    for text in [
        format!("{{\"token\":\"{SECRET}\",\"type\":"),
        SECRET.to_owned(),
        format!("\"{SECRET}"),
        format!("\"{SECRET}\\q\""),
        format!("{{\"{SECRET}\" {SECRET}}}"),
        format!("{{{SECRET}:1}}"),
        format!("[1,{SECRET}]"),
        format!("1{SECRET}"),
        format!("1 {SECRET}"),
        format!("nul{SECRET}"),
        format!("\"\\u{SECRET}\""),
        format!("\"{SECRET}\u{1}\""),
    ] {
        let package = package(&format!("raw:{text}"));
        let instance = loaded(&package).await;
        let error = within(instance.activate(context())).await.unwrap_err();
        internal(&error);
        assert!(error.message().contains("malformed message"), "{error}");
        let cause = std::error::Error::source(&error).expect("the cause");
        assert!(cause.is::<serde_json::Error>(), "{cause}");
        assert!(std::error::Error::source(cause).is_none());
        assert!(!format!("{error:?} {cause} {cause:?}").contains("hunter"));
    }
}

/// Criterion 4: the process lives, but its output is closed.
#[cfg(unix)]
async fn a_closed_output_during_a_call_is_an_internal_error() {
    let package = package("unused");
    let script = format!(
        "echo $$ >> pids; read line; echo '{}'; read line; exec 1>&-; read line",
        json!({"type": "hello", "protocol": PROTOCOL_VERSION})
    );
    let mut config = NativeConfig::new("/bin/sh");
    config.arguments = vec!["-c".into(), script.into(), "sh".into()];
    let (runtime, _crashes) = runtime(config);
    let instance = load(&runtime, &package).await.unwrap();
    let error = within(instance.activate(context())).await.unwrap_err();
    internal(&error);
    assert!(error.message().contains("closed its output"), "{error}");
    assert!(!alive(package.pid()));
}

/// Criterion 4 (R-88): another process holds the output of a process that
/// exits during a call.
#[cfg(unix)]
async fn an_exit_during_a_call_ends_the_call_while_the_output_stays_open() {
    let package = package("exit-held");
    let instance = loaded(&package).await;
    let error = within(instance.activate(context())).await.unwrap_err();
    internal(&error);
    let reason = "ended or closed its output during the call";
    assert!(error.message().contains(reason), "{error}");
    assert!(!alive(package.pid()));
}

/// Criterion 4 (R-88): the answer of a process that exits directly after
/// it is not lost. The exit is then a crash while no call runs.
#[cfg(unix)]
async fn an_answer_before_an_exit_is_kept() {
    for behaviour in ["answer-exit", "answer-exit-held"] {
        let package = package(behaviour);
        let (runtime, mut crashes) = runtime(config());
        let instance = load(&runtime, &package).await.unwrap();
        within(instance.activate(context())).await.expect(behaviour);
        let (_, error) = within(crashes.recv()).await.unwrap();
        assert!(error.message().contains("the process ended"), "{error}");
    }
}

/// Criterion 4 (R-104): the runtime sees the exit of the process before it
/// sees the answer in the pipe. The answer is not lost.
///
/// The order is made with a runtime of one thread, as in
/// [`an_exit_before_the_handshake_is_an_error_of_the_load_and_no_crash`]:
/// the end of some other process wakes the supervisor task, and the test
/// blocks the thread until the answer is in the pipe and the process has
/// ended. Then the supervisor task runs before the runtime looks at the
/// pipe. Where the end of some other process does not wake the supervisor
/// task (Linux with a process file descriptor), the test makes the usual
/// order.
#[cfg(unix)]
fn an_answer_in_the_pipe_is_kept_when_the_exit_is_seen_first() -> std::future::Ready<()> {
    let package = package("answer-exit-late");
    let single = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    single.block_on(async {
        let (runtime, mut crashes) = runtime(config());
        let instance = load(&runtime, &package).await.unwrap();
        let pid = package.pid();
        let mut activate = std::pin::pin!(within(instance.activate(context())));
        let mut step = 0;
        let result = std::future::poll_fn(|context| {
            let result = activate.as_mut().poll(context);
            if result.is_ready() {
                return result;
            }
            match step {
                // The process has the request, so the supervisor task
                // waits for the answer and for the exit.
                0 if package.directory.join("asked").exists() => {
                    let other = std::process::Command::new("/bin/sleep").arg("0").status();
                    assert!(other.unwrap().success());
                    step = 1;
                }
                // The runtime has seen the end of the other process.
                1 => {
                    std::fs::write(package.directory.join("go"), "").unwrap();
                    block_until(|| defunct(pid));
                    step = 2;
                }
                _ => {}
            }
            // Polls again after each turn of the runtime, before the tasks.
            context.waker().wake_by_ref();
            std::task::Poll::Pending
        })
        .await;
        result.unwrap();
        let (_, error) = within(crashes.recv()).await.unwrap();
        assert!(error.message().contains("the process ended"), "{error}");
    });
    std::future::ready(())
}

/// Criterion 4 (R-104): many processes answer and exit at one time, on the
/// runtime of the runner. This makes the order of
/// [`an_answer_in_the_pipe_is_kept_when_the_exit_is_seen_first`] by chance,
/// also where that test cannot make it.
#[cfg(unix)]
async fn answers_before_exits_are_kept_under_load() {
    let mut lost = 0;
    for _ in 0..10 {
        let mut calls = tokio::task::JoinSet::new();
        for _ in 0..40 {
            calls.spawn(async {
                let package = package("answer-exit");
                let instance = loaded(&package).await;
                within(instance.activate(context())).await
            });
        }
        for result in calls.join_all().await {
            lost += usize::from(result.is_err());
        }
    }
    assert_eq!(lost, 0, "lost answers");
}

/// Criterion 4 (R-105): the process ends in the middle of its answer. The
/// reason is the same with and without another process that holds the
/// output.
#[cfg(unix)]
async fn half_an_answer_before_an_exit_is_an_end_of_the_process() {
    for behaviour in ["half-exit", "half-exit-held"] {
        let package = package(behaviour);
        let mut config = config();
        config.grace = Duration::from_millis(100);
        let (runtime, mut crashes) = runtime(config);
        let instance = load(&runtime, &package).await.unwrap();
        let error = within(instance.activate(context())).await.unwrap_err();
        internal(&error);
        let reason = "ended or closed its output during the call";
        assert!(error.message().contains(reason), "{behaviour}: {error}");
        assert!(!alive(package.pid()), "{behaviour}");
        assert!(crashes.try_recv().is_err(), "{behaviour}");
    }
}

/// Criterion 2 (ADR-0024): the runtime reports no crash before the
/// handshake.
///
/// Each load has the worst order: the process has ended before the
/// supervisor task runs for the first time. The runtime of this test has
/// one thread, so the supervisor task cannot run while the test blocks the
/// thread. This is not an `async fn`, as
/// [`a_process_that_is_killed_after_the_grace_time_is_not_left_defunct`].
#[cfg(unix)]
fn an_exit_before_the_handshake_is_an_error_of_the_load_and_no_crash() -> std::future::Ready<()> {
    let package = package("gone");
    let single = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    single.block_on(async {
        let (runtime, mut crashes) = runtime(config());
        for number in 0..50 {
            let mut loading = std::pin::pin!(load(&runtime, &package));
            let mut started = false;
            let result = std::future::poll_fn(|context| {
                let result = loading.as_mut().poll(context);
                if !std::mem::replace(&mut started, true) {
                    block_until(|| package.pids().get(number).is_some_and(|pid| defunct(*pid)));
                }
                result
            })
            .await;
            let error = result.err().unwrap();
            internal(&error);
            assert!(error.message().contains("before the handshake"), "{error}");
            assert!(crashes.try_recv().is_err(), "load {number}");
        }
        assert!(package.pids().iter().all(|pid| !alive(*pid)));
        // All supervisor tasks have ended, and none made a report.
        drop(runtime);
        assert!(within(crashes.recv()).await.is_none());
    });
    std::future::ready(())
}

/// Criterion 5.
#[cfg(unix)]
async fn a_crash_while_no_call_runs_restarts_the_extension_in_a_new_process() {
    let package = package("crash");
    let services = services();
    let mut events = services.events.subscribe::<ExtensionStateChanged>();
    let host = host(&package, services);
    host.discover().await.unwrap();
    let report = within(host.trigger(ActivationTrigger::Command(ID))).await;
    assert!(
        report.not_activated.is_empty(),
        "{:?}",
        report.not_activated
    );
    let first = package.pid();

    std::fs::write(package.directory.join("crash"), "").unwrap();

    let mut states = Vec::new();
    while states.last() != Some(&ExtensionState::Active)
        || !states.contains(&ExtensionState::Failed)
    {
        match within(events.recv()).await.unwrap() {
            Received::Event(event) => {
                if event.to == Some(ExtensionState::Failed) {
                    let reason = event.reason.unwrap();
                    assert!(reason.contains("the process ended"), "{reason}");
                }
                states.extend(event.to);
            }
            Received::Missed(missed) => panic!("{missed} events were missed"),
        }
    }
    assert_eq!(state(&host), ExtensionState::Active);
    let pids = package.pids();
    assert_eq!(pids.len(), 2, "{pids:?}");
    assert_ne!(pids[0], pids[1]);
    assert!(!alive(first));
    assert!(alive(pids[1]));

    // `shutdown` of the host keeps the instances; `unload` drops one.
    let id = ID.parse().unwrap();
    within(host.deactivate(&id)).await.unwrap();
    within(host.unload(&id)).await.unwrap();
    until(|| !alive(pids[1])).await;
}

/// Criterion 5: a message without a request breaks the protocol.
#[cfg(unix)]
async fn a_message_that_answers_no_request_is_reported_as_a_crash() {
    let package = package("talk");
    let (runtime, mut crashes) = runtime(config());
    let instance = load(&runtime, &package).await.unwrap();
    within(instance.activate(context())).await.unwrap();

    let (id, error) = within(crashes.recv()).await.unwrap();
    assert_eq!(id.as_str(), ID);
    internal(&error);
    assert!(error.message().contains("answers no request"), "{error}");
    assert!(!alive(package.pid()));
    let error = within(instance.deactivate()).await.unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Internal);
}

/// Criterion 5: bytes without a line end break the protocol also.
#[cfg(unix)]
async fn bytes_without_a_line_end_while_no_call_runs_are_reported_as_a_crash() {
    let package = package("talk-no-line-end");
    let (runtime, mut crashes) = runtime(config());
    let instance = load(&runtime, &package).await.unwrap();
    within(instance.activate(context())).await.unwrap();

    let (_, error) = within(crashes.recv()).await.unwrap();
    internal(&error);
    assert!(error.message().contains("answers no request"), "{error}");
    assert!(!alive(package.pid()));
}

/// Criterion 6.
#[cfg(unix)]
async fn to_drop_the_instance_ends_the_process() {
    let package = package("ok");
    let (runtime, mut crashes) = runtime(config());
    let instance = load(&runtime, &package).await.unwrap();
    within(instance.activate(context())).await.unwrap();
    let pid = package.pid();
    assert!(alive(pid));

    drop(instance);
    until(|| !alive(pid)).await;
    // An orderly end is no crash: the callback got no report, and the
    // supervisor task, which had the last copy of the callback, has ended.
    drop(runtime);
    assert!(within(crashes.recv()).await.is_none());
}

/// Criterion 6.
#[cfg(unix)]
async fn a_process_that_ignores_its_closed_input_is_killed_after_the_grace_time() {
    let package = package("stubborn");
    let mut config = config();
    config.grace = Duration::from_millis(100);
    let (runtime, _crashes) = runtime(config);
    let instance = load(&runtime, &package).await.unwrap();
    let pid = package.pid();

    drop(instance);
    until(|| !alive(pid)).await;
}

/// Criterion 6 (ADR-0024): one extension has one process at a time. The
/// drop of the instance does not wait, so the next load does.
#[cfg(unix)]
async fn a_load_waits_for_the_end_of_the_old_process_of_the_extension() {
    let package = package("stubborn");
    let mut config = config();
    config.grace = Duration::from_millis(500);
    let (runtime, mut crashes) = runtime(config);
    let instance = load(&runtime, &package).await.unwrap();
    let old = package.pid();

    // A different extension does not wait for this one.
    let mut other = self::package("ok");
    other.manifest.id = "acme.other".parse().unwrap();
    let _other = load(&runtime, &other).await.unwrap();

    // The old process ignores its closed input: it lives for the grace
    // time.
    drop(instance);
    let _instance = load(&runtime, &package).await.unwrap();
    assert!(!alive(old));
    assert_eq!(package.pids().len(), 2);
    // The new process looked for the old process when it started.
    assert!(!package.directory.join("overlap").exists());
    // The runtime ended the old process itself: that is no crash.
    assert!(crashes.try_recv().is_err());
}

/// Criterion 6: the supervisor reads the exit status of the process that it
/// kills. `kill_on_drop` kills also, but it leaves the exit status to a
/// later turn of a Tokio runtime.
///
/// This is not an `async fn`: the runner calls it before it starts its
/// runtime. The runtime of this test stops when `block_on` returns, so
/// after that nothing can read an exit status.
#[cfg(unix)]
fn a_process_that_is_killed_after_the_grace_time_is_not_left_defunct() -> std::future::Ready<()> {
    let package = package("stubborn");
    let mut config = config();
    config.grace = Duration::from_millis(100);
    let single = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    single.block_on(async {
        let (runtime, mut crashes) = runtime(config);
        let instance = load(&runtime, &package).await.unwrap();
        drop(instance);
        // The supervisor task has the last copy of the callback, so the
        // channel ends when the task ends.
        drop(runtime);
        assert!(within(crashes.recv()).await.is_none());
    });
    assert!(!alive(package.pid()));
    std::future::ready(())
}

/// Criterion 6: the host drops a call that exceeds its time limit.
#[cfg(unix)]
async fn a_dropped_call_kills_the_process() {
    let package = package("hang");
    let instance = loaded(&package).await;
    let pid = package.pid();
    let hanging = package.directory.join("hanging");

    tokio::select! {
        result = instance.activate(context()) => panic!("the call returned: {result:?}"),
        () = until(|| hanging.exists()) => {}
    }
    // The instance is not dropped: the dropped call ends the process.
    until(|| !alive(pid)).await;
    let error = within(instance.deactivate()).await.unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Internal);
}

/// Criterion 7.
async fn the_process_gets_only_the_allowed_environment() {
    // Cargo gives this variable to the test program, so the test program
    // has a variable that is not in the list.
    assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());
    assert!(std::env::var_os("PATH").is_some());

    let package = package("env");
    let _instance = loaded(&package).await;
    let names = std::fs::read_to_string(package.directory.join("env")).unwrap();
    let names: Vec<&str> = names.lines().collect();
    assert!(names.contains(&"PATH"), "{names:?}");
    for name in &names {
        // macOS gives this variable to each new process.
        let allowed = ENVIRONMENT.contains(name) || *name == "__CF_USER_TEXT_ENCODING";
        assert!(allowed, "the process has {name}");
    }
}

/// A log output that the test reads.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A log subscriber that writes to the returned capture. It has an empty
/// redactor: the runtime must redact.
fn capture_log() -> (Capture, tracing::dispatcher::DefaultGuard) {
    let capture = Capture::default();
    let writer = {
        let capture = capture.clone();
        move || capture.clone()
    };
    let log = dispatch(&LogConfig::default(), writer, Redactor::new());
    (capture, tracing::dispatcher::set_default(&log))
}

impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// Criterion 7.
async fn error_output_goes_to_the_log_as_untrusted_text() {
    let (capture, _guard) = capture_log();
    let package = package("stderr");
    let _instance = loaded(&package).await;
    until(|| capture.text().contains("after the long line")).await;

    let text = capture.text();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    for line in &lines {
        assert!(line.contains("INFO"), "{line}");
        assert!(line.contains("extension error output"), "{line}");
        assert!(line.contains(&format!("extension=\"{ID}\"")), "{line}");
    }
    let field = "guest_message=\"token [REDACTED]  [2J' level='ERROR\"";
    assert!(lines[0].contains(field), "{}", lines[0]);
    assert!(!text.contains(SECRET));
    assert!(!text.contains('\u{1b}'));
    // A line of 20 KiB is cut to 8 KiB, and the rest is not a new line.
    // The host text of the line has two more: `extension` two times.
    assert_eq!(lines[1].matches('x').count(), 8 * 1024 + 2);
    assert!(!text.contains("end-of-long-line"));
}

/// Criterion 7 (ADR-0024): the error output has a budget for each call.
async fn error_output_past_the_budget_is_dropped_and_counted() {
    let (capture, _guard) = capture_log();
    let package = package("flood");
    let instance = loaded(&package).await;
    // The process writes 300 lines before its answer.
    within(instance.activate(context())).await.unwrap();
    // The end of the error output writes the number of dropped lines.
    drop(instance);
    until(|| capture.text().contains("log lines dropped")).await;

    let text = capture.text();
    assert_eq!(
        text.matches("guest_message=\"flood ").count(),
        100,
        "{text}"
    );
    assert!(text.contains("guest_message=\"flood 99\""), "{text}");
    let last = text.lines().last().unwrap();
    assert!(last.contains("WARN"), "{last}");
    assert!(last.contains("200 log lines dropped"), "{last}");
    assert!(last.contains(&format!("extension=\"{ID}\"")), "{last}");
}

/// Criterion 7 (ADR-0024): the byte part of the budget.
async fn error_output_past_the_byte_budget_is_dropped_and_counted() {
    let (capture, _guard) = capture_log();
    let package = package("flood-bytes");
    let instance = loaded(&package).await;
    // The process writes 20 lines of 4 KiB before its answer.
    within(instance.activate(context())).await.unwrap();
    drop(instance);
    until(|| capture.text().contains("log lines dropped")).await;

    let text = capture.text();
    assert_eq!(text.matches("guest_message=\"bbb").count(), 16, "{text}");
    let last = text.lines().last().unwrap();
    assert!(last.contains("4 log lines dropped"), "{last}");
}

/// Criterion 6 (ADR-0024): another process holds the error output of a
/// process that has ended. The task that reads the error output ends, and
/// it writes the number of dropped lines.
#[cfg(unix)]
async fn to_drop_the_instance_ends_the_error_output_task_while_the_pipe_stays_open() {
    let (capture, _guard) = capture_log();
    let tasks = || {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    };
    let package = package("flood-held");
    let mut config = config();
    config.grace = Duration::from_millis(100);
    let (runtime, _crashes) = runtime(config);
    assert_eq!(tasks(), 0);
    let instance = load(&runtime, &package).await.unwrap();
    within(instance.activate(context())).await.unwrap();
    assert_eq!(tasks(), 2, "the supervisor and the error output");

    drop(instance);
    until(|| tasks() == 0).await;
    let text = capture.text();
    let last = text.lines().last().unwrap();
    assert!(last.contains("200 log lines dropped"), "{text}");
}

// --------------------------------------------------------------- runner

type Test = (&'static str, fn() -> BoxFuture<'static, ()>);

macro_rules! tests {
    ($($(#[$attribute:meta])* $name:ident,)*) => {
        &[$($(#[$attribute])* (stringify!($name), || Box::pin($name())),)*]
    };
}

const TESTS: &[Test] = tests![
    #[cfg(unix)]
    a_host_runs_an_extension_in_one_process,
    #[cfg(unix)]
    a_failed_handshake_is_an_error_and_leaves_no_process,
    a_program_that_cannot_start_is_an_error,
    a_relative_program_path_is_refused,
    a_limit_of_zero_is_refused,
    #[cfg(unix)]
    an_error_answer_to_the_handshake_is_kept_and_leaves_no_process,
    an_error_answer_keeps_its_category_and_its_message,
    #[cfg(unix)]
    a_failure_of_the_process_during_a_call_is_an_internal_error,
    a_malformed_message_keeps_its_cause_without_text_of_the_process,
    #[cfg(unix)]
    a_closed_output_during_a_call_is_an_internal_error,
    #[cfg(unix)]
    an_exit_during_a_call_ends_the_call_while_the_output_stays_open,
    #[cfg(unix)]
    an_answer_before_an_exit_is_kept,
    #[cfg(unix)]
    an_answer_in_the_pipe_is_kept_when_the_exit_is_seen_first,
    #[cfg(unix)]
    answers_before_exits_are_kept_under_load,
    #[cfg(unix)]
    half_an_answer_before_an_exit_is_an_end_of_the_process,
    #[cfg(unix)]
    an_exit_before_the_handshake_is_an_error_of_the_load_and_no_crash,
    #[cfg(unix)]
    a_crash_while_no_call_runs_restarts_the_extension_in_a_new_process,
    #[cfg(unix)]
    a_message_that_answers_no_request_is_reported_as_a_crash,
    #[cfg(unix)]
    bytes_without_a_line_end_while_no_call_runs_are_reported_as_a_crash,
    #[cfg(unix)]
    to_drop_the_instance_ends_the_process,
    #[cfg(unix)]
    a_process_that_ignores_its_closed_input_is_killed_after_the_grace_time,
    #[cfg(unix)]
    a_load_waits_for_the_end_of_the_old_process_of_the_extension,
    #[cfg(unix)]
    a_process_that_is_killed_after_the_grace_time_is_not_left_defunct,
    #[cfg(unix)]
    a_dropped_call_kills_the_process,
    the_process_gets_only_the_allowed_environment,
    error_output_goes_to_the_log_as_untrusted_text,
    error_output_past_the_budget_is_dropped_and_counted,
    error_output_past_the_byte_budget_is_dropped_and_counted,
    #[cfg(unix)]
    to_drop_the_instance_ends_the_error_output_task_while_the_pipe_stays_open,
];

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if let [flag, directory] = &arguments[..]
        && flag == "--child"
    {
        child(Path::new(directory));
    }
    let filters: Vec<&String> = arguments.iter().filter(|a| !a.starts_with('-')).collect();
    let selected = |name: &str| filters.is_empty() || filters.iter().any(|f| name.contains(*f));

    let mut failed = 0;
    let mut passed = 0;
    for (name, test) in TESTS.iter().filter(|(name, _)| selected(name)) {
        let run = std::panic::AssertUnwindSafe(|| {
            // Before the runtime starts: a test that is not an `async fn`
            // runs here, with no runtime of the runner.
            let test = test();
            // The engine has a multi-threaded runtime (ARCHITECTURE.md §5.1).
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(test);
        });
        let result = std::panic::catch_unwind(run);
        if result.is_ok() {
            passed += 1;
            println!("test {name} ... ok");
        } else {
            failed += 1;
            println!("test {name} ... FAILED");
        }
    }
    println!("\ntest result: {passed} passed; {failed} failed");
    #[cfg(not(unix))]
    println!("warning: not Unix, so the tests that check that a process is gone did not run");
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
