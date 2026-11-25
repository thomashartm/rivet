//! Extension host: discovery, lazy activation, deactivation, unload and hot
//! reload of extensions (ARCHITECTURE.md §2.3, §4.3, §4.4, §5.2, §5.7).
//!
//! The host contains no database, cloud or format logic. It talks to
//! extension code only through the runtime contract: [`ExtensionRuntime`]
//! loads a package into an [`ExtensionInstance`], the instance activates and
//! deactivates, and to drop the instance unloads it.
//!
//! # States
//!
//! Each extension has one [`ExtensionState`]. One function decides every
//! state change. It permits the transitions of the state diagram in §4.4 and
//! two additions:
//!
//! - An extension in the state `Resolved` or `Rejected` has no loaded code,
//!   so the host can forget it and discover it again when its manifest, or
//!   the result of the resolution, changes.
//! - An extension in the state `Failed` or `Disabled` has no loaded code
//!   either, so [`ExtensionHost::unload`] and [`ExtensionHost::reload`]
//!   can remove it. Without this, a corrected package could not replace
//!   it. [`ExtensionHost::discover`] alone does not remove it.
//!
//! Each state change is published on the event bus as an
//! [`ExtensionStateChanged`].
//!
//! The state `Active` in an event always means that the activation
//! succeeded. An activation that fails goes from its start state (`Resolved`
//! or `Inactive`) directly to `Failed`.
//!
//! # Failures and restart
//!
//! An extension goes to `Failed` when a call into it fails, panics or
//! exceeds the time limit, or when its runtime reports a crash
//! ([`ExtensionHost::report_crash`]).
//!
//! If the failure was in a `deactivate` call, the caller asked to stop the
//! extension. Thus the host does not restart it: it stays `Failed` until
//! [`ExtensionHost::restart`] or [`ExtensionHost::disable`]. After each
//! other failure the host restarts the extension automatically
//! ([`HostConfig`]):
//!
//! - The host waits a delay, then loads and activates the extension again.
//!   The delay grows with each failure in a row, up to a maximum.
//! - Each planned restart is published as an [`ExtensionRestartScheduled`].
//! - A restart that fails changes no state: the extension stays `Failed`
//!   with the new reason, and the next restart is planned.
//! - [`HostConfig::restart_limit`] is the number of automatic restarts that
//!   are permitted. The failure after the last one gives `Disabled`. Each
//!   failure counts, also when the restart before it was successful: an
//!   extension that starts and crashes again is a crash loop (ADR-0021).
//! - An extension that stayed `Active` for [`HostConfig::reset_after`]
//!   starts again with a failure count of zero. Nothing else sets it to
//!   zero.
//! - [`ExtensionHost::shutdown`] stops all pending restarts, and the host
//!   activates nothing after it.
//!
//! When an extension stops for any reason, the host waits until each of
//! its jobs has ended or was aborted, before the state changes and before
//! the instance is dropped (§4.4, §5.2). The job scheduler aborts a job that
//! does not end in
//! [`JobConfig::cancel_grace`](crate::jobs::JobConfig::cancel_grace). During
//! this stop, the service registry, the two buses and the job scheduler
//! refuse the extension: its code cannot register again or start a job.
//!
//! Limit: the abort cannot stop a blocking job, or a job that does not
//! return to the runtime. Such code runs on after the stop and after a
//! restart of the extension. It keeps its job slot, and it can register
//! again with the id of the extension. The next stop of the extension
//! removes what it registered. The host does not keep the extension stopped
//! for it (ADR-0021).
//!
//! # Time limit
//!
//! Each call into extension code (`load`, `activate`, `deactivate`) has the
//! time limit [`HostConfig::call_timeout`]. After the limit, the host stops
//! waiting, puts the extension in `Failed` and does not call the instance
//! again. The host unloads the instance when the call has ended.
//!
//! Limit: the host cannot stop code that does not return to the async
//! runtime, for example a blocking call or a WASM call that still has fuel.
//! That code can run on after the limit. It cannot change the state of the
//! extension. The host does not wait for it: the automatic restart can load
//! a new instance while the old call runs. When the old call ends:
//!
//! - If the extension is not `Active`, the host releases again what the
//!   extension owns (§5.2).
//! - If the extension is `Active` again, the host releases nothing, because
//!   that removes what the new instance registered. What the old call
//!   registered stays until the next stop of the extension.
//! - In both conditions the host unloads the old instance like each other
//!   instance. The task that waits for the call keeps the host alive.
//!
//! A runtime with one thread cannot end the wait for such a call. There the
//! host compares the time after the call: a call that took longer than the
//! limit failed, although it returned.
//!
//! The drop of an instance (the unload) has the same time limit and the
//! same containment: a panic in it is logged as an `internal` error, and the
//! state change occurs nevertheless. It runs in a blocking task.
//! [`ExtensionHost::shutdown`] drops each instance in this way. If the host
//! is dropped without a shutdown, the instances are dropped on the thread
//! that drops the host: a panic is contained, but there is no time limit.
//!
//! # Concurrency
//!
//! Lifecycle operations run one after the other. Thus two activation events
//! for the same extension activate it one time, and a reload is not mixed
//! with an activation. [`ExtensionHost::extensions`] does not wait for a
//! lifecycle operation.
//!
//! Each lifecycle operation runs in its own task. A caller that drops the
//! future of an operation does not stop it: the operation completes, and
//! the next operation starts after it. Thus each operation needs a Tokio
//! runtime: outside a runtime, and when the runtime stops during the
//! operation, the operation returns an `internal` error.
//!
//! An operation waits for extension code while it holds its turn. The wait
//! has an upper bound for each extension that the operation starts or stops:
//!
//! - [`HostConfig::call_timeout`] for each call: `load`, `activate`,
//!   `deactivate` and the unload;
//! - [`JobConfig::cancel_grace`](crate::jobs::JobConfig::cancel_grace) for
//!   each release of the jobs of the extension.
//!
//! The longest sequence for one extension is a reload whose new activation
//! fails: five calls and two releases. With the defaults, that is not more
//! than 160 s.
//!
//! [`ExtensionHost::discover`] and [`ExtensionHost::reload`] read the
//! discovery directories before they wait for their turn. Thus a slow read
//! delays only the next read, not an activation or the shutdown.
//!
//! ```
//! use rivet_core::bus::{CommandBus, EventBus};
//! use rivet_core::host::{
//!     ExtensionHost, ExtensionInstance, ExtensionRuntime, HostConfig, Services,
//! };
//! use rivet_core::jobs::JobScheduler;
//! use rivet_core::registry::ServiceRegistry;
//! use rivet_core::secrets::SecretStore;
//! use rivet_sdk::error::{Error, Result};
//! use rivet_sdk::extension::BoxFuture;
//! use rivet_sdk::manifest::{Manifest, Version};
//! use std::num::{NonZeroU16, NonZeroUsize};
//! use std::path::Path;
//! use std::sync::Arc;
//!
//! struct NoRuntime;
//!
//! impl ExtensionRuntime for NoRuntime {
//!     fn load<'a>(
//!         &'a self,
//!         _manifest: &'a Manifest,
//!         _directory: &'a Path,
//!     ) -> BoxFuture<'a, Result<Box<dyn ExtensionInstance>>> {
//!         Box::pin(async { Err(Error::internal("this runtime loads nothing")) })
//!     }
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
//! let services = Services {
//!     registry: Arc::new(ServiceRegistry::new()),
//!     commands: Arc::new(CommandBus::new()),
//!     events: Arc::new(EventBus::new(NonZeroU16::MIN)),
//!     jobs: JobScheduler::new(NonZeroUsize::MIN, 0),
//! };
//! let directories = vec!["bundled".into(), "user".into(), "workspace".into()];
//! let sdk = Version::new(0, 1, 0);
//! let config = HostConfig::default();
//! let secrets = Arc::new(SecretStore::new());
//! let host = ExtensionHost::new(
//!     Arc::new(NoRuntime),
//!     services,
//!     secrets,
//!     sdk,
//!     directories,
//!     true,
//!     config,
//! );
//! host.discover().await?;
//! assert!(host.extensions().is_empty());
//! # Ok::<(), Error>(())
//! # }).unwrap();
//! ```

use crate::Owner;
use crate::bus::{CommandBus, EventBus};
use crate::jobs::JobScheduler;
use crate::registry::ServiceRegistry;
use crate::resolve::{
    ActivationIndex, ActivationPlan, ActivationTrigger, Outcome, Resolution, resolve,
};
use crate::secrets::SecretStore;
use crate::settings::Settings;
use rivet_sdk::error::{Error, Result};
use rivet_sdk::extension::BoxFuture;
use rivet_sdk::manifest::{ExtensionId, Manifest, Version};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::task::{AbortHandle, JoinError, JoinHandle};
use tokio::time::Instant;

/// The name of the manifest file in an extension directory (§4.4).
pub const MANIFEST_FILE: &str = "extension.toml";

/// The largest manifest file that discovery reads, in bytes (1 MiB). A
/// larger file is listed in [`ExtensionHost::invalid_packages`].
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// The runtime contract: the only way the host reaches extension code
/// (§4.3).
///
/// The host has one runtime. The WASM runtime and the native runtime
/// implement this trait in later tickets. The selection between two runtimes
/// is added when the second one exists.
pub trait ExtensionRuntime: Send + Sync {
    /// Loads the package in `directory`, which has the manifest `manifest`,
    /// and returns its instance. The instance is not active.
    ///
    /// The host unloads an instance by dropping it, in a blocking task (see
    /// the module documentation for a host that is dropped without a
    /// shutdown). Dropping must release everything the instance holds
    /// (§5.2). A panic in the drop is contained (§5.6). There is no `unload` method,
    /// because an unload that can fail has no state in the diagram of §4.4.
    fn load<'a>(
        &'a self,
        manifest: &'a Manifest,
        directory: &'a Path,
    ) -> BoxFuture<'a, Result<Box<dyn ExtensionInstance>>>;
}

/// One loaded extension, made by [`ExtensionRuntime::load`]. To drop it
/// unloads the extension.
///
/// The host calls each method in a separate task. A panic in a method, or
/// a method that exceeds [`HostConfig::call_timeout`], puts the extension in
/// the state `Failed` (§5.6). A method MUST NOT block its thread: the host
/// cannot stop a call that does not return to the runtime.
pub trait ExtensionInstance: Send + Sync {
    /// Activates the extension. The extension registers its services,
    /// command handlers, event subscriptions and jobs through `context`,
    /// with [`ExtensionContext::owner`] as the owner.
    fn activate(&self, context: ExtensionContext) -> BoxFuture<'_, Result<()>>;

    /// Deactivates the extension. After the call, the host removes every
    /// service, command handler and secret backend of the extension, closes
    /// its event subscriptions and cancels its jobs, also when the call
    /// fails.
    fn deactivate(&self) -> BoxFuture<'_, Result<()>>;
}

/// The shared services that extensions register into (§4.6, §5.4).
#[derive(Clone)]
pub struct Services {
    /// The service registry.
    pub registry: Arc<ServiceRegistry>,
    /// The command bus.
    pub commands: Arc<CommandBus>,
    /// The event bus. The host publishes [`ExtensionStateChanged`] on it.
    pub events: Arc<EventBus>,
    /// The job scheduler.
    pub jobs: JobScheduler,
}

/// What an extension gets when it activates.
#[derive(Clone)]
pub struct ExtensionContext {
    /// The id of the extension. The extension gives it as the owner of each
    /// registration, each event subscription
    /// ([`EventBus::subscribe_owned`]) and each job.
    pub owner: Owner,
    /// The shared services.
    pub services: Services,
}

/// The lifecycle state of an extension (§4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtensionState {
    /// The manifest was read. Dependencies are not resolved yet.
    Discovered,
    /// The dependencies are satisfied. The extension activates on an
    /// activation event.
    Resolved,
    /// The extension cannot be loaded. The reason is in
    /// [`ExtensionStatus::reason`].
    Rejected,
    /// The extension is loaded and active.
    Active,
    /// The extension is loaded and not active.
    Inactive,
    /// A call into the extension failed, or the extension crashed. The
    /// host restarts it automatically ([`HostConfig`]). See also
    /// [`ExtensionHost::restart`] and [`ExtensionHost::disable`].
    Failed,
    /// The extension was disabled after a failure. It stays disabled until
    /// [`ExtensionHost::reload`] or [`ExtensionHost::unload`].
    Disabled,
}

/// The limits and the restart behaviour of the host (§4.3, §4.4).
///
/// [`from_settings`](Self::from_settings) reads it from these settings.
/// Times are integers in milliseconds.
///
/// | Setting | Default | Field |
/// | --- | --- | --- |
/// | `extensions.call_timeout_ms` | 30000 | [`call_timeout`](Self::call_timeout) |
/// | `extensions.restart.backoff_initial_ms` | 100 | [`backoff_initial`](Self::backoff_initial) |
/// | `extensions.restart.backoff_factor` | 2 | [`backoff_factor`](Self::backoff_factor) |
/// | `extensions.restart.backoff_max_ms` | 1000 | [`backoff_max`](Self::backoff_max) |
/// | `extensions.restart.limit` | 5 | [`restart_limit`](Self::restart_limit) |
/// | `extensions.restart.reset_after_ms` | 300000 | [`reset_after`](Self::reset_after) |
///
/// The limit on the jobs of one extension (§4.3) is a limit of the job
/// scheduler: see [`JobConfig`](crate::jobs::JobConfig).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConfig {
    /// The time limit of one call into extension code: `load`, `activate`
    /// or `deactivate`.
    pub call_timeout: Duration,
    /// The delay before the first automatic restart.
    pub backoff_initial: Duration,
    /// The delay is multiplied by this number after each failure in a row.
    pub backoff_factor: u32,
    /// The longest delay before an automatic restart.
    pub backoff_max: Duration,
    /// The automatic restarts that are permitted. The failure after the
    /// last one puts the extension in the state `Disabled`. Each failure
    /// counts, also when the restart before it was successful. With `0`,
    /// the first failure disables the extension.
    pub restart_limit: u32,
    /// An extension that stayed `Active` for this time starts again with a
    /// failure count of zero. Nothing else sets the count to zero.
    pub reset_after: Duration,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            call_timeout: Duration::from_secs(30),
            backoff_initial: Duration::from_millis(100),
            backoff_factor: 2,
            backoff_max: Duration::from_secs(1),
            restart_limit: 5,
            reset_after: Duration::from_secs(300),
        }
    }
}

impl HostConfig {
    /// Reads the configuration from `settings`. A key that no layer sets
    /// has its default (see the table in [`HostConfig`]).
    ///
    /// # Errors
    ///
    /// Returns a `user` error if a value has the wrong type, if a time
    /// limit is `0`, if the backoff factor is
    /// `0`, or if the maximum delay is less than the initial delay.
    pub fn from_settings(settings: &Settings) -> Result<Self> {
        let default = Self::default();
        let millis = |key: &str, default: Duration| -> Result<Duration> {
            let value = settings.get::<u64>(key)?;
            Ok(value.map_or(default, Duration::from_millis))
        };
        let config = Self {
            call_timeout: millis("extensions.call_timeout_ms", default.call_timeout)?,
            backoff_initial: millis(
                "extensions.restart.backoff_initial_ms",
                default.backoff_initial,
            )?,
            backoff_factor: settings
                .get("extensions.restart.backoff_factor")?
                .unwrap_or(default.backoff_factor),
            backoff_max: millis("extensions.restart.backoff_max_ms", default.backoff_max)?,
            restart_limit: settings
                .get("extensions.restart.limit")?
                .unwrap_or(default.restart_limit),
            reset_after: millis("extensions.restart.reset_after_ms", default.reset_after)?,
        };
        let invalid = if config.call_timeout.is_zero() {
            "`extensions.call_timeout_ms` must not be 0"
        } else if config.backoff_initial.is_zero() {
            "`extensions.restart.backoff_initial_ms` must not be 0"
        } else if config.backoff_factor == 0 {
            "`extensions.restart.backoff_factor` must not be 0"
        } else if config.backoff_max < config.backoff_initial {
            "`extensions.restart.backoff_max_ms` must not be less than \
             `extensions.restart.backoff_initial_ms`"
        } else {
            return Ok(config);
        };
        Err(Error::user(format!("invalid settings: {invalid}")))
    }

    /// The delay before the restart after `failures` failures in a row.
    fn backoff(&self, failures: u32) -> Duration {
        let factor = self
            .backoff_factor
            .saturating_pow(failures.saturating_sub(1));
        let delay = self.backoff_initial.saturating_mul(factor);
        delay.min(self.backoff_max)
    }
}

/// The host planned an automatic restart of a failed extension. The host
/// publishes it on the event bus.
///
/// The result of the restart is the next event of the extension: an
/// [`ExtensionStateChanged`] to `Active` if it succeeded; if it failed, the
/// next `ExtensionRestartScheduled`, or an [`ExtensionStateChanged`] to
/// `Disabled`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionRestartScheduled {
    /// The extension.
    pub id: ExtensionId,
    /// The number of this restart in the row of failures. It starts at 1.
    pub attempt: u32,
    /// The time the host waits before the restart.
    pub delay: Duration,
    /// Why the extension failed: the message of the error.
    pub reason: String,
}

/// A state change of one extension. The host publishes it on the event bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionStateChanged {
    /// The extension.
    pub id: ExtensionId,
    /// The state before the change. `None` means the extension is new.
    pub from: Option<ExtensionState>,
    /// The state after the change. `None` means the host removed the
    /// extension.
    pub to: Option<ExtensionState>,
    /// Why the extension is `Rejected` or `Failed`, or why the host
    /// disabled it.
    pub reason: Option<String>,
}

/// One entry of [`ExtensionHost::extensions`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionStatus {
    /// The extension.
    pub id: ExtensionId,
    /// The state.
    pub state: ExtensionState,
    /// Why the extension is `Rejected` or `Failed`, or why the host
    /// disabled it. For `Failed`, it is the reason of the last failure.
    pub reason: Option<String>,
    /// The directory of the package.
    pub directory: PathBuf,
}

/// The result of an operation that activates extensions.
#[derive(Debug, Default)]
pub struct ActivationReport {
    /// The extensions that the operation activated, in activation order.
    /// An extension that was active before is not listed.
    pub activated: Vec<ExtensionId>,
    /// The extensions that the operation did not activate, each with the
    /// reason.
    pub not_activated: BTreeMap<ExtensionId, Error>,
}

/// What can occur to an extension. Input of [`transition`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Resolve,
    Reject,
    Activate,
    Deactivate,
    Fail,
    Restart,
    Disable,
    /// Removes a loaded extension.
    Unload,
    /// Removes an extension that has no loaded code, to discover it again.
    Forget,
}

/// The state machine of §4.4, plus `Forget` and the `Unload` of a failed or
/// disabled extension (see the module documentation).
/// `Ok(None)` means the extension is removed.
///
/// This function is the only place that decides if a state change is legal.
fn transition(from: ExtensionState, event: Lifecycle) -> Result<Option<ExtensionState>> {
    use ExtensionState::{Active, Disabled, Discovered, Failed, Inactive, Rejected, Resolved};
    Ok(match (from, event) {
        (Discovered, Lifecycle::Resolve) => Some(Resolved),
        (Discovered, Lifecycle::Reject) => Some(Rejected),
        (Resolved | Inactive, Lifecycle::Activate) | (Failed, Lifecycle::Restart) => Some(Active),
        (Active, Lifecycle::Deactivate) => Some(Inactive),
        // `Resolved` and `Inactive`: the activation failed.
        (Resolved | Inactive | Active, Lifecycle::Fail) => Some(Failed),
        (Failed, Lifecycle::Disable) => Some(Disabled),
        // `Failed` and `Disabled`: see the module documentation.
        (Inactive | Failed | Disabled, Lifecycle::Unload)
        | (Resolved | Rejected, Lifecycle::Forget) => None,
        _ => {
            return Err(Error::policy(format!(
                "the state {from:?} does not permit {event:?}"
            )));
        }
    })
}

/// One extension directory, as read from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Package {
    directory: PathBuf,
    /// The manifest, or why it is invalid.
    manifest: Result<Manifest, String>,
}

struct Entry {
    package: Package,
    state: ExtensionState,
    reason: Option<String>,
    /// `Some` in the states `Active` and `Inactive`, until the shutdown or
    /// a crash report for the `Inactive` extension.
    instance: Option<Arc<dyn ExtensionInstance>>,
    /// The failures in a row. See [`Entry::end_run`].
    failures: u32,
    /// When the extension became `Active`. `Some` in the state `Active`.
    active_since: Option<Instant>,
    /// The task of the pending automatic restart.
    restart: Option<AbortHandle>,
    /// The dependents that a crash stopped, in activation order: each is
    /// `Inactive`, or `Failed` if its `deactivate` call failed. A
    /// successful restart activates them again.
    revive: Vec<ExtensionId>,
}

impl Entry {
    /// Ends the time in the state `Active`. A run of `reset_after` or
    /// longer sets the failure count to zero.
    fn end_run(&mut self, reset_after: Duration) {
        let since = self.active_since.take();
        if since.is_some_and(|since| since.elapsed() >= reset_after) {
            self.failures = 0;
        }
    }

    /// Stops the pending automatic restart, if there is one.
    fn cancel_restart(&mut self, id: &ExtensionId, why: &str) {
        if let Some(task) = self.restart.take() {
            task.abort();
            tracing::info!(extension = %id, why, "pending restart of the extension stopped");
        }
    }

    /// Returns `true` after the first activation. The host then keeps the
    /// package: a change on disk applies only through a reload.
    fn keeps_package(&self) -> bool {
        use ExtensionState::{Active, Disabled, Failed, Inactive};
        matches!(self.state, Active | Inactive | Failed | Disabled)
    }
}

#[derive(Default)]
struct Scan {
    packages: BTreeMap<ExtensionId, Package>,
    /// Directories that cannot be read as an extension and give no id.
    invalid: Vec<(PathBuf, String)>,
    /// Why the newest package of an id is not in `packages`: it is invalid,
    /// and a valid package of an earlier directory stays.
    refused: BTreeMap<ExtensionId, String>,
}

impl Scan {
    /// Why a reload must not replace the package in `directory` of the
    /// extension `id` (ADR-0017): that directory now holds an invalid
    /// package, or a later directory holds an invalid package with this id.
    /// `packages` then has no package for `id`, or one of an earlier
    /// directory.
    fn broken(&self, id: &ExtensionId, directory: Option<&Path>) -> Option<&String> {
        let here = |(folder, _): &&(PathBuf, String)| Some(folder.as_path()) == directory;
        let in_use = self.invalid.iter().find(here).map(|(_, reason)| reason);
        in_use.or_else(|| self.refused.get(id))
    }
}

/// Reads the manifest file of the extension directory `directory`.
/// `Ok(None)` means that the directory has none. Blocking.
fn read_manifest(directory: &Path) -> Result<Option<String>, String> {
    let path = directory.join(MANIFEST_FILE);
    // A link is not followed. A FIFO or a device is not opened: its read
    // can wait for ever.
    match std::fs::symlink_metadata(&path) {
        Ok(found) if found.is_file() => {}
        Ok(_) => return Err(format!("`{MANIFEST_FILE}` is not a regular file")),
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    }
    // shortcut: a file that changes to a link or a FIFO between the check
    // and the open is followed or blocks this read (and each later discovery
    // and reload, but no other operation); open with `O_NOFOLLOW` and
    // `O_NONBLOCK` when the workspace has a crate for these flags.
    let file = std::fs::File::open(&path).map_err(|error| error.to_string())?;
    let mut limited = file.take(MAX_MANIFEST_BYTES + 1);
    let mut text = String::new();
    let read = limited.read_to_string(&mut text);
    read.map_err(|error| error.to_string())?;
    if limited.limit() == 0 {
        return Err(format!(
            "`{MANIFEST_FILE}` is larger than {MAX_MANIFEST_BYTES} bytes"
        ));
    }
    Ok(Some(text))
}

/// Reads the extension directories. Blocking.
///
/// An extension directory is a real directory: a symbolic link is refused.
/// For one id, a later discovery directory wins, but an invalid package
/// never replaces a valid one (ADR-0017). If two folders of one discovery
/// directory have the same id, the folder with the name of the id wins, also
/// if its manifest is invalid: the installer gives a package that name
/// (ADR-0023), and another folder can only claim the id. Without such a
/// folder, the id is invalid in that directory.
fn scan(directories: &[PathBuf]) -> Scan {
    let mut scan = Scan::default();
    for root in directories {
        // `file_type` does not follow a link.
        let mut entries: Vec<(PathBuf, std::fs::FileType)> = match std::fs::read_dir(root) {
            Ok(entries) => entries
                .filter_map(|entry| {
                    let entry = entry.ok()?;
                    Some((entry.path(), entry.file_type().ok()?))
                })
                .collect(),
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                scan.invalid.push((root.clone(), error.to_string()));
                continue;
            }
        };
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut in_root: BTreeMap<ExtensionId, Vec<Package>> = BTreeMap::new();
        for (directory, kind) in entries {
            if kind.is_symlink() {
                let reason = "a symbolic link is not read as an extension directory";
                scan.invalid.push((directory, reason.to_owned()));
                continue;
            }
            if !kind.is_dir() {
                continue;
            }
            let text = match read_manifest(&directory) {
                Ok(Some(text)) => text,
                Ok(None) => continue,
                Err(reason) => {
                    scan.invalid.push((directory, reason));
                    continue;
                }
            };
            let manifest = Manifest::parse(&text).map_err(|error| error.message().to_owned());
            let id = match &manifest {
                Ok(manifest) => Some(manifest.id.clone()),
                // An invalid manifest that has a valid id is listed with that id.
                Err(_) => text.parse::<toml::Table>().ok().and_then(|table| {
                    let id = table.get("id")?.as_str()?.parse().ok()?;
                    Some(id)
                }),
            };
            let (Some(id), manifest) = (id, manifest) else {
                let reason = "invalid extension manifest: no valid `id`".to_owned();
                scan.invalid.push((directory, reason));
                continue;
            };
            let package = Package {
                directory,
                manifest,
            };
            in_root.entry(id).or_default().push(package);
        }
        for (id, mut folders) in in_root {
            let named = |package: &Package| {
                package.directory.file_name() == Some(std::ffi::OsStr::new(id.as_str()))
            };
            let package = match folders.iter().position(named) {
                _ if folders.len() == 1 => folders.remove(0),
                Some(named) => {
                    let package = folders.remove(named);
                    for other in folders {
                        let reason = format!(
                            "extension `{id}` has a second package in `{}`: only the folder \
                             that has the name of the id is read",
                            root.display()
                        );
                        scan.invalid.push((other.directory, reason));
                    }
                    package
                }
                None => {
                    let all: Vec<String> = folders
                        .iter()
                        .map(|package| format!("`{}`", package.directory.display()))
                        .collect();
                    let reason = format!(
                        "extension `{id}` has two packages in `{}` and no folder has the name \
                         of the id: {}",
                        root.display(),
                        all.join(", ")
                    );
                    Package {
                        directory: folders.remove(folders.len() - 1).directory,
                        manifest: Err(reason),
                    }
                }
            };
            match (&package.manifest, scan.packages.get(&id)) {
                (Err(reason), Some(earlier)) if earlier.manifest.is_ok() => {
                    let reason = format!(
                        "extension `{id}`: {reason}; the valid package in `{}` stays",
                        earlier.directory.display()
                    );
                    scan.refused.insert(id, reason.clone());
                    scan.invalid.push((package.directory, reason));
                }
                _ => {
                    scan.refused.remove(&id);
                    scan.packages.insert(id, package);
                }
            }
        }
    }
    scan
}

/// How the wait for a call into extension code ended.
enum Limited<T> {
    /// The call ended in the time limit, or it ended later with an error.
    Ended(Result<T>),
    /// The call ended after the time limit, with this `Ok` result: it did not
    /// return to the runtime, so the runtime could not end the wait.
    Late(Result<T>),
    /// The call still runs. The runtime was asked to stop it.
    Running,
}

/// Waits for `task`, which runs the call `what` into the code of `id`, not
/// longer than `limit`.
async fn joined<T>(
    id: &ExtensionId,
    what: &str,
    limit: Duration,
    task: &mut JoinHandle<Result<T>>,
) -> Limited<T> {
    // On a runtime with one thread, a call that does not return to the
    // runtime also stops the timer of the limit. Thus the real time is
    // compared again after the call.
    // An error that comes late stays: it says more than the limit (the
    // runtime ends a call at the same limit with its own error).
    let start = std::time::Instant::now();
    match tokio::time::timeout(limit, &mut *task).await {
        Ok(Ok(Ok(value))) if start.elapsed() > limit => Limited::Late(Ok(value)),
        Ok(Ok(result)) => Limited::Ended(result),
        Ok(Err(error)) => {
            let message = format!("extension `{id}` {} in `{what}`", ended(&error));
            Limited::Ended(Err(Error::internal(message).with_source(error)))
        }
        Err(_) => {
            task.abort();
            Limited::Running
        }
    }
}

/// The error of a call that exceeded the time limit: like a panic or a
/// trap, it is a defect of the extension, thus `internal`.
fn overdue(id: &ExtensionId, what: &str, limit: Duration) -> Error {
    Error::internal(format!(
        "extension `{id}` exceeded the time limit of {limit:?} in `{what}`"
    ))
}

/// How a task ended that did not complete.
fn ended(error: &JoinError) -> &'static str {
    if error.is_cancelled() {
        "was cancelled"
    } else {
        "panicked"
    }
}

fn not_on_disk(id: &ExtensionId) -> Error {
    Error::user(format!("extension `{id}` is not in a discovery directory"))
}

fn unknown(id: &ExtensionId) -> Error {
    Error::user(format!("extension `{id}` is not known to the host"))
}

struct Inner {
    entries: BTreeMap<ExtensionId, Entry>,
    invalid: Vec<(PathBuf, String)>,
    resolution: Resolution,
    index: ActivationIndex,
    /// `true` after `shutdown`: the host activates nothing any more.
    stopped: bool,
}

impl Inner {
    /// The packages of the extensions that have no loaded code.
    fn unloaded_packages(&self) -> BTreeMap<ExtensionId, Package> {
        let unloaded = self
            .entries
            .iter()
            .filter(|(_, entry)| !entry.keeps_package());
        unloaded
            .map(|(id, entry)| (id.clone(), entry.package.clone()))
            .collect()
    }

    /// The active extensions that depend on `id`, directly or indirectly,
    /// in activation order.
    fn active_dependents(&self, id: &ExtensionId) -> Vec<ExtensionId> {
        let mut tree = BTreeSet::from([id]);
        let mut dependents = Vec::new();
        for candidate in self.resolution.activation_order() {
            let Some(entry) = self.entries.get(candidate) else {
                continue;
            };
            let Ok(manifest) = &entry.package.manifest else {
                continue;
            };
            let depends = manifest.dependencies.keys().any(|key| tree.contains(key));
            if depends && entry.state == ExtensionState::Active {
                tree.insert(candidate);
                dependents.push(candidate.clone());
            }
        }
        dependents
    }
}

/// The extension host. See the [module documentation](self).
///
/// All methods take `&self`. [`ExtensionHost::new`] returns the host in an
/// [`Arc`].
pub struct ExtensionHost {
    /// For the restart tasks. They must not keep the host alive.
    this: Weak<Self>,
    config: HostConfig,
    runtime: Arc<dyn ExtensionRuntime>,
    services: Services,
    /// Not in [`Services`]: an extension must not get the store (§7.4).
    secrets: Arc<SecretStore>,
    sdk_version: Version,
    directories: Vec<PathBuf>,
    headless: bool,
    /// Held for the whole of each lifecycle operation, by the task of the
    /// operation, also while the operation waits for extension code. The
    /// module documentation gives the upper bound of that wait.
    // shortcut: one lock for all extensions, so a slow activation delays the
    // activation of an unrelated extension; use one lock per dependency tree
    // when that delay is measured as a problem.
    lifecycle: tokio::sync::Mutex<()>,
    /// Held from the read of the discovery directories until its result is
    /// applied. Always taken before `lifecycle`.
    scanning: tokio::sync::Mutex<()>,
    /// Never held across an `.await`.
    inner: Mutex<Inner>,
}

impl ExtensionHost {
    /// Creates a host with no extensions. Call [`discover`](Self::discover)
    /// to find them.
    ///
    /// - `secrets` is the secret store of the core. When an extension stops,
    ///   the host removes the secret backends that the extension owns. The
    ///   host does not give the store to an extension (§7.4).
    /// - `sdk_version` is the SDK version of the host. An extension whose
    ///   SDK range does not include it is rejected (§4.5).
    /// - `directories` are the discovery directories in the order bundled,
    ///   user, workspace. If an extension id is in more than one of them,
    ///   the package in the later directory wins. A directory that does not
    ///   exist is ignored.
    /// - `headless` is `true` in a process without a UI. An extension with
    ///   `requires_ui = true` does not activate there.
    /// - `config` gives the time limit and the restart behaviour.
    ///
    /// The automatic restart needs the Tokio runtime with its timer.
    pub fn new(
        runtime: Arc<dyn ExtensionRuntime>,
        services: Services,
        secrets: Arc<SecretStore>,
        sdk_version: Version,
        directories: Vec<PathBuf>,
        headless: bool,
        config: HostConfig,
    ) -> Arc<Self> {
        let resolution = Resolution::default();
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            config,
            runtime,
            services,
            secrets,
            sdk_version,
            directories,
            headless,
            lifecycle: tokio::sync::Mutex::default(),
            scanning: tokio::sync::Mutex::default(),
            inner: Mutex::new(Inner {
                entries: BTreeMap::new(),
                invalid: Vec::new(),
                index: ActivationIndex::new(&resolution),
                resolution,
                stopped: false,
            }),
        })
    }

    /// Returns the state of every extension, sorted by id.
    pub fn extensions(&self) -> Vec<ExtensionStatus> {
        let inner = self.inner();
        let status = |(id, entry): (&ExtensionId, &Entry)| ExtensionStatus {
            id: id.clone(),
            state: entry.state,
            reason: entry.reason.clone(),
            directory: entry.package.directory.clone(),
        };
        inner.entries.iter().map(status).collect()
    }

    /// Returns the directories that the last [`discover`](Self::discover)
    /// did not accept as an extension, each with the reason:
    ///
    /// - a directory that cannot be read as an extension and gives no
    ///   extension id;
    /// - a symbolic link, a manifest that is not a regular file, and a
    ///   manifest above [`MAX_MANIFEST_BYTES`];
    /// - an invalid package that has the id of a valid package in an
    ///   earlier discovery directory. The valid package stays.
    ///
    /// Each other invalid manifest that has a valid `id` is in
    /// [`extensions`](Self::extensions) instead, in the state `Rejected`.
    pub fn invalid_packages(&self) -> Vec<(PathBuf, String)> {
        self.inner().invalid.clone()
    }

    /// Reads the discovery directories and resolves the dependencies.
    ///
    /// An extension is an immediate sub-directory that contains
    /// `extension.toml`. Discovery follows no symbolic link. Discovery
    /// activates nothing. An invalid manifest rejects only its extension.
    ///
    /// The method can be called again. An extension that was activated
    /// before keeps its manifest: use [`reload`](Self::reload) to apply a
    /// change. An extension without loaded code is read again.
    ///
    /// # Errors
    ///
    /// Returns an `internal` error if the read of the directories panicked,
    /// if the caller is not in a Tokio runtime, or if the runtime stopped
    /// during the operation. Each other operation of the host returns the
    /// same error for the last two conditions.
    pub async fn discover(&self) -> Result<()> {
        self.scanned(|host, scan| async move {
            let scan = scan?;
            let unloaded = {
                let mut inner = host.inner();
                inner.invalid = scan.invalid;
                host.reconcile(&mut inner, scan.packages)
            };
            host.drop_instances(unloaded).await;
            Ok(())
        })
        .await?
    }

    /// Activates the extensions that `trigger` selects, each after its
    /// dependencies (§4.4). An extension is loaded on its first activation.
    ///
    /// A failing or panicking activation, or one that exceeds the time
    /// limit, puts that extension in the state `Failed` and removes what it
    /// registered. The host restarts it automatically ([`HostConfig`]). The other extensions still
    /// activate, but not the dependents of the failed extension. The report
    /// gives the reason for each extension that did not activate. After
    /// [`shutdown`](Self::shutdown), the reason is a `policy` error for each
    /// selected extension. If the operation cannot run or cannot end (see
    /// [`discover`](Self::discover)), the reason is that `internal` error.
    pub async fn trigger(&self, trigger: ActivationTrigger<'_>) -> ActivationReport {
        // The task of the operation cannot borrow the name in `trigger`.
        type Plan = Box<dyn FnOnce(&ActivationIndex, bool) -> ActivationPlan + Send>;
        let plan: Plan = match trigger {
            ActivationTrigger::ExtensionPoint(point) => Box::new(move |index, headless| {
                index.plan(ActivationTrigger::ExtensionPoint(point), headless)
            }),
            ActivationTrigger::Command(name) => {
                let name = name.to_owned();
                Box::new(move |index, headless| {
                    index.plan(ActivationTrigger::Command(&name), headless)
                })
            }
            ActivationTrigger::Connection(name) => {
                let name = name.to_owned();
                Box::new(move |index, headless| {
                    index.plan(ActivationTrigger::Connection(&name), headless)
                })
            }
        };
        let operation = self.operation(|host| async move {
            let plan = plan(&host.inner().index, host.headless);
            let mut report = ActivationReport {
                activated: Vec::new(),
                not_activated: plan.blocked,
            };
            host.activate_all(plan.activate, &mut report).await;
            report
        });
        operation.await.unwrap_or_else(|error| {
            let plan = self.inner().index.plan(trigger, self.headless);
            let mut report = ActivationReport {
                activated: Vec::new(),
                not_activated: plan.blocked,
            };
            for id in plan.activate {
                let reason = Error::internal(error.message());
                report.not_activated.insert(id, reason);
            }
            report
        })
    }

    /// Deactivates the active extension `id`, after the active extensions
    /// that depend on it. For each of them, the host then removes its
    /// services and command handlers and cancels its jobs (§5.2).
    ///
    /// # Errors
    ///
    /// - A `user` error if the host does not know `id`.
    /// - A `policy` error if the extension is not `Active`.
    /// - The first error of a `deactivate` call. That extension is `Failed`.
    ///   The host does not restart it automatically. The other extensions
    ///   are deactivated nevertheless.
    pub async fn deactivate(&self, id: &ExtensionId) -> Result<()> {
        let id = id.clone();
        self.operation(|host| async move { host.deactivate_tree(&id).await })
            .await?
    }

    /// Unloads the extension `id`, which is `Inactive`, `Failed` or
    /// `Disabled`: drops its instance and removes it from the host. A later
    /// [`discover`](Self::discover) finds it again, in the state `Resolved`
    /// if it resolves. Extensions that depend on it become `Rejected` until
    /// then. The pending restart of `id`, and of a failed extension that
    /// depends on it, is stopped: that extension stays `Failed`.
    ///
    /// # Errors
    ///
    /// - A `user` error if the host does not know `id`.
    /// - A `policy` error if the extension is in another state.
    pub async fn unload(&self, id: &ExtensionId) -> Result<()> {
        let id = id.clone();
        self.operation(|host| async move {
            let unloaded = {
                let mut inner = host.inner();
                let entry = host.unload_entry(&mut inner, &id)?;
                let packages = inner.unloaded_packages();
                let mut unloaded = Vec::from_iter(entry.map(|entry| (id.clone(), entry)));
                unloaded.extend(host.reconcile(&mut inner, packages));
                unloaded
            };
            host.drop_instances(unloaded).await;
            Ok(())
        })
        .await?
    }

    /// Hot reload (§4.4): reads the package of `id` again, deactivates `id`
    /// and its dependents, unloads `id`, resolves all extensions again and
    /// activates what was active before.
    ///
    /// Only extensions that were active are activated. The report lists
    /// them, and each extension that could not activate again, with the
    /// reason: `id` itself if its `load` or `activate` call failed (it is
    /// `Failed` then), and its dependents.
    ///
    /// A `Failed` or `Disabled` extension is replaced by the new package
    /// and is `Resolved`, with a failure count of zero: its next activation
    /// event loads the new version. This is the way out of `Disabled`.
    ///
    /// # Errors
    ///
    /// - A `user` error if the directory of the package now holds an invalid
    ///   package, or if a later discovery directory holds an invalid package
    ///   with this id. The host changes nothing: it never goes back to a
    ///   valid package of an earlier directory (ADR-0017).
    /// - A `user` error if the package is not on disk any more, or if the
    ///   new manifest is invalid or does not resolve. If the extension was
    ///   activated before (`Active`, `Inactive`, `Failed` or `Disabled`),
    ///   the host checks this first and changes nothing: the old version
    ///   and its dependents stay as they are. An extension without loaded
    ///   code is `Rejected` with the reason, or removed.
    /// - The error of its `deactivate` call. The extension is `Failed`. The
    ///   host does not restart it automatically.
    /// - An `internal` error if the read of the directories panicked.
    pub async fn reload(&self, id: &ExtensionId) -> Result<ActivationReport> {
        let id = id.clone();
        self.scanned(|host, scan| async move { host.reload_locked(&id, scan?).await })
            .await?
    }

    /// The body of [`reload`](Self::reload). `scan` is what is on disk.
    async fn reload_locked(&self, id: &ExtensionId, mut scan: Scan) -> Result<ActivationReport> {
        let state = |host: &Self| host.inner().entries.get(id).map(|entry| entry.state);
        // Only `id` is read again. The other extensions keep their package.
        let new = scan.packages.remove(id);
        let mut was_active = BTreeSet::new();
        let mut report = ActivationReport::default();
        {
            let inner = self.inner();
            let entry = inner.entries.get(id);
            let in_use = entry.map(|entry| entry.package.directory.as_path());
            if let Some(reason) = scan.broken(id, in_use) {
                return Err(Error::user(reason.clone()));
            }
            // The old version stops only if the new package can replace it.
            if entry.is_some_and(Entry::keeps_package) {
                self.replaceable(&inner, id, new.as_ref())?;
            }
            if entry.is_some_and(|entry| entry.state == ExtensionState::Active) {
                was_active.extend(inner.active_dependents(id));
                was_active.insert(id.clone());
            }
        }
        if !was_active.is_empty()
            && let Err(error) = self.deactivate_tree(id).await
            && state(self) != Some(ExtensionState::Inactive)
        {
            return Err(error);
        }
        let unloaded = {
            let mut inner = self.inner();
            let old = match inner.entries.get(id) {
                Some(entry) if entry.keeps_package() => self.unload_entry(&mut inner, id)?,
                _ => None,
            };
            let mut packages = inner.unloaded_packages();
            packages.remove(id);
            packages.extend(new.map(|package| (id.clone(), package)));
            let mut unloaded = Vec::from_iter(old.map(|entry| (id.clone(), entry)));
            unloaded.extend(self.reconcile(&mut inner, packages));
            unloaded
        };
        self.drop_instances(unloaded).await;

        let order: Vec<ExtensionId> = {
            let inner = self.inner();
            match inner.entries.get(id) {
                None => return Err(not_on_disk(id)),
                Some(entry) if entry.state == ExtensionState::Rejected => {
                    return Err(Error::user(entry.reason.clone().unwrap_or_default()));
                }
                Some(_) => {}
            }
            for dependent in &was_active {
                if let Some(entry) = inner.entries.get(dependent)
                    && entry.state == ExtensionState::Rejected
                {
                    let reason = Error::user(entry.reason.clone().unwrap_or_default());
                    report.not_activated.insert(dependent.clone(), reason);
                }
            }
            let order = inner.resolution.activation_order();
            order.filter(|&x| was_active.contains(x)).cloned().collect()
        };
        self.activate_all(order, &mut report).await;
        Ok(report)
    }

    /// Checks that `package` can replace the package of `id`: it is on
    /// disk, its manifest is valid and it resolves with the other
    /// extensions.
    fn replaceable(
        &self,
        inner: &Inner,
        id: &ExtensionId,
        package: Option<&Package>,
    ) -> Result<()> {
        let package = package.ok_or_else(|| not_on_disk(id))?;
        let manifest = package.manifest.clone().map_err(Error::user)?;
        let others = inner.entries.iter().filter(|(other, _)| *other != id);
        let mut manifests: Vec<Manifest> = others
            .filter_map(|(_, entry)| entry.package.manifest.clone().ok())
            .collect();
        manifests.push(manifest);
        match resolve(&manifests, &self.sdk_version).outcomes().get(id) {
            Some(Outcome::Rejected { reason }) => Err(Error::user(reason.message().to_owned())),
            _ => Ok(()),
        }
    }

    /// Removes the extension `id`, which has no active code, and stops its
    /// pending restart. Returns the entry for `drop_instances`.
    fn unload_entry(&self, inner: &mut Inner, id: &ExtensionId) -> Result<Option<Entry>> {
        let entry = self.apply(inner, id, Lifecycle::Unload, None)?;
        Ok(entry.map(|mut entry| {
            entry.cancel_restart(id, "the extension was unloaded");
            entry
        }))
    }

    /// Activates the failed extension `id` again, without the delay of the
    /// automatic restart. It replaces a pending automatic restart. After a
    /// success, the host activates the dependents again that a crash of
    /// `id` deactivated.
    ///
    /// # Errors
    ///
    /// - A `user` error if the host does not know `id`.
    /// - A `policy` error if the extension is not `Failed`, or if it has
    ///   `requires_ui = true` in a headless host.
    /// - A `policy` error if a dependency is not active. This counts as a
    ///   failed restart.
    /// - The error of the `load` or `activate` call. The extension stays
    ///   `Failed`, and the failure counts as a failed restart.
    pub async fn restart(&self, id: &ExtensionId) -> Result<()> {
        let id = id.clone();
        self.operation(|host| async move { host.restart_one(&id).await })
            .await?
    }

    /// Handles a crash of the extension `id`, for example a WASM trap
    /// outside a lifecycle call or the end of a native process. The runtime
    /// of the extension calls it. `error` is the reason; it must not contain
    /// secrets.
    ///
    /// The host deactivates the active dependents first, puts `id` in the
    /// state `Failed`, releases what it owns (§5.2) and drops its instance.
    /// It does not call the crashed instance. Then the automatic restart
    /// applies ([`HostConfig`]). A successful restart activates the
    /// dependents again, also a dependent whose `deactivate` call failed
    /// here and that is `Failed` thus.
    ///
    /// If `id` is not `Active` (ADR-0021), the host only unloads the
    /// instance, if it has one (an `Inactive` extension): the instance is
    /// dead. The state does not change, no failure is counted and nothing
    /// restarts. The next activation loads a new instance.
    ///
    /// # Errors
    ///
    /// - A `user` error if the host does not know `id`.
    pub async fn report_crash(&self, id: &ExtensionId, error: Error) -> Result<()> {
        let id = id.clone();
        self.operation(|host| async move { host.crash(&id, &error).await })
            .await?
    }

    /// The body of [`report_crash`](Self::report_crash).
    async fn crash(&self, id: &ExtensionId, error: &Error) -> Result<()> {
        let (state, dead) = {
            let mut inner = self.inner();
            let entry = inner.entries.get_mut(id).ok_or_else(|| unknown(id))?;
            match entry.state {
                ExtensionState::Active => (entry.state, None),
                // The instance has ended. The next activation loads a new one.
                state => (state, entry.instance.take()),
            }
        };
        if state != ExtensionState::Active {
            let unloaded = dead.is_some();
            tracing::warn!(extension = %id, ?state, %error, unloaded, "crash report for an extension that is not active");
            self.drop_instance(id, dead).await;
            return Ok(());
        }
        let dependents = self.inner().active_dependents(id);
        for dependent in dependents.iter().rev() {
            // A dependent that fails here is `Failed` until the restart of
            // `id` succeeds.
            if let Err(error) = self.deactivate_one(dependent).await {
                tracing::warn!(extension = %dependent, %error, "deactivation after a crash failed");
            }
        }
        if let Some(entry) = self.inner().entries.get_mut(id) {
            entry.revive = dependents;
        }
        self.fail(id, error, true).await
    }

    /// Disables the failed extension `id` and stops its pending restart. A
    /// disabled extension does not activate again until a
    /// [`reload`](Self::reload).
    ///
    /// # Errors
    ///
    /// - A `user` error if the host does not know `id`.
    /// - A `policy` error if the extension is not `Failed`.
    pub async fn disable(&self, id: &ExtensionId) -> Result<()> {
        let _lifecycle = self.lifecycle.lock().await;
        let mut inner = self.inner();
        self.apply(&mut inner, id, Lifecycle::Disable, None)?;
        if let Some(entry) = inner.entries.get_mut(id) {
            entry.cancel_restart(id, "the extension was disabled");
            entry.revive.clear();
        }
        Ok(())
    }

    /// Deactivates all active extensions in reverse dependency order
    /// (§5.7), then drops the instance of each loaded extension in the same
    /// order, also of an extension that was `Inactive` before. The states
    /// stay readable. A failure does not stop the shutdown. Returns the extensions whose `deactivate` call failed, each
    /// with the error. If the operation cannot run or cannot end (see
    /// [`discover`](Self::discover)), it returns each active extension with
    /// that `internal` error.
    ///
    /// The shutdown stops all pending restarts. After it, the host does not
    /// activate or restart an extension: each attempt is a `policy` error.
    ///
    /// The shutdown waits for the lifecycle operation that runs. The time
    /// limit of a call into an extension ([`HostConfig::call_timeout`])
    /// ends that wait.
    pub async fn shutdown(&self) -> BTreeMap<ExtensionId, Error> {
        let operation = self.operation(|host| async move { host.shutdown_locked().await });
        operation.await.unwrap_or_else(|error| {
            let inner = self.inner();
            let active = inner.entries.iter();
            let active = active.filter(|(_, entry)| entry.state == ExtensionState::Active);
            active
                .map(|(id, _)| (id.clone(), Error::internal(error.message())))
                .collect()
        })
    }

    /// The body of [`shutdown`](Self::shutdown).
    async fn shutdown_locked(&self) -> BTreeMap<ExtensionId, Error> {
        let order: Vec<ExtensionId> = {
            let mut inner = self.inner();
            inner.stopped = true;
            for (id, entry) in &mut inner.entries {
                entry.cancel_restart(id, "the host shuts down");
            }
            let active = |id: &&ExtensionId| {
                let entry = inner.entries.get(*id);
                entry.is_some_and(|entry| entry.state == ExtensionState::Active)
            };
            let order = inner.resolution.shutdown_order();
            order.filter(active).cloned().collect()
        };
        let mut failures = BTreeMap::new();
        for id in order {
            if let Err(error) = self.deactivate_one(&id).await {
                failures.insert(id, error);
            }
        }
        // Each instance, also of an extension that was `Inactive` before:
        // a child process lives as long as its instance (ADR-0021). The
        // states stay. Without this, the instances are dropped with the
        // host, on the thread of its last owner.
        let loaded: Vec<ExtensionId> = {
            let inner = self.inner();
            inner.resolution.shutdown_order().cloned().collect()
        };
        for id in loaded {
            let instance = {
                let mut inner = self.inner();
                let entry = inner.entries.get_mut(&id);
                entry.and_then(|entry| entry.instance.take())
            };
            self.drop_instance(&id, instance).await;
        }
        failures
    }

    /// Runs one lifecycle operation in its own task, which holds the
    /// lifecycle lock. Thus a caller that drops its future does not stop
    /// the operation between two steps.
    async fn operation<T, F, Fut>(&self, body: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Self>) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send,
    {
        self.detached(|host| async move {
            let _lifecycle = host.lifecycle.lock().await;
            body(Arc::clone(&host)).await
        })
        .await
    }

    /// Runs one lifecycle operation like [`operation`](Self::operation),
    /// and gives it what is on disk.
    ///
    /// The read of the directories can be slow, so it is before the
    /// lifecycle lock: it delays no activation and no shutdown. This is
    /// safe, because the read uses no state of the host, and because the
    /// `scanning` lock applies the results in the order of the reads: a
    /// newer read is never replaced by an older one.
    async fn scanned<T, F, Fut>(&self, body: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Self>, Result<Scan>) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send,
    {
        self.detached(|host| async move {
            let _scanning = host.scanning.lock().await;
            let scan = host.scan().await;
            let _lifecycle = host.lifecycle.lock().await;
            body(Arc::clone(&host), scan).await
        })
        .await
    }

    /// Runs `body` in its own task and waits for it.
    ///
    /// Returns an `internal` error if the caller is not in a Tokio runtime,
    /// or if the runtime stopped before `body` ended.
    async fn detached<T, F, Fut>(&self, body: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Self>) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send,
    {
        let host = self.this.upgrade();
        let host = host.ok_or_else(|| Error::internal("the extension host is not in its `Arc`"))?;
        let runtime = Handle::try_current().map_err(|error| {
            let message = "a lifecycle operation can start only inside the Tokio runtime";
            Error::internal(message).with_source(error)
        })?;
        let task = runtime.spawn(async move { body(host).await });
        match task.await.map_err(JoinError::try_into_panic) {
            Ok(result) => Ok(result),
            // A panic of the host itself, not of an extension.
            Err(Ok(panic)) => std::panic::resume_unwind(panic),
            Err(Err(error)) => {
                let message = "the Tokio runtime stopped during a lifecycle operation";
                Err(Error::internal(message).with_source(error))
            }
        }
    }

    /// Runs the call `what` into the code of `id` in a separate task, so
    /// that a panic in the call is an `internal` error and not a panic of
    /// the host (§5.6). A call that takes longer than
    /// [`HostConfig::call_timeout`] is an `internal` error also.
    ///
    /// `keep` is the instance that the call uses. If the call runs on after
    /// the time limit, [`follow`](Self::follow) unloads it when the call
    /// ended.
    // shortcut: the abort stops the call at its next `.await` only, so code
    // that does not return to the runtime runs on until it returns; the WASM
    // runtime (#4, epoch interruption) and the native host process (#95)
    // must stop it.
    async fn contained<T: Send + 'static>(
        &self,
        id: &ExtensionId,
        what: &str,
        keep: Option<Arc<dyn ExtensionInstance>>,
        call: impl Future<Output = Result<T>> + Send + 'static,
    ) -> Result<T> {
        let limit = self.config.call_timeout;
        let mut task = tokio::spawn(call);
        match joined(id, what, limit, &mut task).await {
            Limited::Ended(result) => return result,
            // A late `load` gives an instance. It is unloaded.
            Limited::Late(result) => self.drop_instance(id, Some(result)).await,
            Limited::Running => self.follow(id, task, keep),
        }
        Err(overdue(id, what, limit))
    }

    /// Follows the call `task` into the code of `id`, which runs on after
    /// the time limit. When the call has ended, the host releases what the
    /// call registered after the failure, and unloads what the call held:
    /// the instance `keep`, or the instance that a `load` call returned.
    ///
    /// There is no release if the extension is `Active` again at that time:
    /// the release would remove what the new instance registered. What the
    /// old call registered then stays until the next release of `id`.
    ///
    /// The task of this function keeps the host alive until the call ended.
    fn follow<T: Send + 'static>(
        &self,
        id: &ExtensionId,
        task: JoinHandle<Result<T>>,
        keep: Option<Arc<dyn ExtensionInstance>>,
    ) {
        // An operation holds the host.
        let Some(host) = self.this.upgrade() else {
            return;
        };
        let id = id.clone();
        tokio::spawn(async move {
            let result = task.await;
            // No operation changes the state between the check and the release.
            let _lifecycle = host.lifecycle.lock().await;
            let active = {
                let inner = host.inner();
                let entry = inner.entries.get(&id);
                entry.is_some_and(|entry| entry.state == ExtensionState::Active)
            };
            if active {
                tracing::warn!(extension = %id, "a call that exceeded the time limit ended after the restart of the extension");
            } else {
                host.release(&id).await;
            }
            host.drop_instance(&id, Some((result, keep))).await;
        });
    }

    /// Unloads the instance of `id`: drops it in a blocking task, with the
    /// time limit and the containment of each call into extension code.
    /// `instance` is the instance, or a value that holds it.
    async fn drop_instance<D: Send + 'static>(&self, id: &ExtensionId, instance: Option<D>) {
        let Some(instance) = instance else {
            return;
        };
        let mut unload = tokio::task::spawn_blocking(move || {
            drop(instance);
            Ok(())
        });
        let limit = self.config.call_timeout;
        let result = match joined(id, "unload", limit, &mut unload).await {
            Limited::Ended(result) => result,
            Limited::Late(_) | Limited::Running => Err(overdue(id, "unload", limit)),
        };
        if let Err(error) = result {
            tracing::error!(extension = %id, %error, "unload of the extension failed");
        }
    }

    /// Unloads the instances of the entries that a state change removed.
    async fn drop_instances(&self, removed: Vec<(ExtensionId, Entry)>) {
        for (id, entry) in removed {
            self.drop_instance(&id, entry.instance).await;
        }
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn scan(&self) -> Result<Scan> {
        let directories = self.directories.clone();
        let scan = tokio::task::spawn_blocking(move || scan(&directories)).await;
        scan.map_err(|error| {
            let message = format!("extension discovery {}", ended(&error));
            Error::internal(message).with_source(error)
        })
    }

    fn publish(
        &self,
        id: &ExtensionId,
        from: Option<ExtensionState>,
        to: Option<ExtensionState>,
        reason: Option<String>,
    ) {
        tracing::debug!(extension = %id, ?from, ?to, reason, "extension state changed");
        let id = id.clone();
        let event = ExtensionStateChanged {
            id,
            from,
            to,
            reason,
        };
        self.services.events.publish(event);
    }

    /// Makes one state change: the only code that writes a state. Returns
    /// the entry if the change removed the extension. The caller gives it
    /// to `drop_instances` after it released the lock, because the drop
    /// runs extension code.
    fn apply(
        &self,
        inner: &mut Inner,
        id: &ExtensionId,
        event: Lifecycle,
        reason: Option<String>,
    ) -> Result<Option<Entry>> {
        let entry = inner.entries.get_mut(id).ok_or_else(|| unknown(id))?;
        let from = entry.state;
        let to = transition(from, event)
            .map_err(|error| Error::policy(format!("extension `{id}`: {}", error.message())))?;
        let removed = match to {
            Some(state) => {
                entry.state = state;
                entry.reason.clone_from(&reason);
                None
            }
            None => inner.entries.remove(id),
        };
        self.publish(id, Some(from), to, reason);
        Ok(removed)
    }

    /// Makes the entries equal to `packages` plus the extensions that keep
    /// their package, and resolves all of them again. Returns the entries it
    /// removed, for the caller to give to `drop_instances` after it released
    /// the lock.
    fn reconcile(
        &self,
        inner: &mut Inner,
        mut packages: BTreeMap<ExtensionId, Package>,
    ) -> Vec<(ExtensionId, Entry)> {
        for (id, entry) in &inner.entries {
            if entry.keeps_package() {
                packages.insert(id.clone(), entry.package.clone());
            }
        }
        let manifests = packages
            .values()
            .filter_map(|package| package.manifest.clone().ok());
        let manifests: Vec<Manifest> = manifests.collect();
        let resolution = resolve(&manifests, &self.sdk_version);

        let mut removed = Vec::new();
        let ids = inner.entries.keys().chain(packages.keys()).cloned();
        for id in ids.collect::<BTreeSet<ExtensionId>>() {
            // The package and why it is rejected, if it is.
            let wanted = packages.remove(&id).map(|package| {
                let rejected = match (&package.manifest, resolution.outcomes().get(&id)) {
                    (Err(reason), _) => Some(reason.clone()),
                    (Ok(_), Some(Outcome::Rejected { reason })) => {
                        Some(reason.message().to_owned())
                    }
                    (Ok(_), _) => None,
                };
                (package, rejected)
            });
            if let Some(entry) = inner.entries.get(&id) {
                let keep = match (&wanted, entry.state) {
                    (None, _) => false,
                    // An inactive extension that does not resolve any more is unloaded.
                    (Some((_, rejected)), ExtensionState::Inactive) => rejected.is_none(),
                    (Some(_), _) if entry.keeps_package() => true,
                    (Some((package, rejected)), _) => {
                        *package == entry.package && *rejected == entry.reason
                    }
                };
                if keep {
                    continue;
                }
                let event = match entry.state {
                    ExtensionState::Inactive => Lifecycle::Unload,
                    _ => Lifecycle::Forget,
                };
                // `keep` is `true` for each state that permits neither event.
                let entry = self.apply(inner, &id, event, None).ok().flatten();
                removed.extend(entry.map(|entry| (id.clone(), entry)));
            }
            let Some((package, rejected)) = wanted else {
                continue;
            };
            let entry = Entry {
                package,
                state: ExtensionState::Discovered,
                reason: None,
                instance: None,
                failures: 0,
                active_since: None,
                restart: None,
                revive: Vec::new(),
            };
            inner.entries.insert(id.clone(), entry);
            self.publish(&id, None, Some(ExtensionState::Discovered), None);
            let event = match rejected {
                Some(_) => Lifecycle::Reject,
                None => Lifecycle::Resolve,
            };
            // `Discovered` permits both events.
            let entry = self.apply(inner, &id, event, rejected).ok().flatten();
            removed.extend(entry.map(|entry| (id.clone(), entry)));
        }
        // A failed extension that does not resolve any more cannot restart.
        for (id, entry) in &mut inner.entries {
            if let Some(Outcome::Rejected { .. }) = resolution.outcomes().get(id) {
                entry.cancel_restart(id, "the extension does not resolve any more");
            }
        }
        inner.index = ActivationIndex::new(&resolution);
        inner.resolution = resolution;
        removed
    }

    /// Releases everything that `owner` registered (§5.2), also its secret
    /// backends. It does not change the grants of `owner`: a grant is the
    /// decision of the user and ends only with an uninstall or a new review
    /// (§4.7, ADR-0020).
    ///
    /// From its start to its end, the registry, the two buses, the job
    /// scheduler and the secret store refuse `owner`: code that still runs
    /// cannot register behind the release (ADR-0021).
    ///
    /// It waits until each job of `owner` has ended or was aborted. The job
    /// scheduler limits this wait: it aborts a job that ignores the cancel
    /// request. The registrations are removed after that wait, so that the
    /// state of the extension and its registrations change together.
    async fn release(&self, owner: &Owner) {
        self.services.registry.close_owner(owner);
        self.services.commands.close_owner(owner);
        self.services.events.close_owner(owner);
        self.services.jobs.close_owner(owner);
        self.secrets.close_owner(owner);
        self.services.jobs.stop_owner(owner).await;
        self.services.registry.unregister_owner(owner);
        self.services.commands.unregister_owner(owner);
        self.services.events.unsubscribe_owner(owner);
        // After the jobs, like the other registrations. A resolve that
        // runs holds its own reference to the backend.
        self.secrets.unregister_owner(owner);
        self.services.registry.open_owner(owner);
        self.services.commands.open_owner(owner);
        self.services.events.open_owner(owner);
        self.services.jobs.open_owner(owner);
        self.secrets.open_owner(owner);
        let running = self.services.jobs.aborted_running(owner);
        if running > 0 {
            tracing::warn!(extension = %owner, jobs = running, "the release of the extension ended, but the code of aborted jobs has not stopped: it can register again");
        }
    }

    /// Handles a failure of `id`: releases what it owns, puts it in the
    /// state `Failed` and unloads its instance. An extension that is
    /// `Failed` already (a failed restart) stays `Failed` with the new
    /// reason. With `restart`, the restart policy applies; without it, the
    /// extension stays `Failed` (a failed `deactivate` call).
    async fn fail(&self, id: &ExtensionId, error: &Error, restart: bool) -> Result<()> {
        self.release(id).await;
        let instance = {
            let mut inner = self.inner();
            let reason = error.message().to_owned();
            let entry = inner.entries.get_mut(id).ok_or_else(|| unknown(id))?;
            if entry.state == ExtensionState::Failed {
                entry.reason = Some(reason.clone());
            } else {
                self.apply(&mut inner, id, Lifecycle::Fail, Some(reason.clone()))?;
            }
            if restart {
                self.after_failure(&mut inner, id, &reason);
            } else {
                tracing::warn!(extension = %id, reason, "extension failed in its deactivation");
            }
            let entry = inner.entries.get_mut(id);
            entry.and_then(|entry| {
                entry.end_run(self.config.reset_after);
                entry.instance.take()
            })
        };
        self.drop_instance(id, instance).await;
        Ok(())
    }

    /// Counts a failure of the failed extension `id`. Then it disables the
    /// extension if the restart limit is reached, or plans the restart.
    fn after_failure(&self, inner: &mut Inner, id: &ExtensionId, reason: &str) {
        let Some(entry) = inner.entries.get_mut(id) else {
            return;
        };
        entry.end_run(self.config.reset_after);
        entry.failures = entry.failures.saturating_add(1);
        let failures = entry.failures;
        tracing::warn!(extension = %id, failures, reason, "extension failed");
        let limit = self.config.restart_limit;
        if failures > limit {
            entry.revive.clear();
            tracing::warn!(extension = %id, reason, "extension disabled: restart limit reached");
            let reason = format!("the restart limit of {limit} is reached; last failure: {reason}");
            // `Failed` permits `Disable`.
            let _ = self.apply(inner, id, Lifecycle::Disable, Some(reason));
            return;
        }
        let delay = self.config.backoff(failures);
        let (host, extension) = (self.this.clone(), id.clone());
        let task = tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            if let Some(host) = host.upgrade() {
                host.restart_after_delay(&extension).await;
            }
        });
        entry.cancel_restart(id, "a new restart replaces it");
        entry.restart = Some(task.abort_handle());
        tracing::info!(extension = %id, attempt = failures, ?delay, reason, "restart of the extension planned");
        self.services.events.publish(ExtensionRestartScheduled {
            id: id.clone(),
            attempt: failures,
            delay,
            reason: reason.to_owned(),
        });
    }

    /// The end of a restart task: restarts `id` if the restart is still
    /// pending.
    async fn restart_after_delay(&self, id: &ExtensionId) {
        let _lifecycle = self.lifecycle.lock().await;
        // Each operation that stops a restart holds the lifecycle lock. Thus
        // nothing aborts this task after it took its own handle.
        let pending = {
            let mut inner = self.inner();
            let entry = inner.entries.get_mut(id);
            entry.and_then(|entry| entry.restart.take())
        };
        if pending.is_none() {
            return;
        }
        match self.restart_one(id).await {
            Ok(()) => tracing::info!(extension = %id, "extension restarted"),
            Err(error) => {
                tracing::warn!(extension = %id, %error, "restart of the extension failed")
            }
        }
    }

    /// Restarts the failed extension `id` now. After a success, activates
    /// the dependents again that a crash of `id` deactivated.
    async fn restart_one(&self, id: &ExtensionId) -> Result<()> {
        if let Some(entry) = self.inner().entries.get_mut(id) {
            entry.cancel_restart(id, "the extension restarts now");
        }
        self.activate_one(id, Lifecycle::Restart).await?;
        let revive = {
            let mut inner = self.inner();
            let entry = inner.entries.get_mut(id);
            entry.map(|entry| std::mem::take(&mut entry.revive))
        };
        for dependent in revive.unwrap_or_default() {
            let failed = {
                let inner = self.inner();
                let entry = inner.entries.get(&dependent);
                entry.is_some_and(|entry| entry.state == ExtensionState::Failed)
            };
            let event = match failed {
                // Its `deactivate` call failed in the crash.
                true => Lifecycle::Restart,
                false => Lifecycle::Activate,
            };
            // A dependent that fails is `Failed` and has its own restart.
            if let Err(error) = self.activate_one(&dependent, event).await {
                tracing::warn!(extension = %dependent, %error, "activation after a restart failed");
            }
        }
        Ok(())
    }

    /// Activates `ids` in the given order and adds the results to `report`.
    async fn activate_all(&self, ids: Vec<ExtensionId>, report: &mut ActivationReport) {
        for id in ids {
            match self.activate_one(&id, Lifecycle::Activate).await {
                Ok(true) => report.activated.push(id),
                Ok(false) => {}
                Err(error) => {
                    report.not_activated.insert(id, error);
                }
            }
        }
    }

    /// Loads `id` if it is not loaded, and activates it. `event` is
    /// `Activate` or `Restart`. Returns `false` if `id` was active already.
    async fn activate_one(&self, id: &ExtensionId, event: Lifecycle) -> Result<bool> {
        let prepared = {
            let inner = self.inner();
            let entry = inner.entries.get(id).ok_or_else(|| unknown(id))?;
            if entry.state == ExtensionState::Active && event == Lifecycle::Activate {
                return Ok(false);
            }
            let refuse = |reason: &str| format!("extension `{id}` cannot activate: {reason}");
            if inner.stopped {
                return Err(Error::policy(refuse("the host shut down")));
            }
            transition(entry.state, event)
                .map_err(|error| Error::policy(refuse(error.message())))?;
            let manifest = entry.package.manifest.clone().map_err(Error::user)?;
            if self.headless && manifest.requires_ui {
                let reason = "it has `requires_ui = true` and the process is headless";
                return Err(Error::policy(refuse(reason)));
            }
            let inactive = |dependency: &&ExtensionId| {
                let entry = inner.entries.get(*dependency);
                entry.is_none_or(|entry| entry.state != ExtensionState::Active)
            };
            match manifest.dependencies.keys().find(inactive) {
                Some(dependency) => {
                    let reason = format!("its dependency `{dependency}` is not active");
                    Err(Error::policy(refuse(&reason)))
                }
                None => {
                    let directory = entry.package.directory.clone();
                    Ok((entry.instance.clone(), manifest, directory))
                }
            }
        };
        let (instance, manifest, directory) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                // A restart that cannot start is a failed restart.
                if event == Lifecycle::Restart {
                    self.fail(id, &error, true).await?;
                }
                return Err(error);
            }
        };

        let result = async {
            let instance = match instance {
                Some(instance) => instance,
                None => {
                    let runtime = Arc::clone(&self.runtime);
                    let load = async move { runtime.load(&manifest, &directory).await };
                    let instance: Arc<dyn ExtensionInstance> =
                        self.contained(id, "load", None, load).await?.into();
                    if let Some(entry) = self.inner().entries.get_mut(id) {
                        entry.instance = Some(Arc::clone(&instance));
                    }
                    instance
                }
            };
            let context = ExtensionContext {
                owner: id.clone(),
                services: self.services.clone(),
            };
            let keep = Some(Arc::clone(&instance));
            let activate = async move { instance.activate(context).await };
            self.contained(id, "activate", keep, activate).await
        }
        .await;

        match result {
            Ok(()) => {
                let mut inner = self.inner();
                self.apply(&mut inner, id, event, None)?;
                if let Some(entry) = inner.entries.get_mut(id) {
                    entry.active_since = Some(Instant::now());
                }
                Ok(true)
            }
            Err(error) => {
                self.fail(id, &error, true).await?;
                Err(error)
            }
        }
    }

    /// Deactivates the active extension `id` and releases what it owns.
    async fn deactivate_one(&self, id: &ExtensionId) -> Result<()> {
        let instance = {
            let inner = self.inner();
            let entry = inner.entries.get(id).ok_or_else(|| unknown(id))?;
            transition(entry.state, Lifecycle::Deactivate)
                .map_err(|error| Error::policy(format!("extension `{id}`: {}", error.message())))?;
            entry.instance.clone()
        };
        let result = match instance {
            Some(instance) => {
                let keep = Some(Arc::clone(&instance));
                let deactivate = async move { instance.deactivate().await };
                self.contained(id, "deactivate", keep, deactivate).await
            }
            None => Ok(()),
        };
        match result {
            Ok(()) => {
                self.release(id).await;
                let mut inner = self.inner();
                self.apply(&mut inner, id, Lifecycle::Deactivate, None)?;
                if let Some(entry) = inner.entries.get_mut(id) {
                    entry.end_run(self.config.reset_after);
                }
                Ok(())
            }
            Err(error) => {
                // The caller asked to stop the extension: no restart.
                self.fail(id, &error, false).await?;
                Err(error)
            }
        }
    }

    /// Deactivates the active dependents of `id`, then `id`. Returns the
    /// first error and continues after it.
    async fn deactivate_tree(&self, id: &ExtensionId) -> Result<()> {
        let mut order = {
            let inner = self.inner();
            let entry = inner.entries.get(id).ok_or_else(|| unknown(id))?;
            transition(entry.state, Lifecycle::Deactivate)
                .map_err(|error| Error::policy(format!("extension `{id}`: {}", error.message())))?;
            inner.active_dependents(id)
        };
        order.reverse();
        order.push(id.clone());
        let mut first = Ok(());
        for extension in &order {
            let result = self.deactivate_one(extension).await;
            if first.is_ok() {
                first = result;
            }
        }
        first
    }
}

impl Drop for ExtensionHost {
    /// Stops the restart tasks, so that no timer waits for a host that is
    /// gone.
    ///
    /// Then it drops the instances that are left, in reverse dependency
    /// order. There are none after [`ExtensionHost::shutdown`]. A panic in
    /// a drop is contained. These drops run on the thread that drops the
    /// host, without a time limit: call `shutdown` first.
    fn drop(&mut self) {
        let inner = self.inner.get_mut();
        let inner = inner.unwrap_or_else(PoisonError::into_inner);
        let mut ids: Vec<ExtensionId> = inner.resolution.shutdown_order().cloned().collect();
        // An entry that the resolution does not have.
        ids.extend(inner.entries.keys().cloned());
        for id in ids {
            let Some(entry) = inner.entries.get_mut(&id) else {
                continue;
            };
            entry.cancel_restart(&id, "the host is dropped");
            let Some(instance) = entry.instance.take() else {
                continue;
            };
            let unload = std::panic::AssertUnwindSafe(move || drop(instance));
            if std::panic::catch_unwind(unload).is_err() {
                tracing::error!(extension = %id, "unload of the extension panicked");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::{Received, Subscription};
    use crate::jobs::JobHandle;
    use crate::secrets::{SecretBackend, SecretFuture};
    use rivet_sdk::error::ErrorCategory;
    use rivet_sdk::secret::Secret;
    use std::num::{NonZeroU16, NonZeroUsize};
    use tempfile::TempDir;

    use ExtensionState::{Active, Disabled, Discovered, Failed, Inactive, Rejected, Resolved};

    #[derive(Clone, Copy)]
    enum Mode {
        Fail,
        Panic,
        /// The call never returns.
        Hang,
        /// The call returns after `Fake::gate` is notified.
        Wait,
        /// The call blocks its thread for this real time: it does not
        /// return to the runtime.
        Sleep(Duration),
        /// The call blocks its thread until the test removes the mode
        /// `hold <call>`.
        Block,
    }

    /// The record of the fake runtime: what the host called, and what must
    /// fail.
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<String>>,
        modes: Mutex<BTreeMap<String, Mode>>,
        jobs: Mutex<BTreeMap<String, JobHandle<()>>>,
        subscriptions: Mutex<BTreeMap<String, Subscription<Ping>>>,
        gate: tokio::sync::Notify,
        /// The store of the host. The host gives it to no extension; the
        /// fake stands for the host service that registers a backend.
        secrets: Arc<SecretStore>,
        /// The threads that ran async extension code.
        workers: Mutex<Vec<std::thread::ThreadId>>,
    }

    /// The secret backend of each fake extension.
    struct Fixed;

    impl SecretBackend for Fixed {
        fn resolve<'a>(&'a self, _path: &'a str) -> SecretFuture<'a> {
            Box::pin(async { Ok(Secret::from(String::from("value"))) })
        }
    }

    /// An event that each fake extension subscribes to.
    #[derive(Debug, Clone, PartialEq)]
    struct Ping;

    impl Fake {
        fn log(&self, call: &str) {
            self.calls.lock().unwrap().push(call.to_owned());
        }

        /// Records `call`, then fails, panics or hangs if the test asked
        /// for it.
        async fn call(&self, call: &str) -> Result<()> {
            self.log(call);
            self.workers
                .lock()
                .unwrap()
                .push(std::thread::current().id());
            match self.mode(call) {
                None => Ok(()),
                Some(Mode::Fail) => Err(Error::connectivity(format!("{call} failed"))),
                Some(Mode::Panic) => panic!("{call} panicked"),
                Some(Mode::Hang) => std::future::pending().await,
                Some(Mode::Wait) => {
                    self.gate.notified().await;
                    Ok(())
                }
                Some(Mode::Sleep(time)) => {
                    self.blocking(|| std::thread::sleep(time));
                    Ok(())
                }
                Some(Mode::Block) => {
                    let hold = format!("hold {call}");
                    self.blocking(|| {
                        while self.mode(&hold).is_some() {
                            std::thread::sleep(MS);
                        }
                    });
                    Ok(())
                }
            }
        }

        /// Runs `block`, which blocks its thread, inside a call that does
        /// not return to the runtime. On a runtime with more than one
        /// thread, the runtime gets a new worker for that time: a blocked
        /// worker can leave no thread that drives the timer, and then no
        /// time limit ends.
        fn blocking(&self, block: impl FnOnce()) {
            match Handle::current().runtime_flavor() {
                tokio::runtime::RuntimeFlavor::MultiThread => {
                    tokio::task::block_in_place(block);
                    // The thread can be a thread of the blocking pool from
                    // now on: it is not known as an async worker any more.
                    let here = std::thread::current().id();
                    self.workers.lock().unwrap().retain(|id| *id != here);
                }
                _ => block(),
            }
        }

        fn mode(&self, call: &str) -> Option<Mode> {
            self.modes.lock().unwrap().get(call).copied()
        }

        /// Waits until the host made `call`. Does not use the clock.
        async fn called(&self, call: &str) {
            while self.count(call) == 0 {
                tokio::task::yield_now().await;
            }
        }

        /// How many times the host made `call`, since the last `take_calls`.
        fn count(&self, call: &str) -> usize {
            let calls = self.calls.lock().unwrap();
            calls.iter().filter(|made| *made == call).count()
        }

        fn set(&self, call: &str, mode: Option<Mode>) {
            let mut modes = self.modes.lock().unwrap();
            match mode {
                Some(mode) => modes.insert(call.to_owned(), mode),
                None => modes.remove(call),
            };
        }

        fn take_calls(&self) -> Vec<String> {
            std::mem::take(&mut self.calls.lock().unwrap())
        }
    }

    /// What code of `owner` can try after the host asked it to stop: a job,
    /// a service, a command handler and an event subscription. Each has the
    /// name `<owner>.late`.
    fn register_late(fake: &Fake, services: &Services, owner: &Owner) {
        let name = format!("{owner}.late");
        let _ = services
            .jobs
            .spawn(owner.clone(), "late", |job| async move {
                job.cancelled().await;
                Err::<(), _>(Error::cancelled("stopped"))
            });
        let service: Arc<str> = Arc::from("late");
        let version = Version::new(1, 0, 0);
        let _ = services
            .registry
            .register(owner.clone(), &name, version, service);
        let handler = |(): ()| async { Ok(()) };
        let _ = services.commands.register(owner.clone(), &name, handler);
        let subscription = services.events.subscribe_owned(owner.clone());
        let mut subscriptions = fake.subscriptions.lock().unwrap();
        subscriptions.insert(name.clone(), subscription);
        // The scheme `<owner>.late2`: the job of the fake has `<owner>.late`.
        let backend = fake
            .secrets
            .register(owner.clone(), &format!("{name}2"), Arc::new(Fixed));
        if let Err(error) = backend {
            fake.log(&format!("backend {name}2: {:?}", error.category()));
        }
    }

    struct FakeRuntime(Arc<Fake>);

    impl ExtensionRuntime for FakeRuntime {
        fn load<'a>(
            &'a self,
            manifest: &'a Manifest,
            directory: &'a Path,
        ) -> BoxFuture<'a, Result<Box<dyn ExtensionInstance>>> {
            Box::pin(async move {
                assert!(directory.join(MANIFEST_FILE).is_file());
                self.0
                    .call(&format!("load {}@{}", manifest.id, manifest.version))
                    .await?;
                let instance = FakeInstance {
                    id: manifest.id.clone(),
                    fake: Arc::clone(&self.0),
                };
                Ok(Box::new(instance) as Box<dyn ExtensionInstance>)
            })
        }
    }

    struct FakeInstance {
        id: ExtensionId,
        fake: Arc<Fake>,
    }

    impl ExtensionInstance for FakeInstance {
        /// Registers the service `<id>.service`, the command `<id>.command`
        /// and a secret backend for the scheme `<id>`, subscribes to `Ping`
        /// and starts a job that runs until it is cancelled. The job then
        /// registers a secret backend for the scheme `<id>.late`.
        fn activate(&self, context: ExtensionContext) -> BoxFuture<'_, Result<()>> {
            Box::pin(async move {
                let ExtensionContext { owner, services } = context;
                let service: Arc<str> = Arc::from("service");
                let name = format!("{owner}.service");
                let version = Version::new(1, 0, 0);
                services
                    .registry
                    .register(owner.clone(), &name, version, service)?;
                let name = format!("{owner}.command");
                let handler = |(): ()| async { Ok(()) };
                services.commands.register(owner.clone(), &name, handler)?;
                let secrets = Arc::clone(&self.fake.secrets);
                secrets.register(owner.clone(), owner.as_str(), Arc::new(Fixed))?;
                let subscription = services.events.subscribe_owned(owner.clone());
                self.fake
                    .subscriptions
                    .lock()
                    .unwrap()
                    .insert(owner.to_string(), subscription);
                // `job <id>` = `Hang`: the job ignores the cancel request.
                let stubborn = self.fake.mode(&format!("job {owner}")).is_some();
                let backend_owner = owner.clone();
                // `job <id> late`: the job answers the cancel request with
                // `register_late`.
                let answers = self.fake.mode(&format!("job {owner} late")).is_some();
                // `late <id>`: the activation calls `register_late` at its end.
                let late = self.fake.mode(&format!("late {owner}")).is_some();
                let (fake, again, of) = (Arc::clone(&self.fake), services.clone(), owner.clone());
                let job = services
                    .jobs
                    .spawn(owner.clone(), "work", move |job| async move {
                        if stubborn {
                            std::future::pending::<()>().await;
                        }
                        job.cancelled().await;
                        // Refused while the host stops the extension.
                        let _ = secrets.register(
                            backend_owner.clone(),
                            &format!("{backend_owner}.late"),
                            Arc::new(Fixed),
                        );
                        if answers {
                            register_late(&fake, &again, &of);
                        }
                        Err(Error::cancelled("stopped"))
                    })?;
                // `blocking <id>`: a blocking job that ignores the cancel
                // request. It runs until the test removes the mode.
                let blocking = format!("blocking {owner}");
                if self.fake.mode(&blocking).is_some() {
                    let fake = Arc::clone(&self.fake);
                    services
                        .jobs
                        .spawn_blocking(owner.clone(), "blocking", move |_| {
                            fake.log(&blocking);
                            while fake.mode(&blocking).is_some() {
                                std::thread::sleep(MS);
                            }
                            Ok(())
                        })?;
                }
                self.fake
                    .jobs
                    .lock()
                    .unwrap()
                    .insert(owner.to_string(), job);
                // Gives a concurrent activation the chance to run.
                tokio::task::yield_now().await;
                let result = self.fake.call(&format!("activate {owner}")).await;
                if late {
                    register_late(&self.fake, &services, &owner);
                }
                result
            })
        }

        fn deactivate(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async move { self.fake.call(&format!("deactivate {}", self.id)).await })
        }
    }

    impl Drop for FakeInstance {
        fn drop(&mut self) {
            let call = format!("unload {}", self.id);
            self.fake.log(&call);
            // The host drops an instance in a blocking task.
            let here = std::thread::current().id();
            if self.fake.workers.lock().unwrap().contains(&here) {
                self.fake.log(&format!("{call} on an async worker"));
            }
            if self.fake.mode(&call).is_some() {
                panic!("{call} panicked");
            }
        }
    }

    fn id(text: &str) -> ExtensionId {
        text.parse().unwrap()
    }

    /// A manifest that activates on the command with the name of the id.
    fn manifest(id: &str, version: &str, dependencies: &[&str], top: &str) -> String {
        let dependencies: String = dependencies
            .iter()
            .map(|dependency| format!("\"{dependency}\" = \"^1\"\n"))
            .collect();
        format!(
            "id = \"{id}\"\nversion = \"{version}\"\nsdk = \"^0.1\"\n{top}\n\
             [dependencies]\n{dependencies}\n\
             [[activation]]\non = \"command\"\ncommand = \"{id}\"\n"
        )
    }

    const BUNDLED: usize = 0;
    const USER: usize = 1;
    const WORKSPACE: usize = 2;

    struct Fixture {
        fake: Arc<Fake>,
        services: Services,
        host: Arc<ExtensionHost>,
        events: Subscription<ExtensionStateChanged>,
        restarts: Subscription<ExtensionRestartScheduled>,
        roots: [TempDir; 3],
    }

    fn fixture(headless: bool) -> Fixture {
        fixture_with(headless, HostConfig::default())
    }

    fn fixture_with(headless: bool, config: HostConfig) -> Fixture {
        let fake = Arc::new(Fake::default());
        let services = Services {
            registry: Arc::new(ServiceRegistry::new()),
            commands: Arc::new(CommandBus::new()),
            events: Arc::new(EventBus::new(NonZeroU16::new(1024).unwrap())),
            jobs: JobScheduler::new(NonZeroUsize::new(16).unwrap(), 16),
        };
        let roots = [(); 3].map(|()| tempfile::tempdir().unwrap());
        let directories = roots.iter().map(|root| root.path().to_owned()).collect();
        let host = ExtensionHost::new(
            Arc::new(FakeRuntime(Arc::clone(&fake))),
            services.clone(),
            Arc::clone(&fake.secrets),
            Version::new(0, 1, 0),
            directories,
            headless,
            config,
        );
        Fixture {
            fake,
            events: services.events.subscribe(),
            restarts: services.events.subscribe(),
            services,
            host,
            roots,
        }
    }

    fn line(event: &ExtensionStateChanged) -> String {
        let name = |state: Option<ExtensionState>| {
            state.map_or("none".to_owned(), |state| format!("{state:?}"))
        };
        format!("{}: {} -> {}", event.id, name(event.from), name(event.to))
    }

    /// Lets `time` of the paused test clock go by. No test waits for real
    /// time.
    async fn pass(time: Duration) {
        tokio::time::sleep(time).await;
    }

    impl Fixture {
        /// Writes `<root>/<folder>/extension.toml`.
        fn write(&self, root: usize, folder: &str, manifest: &str) {
            let directory = self.roots[root].path().join(folder);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join(MANIFEST_FILE), manifest).unwrap();
        }

        /// Writes a valid version 1.0.0 extension to the user directory.
        fn add(&self, id: &str, dependencies: &[&str]) {
            self.write(USER, id, &manifest(id, "1.0.0", dependencies, ""));
        }

        fn status(&self, id: &str) -> Option<ExtensionStatus> {
            let mut all = self.host.extensions().into_iter();
            all.find(|status| status.id.as_str() == id)
        }

        fn state(&self, id: &str) -> Option<ExtensionState> {
            self.status(id).map(|status| status.state)
        }

        fn reason(&self, id: &str) -> String {
            self.status(id).and_then(|status| status.reason).unwrap()
        }

        async fn go(&self, command: &str) -> ActivationReport {
            self.host.trigger(ActivationTrigger::Command(command)).await
        }

        /// The state changes since the last call, as `id: from -> to`.
        async fn changes(&mut self) -> Vec<String> {
            self.events().await.iter().map(line).collect()
        }

        /// The state change events since the last call.
        async fn events(&mut self) -> Vec<ExtensionStateChanged> {
            let end = ExtensionStateChanged {
                id: id("end"),
                from: None,
                to: None,
                reason: None,
            };
            self.services.events.publish(end.clone());
            let mut events = Vec::new();
            loop {
                match self.events.recv().await {
                    Some(Received::Event(event)) if event == end => return events,
                    Some(Received::Event(event)) => events.push(event),
                    other => panic!("unexpected {other:?}"),
                }
            }
        }

        /// Waits until `id` changes to `state`. Returns the state changes
        /// up to and including that one. The paused clock advances.
        async fn until(&mut self, id: &str, state: ExtensionState) -> Vec<String> {
            let mut changes = Vec::new();
            loop {
                // On the paused clock, the limit ends a wait for an event
                // that does not come.
                let next = tokio::time::timeout(DAY, self.events.recv()).await;
                match next.expect("the state change occurs") {
                    Some(Received::Event(event)) => {
                        changes.push(line(&event));
                        if event.id.as_str() == id && event.to == Some(state) {
                            return changes;
                        }
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
        }

        /// Waits for the next planned restart. The paused clock advances.
        async fn scheduled(&mut self) -> ExtensionRestartScheduled {
            let next = tokio::time::timeout(DAY, self.restarts.recv()).await;
            match next.expect("a restart is planned") {
                Some(Received::Event(event)) => event,
                other => panic!("unexpected {other:?}"),
            }
        }

        /// The restarts planned since the last call, as `(id, attempt)`.
        async fn all_scheduled(&mut self) -> Vec<(String, u32)> {
            let end = ExtensionRestartScheduled {
                id: id("end"),
                attempt: 0,
                delay: Duration::ZERO,
                reason: String::new(),
            };
            self.services.events.publish(end.clone());
            let mut all = Vec::new();
            loop {
                let event = self.scheduled().await;
                if event == end {
                    return all;
                }
                all.push((event.id.to_string(), event.attempt));
            }
        }

        /// `true` if the service and the command of `owner` are registered.
        async fn registered(&self, owner: &str) -> (bool, bool) {
            let any = semver::VersionReq::STAR;
            let registry = &self.services.registry;
            let service = registry.lookup::<str>(&format!("{owner}.service"), &any);
            let name = format!("{owner}.command");
            let command = self.services.commands.execute::<(), ()>(&name, ()).await;
            (service.is_ok(), command.is_ok())
        }

        /// `true` if the secret backend that `owner` registered in its
        /// activation resolves.
        async fn has_backend(&self, owner: &str) -> bool {
            let uri = format!("{owner}://x").parse().unwrap();
            self.fake.secrets.resolve(&uri).await.is_ok()
        }

        /// Asserts that the store has no secret backend of `owner`: not the
        /// one from its activation and not the one its job registers when
        /// the job is cancelled.
        async fn assert_no_backend(&self, owner: &str) {
            for scheme in [owner.to_owned(), format!("{owner}.late")] {
                let uri = format!("{scheme}://x").parse().unwrap();
                let error = self.fake.secrets.resolve(&uri).await.err();
                let error = error.unwrap_or_else(|| panic!("`{scheme}` has a backend"));
                assert_eq!(error.category(), ErrorCategory::User, "{scheme}");
                let message = error.message();
                assert!(
                    message.contains("no secret backend is registered"),
                    "{message}"
                );
            }
        }

        /// What is left of `register_late` of `owner`: the number of its
        /// jobs that have not ended, and `true` for the service, the command
        /// handler and the open subscription.
        async fn late(&self, owner: &str) -> (usize, bool, bool, bool) {
            let name = format!("{owner}.late");
            let jobs = self.services.jobs.jobs();
            let left = |job: &&crate::jobs::JobSnapshot| {
                job.owner.as_str() == owner && job.kind == "late" && !job.state.is_finished()
            };
            let any = semver::VersionReq::STAR;
            let service = self.services.registry.lookup::<str>(&name, &any);
            let command = self.services.commands.execute::<(), ()>(&name, ()).await;
            let subscription = self.fake.subscriptions.lock().unwrap().remove(&name);
            self.services.events.publish(Ping);
            let open = match subscription {
                Some(mut subscription) => subscription.recv().await.is_some(),
                None => false,
            };
            let jobs = jobs.iter().filter(left).count();
            (jobs, service.is_ok(), command.is_ok(), open)
        }

        /// Takes the job that `owner` started in its last activation.
        fn job(&self, owner: &str) -> JobHandle<()> {
            self.fake.jobs.lock().unwrap().remove(owner).unwrap()
        }

        /// Waits for the last job of `owner` and returns the category of its
        /// error.
        async fn job_end(&self, owner: &str) -> ErrorCategory {
            self.job(owner).join().await.unwrap_err().category()
        }
    }

    #[test]
    fn transition_permits_only_the_state_diagram() {
        use Lifecycle::{
            Activate, Deactivate, Disable, Fail, Forget, Reject, Resolve, Restart, Unload,
        };
        let legal = [
            (Discovered, Resolve, Some(Resolved)),
            (Discovered, Reject, Some(Rejected)),
            (Resolved, Activate, Some(Active)),
            (Active, Deactivate, Some(Inactive)),
            (Inactive, Activate, Some(Active)),
            (Active, Fail, Some(Failed)),
            // The activation failed.
            (Resolved, Fail, Some(Failed)),
            (Inactive, Fail, Some(Failed)),
            (Failed, Restart, Some(Active)),
            (Failed, Disable, Some(Disabled)),
            (Inactive, Unload, None),
            // Not in the diagram: see the module documentation.
            (Failed, Unload, None),
            (Disabled, Unload, None),
            (Resolved, Forget, None),
            (Rejected, Forget, None),
        ];
        let states = [
            Discovered, Resolved, Rejected, Active, Inactive, Failed, Disabled,
        ];
        let events = [
            Resolve, Reject, Activate, Deactivate, Fail, Restart, Disable, Unload, Forget,
        ];
        for from in states {
            for event in events {
                let expected = legal.iter().find(|row| row.0 == from && row.1 == event);
                let found = transition(from, event);
                match expected {
                    Some(row) => assert_eq!(found.unwrap(), row.2, "{from:?} {event:?}"),
                    None => {
                        let error = found.expect_err(&format!("{from:?} {event:?}"));
                        assert_eq!(error.category(), ErrorCategory::Policy);
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn discovery_lists_states_and_activates_nothing() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.add("needs-missing", &["missing"]);
        f.write(USER, "bad-sdk", "id = \"bad-sdk\"\nversion = \"1.0.0\"\n");
        f.write(USER, "no-id", "this is not a manifest");
        std::fs::create_dir(f.roots[USER].path().join("not-an-extension")).unwrap();
        std::fs::write(f.roots[USER].path().join("file"), "").unwrap();

        f.host.discover().await.unwrap();

        assert_eq!(f.state("a"), Some(Resolved));
        assert_eq!(f.state("b"), Some(Resolved));
        // The resolver gives the reason.
        assert_eq!(f.state("needs-missing"), Some(Rejected));
        assert!(
            f.reason("needs-missing")
                .contains("`missing` is not present")
        );
        // An invalid manifest rejects only its extension.
        assert_eq!(f.state("bad-sdk"), Some(Rejected));
        assert!(f.reason("bad-sdk").contains("missing field `sdk`"));
        assert_eq!(f.host.extensions().len(), 4);
        let invalid = f.host.invalid_packages();
        assert_eq!(invalid.len(), 1);
        assert!(invalid[0].0.ends_with("no-id"));
        // Lazy: discovery calls no extension code.
        assert!(f.fake.take_calls().is_empty());
        assert_eq!(
            f.changes().await,
            [
                "a: none -> Discovered",
                "a: Discovered -> Resolved",
                "b: none -> Discovered",
                "b: Discovered -> Resolved",
                "bad-sdk: none -> Discovered",
                "bad-sdk: Discovered -> Rejected",
                "needs-missing: none -> Discovered",
                "needs-missing: Discovered -> Rejected",
            ]
        );

        // A second discovery with no change on disk changes nothing.
        f.host.discover().await.unwrap();
        assert!(f.changes().await.is_empty());

        // A corrected manifest is read again.
        f.add("bad-sdk", &[]);
        f.host.discover().await.unwrap();
        assert_eq!(f.state("bad-sdk"), Some(Resolved));
        assert_eq!(
            f.changes().await,
            [
                "bad-sdk: Rejected -> none",
                "bad-sdk: none -> Discovered",
                "bad-sdk: Discovered -> Resolved",
            ]
        );
    }

    #[tokio::test]
    async fn a_later_directory_wins_for_the_same_id() {
        let f = fixture(true);
        f.write(BUNDLED, "a", &manifest("a", "1.0.0", &[], ""));
        f.write(USER, "a", &manifest("a", "1.1.0", &[], ""));
        f.write(WORKSPACE, "a-fork", &manifest("a", "1.2.0", &[], ""));
        f.write(USER, "twice-1", &manifest("twice", "1.0.0", &[], ""));
        f.write(USER, "twice-2", &manifest("twice", "1.0.0", &[], ""));

        f.host.discover().await.unwrap();
        f.go("a").await;

        let a = f.status("a").unwrap();
        assert_eq!(a.directory, f.roots[WORKSPACE].path().join("a-fork"));
        assert_eq!(f.fake.take_calls(), ["load a@1.2.0", "activate a"]);
        // The same id two times in one directory is an error.
        assert_eq!(f.state("twice"), Some(Rejected));
        assert!(f.reason("twice").contains("two packages"));
    }

    #[tokio::test]
    async fn a_trigger_activates_dependencies_first_and_nothing_else() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.add("c", &["b"]);
        f.add("other", &[]);
        f.host.discover().await.unwrap();
        f.changes().await;

        let report = f.go("c").await;

        assert_eq!(report.activated, [id("a"), id("b"), id("c")]);
        assert!(report.not_activated.is_empty());
        assert_eq!(
            f.fake.take_calls(),
            [
                "load a@1.0.0",
                "activate a",
                "load b@1.0.0",
                "activate b",
                "load c@1.0.0",
                "activate c",
            ]
        );
        assert_eq!(f.state("c"), Some(Active));
        assert_eq!(f.state("other"), Some(Resolved));
        assert_eq!(
            f.changes().await,
            [
                "a: Resolved -> Active",
                "b: Resolved -> Active",
                "c: Resolved -> Active",
            ]
        );

        // An active extension does not activate again.
        let report = f.go("c").await;
        assert!(report.activated.is_empty());
        assert!(f.fake.take_calls().is_empty());
        // An event that no extension has activates nothing.
        assert!(f.go("unknown").await.activated.is_empty());
        // A new discovery does not change an extension that is loaded.
        f.host.discover().await.unwrap();
        assert!(f.changes().await.is_empty());
        assert_eq!(f.state("c"), Some(Active));
    }

    #[tokio::test]
    async fn requires_ui_does_not_activate_in_a_headless_host() {
        for headless in [true, false] {
            let f = fixture(headless);
            f.write(
                USER,
                "ui",
                &manifest("ui", "1.0.0", &[], "requires_ui = true"),
            );
            f.add("on-ui", &["ui"]);
            f.host.discover().await.unwrap();

            let ui = f.go("ui").await;
            let on_ui = f.go("on-ui").await;

            if headless {
                assert!(ui.activated.is_empty());
                assert!(on_ui.activated.is_empty());
                let blocked = &on_ui.not_activated[&id("on-ui")];
                assert_eq!(blocked.category(), ErrorCategory::Policy);
                assert_eq!(f.state("ui"), Some(Resolved));
                assert_eq!(f.state("on-ui"), Some(Resolved));
                assert!(f.fake.take_calls().is_empty());
            } else {
                assert_eq!(ui.activated, [id("ui")]);
                assert_eq!(on_ui.activated, [id("on-ui")]);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn simultaneous_triggers_activate_one_time() {
        let f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.host.discover().await.unwrap();

        let triggers: Vec<_> = (0..16)
            .map(|_| {
                let host = Arc::clone(&f.host);
                tokio::spawn(async move { host.trigger(ActivationTrigger::Command("b")).await })
            })
            .collect();
        let mut activated = 0;
        for trigger in triggers {
            let report = trigger.await.unwrap();
            assert!(report.not_activated.is_empty());
            activated += report.activated.len();
        }

        assert_eq!(activated, 2);
        assert_eq!(
            f.fake.take_calls(),
            ["load a@1.0.0", "activate a", "load b@1.0.0", "activate b"]
        );
    }

    #[tokio::test]
    async fn a_failing_or_panicking_activation_is_contained() {
        for (mode, category) in [
            (Mode::Fail, ErrorCategory::Connectivity),
            (Mode::Panic, ErrorCategory::Internal),
        ] {
            let mut f = fixture(true);
            f.add("a", &[]);
            f.add("b", &["a"]);
            f.add("c", &[]);
            f.host.discover().await.unwrap();
            f.changes().await;
            f.fake.set("activate a", Some(mode));

            let report = f.go("b").await;

            assert!(report.activated.is_empty());
            assert_eq!(report.not_activated[&id("a")].category(), category);
            let b = &report.not_activated[&id("b")];
            assert!(b.message().contains("dependency `a` is not active"));
            // An expected condition, not a defect.
            assert_eq!(b.category(), ErrorCategory::Policy);
            assert_eq!(f.state("a"), Some(Failed));
            assert!(f.reason("a").contains("activate"));
            assert_eq!(f.state("b"), Some(Resolved));
            // What the extension registered before the failure is removed.
            assert_eq!(f.registered("a").await, (false, false));
            assert_eq!(f.job_end("a").await, ErrorCategory::Cancelled);
            assert_eq!(f.changes().await, ["a: Resolved -> Failed"]);
            // The instance is unloaded.
            assert_eq!(
                f.fake.take_calls(),
                ["load a@1.0.0", "activate a", "unload a"]
            );

            // The host and the other extensions work.
            assert_eq!(f.go("c").await.activated, [id("c")]);
            // A failed extension does not activate on an event.
            let again = f.go("a").await;
            assert_eq!(
                again.not_activated[&id("a")].category(),
                ErrorCategory::Policy
            );
            f.fake.take_calls();

            // A restart that fails keeps the state `Failed`.
            f.host.restart(&id("a")).await.unwrap_err();
            assert_eq!(f.state("a"), Some(Failed));
            // A restart that succeeds makes the extension active.
            f.fake.set("activate a", None);
            f.host.restart(&id("a")).await.unwrap();
            assert_eq!(f.state("a"), Some(Active));
            assert_eq!(f.registered("a").await, (true, true));
            assert_eq!(f.go("b").await.activated, [id("b")]);
            f.host.restart(&id("a")).await.unwrap_err();
        }
    }

    #[tokio::test]
    async fn a_failing_load_is_contained() {
        for (mode, category) in [
            (Mode::Fail, ErrorCategory::Connectivity),
            (Mode::Panic, ErrorCategory::Internal),
        ] {
            let f = fixture(true);
            f.add("a", &[]);
            f.host.discover().await.unwrap();
            f.fake.set("load a@1.0.0", Some(mode));

            let report = f.go("a").await;

            let error = &report.not_activated[&id("a")];
            assert_eq!(error.category(), category);
            assert_eq!(f.state("a"), Some(Failed));
            assert_eq!(f.reason("a"), error.message());
            assert_eq!(f.fake.take_calls(), ["load a@1.0.0"]);
        }
    }

    #[tokio::test]
    async fn a_failed_extension_can_be_disabled() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        let error = f.host.disable(&id("a")).await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Policy);
        f.fake.set("activate a", Some(Mode::Fail));
        f.go("a").await;
        f.changes().await;

        f.host.disable(&id("a")).await.unwrap();

        assert_eq!(f.state("a"), Some(Disabled));
        assert_eq!(f.changes().await, ["a: Failed -> Disabled"]);
        let report = f.go("a").await;
        assert_eq!(
            report.not_activated[&id("a")].category(),
            ErrorCategory::Policy
        );
        f.host.restart(&id("a")).await.unwrap_err();
        assert_eq!(f.state("a"), Some(Disabled));
    }

    #[tokio::test]
    async fn deactivation_takes_dependents_first_and_releases_what_they_own() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.add("c", &[]);
        f.host.discover().await.unwrap();
        f.go("b").await;
        f.go("c").await;
        assert_eq!(f.registered("a").await, (true, true));
        f.fake.take_calls();
        f.changes().await;

        f.host.deactivate(&id("a")).await.unwrap();

        assert_eq!(f.fake.take_calls(), ["deactivate b", "deactivate a"]);
        assert_eq!(
            f.changes().await,
            ["b: Active -> Inactive", "a: Active -> Inactive"]
        );
        for owner in ["a", "b"] {
            assert_eq!(f.registered(owner).await, (false, false));
            assert_eq!(f.job_end(owner).await, ErrorCategory::Cancelled);
        }
        // An extension that does not depend on `a` is not changed.
        assert_eq!(f.state("c"), Some(Active));
        assert_eq!(f.registered("c").await, (true, true));

        let error = f.host.deactivate(&id("a")).await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Policy);
        let error = f.host.deactivate(&id("unknown")).await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::User);

        // An inactive extension activates again and is not loaded again.
        assert_eq!(f.go("b").await.activated, [id("a"), id("b")]);
        assert_eq!(f.fake.take_calls(), ["activate a", "activate b"]);
        assert_eq!(
            f.changes().await,
            ["a: Inactive -> Active", "b: Inactive -> Active"]
        );
    }

    #[tokio::test]
    async fn a_failing_deactivation_still_releases_what_the_extension_owns() {
        for mode in [Mode::Fail, Mode::Panic] {
            let f = fixture(true);
            f.add("a", &[]);
            f.add("b", &["a"]);
            f.host.discover().await.unwrap();
            f.go("b").await;
            f.fake.set("deactivate b", Some(mode));

            f.host.deactivate(&id("a")).await.unwrap_err();

            assert_eq!(f.state("b"), Some(Failed));
            assert_eq!(f.state("a"), Some(Inactive));
            assert_eq!(f.registered("b").await, (false, false));
            assert_eq!(f.job_end("b").await, ErrorCategory::Cancelled);
        }
    }

    #[tokio::test]
    async fn unload_removes_the_extension_and_discovery_finds_it_again() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.host.discover().await.unwrap();
        f.go("b").await;

        // Only an inactive extension can be unloaded.
        let error = f.host.unload(&id("a")).await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Policy);
        f.host.deactivate(&id("a")).await.unwrap();
        f.fake.take_calls();
        f.changes().await;

        f.host.unload(&id("a")).await.unwrap();

        assert_eq!(f.state("a"), None);
        // `b` was loaded and cannot resolve without `a`.
        assert_eq!(f.state("b"), Some(Rejected));
        assert_eq!(f.fake.take_calls(), ["unload a", "unload b"]);
        assert_eq!(
            f.changes().await,
            [
                "a: Inactive -> none",
                "b: Inactive -> none",
                "b: none -> Discovered",
                "b: Discovered -> Rejected",
            ]
        );
        assert!(f.go("b").await.activated.is_empty());

        f.host.discover().await.unwrap();

        assert_eq!(f.state("a"), Some(Resolved));
        assert_eq!(f.state("b"), Some(Resolved));
        assert_eq!(f.go("b").await.activated, [id("a"), id("b")]);
        let calls = f.fake.take_calls();
        assert_eq!(calls[0], "load a@1.0.0");
    }

    #[tokio::test]
    async fn reload_loads_the_new_version_and_activates_the_dependents_again() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.add("c", &[]);
        f.host.discover().await.unwrap();
        f.go("b").await;
        f.go("c").await;
        f.fake.take_calls();
        f.changes().await;
        f.write(USER, "a", &manifest("a", "1.1.0", &[], ""));
        let old_job = f.job("a");

        let report = f.host.reload(&id("a")).await.unwrap();

        assert_eq!(report.activated, [id("a"), id("b")]);
        assert!(report.not_activated.is_empty());
        // Deactivate, unload, load the new version, activate.
        assert_eq!(
            f.fake.take_calls(),
            [
                "deactivate b",
                "deactivate a",
                "unload a",
                "load a@1.1.0",
                "activate a",
                "activate b",
            ]
        );
        assert_eq!(
            f.changes().await,
            [
                "b: Active -> Inactive",
                "a: Active -> Inactive",
                "a: Inactive -> none",
                "a: none -> Discovered",
                "a: Discovered -> Resolved",
                "a: Resolved -> Active",
                "b: Inactive -> Active",
            ]
        );
        // The handles of the old version are closed.
        let old_job = old_job.join().await.unwrap_err();
        assert_eq!(old_job.category(), ErrorCategory::Cancelled);
        assert_eq!(f.registered("a").await, (true, true));
        assert_eq!(f.registered("b").await, (true, true));
        assert_eq!(f.state("c"), Some(Active));

        // A reload of an extension that is not active activates nothing.
        let report = f.host.reload(&id("other")).await;
        assert_eq!(report.unwrap_err().category(), ErrorCategory::User);
        f.add("other", &[]);
        let report = f.host.reload(&id("other")).await.unwrap();
        assert!(report.activated.is_empty());
        assert_eq!(f.state("other"), Some(Resolved));
    }

    #[tokio::test]
    async fn reload_validates_the_new_package_before_it_stops_the_old_version() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.host.discover().await.unwrap();
        f.go("b").await;
        f.fake.take_calls();
        f.changes().await;
        let folder = f.roots[USER].path().join("a");

        // An invalid manifest, a manifest that does not resolve, no package.
        f.write(USER, "a", "id = \"a\"\nversion = \"not a version\"\n");
        let invalid = f.host.reload(&id("a")).await.unwrap_err();
        f.write(USER, "a", &manifest("a", "1.1.0", &["missing"], ""));
        let unresolved = f.host.reload(&id("a")).await.unwrap_err();
        std::fs::remove_dir_all(&folder).unwrap();
        let removed = f.host.reload(&id("a")).await.unwrap_err();

        assert!(invalid.message().contains("invalid extension manifest"));
        assert!(unresolved.message().contains("`missing` is not present"));
        assert!(removed.message().contains("not in a discovery directory"));
        for error in [invalid, unresolved, removed] {
            assert_eq!(error.category(), ErrorCategory::User);
        }
        // The old version and its dependent were not stopped.
        assert!(f.fake.take_calls().is_empty());
        assert!(f.changes().await.is_empty());
        for owner in ["a", "b"] {
            assert_eq!(f.state(owner), Some(Active));
            assert_eq!(f.registered(owner).await, (true, true));
        }

        // The reload of the corrected manifest replaces the old version.
        f.write(USER, "a", &manifest("a", "1.1.0", &[], ""));
        let report = f.host.reload(&id("a")).await.unwrap();
        assert_eq!(report.activated, [id("a"), id("b")]);
        assert_eq!(f.fake.count("load a@1.1.0"), 1);
    }

    #[tokio::test]
    async fn reload_of_an_extension_without_loaded_code_reads_its_manifest_again() {
        let f = fixture(true);
        f.add("b", &["a"]);
        f.write(USER, "a", "id = \"a\"\nversion = \"not a version\"\n");
        f.host.discover().await.unwrap();

        let error = f.host.reload(&id("a")).await.unwrap_err();

        assert_eq!(error.category(), ErrorCategory::User);
        assert!(error.message().contains("invalid extension manifest"));
        assert_eq!(f.state("a"), Some(Rejected));
        assert_eq!(f.reason("a"), error.message());
        // An invalid manifest is not an input of the resolver.
        assert_eq!(f.state("b"), Some(Rejected));
        assert!(f.reason("b").contains("`a` is not present"));

        // The reload of the corrected manifest resolves both again.
        f.add("a", &[]);
        f.host.reload(&id("a")).await.unwrap();
        assert_eq!(f.state("a"), Some(Resolved));
        assert_eq!(f.state("b"), Some(Resolved));
        assert_eq!(f.go("b").await.activated, [id("a"), id("b")]);
    }

    #[tokio::test]
    async fn reload_reports_a_dependent_that_does_not_resolve_any_more() {
        let f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.host.discover().await.unwrap();
        f.go("b").await;
        // `b` depends on `a` `^1`.
        f.write(USER, "a", &manifest("a", "2.0.0", &[], ""));

        let report = f.host.reload(&id("a")).await.unwrap();

        assert_eq!(report.activated, [id("a")]);
        assert!(report.not_activated[&id("b")].message().contains("`^1`"));
        assert_eq!(f.state("a"), Some(Active));
        assert_eq!(f.state("b"), Some(Rejected));
        assert_eq!(f.registered("b").await, (false, false));
    }

    #[tokio::test]
    async fn shutdown_deactivates_in_reverse_dependency_order_and_continues_after_a_failure() {
        let f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.add("c", &["b"]);
        f.add("idle", &[]);
        f.host.discover().await.unwrap();
        f.go("c").await;
        f.fake.take_calls();
        f.fake.set("deactivate b", Some(Mode::Fail));

        let failures = f.host.shutdown().await;

        // Each instance is dropped after the deactivations.
        assert_eq!(
            f.fake.take_calls(),
            [
                "deactivate c",
                "deactivate b",
                "unload b",
                "deactivate a",
                "unload c",
                "unload a"
            ]
        );
        assert_eq!(failures.keys().collect::<Vec<_>>(), [&id("b")]);
        // The states stay readable.
        assert_eq!(f.state("a"), Some(Inactive));
        assert_eq!(f.state("b"), Some(Failed));
        assert_eq!(f.state("c"), Some(Inactive));
        assert_eq!(f.state("idle"), Some(Resolved));
        for owner in ["a", "b", "c"] {
            assert_eq!(f.registered(owner).await, (false, false));
        }
        assert!(f.host.shutdown().await.is_empty());
    }

    const MS: Duration = Duration::from_millis(1);
    const HOUR: Duration = Duration::from_secs(3600);
    const DAY: Duration = Duration::from_secs(24 * 3600);

    #[tokio::test(start_paused = true)]
    async fn a_call_that_exceeds_the_time_limit_fails_the_extension() {
        let limit = HostConfig::default().call_timeout;
        for call in ["load a@1.0.0", "activate a"] {
            let mut f = fixture(true);
            f.add("a", &[]);
            f.host.discover().await.unwrap();
            f.changes().await;
            f.fake.set(call, Some(Mode::Hang));
            let start = Instant::now();

            let report = f.go("a").await;

            assert_eq!(start.elapsed(), limit, "{call}");
            let error = &report.not_activated[&id("a")];
            assert_eq!(error.category(), ErrorCategory::Internal);
            assert!(error.message().contains("exceeded the time limit"));
            assert_eq!(f.state("a"), Some(Failed));
            assert_eq!(f.reason("a"), error.message());
            assert_eq!(f.changes().await, ["a: Resolved -> Failed"]);
            assert_eq!(f.registered("a").await, (false, false));
            // The instance is unloaded when the stopped call has ended. It
            // is not called again.
            if call == "activate a" {
                assert_eq!(f.job_end("a").await, ErrorCategory::Cancelled);
                f.fake.called("unload a").await;
                let calls = f.fake.take_calls();
                assert_eq!(calls, ["load a@1.0.0", "activate a", "unload a"]);
            } else {
                assert_eq!(f.fake.take_calls(), ["load a@1.0.0"]);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_deactivation_that_exceeds_the_time_limit_fails_the_extension() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.host.discover().await.unwrap();
        f.go("b").await;
        f.fake.take_calls();
        f.changes().await;
        f.fake.set("deactivate b", Some(Mode::Hang));
        let start = Instant::now();

        let error = f.host.deactivate(&id("a")).await.unwrap_err();

        assert_eq!(start.elapsed(), HostConfig::default().call_timeout);
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert!(error.message().contains("time limit"));
        assert!(error.message().contains("`deactivate`"));
        // The other lifecycle operations continue.
        assert_eq!(
            f.changes().await,
            ["b: Active -> Failed", "a: Active -> Inactive"]
        );
        // The instance is unloaded when the stopped call has ended, after
        // the operation.
        f.fake.called("unload b").await;
        assert_eq!(
            f.fake.take_calls(),
            ["deactivate b", "deactivate a", "unload b"]
        );
        assert_eq!(f.registered("b").await, (false, false));
        assert_eq!(f.job_end("b").await, ErrorCategory::Cancelled);
    }

    #[tokio::test(start_paused = true)]
    async fn a_hanging_activation_blocks_another_extension_only_up_to_the_time_limit() {
        let f = fixture(true);
        f.add("a", &[]);
        f.add("c", &[]);
        f.host.discover().await.unwrap();
        f.fake.set("activate a", Some(Mode::Hang));
        let start = Instant::now();

        // `a` takes the lifecycle lock first.
        let (a, c) = tokio::join!(f.go("a"), f.go("c"));

        assert_eq!(start.elapsed(), HostConfig::default().call_timeout);
        assert!(a.activated.is_empty());
        assert_eq!(c.activated, [id("c")]);
        assert_eq!(f.state("a"), Some(Failed));
        assert_eq!(f.state("c"), Some(Active));
    }

    #[tokio::test(start_paused = true)]
    async fn the_restart_delay_grows_with_each_failure_up_to_the_maximum() {
        let config = HostConfig {
            backoff_max: 400 * MS,
            restart_limit: 10,
            ..HostConfig::default()
        };
        let mut f = fixture_with(true, config);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        f.changes().await;
        f.fake.set("activate a", Some(Mode::Fail));
        let start = Instant::now();

        f.go("a").await;

        // (attempt, announced delay, time of the failure before it).
        let mut observed = Vec::new();
        for _ in 0..5 {
            let event = f.scheduled().await;
            assert_eq!(event.id, id("a"));
            assert_eq!(event.reason, "activate a failed");
            observed.push((event.attempt, event.delay, start.elapsed()));
        }
        assert_eq!(
            observed,
            [
                (1, 100 * MS, Duration::ZERO),
                (2, 200 * MS, 100 * MS),
                (3, 400 * MS, 300 * MS),
                (4, 400 * MS, 700 * MS),
                (5, 400 * MS, 1100 * MS),
            ]
        );
        // One activation and four restarts. Each restart loads again.
        assert_eq!(f.fake.count("activate a"), 5);
        assert_eq!(f.fake.count("load a@1.0.0"), 5);
        // A failed restart is not a state change.
        assert_eq!(f.state("a"), Some(Failed));
        assert_eq!(f.changes().await, ["a: Resolved -> Failed"]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_extension_is_disabled_after_the_restart_limit_and_not_restarted_again() {
        let config = HostConfig {
            restart_limit: 2,
            ..HostConfig::default()
        };
        let mut f = fixture_with(true, config);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        f.changes().await;
        f.fake.set("activate a", Some(Mode::Fail));
        let start = Instant::now();

        f.go("a").await;
        let changes = f.until("a", Disabled).await;

        // The two restarts: after 100 ms and after 200 ms more.
        assert_eq!(start.elapsed(), 300 * MS);
        assert_eq!(changes, ["a: Resolved -> Failed", "a: Failed -> Disabled"]);
        assert_eq!(f.fake.count("activate a"), 3);
        let reason = f.reason("a");
        assert!(reason.contains("restart limit of 2"), "{reason}");
        assert!(reason.contains("activate a failed"), "{reason}");
        assert_eq!(f.all_scheduled().await.len(), 2);

        pass(HOUR).await;

        assert_eq!(f.fake.count("activate a"), 3);
        assert_eq!(f.state("a"), Some(Disabled));
        assert!(f.all_scheduled().await.is_empty());
        assert!(f.changes().await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_stable_run_resets_the_failure_count() {
        let config = HostConfig {
            restart_limit: 2,
            ..HostConfig::default()
        };
        let reset_after = config.reset_after;
        let mut f = fixture_with(true, config);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        f.go("a").await;
        f.changes().await;
        let crash = || Error::internal("trap");

        // Two crashes with a short run between them: the count grows.
        f.host.report_crash(&id("a"), crash()).await.unwrap();
        assert_eq!(f.scheduled().await.attempt, 1);
        f.until("a", Active).await;
        pass(reset_after - MS).await;
        f.host.report_crash(&id("a"), crash()).await.unwrap();
        let second = f.scheduled().await;
        assert_eq!((second.attempt, second.delay), (2, 200 * MS));
        f.until("a", Active).await;

        // After a stable run the count starts again. Without the reset this
        // third failure reaches the limit.
        pass(reset_after).await;
        f.host.report_crash(&id("a"), crash()).await.unwrap();
        let third = f.scheduled().await;
        assert_eq!((third.attempt, third.delay), (1, 100 * MS));
        f.until("a", Active).await;

        // A short run again: two more failures reach the limit.
        f.host.report_crash(&id("a"), crash()).await.unwrap();
        f.until("a", Active).await;
        f.host.report_crash(&id("a"), crash()).await.unwrap();
        assert_eq!(f.state("a"), Some(Disabled));
    }

    #[tokio::test(start_paused = true)]
    async fn a_reported_crash_fails_the_extension_and_the_restart_activates_the_dependents_again() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.add("c", &["b"]);
        f.add("other", &[]);
        f.add("idle", &[]);
        f.host.discover().await.unwrap();
        f.go("c").await;
        f.go("other").await;
        f.fake.take_calls();
        f.changes().await;
        let start = Instant::now();

        let crash = Error::internal("trap: out of bounds");
        f.host.report_crash(&id("a"), crash).await.unwrap();

        // The dependents first. The crashed instance is not called.
        assert_eq!(
            f.fake.take_calls(),
            ["deactivate c", "deactivate b", "unload a"]
        );
        assert_eq!(
            f.changes().await,
            [
                "c: Active -> Inactive",
                "b: Active -> Inactive",
                "a: Active -> Failed",
            ]
        );
        assert_eq!(f.reason("a"), "trap: out of bounds");
        for owner in ["a", "b", "c"] {
            assert_eq!(f.registered(owner).await, (false, false));
            assert_eq!(f.job_end(owner).await, ErrorCategory::Cancelled);
        }
        assert_eq!(f.state("other"), Some(Active));
        assert_eq!(f.registered("other").await, (true, true));
        let planned = f.scheduled().await;
        assert_eq!((planned.attempt, planned.delay), (1, 100 * MS));
        assert_eq!(planned.reason, "trap: out of bounds");

        // The restart, then the dependents in dependency order.
        assert_eq!(
            f.until("c", Active).await,
            [
                "a: Failed -> Active",
                "b: Inactive -> Active",
                "c: Inactive -> Active",
            ]
        );
        assert_eq!(start.elapsed(), 100 * MS);
        assert_eq!(
            f.fake.take_calls(),
            ["load a@1.0.0", "activate a", "activate b", "activate c"]
        );
        for owner in ["a", "b", "c"] {
            assert_eq!(f.registered(owner).await, (true, true));
        }

        // A report for an extension without an instance changes nothing.
        let crash = Error::internal("trap");
        f.host.report_crash(&id("idle"), crash).await.unwrap();
        assert_eq!(f.state("idle"), Some(Resolved));
        assert!(f.changes().await.is_empty());
        let crash = Error::internal("trap");
        let unknown = f.host.report_crash(&id("unknown"), crash).await;
        assert_eq!(unknown.unwrap_err().category(), ErrorCategory::User);
    }

    #[tokio::test(start_paused = true)]
    async fn a_reported_crash_of_an_inactive_extension_unloads_its_instance_only() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        f.go("a").await;
        f.host.deactivate(&id("a")).await.unwrap();
        f.fake.take_calls();
        f.changes().await;

        // The process of the inactive extension ended.
        let crash = Error::internal("the process has ended");
        f.host.report_crash(&id("a"), crash).await.unwrap();

        assert_eq!(f.fake.take_calls(), ["unload a"]);
        // No state change, no failure, no restart.
        pass(DAY).await;
        assert!(f.changes().await.is_empty());
        assert!(f.all_scheduled().await.is_empty());
        let status = f.status("a").unwrap();
        assert_eq!((status.state, status.reason), (Inactive, None));
        // The next activation loads a new instance.
        assert_eq!(f.go("a").await.activated, [id("a")]);
        assert_eq!(f.fake.take_calls(), ["load a@1.0.0", "activate a"]);
        // A second report for the instance that is gone changes nothing.
        f.host.deactivate(&id("a")).await.unwrap();
        for _ in 0..2 {
            let crash = Error::internal("the process has ended");
            f.host.report_crash(&id("a"), crash).await.unwrap();
        }
        assert_eq!(f.fake.take_calls(), ["deactivate a", "unload a"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_manual_restart_activates_the_dependents_again_and_replaces_the_pending_restart() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.host.discover().await.unwrap();
        f.go("b").await;
        f.host
            .report_crash(&id("a"), Error::internal("trap"))
            .await
            .unwrap();
        f.fake.take_calls();
        f.changes().await;

        f.host.restart(&id("a")).await.unwrap();

        assert_eq!(
            f.changes().await,
            ["a: Failed -> Active", "b: Inactive -> Active"]
        );
        pass(HOUR).await;
        assert_eq!(f.fake.count("activate a"), 1);
        assert!(f.changes().await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn the_dependents_of_a_disabled_extension_stay_inactive() {
        let config = HostConfig {
            restart_limit: 0,
            ..HostConfig::default()
        };
        let mut f = fixture_with(true, config);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.host.discover().await.unwrap();
        f.go("b").await;
        f.changes().await;

        f.host
            .report_crash(&id("a"), Error::internal("trap"))
            .await
            .unwrap();
        pass(HOUR).await;

        assert_eq!(
            f.changes().await,
            [
                "b: Active -> Inactive",
                "a: Active -> Failed",
                "a: Failed -> Disabled",
            ]
        );
        assert!(f.all_scheduled().await.is_empty());
        assert_eq!(f.state("b"), Some(Inactive));
    }

    #[tokio::test(start_paused = true)]
    async fn a_restart_without_an_active_dependency_is_a_failed_restart() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.host.discover().await.unwrap();
        f.go("b").await;
        f.host
            .report_crash(&id("b"), Error::internal("trap"))
            .await
            .unwrap();
        assert_eq!(f.scheduled().await.attempt, 1);
        // This does not stop the pending restart of `b`.
        f.host.deactivate(&id("a")).await.unwrap();
        f.fake.take_calls();
        f.changes().await;

        let next = f.scheduled().await;

        assert_eq!((next.attempt, next.delay), (2, 200 * MS));
        assert!(next.reason.contains("dependency `a` is not active"));
        assert_eq!(f.reason("b"), next.reason);
        assert_eq!(f.state("b"), Some(Failed));
        // The extension was not called.
        assert!(f.fake.take_calls().is_empty());
        assert!(f.changes().await.is_empty());
        // An expected condition, not a defect.
        let error = f.host.restart(&id("b")).await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Policy);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_stops_pending_restarts() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.add("c", &[]);
        f.host.discover().await.unwrap();
        f.fake.set("activate a", Some(Mode::Fail));
        f.go("a").await;
        assert_eq!(f.all_scheduled().await, [("a".to_owned(), 1)]);

        assert!(f.host.shutdown().await.is_empty());
        pass(HOUR).await;

        assert_eq!(f.fake.count("activate a"), 1);
        assert_eq!(f.state("a"), Some(Failed));
        assert!(f.all_scheduled().await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_deactivation_does_not_start_the_automatic_restart() {
        for mode in [Mode::Fail, Mode::Hang] {
            let mut f = fixture(true);
            f.add("a", &[]);
            f.add("b", &["a"]);
            f.host.discover().await.unwrap();
            f.go("b").await;
            f.changes().await;
            f.fake.set("deactivate a", Some(mode));
            f.fake.set("deactivate b", Some(mode));

            // By a user request, and as a dependent of a crashed extension.
            f.host.deactivate(&id("b")).await.unwrap_err();
            let crash = Error::internal("trap");
            f.host.report_crash(&id("a"), crash).await.unwrap();
            f.host.disable(&id("a")).await.unwrap();
            pass(HOUR).await;

            assert_eq!(f.state("b"), Some(Failed));
            assert_eq!(f.fake.count("activate b"), 1);
            // Only the crash planned a restart.
            assert_eq!(f.all_scheduled().await, [("a".to_owned(), 1)]);
            assert_eq!(
                f.changes().await,
                [
                    "b: Active -> Failed",
                    "a: Active -> Failed",
                    "a: Failed -> Disabled",
                ]
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn disable_stops_the_pending_restart() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        f.fake.set("activate a", Some(Mode::Fail));
        f.go("a").await;
        assert_eq!(f.all_scheduled().await, [("a".to_owned(), 1)]);

        f.host.disable(&id("a")).await.unwrap();
        pass(HOUR).await;

        assert_eq!(f.fake.count("activate a"), 1);
        assert_eq!(f.state("a"), Some(Disabled));
        assert!(f.all_scheduled().await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn unload_stops_the_pending_restart_of_a_failed_dependent() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.host.discover().await.unwrap();
        f.go("b").await;
        f.host
            .report_crash(&id("b"), Error::internal("trap"))
            .await
            .unwrap();
        assert_eq!(f.all_scheduled().await, [("b".to_owned(), 1)]);
        f.host.deactivate(&id("a")).await.unwrap();

        f.host.unload(&id("a")).await.unwrap();
        pass(HOUR).await;

        // Without the stop, the restart fails and the next one is planned.
        assert!(f.all_scheduled().await.is_empty());
        assert_eq!(f.state("a"), None);
        assert_eq!(f.state("b"), Some(Failed));
        assert_eq!(f.fake.count("load b@1.0.0"), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_host_restarts_nothing() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        f.fake.set("activate a", Some(Mode::Fail));
        f.go("a").await;
        let host = Arc::downgrade(&f.host);
        f.host = fixture(true).host;

        // The pending restart does not keep the host alive.
        assert!(host.upgrade().is_none());
        pass(HOUR).await;
        assert_eq!(f.fake.count("activate a"), 1);
    }

    #[test]
    fn the_configuration_has_documented_defaults_and_reads_the_settings() {
        use crate::settings::Layer;
        let default = HostConfig::default();
        assert_eq!(default.call_timeout, Duration::from_secs(30));
        assert_eq!(default.backoff_initial, 100 * MS);
        assert_eq!(default.backoff_factor, 2);
        assert_eq!(default.backoff_max, Duration::from_secs(1));
        // Each default delay is in the target of §9: a restart in 1 s.
        let delays: Vec<Duration> = (1..=5).map(|failures| default.backoff(failures)).collect();
        let expected = [100, 200, 400, 800, 1000].map(Duration::from_millis);
        assert_eq!(delays, expected);
        assert_eq!(default.restart_limit, 5);
        assert_eq!(default.reset_after, Duration::from_secs(300));
        // The delay does not overflow.
        assert_eq!(default.backoff(u32::MAX), default.backoff_max);

        let read = |text: &str| {
            let mut settings = Settings::new();
            let text = format!("schema_version = 1\n{text}");
            settings.set_layer(Layer::User, "test", &text).unwrap();
            HostConfig::from_settings(&settings)
        };
        assert_eq!(read("").unwrap(), default);
        let config = read(
            "[extensions]\ncall_timeout_ms = 500\n\
             [extensions.restart]\nbackoff_initial_ms = 10\nbackoff_factor = 3\n\
             backoff_max_ms = 90\nlimit = 7\nreset_after_ms = 1000\n",
        );
        let expected = HostConfig {
            call_timeout: 500 * MS,
            backoff_initial: 10 * MS,
            backoff_factor: 3,
            backoff_max: 90 * MS,
            restart_limit: 7,
            reset_after: Duration::from_secs(1),
        };
        assert_eq!(config.unwrap(), expected);

        for invalid in [
            "[extensions]\ncall_timeout_ms = 0\n",
            "[extensions]\ncall_timeout_ms = \"soon\"\n",
            "[extensions.restart]\nbackoff_initial_ms = 0\n",
            "[extensions.restart]\nbackoff_factor = 0\n",
            "[extensions.restart]\nbackoff_max_ms = 50\n",
            "[extensions.restart]\nlimit = -1\n",
        ] {
            let error = read(invalid).expect_err(invalid);
            assert_eq!(error.category(), ErrorCategory::User, "{invalid}");
        }
    }

    #[tokio::test]
    async fn a_panic_in_the_unload_of_an_instance_is_contained() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.add("c", &[]);
        f.host.discover().await.unwrap();
        f.go("a").await;
        f.host.deactivate(&id("a")).await.unwrap();
        f.fake.set("unload a", Some(Mode::Panic));
        f.changes().await;

        // In a task, so that a panic of the host is a result of the test.
        let host = Arc::clone(&f.host);
        let unload = tokio::spawn(async move { host.unload(&id("a")).await });

        unload.await.expect("no panic").unwrap();
        // The state change still happens.
        assert_eq!(f.changes().await, ["a: Inactive -> none"]);

        // The unload after a failure.
        f.host.discover().await.unwrap();
        f.fake.set("activate a", Some(Mode::Fail));
        let host = Arc::clone(&f.host);
        let trigger =
            tokio::spawn(async move { host.trigger(ActivationTrigger::Command("a")).await });

        let report = trigger.await.expect("no panic");
        assert_eq!(
            report.not_activated[&id("a")].category(),
            ErrorCategory::Connectivity
        );
        assert_eq!(f.state("a"), Some(Failed));
        // The host works.
        assert_eq!(f.go("c").await.activated, [id("c")]);
    }

    #[tokio::test(start_paused = true)]
    async fn reload_ends_the_jobs_of_the_old_version_before_the_unload() {
        let grace = crate::jobs::JobConfig::default().cancel_grace;
        let f = fixture(true);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        f.fake.set("job a", Some(Mode::Hang));
        f.go("a").await;
        let old_job = f.job("a");
        f.fake.set("job a", None);
        f.fake.take_calls();
        let start = Instant::now();

        f.host.reload(&id("a")).await.unwrap();

        // The host waited for the job, which the scheduler aborted.
        assert_eq!(start.elapsed(), grace);
        let error = old_job.join().await.unwrap_err();
        assert!(error.message().contains("was aborted"), "{error}");
        let running = |job: &crate::jobs::JobSnapshot| {
            job.owner == id("a") && job.state == crate::jobs::JobState::Running
        };
        // Only the job of the new instance runs.
        let jobs = f.services.jobs.jobs();
        assert_eq!(jobs.into_iter().filter(running).count(), 1);
        assert_eq!(
            f.fake.take_calls(),
            ["deactivate a", "unload a", "load a@1.0.0", "activate a"]
        );
    }

    #[tokio::test]
    async fn an_operation_completes_when_its_caller_is_dropped() {
        let f = fixture(true);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        f.fake.set("activate a", Some(Mode::Wait));
        let host = Arc::clone(&f.host);
        let trigger =
            tokio::spawn(async move { host.trigger(ActivationTrigger::Command("a")).await });
        f.fake.called("activate a").await;

        trigger.abort();
        assert!(trigger.await.unwrap_err().is_cancelled());
        f.fake.gate.notify_one();
        // The second trigger waits for the first operation.
        let report = f.go("a").await;

        assert!(report.activated.is_empty());
        assert!(report.not_activated.is_empty());
        assert_eq!(f.state("a"), Some(Active));
        assert_eq!(f.fake.count("activate a"), 1);
        assert_eq!(f.registered("a").await, (true, true));
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_completes_although_an_activation_hangs_and_then_the_host_refuses_work() {
        let f = fixture(true);
        f.add("a", &[]);
        f.add("b", &[]);
        f.add("c", &[]);
        f.host.discover().await.unwrap();
        f.go("b").await;
        f.fake.set("activate a", Some(Mode::Hang));
        let host = Arc::clone(&f.host);
        let trigger =
            tokio::spawn(async move { host.trigger(ActivationTrigger::Command("a")).await });
        f.fake.called("activate a").await;
        let start = Instant::now();

        assert!(f.host.shutdown().await.is_empty());

        // The time limit of the activation ends the wait.
        assert_eq!(start.elapsed(), HostConfig::default().call_timeout);
        assert!(trigger.await.unwrap().activated.is_empty());
        assert_eq!(f.state("b"), Some(Inactive));
        f.fake.called("unload a").await;
        f.fake.take_calls();

        // After the shutdown the host activates nothing.
        for command in ["b", "c"] {
            let report = f.go(command).await;
            let error = &report.not_activated[&id(command)];
            assert_eq!(error.category(), ErrorCategory::Policy);
            assert!(error.message().contains("shut down"), "{error}");
        }
        let error = f.host.restart(&id("a")).await.unwrap_err();
        assert!(error.message().contains("shut down"), "{error}");
        pass(HOUR).await;
        assert!(f.fake.take_calls().is_empty());
        assert_eq!(f.state("a"), Some(Failed));
    }

    // --- Review findings R-19, R-20, R-23 ---

    #[cfg(unix)]
    #[tokio::test]
    async fn discovery_does_not_read_a_manifest_that_is_not_a_regular_file() {
        let f = fixture(true);
        f.add("a", &[]);
        let evil = f.roots[USER].path().join("evil");
        std::fs::create_dir(&evil).unwrap();
        let fifo = evil.join(MANIFEST_FILE);
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        assert!(made.unwrap().success());

        // Real time: a read of the FIFO never ends.
        let found = tokio::time::timeout(Duration::from_secs(5), f.host.discover()).await;
        if found.is_err() {
            // Ends the read that waits in the FIFO, so that the test can end.
            drop(std::fs::OpenOptions::new().write(true).open(&fifo));
        }
        found.expect("discovery does not wait for a FIFO").unwrap();

        let invalid = f.host.invalid_packages();
        assert_eq!(invalid.len(), 1);
        assert_eq!(invalid[0].0, evil);
        assert!(invalid[0].1.contains("not a regular file"), "{invalid:?}");
        // The other extensions and the other operations work.
        assert_eq!(f.go("a").await.activated, [id("a")]);
        assert!(f.host.shutdown().await.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn discovery_does_not_follow_symbolic_links() {
        use std::os::unix::fs::symlink;
        let f = fixture(true);
        let outside = tempfile::tempdir().unwrap();
        let package = outside.path().join("out");
        std::fs::create_dir(&package).unwrap();
        let text = manifest("out", "1.0.0", &[], "");
        std::fs::write(package.join(MANIFEST_FILE), text).unwrap();
        let user = f.roots[USER].path();
        // A link to a directory, and a real directory with a link to a manifest.
        symlink(&package, user.join("link")).unwrap();
        std::fs::create_dir(user.join("file-link")).unwrap();
        let target = package.join(MANIFEST_FILE);
        symlink(target, user.join("file-link").join(MANIFEST_FILE)).unwrap();

        f.host.discover().await.unwrap();

        assert!(f.host.extensions().is_empty());
        let invalid = f.host.invalid_packages();
        assert_eq!(invalid.len(), 2, "{invalid:?}");
        assert_eq!(invalid[0].0, user.join("file-link"));
        assert!(invalid[0].1.contains("not a regular file"), "{invalid:?}");
        assert_eq!(invalid[1].0, user.join("link"));
        assert!(invalid[1].1.contains("symbolic link"), "{invalid:?}");
    }

    #[tokio::test]
    async fn discovery_refuses_a_manifest_above_the_size_limit() {
        let f = fixture(true);
        let limit = 1024 * 1024;
        let text = manifest("at-limit", "1.0.0", &[], "");
        let padding = "#".repeat(limit - text.len());
        f.write(USER, "at-limit", &format!("{text}{padding}"));
        let text = manifest("above", "1.0.0", &[], "");
        let padding = "#".repeat(limit + 1 - text.len());
        f.write(USER, "above", &format!("{text}{padding}"));

        f.host.discover().await.unwrap();

        assert_eq!(f.state("at-limit"), Some(Resolved));
        assert_eq!(f.state("above"), None);
        let invalid = f.host.invalid_packages();
        assert_eq!(invalid.len(), 1);
        assert!(invalid[0].0.ends_with("above"));
        assert!(invalid[0].1.contains("larger than"), "{invalid:?}");
    }

    #[tokio::test]
    async fn an_invalid_package_does_not_replace_a_valid_one_from_an_earlier_directory() {
        let f = fixture(true);
        f.write(BUNDLED, "a", &manifest("a", "1.0.0", &[], ""));
        // No version.
        f.write(WORKSPACE, "whatever", "id = \"a\"\n");
        f.write(BUNDLED, "b", &manifest("b", "1.0.0", &[], ""));
        f.write(USER, "b-1", &manifest("b", "1.1.0", &[], ""));
        f.write(USER, "b-2", &manifest("b", "1.2.0", &[], ""));

        f.host.discover().await.unwrap();

        for extension in ["a", "b"] {
            let status = f.status(extension).unwrap();
            assert_eq!(status.state, Resolved, "{extension}");
            let bundled = f.roots[BUNDLED].path().join(extension);
            assert_eq!(status.directory, bundled);
        }
        let invalid = f.host.invalid_packages();
        assert_eq!(invalid.len(), 2, "{invalid:?}");
        assert_eq!(invalid[0].0, f.roots[USER].path().join("b-2"));
        assert!(invalid[0].1.contains("two packages"), "{invalid:?}");
        assert_eq!(invalid[1].0, f.roots[WORKSPACE].path().join("whatever"));
        assert!(invalid[1].1.contains("missing field"), "{invalid:?}");
        assert_eq!(f.go("a").await.activated, [id("a")]);
        assert_eq!(f.fake.take_calls(), ["load a@1.0.0", "activate a"]);
    }

    #[tokio::test]
    async fn reload_of_a_broken_package_fails_and_keeps_the_running_extension() {
        let f = fixture(true);
        f.write(BUNDLED, "a", &manifest("a", "1.0.0", &[], ""));
        f.write(WORKSPACE, "a", &manifest("a", "2.0.0", &[], ""));
        f.write(BUNDLED, "b", &manifest("b", "1.0.0", &[], ""));
        f.host.discover().await.unwrap();
        f.go("a").await;
        f.go("b").await;
        f.fake.take_calls();

        // The package in use: a manifest without a version, then without an id.
        f.write(WORKSPACE, "a", "id = \"a\"\n");
        let no_version = f.host.reload(&id("a")).await.unwrap_err();
        f.write(WORKSPACE, "a", "version = \"2.0.0\"\n");
        let no_id = f.host.reload(&id("a")).await.unwrap_err();
        // A new, invalid package in a later directory than the one in use.
        f.write(USER, "b", "id = \"b\"\n");
        let later = f.host.reload(&id("b")).await.unwrap_err();

        assert!(
            no_version.message().contains("missing field"),
            "{no_version}"
        );
        assert!(no_id.message().contains("no valid `id`"), "{no_id}");
        assert!(later.message().contains("missing field"), "{later}");
        for error in [no_version, no_id, later] {
            assert_eq!(error.category(), ErrorCategory::User);
        }
        // Nothing was stopped, and no older package was loaded.
        assert!(f.fake.take_calls().is_empty());
        for (extension, root) in [("a", WORKSPACE), ("b", BUNDLED)] {
            let status = f.status(extension).unwrap();
            assert_eq!(status.state, Active, "{extension}");
            assert_eq!(status.directory, f.roots[root].path().join(extension));
        }

        // The corrected package is loaded.
        f.write(WORKSPACE, "a", &manifest("a", "2.1.0", &[], ""));
        assert_eq!(f.host.reload(&id("a")).await.unwrap().activated, [id("a")]);
        assert_eq!(f.fake.count("load a@2.1.0"), 1);
    }

    #[tokio::test]
    async fn the_folder_with_the_name_of_the_id_wins_in_one_directory() {
        let f = fixture(true);
        f.add("a", &[]);
        // Each of them only claims the id `a`.
        f.write(USER, "evil", "id = \"a\"\n");
        f.write(USER, "z-copy", &manifest("a", "9.0.0", &[], ""));
        // The folder `b` is invalid: it wins also, and `b` is rejected.
        f.write(USER, "b", "id = \"b\"\n");
        f.write(USER, "b-copy", &manifest("b", "1.0.0", &[], ""));

        f.host.discover().await.unwrap();

        let user = f.roots[USER].path();
        let a = f.status("a").unwrap();
        assert_eq!((a.state, a.directory), (Resolved, user.join("a")));
        let b = f.status("b").unwrap();
        assert_eq!((b.state, b.directory), (Rejected, user.join("b")));
        assert!(f.reason("b").contains("missing field"), "{}", f.reason("b"));
        let invalid = f.host.invalid_packages();
        let folders: Vec<_> = invalid.iter().map(|(folder, _)| folder.clone()).collect();
        // In the order of the ids.
        let copies = ["evil", "z-copy", "b-copy"].map(|folder| user.join(folder));
        assert_eq!(folders, copies);
        for (_, reason) in &invalid {
            assert!(reason.contains("has the name of the id"), "{reason}");
        }
        assert_eq!(f.go("a").await.activated, [id("a")]);
        assert_eq!(f.fake.take_calls(), ["load a@1.0.0", "activate a"]);
    }

    #[tokio::test]
    async fn the_event_subscriptions_of_an_extension_end_when_it_stops() {
        let f = fixture(true);
        for extension in ["stays", "deactivated", "crashed", "failed"] {
            f.add(extension, &[]);
        }
        f.host.discover().await.unwrap();
        f.fake.set("activate failed", Some(Mode::Fail));
        for extension in ["stays", "deactivated", "crashed", "failed"] {
            f.go(extension).await;
        }
        let subscription = |owner: &str| f.fake.subscriptions.lock().unwrap().remove(owner);

        f.host.deactivate(&id("deactivated")).await.unwrap();
        let crash = Error::internal("trap");
        f.host.report_crash(&id("crashed"), crash).await.unwrap();
        f.services.events.publish(Ping);

        let mut open = subscription("stays").unwrap();
        assert_eq!(open.recv().await, Some(Received::Event(Ping)));
        for owner in ["deactivated", "crashed", "failed"] {
            let mut closed = subscription(owner).unwrap();
            assert_eq!(closed.recv().await, None, "{owner}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_or_disabled_extension_can_be_replaced() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.host.discover().await.unwrap();
        f.fake.set("activate a", Some(Mode::Fail));
        f.go("a").await;
        assert_eq!(f.all_scheduled().await, [("a".to_owned(), 1)]);
        f.fake.set("activate a", None);
        f.fake.take_calls();
        f.changes().await;

        // Reload from `Failed`, with the version 1.1.0 on disk.
        f.write(USER, "a", &manifest("a", "1.1.0", &[], ""));
        let report = f.host.reload(&id("a")).await.unwrap();
        assert!(report.activated.is_empty());
        assert_eq!(
            f.changes().await,
            [
                "a: Failed -> none",
                "a: none -> Discovered",
                "a: Discovered -> Resolved",
            ]
        );
        // The pending restart of the old version is stopped.
        pass(HOUR).await;
        assert!(f.fake.take_calls().is_empty());
        assert_eq!(f.go("b").await.activated, [id("a"), id("b")]);
        assert_eq!(f.fake.count("load a@1.1.0"), 1);

        // Unload from `Failed`. Discovery finds the extension again.
        let crash = Error::internal("trap");
        f.host.report_crash(&id("a"), crash).await.unwrap();
        f.fake.take_calls();
        f.host.unload(&id("a")).await.unwrap();
        assert_eq!(f.state("a"), None);
        pass(HOUR).await;
        // `b` was loaded and cannot resolve without `a`. No restart of `a`.
        assert_eq!(f.fake.take_calls(), ["unload b"]);
        f.host.discover().await.unwrap();
        assert_eq!(f.go("b").await.activated, [id("a"), id("b")]);

        // Reload from `Disabled`: the same as from `Failed`.
        let crash = Error::internal("trap");
        f.host.report_crash(&id("a"), crash).await.unwrap();
        f.host.disable(&id("a")).await.unwrap();
        f.write(USER, "a", &manifest("a", "2.0.0", &[], ""));
        f.changes().await;
        let report = f.host.reload(&id("a")).await.unwrap();
        assert!(report.activated.is_empty());
        // `b` needs `a` `^1`: the host resolved with the new manifest.
        assert_eq!(
            f.changes().await,
            [
                "a: Disabled -> none",
                "a: none -> Discovered",
                "a: Discovered -> Resolved",
                "b: Inactive -> none",
                "b: none -> Discovered",
                "b: Discovered -> Rejected",
            ]
        );
        assert!(f.reason("b").contains("`^1`"));
        assert_eq!(f.go("a").await.activated, [id("a")]);
        assert_eq!(f.fake.count("load a@2.0.0"), 1);

        // Unload from `Disabled`. Discovery finds the extension again.
        let crash = Error::internal("trap");
        f.host.report_crash(&id("a"), crash).await.unwrap();
        f.host.disable(&id("a")).await.unwrap();
        f.host.unload(&id("a")).await.unwrap();
        assert_eq!(f.state("a"), None);
        f.host.discover().await.unwrap();
        assert_eq!(f.state("a"), Some(Resolved));
    }

    #[tokio::test]
    async fn reload_returns_the_report_when_the_activation_fails() {
        let f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.host.discover().await.unwrap();
        f.go("b").await;
        f.fake.set("activate a", Some(Mode::Fail));

        let report = f.host.reload(&id("a")).await.unwrap();

        assert!(report.activated.is_empty());
        let a = &report.not_activated[&id("a")];
        assert_eq!(a.category(), ErrorCategory::Connectivity);
        let b = &report.not_activated[&id("b")];
        assert!(b.message().contains("dependency `a` is not active"));
        assert_eq!(f.state("a"), Some(Failed));
        assert_eq!(f.state("b"), Some(Inactive));
    }

    #[tokio::test]
    async fn reload_does_not_activate_a_version_that_requires_a_ui_in_a_headless_host() {
        let f = fixture(true);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        f.go("a").await;
        f.fake.take_calls();
        let ui = manifest("a", "1.1.0", &[], "requires_ui = true");
        f.write(USER, "a", &ui);

        let report = f.host.reload(&id("a")).await.unwrap();

        assert!(report.activated.is_empty());
        let error = &report.not_activated[&id("a")];
        assert_eq!(error.category(), ErrorCategory::Policy);
        assert!(error.message().contains("requires_ui"), "{error}");
        assert_eq!(f.state("a"), Some(Resolved));
        assert_eq!(f.fake.take_calls(), ["deactivate a", "unload a"]);
    }

    #[tokio::test]
    async fn a_cancelled_call_is_not_reported_as_a_panic() {
        let cancelled: JoinHandle<Result<()>> = tokio::spawn(std::future::pending());
        cancelled.abort();
        let panicked: JoinHandle<Result<()>> = tokio::spawn(async { panic!("defect") });

        let (mut cancelled, mut panicked) = (cancelled, panicked);
        let cancelled = joined(&id("a"), "activate", DAY, &mut cancelled).await;
        let panicked = joined(&id("a"), "activate", DAY, &mut panicked).await;

        let (Limited::Ended(Err(cancelled)), Limited::Ended(Err(panicked))) = (cancelled, panicked)
        else {
            panic!("a call that ended in the time limit is not overdue");
        };
        assert_eq!(cancelled.category(), ErrorCategory::Internal);
        assert_eq!(
            cancelled.message(),
            "extension `a` was cancelled in `activate`"
        );
        assert_eq!(panicked.message(), "extension `a` panicked in `activate`");
    }

    #[tokio::test]
    async fn a_state_change_event_gives_the_reason() {
        let config = HostConfig {
            restart_limit: 0,
            ..HostConfig::default()
        };
        let mut f = fixture_with(true, config);
        f.add("a", &[]);
        f.add("needs-missing", &["missing"]);
        f.host.discover().await.unwrap();
        f.fake.set("activate a", Some(Mode::Fail));
        f.go("a").await;

        let events = f.events().await;

        let reasons: Vec<(String, Option<String>)> = events
            .iter()
            .map(|event| (line(event), event.reason.clone()))
            .collect();
        let reason = |change: &str| {
            let found = reasons.iter().find(|(line, _)| line == change);
            found.unwrap_or_else(|| panic!("no {change}")).1.clone()
        };
        assert_eq!(reason("a: none -> Discovered"), None);
        assert_eq!(reason("a: Discovered -> Resolved"), None);
        let rejected = reason("needs-missing: Discovered -> Rejected").unwrap();
        assert!(rejected.contains("`missing` is not present"), "{rejected}");
        let failed = reason("a: Resolved -> Failed");
        assert_eq!(failed.as_deref(), Some("activate a failed"));
        let disabled = reason("a: Failed -> Disabled").unwrap();
        assert!(disabled.contains("restart limit of 0"), "{disabled}");
        // The reason in the event is the reason in the status.
        assert_eq!(f.reason("a"), disabled);
    }

    /// A fixture with the extension `a`, discovered. With `active`, `a` is
    /// active and its secret backend resolves.
    async fn with_backend(active: bool, config: HostConfig) -> Fixture {
        let mut f = fixture_with(true, config);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        if active {
            assert_eq!(f.go("a").await.activated, [id("a")]);
            assert!(f.has_backend("a").await);
        }
        f.changes().await;
        f
    }

    #[tokio::test(start_paused = true)]
    async fn deactivation_removes_the_secret_backends_of_that_extension_only() {
        let f = with_backend(true, HostConfig::default()).await;
        f.add("other", &[]);
        f.host.discover().await.unwrap();
        f.go("other").await;

        f.host.deactivate(&id("a")).await.unwrap();

        f.assert_no_backend("a").await;
        assert!(f.has_backend("other").await);
        // The backend of the core has no owner. It is still registered: its
        // scheme is not free.
        let keychain = f
            .fake
            .secrets
            .register(id("a"), "keychain", Arc::new(Fixed));
        assert_eq!(keychain.unwrap_err().category(), ErrorCategory::Policy);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_activation_removes_the_secret_backends() {
        let f = with_backend(false, HostConfig::default()).await;
        f.fake.set("activate a", Some(Mode::Fail));

        f.go("a").await;

        assert_eq!(f.state("a"), Some(Failed));
        f.assert_no_backend("a").await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_panic_in_the_activation_removes_the_secret_backends() {
        let f = with_backend(false, HostConfig::default()).await;
        f.fake.set("activate a", Some(Mode::Panic));

        f.go("a").await;

        assert_eq!(f.state("a"), Some(Failed));
        f.assert_no_backend("a").await;
    }

    #[tokio::test(start_paused = true)]
    async fn an_activation_that_exceeds_the_time_limit_removes_the_secret_backends() {
        let f = with_backend(false, HostConfig::default()).await;
        f.fake.set("activate a", Some(Mode::Hang));

        f.go("a").await;

        assert_eq!(f.state("a"), Some(Failed));
        f.assert_no_backend("a").await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_reported_crash_removes_the_secret_backends() {
        let f = with_backend(true, HostConfig::default()).await;

        let crash = Error::internal("trap");
        f.host.report_crash(&id("a"), crash).await.unwrap();

        assert_eq!(f.state("a"), Some(Failed));
        f.assert_no_backend("a").await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_deactivation_removes_the_secret_backends() {
        let f = with_backend(true, HostConfig::default()).await;
        f.fake.set("deactivate a", Some(Mode::Fail));

        f.host.deactivate(&id("a")).await.unwrap_err();

        assert_eq!(f.state("a"), Some(Failed));
        f.assert_no_backend("a").await;
    }

    #[tokio::test(start_paused = true)]
    async fn an_unloaded_extension_has_no_secret_backends() {
        let f = with_backend(true, HostConfig::default()).await;
        f.host.deactivate(&id("a")).await.unwrap();

        f.host.unload(&id("a")).await.unwrap();

        assert_eq!(f.state("a"), None);
        f.assert_no_backend("a").await;
    }

    #[tokio::test(start_paused = true)]
    async fn reload_removes_the_secret_backends_of_the_old_version() {
        for version in ["1.0.0", "2.0.0"] {
            let f = with_backend(true, HostConfig::default()).await;
            f.write(USER, "a", &manifest("a", version, &[], ""));
            // The new version registers no backend: its activation fails
            // before that, in the load.
            f.fake.set(&format!("load a@{version}"), Some(Mode::Fail));

            let report = f.host.reload(&id("a")).await.unwrap();

            assert!(report.not_activated.contains_key(&id("a")), "{version}");
            assert_eq!(f.fake.count("unload a"), 1, "{version}");
            f.assert_no_backend("a").await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn reload_registers_the_secret_backend_of_the_new_version() {
        let f = with_backend(true, HostConfig::default()).await;
        f.write(USER, "a", &manifest("a", "2.0.0", &[], ""));

        let report = f.host.reload(&id("a")).await.unwrap();

        // The scheme was free again, or the activation had failed.
        assert_eq!(report.activated, [id("a")]);
        assert!(f.has_backend("a").await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_disabled_extension_has_no_secret_backends() {
        let config = HostConfig {
            restart_limit: 1,
            ..HostConfig::default()
        };
        let mut f = with_backend(true, config).await;
        f.fake.set("activate a", Some(Mode::Fail));

        let crash = Error::internal("trap");
        f.host.report_crash(&id("a"), crash).await.unwrap();
        f.until("a", Disabled).await;

        f.assert_no_backend("a").await;
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_removes_the_secret_backends() {
        let f = with_backend(true, HostConfig::default()).await;

        assert!(f.host.shutdown().await.is_empty());

        assert_eq!(f.state("a"), Some(Inactive));
        f.assert_no_backend("a").await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_restarted_extension_registers_its_secret_backend_again() {
        let mut f = with_backend(true, HostConfig::default()).await;

        let crash = Error::internal("trap");
        f.host.report_crash(&id("a"), crash).await.unwrap();
        f.assert_no_backend("a").await;
        f.until("a", Active).await;

        assert!(f.has_backend("a").await);
    }

    // --- Review findings R-16, R-17, R-49 to R-53 ---

    #[tokio::test]
    async fn shutdown_unloads_the_instances_and_contains_a_panic_in_each_drop() {
        let f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.add("c", &[]);
        f.host.discover().await.unwrap();
        f.go("b").await;
        // `c` is loaded and not active.
        f.go("c").await;
        f.host.deactivate(&id("c")).await.unwrap();
        for unload in ["unload a", "unload b", "unload c"] {
            f.fake.set(unload, Some(Mode::Panic));
        }
        f.fake.take_calls();
        let Fixture { host, fake, .. } = f;

        // In a task, so that a panic of the host is a result of the test.
        let end = tokio::spawn(async move {
            let failures = host.shutdown().await;
            let left: Vec<_> = host.extensions().iter().map(|x| x.state).collect();
            drop(host);
            (failures, left)
        });

        let (failures, left) = end.await.expect("no panic");
        assert!(failures.is_empty());
        // The states stay readable.
        assert_eq!(left, [Inactive, Inactive, Inactive]);
        // The deactivation, then the drop of each instance, also of `c`, in
        // reverse dependency order.
        let calls = fake.take_calls();
        assert_eq!(calls[..2], ["deactivate b", "deactivate a"]);
        let unloads: BTreeSet<&str> = calls[2..].iter().map(String::as_str).collect();
        assert_eq!(
            unloads,
            BTreeSet::from(["unload a", "unload b", "unload c"])
        );
        let position = |call: &str| calls.iter().position(|made| made == call);
        assert!(position("unload b") < position("unload a"), "{calls:?}");
    }

    #[tokio::test]
    async fn the_drop_of_a_host_that_was_not_shut_down_contains_a_panic_in_each_instance() {
        let f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.host.discover().await.unwrap();
        f.go("b").await;
        f.fake.set("unload a", Some(Mode::Panic));
        f.fake.set("unload b", Some(Mode::Panic));
        f.fake.take_calls();
        let Fixture { host, fake, .. } = f;

        let dropped = std::thread::spawn(move || drop(host)).join();

        assert!(dropped.is_ok(), "the drop of the host panicked");
        // The dependent first.
        assert_eq!(fake.take_calls(), ["unload b", "unload a"]);
    }

    #[tokio::test]
    async fn an_extension_that_stops_cannot_start_jobs_or_register() {
        let f = fixture(true);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        f.fake.set("job a late", Some(Mode::Fail));
        f.go("a").await;

        f.host.deactivate(&id("a")).await.unwrap();

        assert_eq!(f.late("a").await, (0, false, false, false));
        // The secret store refused the backend: it was never there.
        assert_eq!(f.fake.count("backend a.late2: Policy"), 1);
        let late = "a.late2://x".parse().unwrap();
        assert!(f.fake.secrets.resolve(&late).await.is_err());
        f.host.unload(&id("a")).await.unwrap();
        assert_eq!(f.late("a").await, (0, false, false, false));

        // After the stop, the extension can register again.
        f.fake.set("job a late", None);
        f.host.discover().await.unwrap();
        assert_eq!(f.go("a").await.activated, [id("a")]);
        assert_eq!(f.registered("a").await, (true, true));
    }

    #[tokio::test(start_paused = true)]
    async fn the_state_and_the_registrations_agree_while_the_host_waits_for_the_jobs() {
        let grace = crate::jobs::JobConfig::default().cancel_grace;
        let f = fixture(true);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        f.fake.set("job a", Some(Mode::Hang));
        f.go("a").await;
        let host = Arc::clone(&f.host);
        let deactivate = tokio::spawn(async move { host.deactivate(&id("a")).await });

        pass(grace / 2).await;

        // The host waits for the job. The extension is not stopped yet.
        assert_eq!(f.fake.count("deactivate a"), 1);
        assert_eq!(f.state("a"), Some(Active));
        assert_eq!(f.registered("a").await, (true, true));
        deactivate.await.unwrap().unwrap();
        assert_eq!(f.state("a"), Some(Inactive));
        assert_eq!(f.registered("a").await, (false, false));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_call_that_runs_on_after_the_time_limit_is_released_again_when_it_ends() {
        // No restart: the extension is not active when the old call ends.
        let config = HostConfig {
            call_timeout: 50 * MS,
            restart_limit: 0,
            ..HostConfig::default()
        };
        let f = fixture_with(true, config);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        // The call does not return to the runtime. It registers at its end.
        f.fake.set("activate a", Some(Mode::Sleep(400 * MS)));
        f.fake.set("late a", Some(Mode::Fail));

        let report = f.go("a").await;

        let error = &report.not_activated[&id("a")];
        assert!(error.message().contains("exceeded the time limit"));
        assert_eq!(f.state("a"), Some(Disabled));
        // The old call ends. Then the host unloads its instance, in a
        // blocking task.
        f.fake.called("unload a").await;
        assert_eq!(
            f.fake.take_calls(),
            ["load a@1.0.0", "activate a", "unload a"]
        );
        // What the old call registered at its end is released.
        assert_eq!(f.late("a").await, (0, false, false, false));
        assert_eq!(f.registered("a").await, (false, false));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_call_that_ends_after_the_restart_does_not_release_the_new_instance() {
        // The test controls the order: the automatic restart is too late,
        // and the old call ends when the test permits it.
        let config = HostConfig {
            call_timeout: 50 * MS,
            backoff_initial: Duration::from_secs(3600),
            backoff_max: Duration::from_secs(3600),
            ..HostConfig::default()
        };
        let f = fixture_with(true, config);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        f.fake.set("activate a", Some(Mode::Block));
        f.fake.set("hold activate a", Some(Mode::Fail));
        f.fake.set("late a", Some(Mode::Fail));

        let report = f.go("a").await;

        f.fake.set("activate a", None);
        f.fake.set("late a", None);
        assert!(report.not_activated.contains_key(&id("a")));
        // The restart does not wait for the old call.
        f.host.restart(&id("a")).await.unwrap();
        assert_eq!(f.state("a"), Some(Active));
        assert_eq!(f.fake.count("unload a"), 0);
        f.fake.set("hold activate a", None);
        f.fake.called("unload a").await;
        // One unload: the old instance, in a blocking task.
        assert_eq!(
            f.fake.take_calls(),
            [
                "load a@1.0.0",
                "activate a",
                "load a@1.0.0",
                "activate a",
                "unload a"
            ]
        );
        // The new instance keeps what it registered. What the old call
        // registered at its end stays also, until the next stop.
        assert_eq!(f.registered("a").await, (true, true));
        assert_eq!(f.late("a").await, (1, true, true, true));
        f.fake.set("late a", Some(Mode::Fail));
        f.host.deactivate(&id("a")).await.unwrap();
        // `late` took the subscription. The job, service and command are gone.
        assert_eq!(f.late("a").await, (0, false, false, false));
        assert_eq!(f.registered("a").await, (false, false));
    }

    #[tokio::test]
    async fn a_call_that_does_not_yield_is_limited_on_a_runtime_with_one_thread() {
        let config = HostConfig {
            call_timeout: 50 * MS,
            ..HostConfig::default()
        };
        let f = fixture_with(true, config);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        f.fake.set("activate a", Some(Mode::Sleep(200 * MS)));

        let report = f.go("a").await;

        f.fake.set("activate a", None);
        let error = &report.not_activated[&id("a")];
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert!(error.message().contains("exceeded the time limit"));
        assert_eq!(f.state("a"), Some(Failed));
        assert_eq!(f.registered("a").await, (false, false));
        assert_eq!(f.fake.count("unload a"), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_dependent_whose_deactivation_failed_in_a_crash_is_restarted_with_its_dependency() {
        let mut f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.add("c", &["b"]);
        f.host.discover().await.unwrap();
        f.go("c").await;
        f.changes().await;
        f.fake.set("deactivate b", Some(Mode::Fail));

        let crash = Error::internal("trap");
        f.host.report_crash(&id("a"), crash).await.unwrap();

        assert_eq!(f.state("b"), Some(Failed));
        f.fake.set("deactivate b", None);
        assert_eq!(
            f.until("c", Active).await,
            [
                "c: Active -> Inactive",
                "b: Active -> Failed",
                "a: Active -> Failed",
                "a: Failed -> Active",
                "b: Failed -> Active",
                "c: Inactive -> Active",
            ]
        );
        for owner in ["a", "b", "c"] {
            assert_eq!(f.registered(owner).await, (true, true));
        }
    }

    #[test]
    fn an_operation_outside_a_runtime_is_an_error_and_not_a_panic() {
        use std::task::{Context, Poll, Waker};
        let f = fixture(true);
        f.add("a", &[]);
        // Without a runtime, each operation ends in its first poll.
        let mut context = Context::from_waker(Waker::noop());

        let discover = std::pin::pin!(f.host.discover());
        let Poll::Ready(found) = discover.poll(&mut context) else {
            panic!("`discover` waits");
        };
        let error = found.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert!(error.message().contains("Tokio runtime"), "{error}");
        let a = id("a");
        let unload = std::pin::pin!(f.host.unload(&a));
        let Poll::Ready(Err(error)) = unload.poll(&mut context) else {
            panic!("`unload` waits or succeeds");
        };
        assert_eq!(error.category(), ErrorCategory::Internal);
        let trigger = std::pin::pin!(f.go("a"));
        assert!(trigger.poll(&mut context).is_ready());
        let shutdown = std::pin::pin!(f.host.shutdown());
        assert!(shutdown.poll(&mut context).is_ready());
    }

    #[test]
    fn a_runtime_that_stops_during_an_operation_gives_an_error_and_not_a_panic() {
        let runtime = || {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            builder.worker_threads(1).enable_all().build().unwrap()
        };
        let (stopping, caller) = (runtime(), runtime());
        let f = fixture(true);
        f.add("a", &[]);
        stopping.block_on(f.host.discover()).unwrap();
        f.fake.set("activate a", Some(Mode::Wait));

        let report = caller.block_on(async {
            let mut trigger = std::pin::pin!(f.go("a"));
            {
                // The operation starts in the runtime that stops.
                let _stopping = stopping.enter();
                let ready = std::future::poll_fn(|context| {
                    std::task::Poll::Ready(trigger.as_mut().poll(context).is_ready())
                });
                assert!(!ready.await);
            }
            f.fake.called("activate a").await;
            stopping.shutdown_background();
            trigger.await
        });

        let error = &report.not_activated[&id("a")];
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert!(error.message().contains("runtime stopped"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_blocking_job_that_ignores_the_cancel_request_does_not_stop_the_unload() {
        let grace = crate::jobs::JobConfig::default().cancel_grace;
        let f = fixture(true);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        f.fake.set("blocking a", Some(Mode::Hang));
        f.go("a").await;
        f.fake.called("blocking a").await;
        let host = Arc::clone(&f.host);
        let stop = tokio::spawn(async move { host.deactivate(&id("a")).await });
        // The clock does not advance by itself while blocking work runs.
        // The steps are small: only the grace period must end, not the
        // time limit of the `deactivate` call.
        while !stop.is_finished() {
            tokio::time::advance(grace / 5).await;
        }
        let stopped = stop.await.unwrap();
        let unloaded = f.host.unload(&id("a")).await;

        let jobs = f.services.jobs.jobs();
        let blocking = jobs.iter().find(|job| job.kind == "blocking").unwrap();
        let running = f.services.jobs.aborted_running(&id("a"));
        // Lets the code end, so that the runtime of the test can stop.
        f.fake.set("blocking a", None);
        // The documented limit: the host waited for the abort, not for the
        // code. The job is `Cancelled` and its code still ran.
        stopped.unwrap();
        unloaded.unwrap();
        assert_eq!(f.state("a"), None);
        assert_eq!(f.fake.count("unload a"), 1);
        assert_eq!(blocking.state, crate::jobs::JobState::Cancelled);
        assert_eq!(running, 1);
        assert_eq!(f.registered("a").await, (false, false));
    }
}
