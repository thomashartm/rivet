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
//! one addition: an extension in the state `Resolved` or `Rejected` has no
//! loaded code, so the host can forget it and discover it again when its
//! manifest, or the result of the resolution, changes. Each state change is
//! published on the event bus as an [`ExtensionStateChanged`].
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
//! - After [`HostConfig::restart_limit`] failed restarts in a row the
//!   extension goes to `Disabled`.
//! - An extension that stayed `Active` for [`HostConfig::reset_after`]
//!   starts again with a failure count of zero.
//! - [`ExtensionHost::shutdown`] stops all pending restarts, and the host
//!   activates nothing after it.
//!
//! When an extension stops for any reason, the host waits until its jobs
//! have ended, before the state changes and before the instance is dropped
//! (§4.4, §5.2). The job scheduler aborts a job that does not end in
//! [`JobConfig::cancel_grace`](crate::jobs::JobConfig::cancel_grace).
//!
//! # Time limit
//!
//! Each call into extension code (`load`, `activate`, `deactivate`) has the
//! time limit [`HostConfig::call_timeout`]. After the limit, the host stops
//! waiting, puts the extension in `Failed`, drops the instance and does not
//! call it again. The host cannot stop code that does not return to the
//! async runtime, for example a blocking call or a WASM call that still has
//! fuel: that code can run on after the limit. It cannot change the state
//! of the extension.
//!
//! The drop of an instance (the unload) has the same time limit and the
//! same containment: a panic in it is logged as an `internal` error, and the
//! state change occurs nevertheless.
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
//! the next operation starts after it.
//!
//! ```
//! use rivet_core::bus::{CommandBus, EventBus};
//! use rivet_core::host::{
//!     ExtensionHost, ExtensionInstance, ExtensionRuntime, HostConfig, Services,
//! };
//! use rivet_core::jobs::JobScheduler;
//! use rivet_core::registry::ServiceRegistry;
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
//! let host = ExtensionHost::new(Arc::new(NoRuntime), services, sdk, directories, true, config);
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
use crate::settings::Settings;
use rivet_sdk::error::{Error, Result};
use rivet_sdk::extension::BoxFuture;
use rivet_sdk::manifest::{ExtensionId, Manifest, Version};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::Instant;

/// The name of the manifest file in an extension directory (§4.4).
pub const MANIFEST_FILE: &str = "extension.toml";

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
    /// The host unloads an instance by dropping it, in a blocking task.
    /// Dropping must release everything the instance holds (§5.2). A panic
    /// in the drop is contained (§5.6). There is no `unload` method,
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
/// the state `Failed` (§5.6).
pub trait ExtensionInstance: Send + Sync {
    /// Activates the extension. The extension registers its services,
    /// command handlers and jobs through `context`, with
    /// [`ExtensionContext::owner`] as the owner.
    fn activate(&self, context: ExtensionContext) -> BoxFuture<'_, Result<()>>;

    /// Deactivates the extension. After the call, the host removes every
    /// service and command handler of the extension and cancels its jobs,
    /// also when the call fails.
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
    /// registration and each job.
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
    /// The extension was disabled after a failure. It stays disabled.
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
    /// How many restarts in a row can fail. The next failure puts the
    /// extension in the state `Disabled`. With `0`, the first failure
    /// disables the extension.
    pub restart_limit: u32,
    /// An extension that stayed `Active` for this time starts again with a
    /// failure count of zero.
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

/// The state machine of §4.4, plus `Forget` (see the module documentation).
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
        (Inactive, Lifecycle::Unload) | (Resolved | Rejected, Lifecycle::Forget) => None,
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
    /// `Some` in the states `Active` and `Inactive`.
    instance: Option<Arc<dyn ExtensionInstance>>,
    /// The failures in a row. See [`Entry::end_run`].
    failures: u32,
    /// When the extension became `Active`. `Some` in the state `Active`.
    active_since: Option<Instant>,
    /// The task of the pending automatic restart.
    restart: Option<AbortHandle>,
    /// The dependents that a crash deactivated, in activation order. A
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
}

/// Reads the extension directories. Blocking.
///
/// For one id, a later discovery directory wins. Two packages with the same
/// id in the same discovery directory make the id invalid.
fn scan(directories: &[PathBuf]) -> Scan {
    let mut scan = Scan::default();
    for root in directories {
        let mut folders: Vec<PathBuf> = match std::fs::read_dir(root) {
            Ok(entries) => entries
                .filter_map(|entry| Some(entry.ok()?.path()))
                .filter(|path| path.is_dir())
                .collect(),
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                scan.invalid.push((root.clone(), error.to_string()));
                continue;
            }
        };
        folders.sort();
        let mut in_root: BTreeMap<ExtensionId, PathBuf> = BTreeMap::new();
        for directory in folders {
            let text = match std::fs::read_to_string(directory.join(MANIFEST_FILE)) {
                Ok(text) => text,
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                Err(error) => {
                    scan.invalid.push((directory, error.to_string()));
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
            let manifest = match in_root.insert(id.clone(), directory.clone()) {
                Some(other) => Err(format!(
                    "extension `{id}` has two packages in `{}`: `{}` and `{}`",
                    root.display(),
                    other.display(),
                    directory.display()
                )),
                None => manifest,
            };
            let package = Package {
                directory,
                manifest,
            };
            scan.packages.insert(id, package);
        }
    }
    scan
}

/// Runs a call into extension code in a separate task, so that a panic in
/// the call is an `internal` error and not a panic of the host (§5.6). A
/// call that takes longer than `limit` is an `internal` error also: like a
/// panic or a trap, it is a defect of the extension.
// shortcut: the abort stops the call at its next `.await` only, so code
// that does not return to the runtime runs on and can still register a
// service after the host released what the extension owns; the WASM runtime
// (#4, epoch interruption) and the native host process (#95) must stop it.
async fn contained<T: Send + 'static>(
    id: &ExtensionId,
    what: &str,
    limit: Duration,
    call: impl Future<Output = Result<T>> + Send + 'static,
) -> Result<T> {
    joined(id, what, limit, tokio::spawn(call)).await
}

/// Waits for `task`, which runs the call `what` into the code of `id`, not
/// longer than `limit`.
async fn joined<T>(
    id: &ExtensionId,
    what: &str,
    limit: Duration,
    mut task: JoinHandle<Result<T>>,
) -> Result<T> {
    match tokio::time::timeout(limit, &mut task).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            let message = format!("extension `{id}` panicked in `{what}`");
            Err(Error::internal(message).with_source(error))
        }
        Err(_) => {
            // The result of the call, if one comes, is dropped with the task.
            task.abort();
            Err(Error::internal(format!(
                "extension `{id}` exceeded the time limit of {limit:?} in `{what}`"
            )))
        }
    }
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
    sdk_version: Version,
    directories: Vec<PathBuf>,
    headless: bool,
    /// Held for the whole of each lifecycle operation, by the task of the
    /// operation.
    // shortcut: one lock for all extensions, so a slow activation delays the
    // activation of an unrelated extension; use one lock per dependency tree
    // when that delay is measured as a problem.
    lifecycle: tokio::sync::Mutex<()>,
    /// Never held across an `.await`.
    inner: Mutex<Inner>,
}

impl ExtensionHost {
    /// Creates a host with no extensions. Call [`discover`](Self::discover)
    /// to find them.
    ///
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
            sdk_version,
            directories,
            headless,
            lifecycle: tokio::sync::Mutex::default(),
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
    /// could not read as an extension and that give no extension id, each
    /// with the reason. An invalid manifest that has a valid `id` is in
    /// [`extensions`](Self::extensions) instead, in the state `Rejected`.
    pub fn invalid_packages(&self) -> Vec<(PathBuf, String)> {
        self.inner().invalid.clone()
    }

    /// Reads the discovery directories and resolves the dependencies.
    ///
    /// An extension is an immediate sub-directory that contains
    /// `extension.toml`. Discovery activates nothing. An invalid manifest
    /// rejects only its extension.
    ///
    /// The method can be called again. An extension that was activated
    /// before keeps its manifest: use [`reload`](Self::reload) to apply a
    /// change. An extension without loaded code is read again.
    ///
    /// # Errors
    ///
    /// Returns an `internal` error if the read of the directories panicked.
    pub async fn discover(&self) -> Result<()> {
        self.operation(|host| async move {
            let scan = host.scan().await?;
            let unloaded = {
                let mut inner = host.inner();
                inner.invalid = scan.invalid;
                host.reconcile(&mut inner, scan.packages)
            };
            host.drop_instances(unloaded).await;
            Ok(())
        })
        .await
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
    /// selected extension.
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
        self.operation(|host| async move {
            let plan = plan(&host.inner().index, host.headless);
            let mut report = ActivationReport {
                activated: Vec::new(),
                not_activated: plan.blocked,
            };
            host.activate_all(plan.activate, &mut report).await;
            report
        })
        .await
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
            .await
    }

    /// Unloads the inactive extension `id`: drops its instance and removes
    /// it from the host. A later [`discover`](Self::discover) finds it
    /// again. Extensions that depend on it become `Rejected` until then.
    /// The pending restart of a failed extension that depends on it is
    /// stopped: that extension stays `Failed`.
    ///
    /// # Errors
    ///
    /// - A `user` error if the host does not know `id`.
    /// - A `policy` error if the extension is not `Inactive`.
    pub async fn unload(&self, id: &ExtensionId) -> Result<()> {
        let id = id.clone();
        self.operation(|host| async move {
            let unloaded = {
                let mut inner = host.inner();
                let entry = host.apply(&mut inner, &id, Lifecycle::Unload, None)?;
                let packages = inner.unloaded_packages();
                let mut unloaded = Vec::from_iter(entry.map(|entry| (id.clone(), entry)));
                unloaded.extend(host.reconcile(&mut inner, packages));
                unloaded
            };
            host.drop_instances(unloaded).await;
            Ok(())
        })
        .await
    }

    /// Hot reload (§4.4): deactivates `id` and its dependents, unloads
    /// `id`, reads its manifest again, resolves all extensions again and
    /// activates what was active before.
    ///
    /// The extension must be `Active`, `Inactive`, `Resolved` or `Rejected`,
    /// or new on disk. Only extensions that were active are activated. The
    /// report lists them, and the dependents that could not activate again.
    ///
    /// # Errors
    ///
    /// The reload fails in these cases. The host stays consistent: no
    /// extension of the tree is active, and each extension that does not
    /// resolve is `Rejected` with its reason.
    ///
    /// - A `policy` error if the extension is `Failed` or `Disabled`.
    /// - The error of its `deactivate` call. The extension is `Failed`. The
    ///   host does not restart it automatically.
    /// - A `user` error if the package is not on disk any more, or if the
    ///   new manifest is invalid or does not resolve.
    /// - The error of its `load` or `activate` call. The extension is
    ///   `Failed`.
    pub async fn reload(&self, id: &ExtensionId) -> Result<ActivationReport> {
        let id = id.clone();
        self.operation(|host| async move { host.reload_locked(&id).await })
            .await
    }

    /// The body of [`reload`](Self::reload).
    async fn reload_locked(&self, id: &ExtensionId) -> Result<ActivationReport> {
        let state = |host: &Self| host.inner().entries.get(id).map(|entry| entry.state);
        let mut was_active = BTreeSet::new();
        let mut report = ActivationReport::default();
        match state(self) {
            Some(ExtensionState::Active) => {
                was_active.extend(self.inner().active_dependents(id));
                was_active.insert(id.clone());
                if let Err(error) = self.deactivate_tree(id).await
                    && state(self) != Some(ExtensionState::Inactive)
                {
                    return Err(error);
                }
            }
            Some(from @ (ExtensionState::Failed | ExtensionState::Disabled)) => {
                return Err(Error::policy(format!(
                    "extension `{id}` cannot reload from the state {from:?}"
                )));
            }
            _ => {}
        }
        let mut scan = self.scan().await?;
        let unloaded = {
            let mut inner = self.inner();
            let old = match inner.entries.get(id) {
                Some(entry) if entry.state == ExtensionState::Inactive => {
                    self.apply(&mut inner, id, Lifecycle::Unload, None)?
                }
                _ => None,
            };
            // Only `id` is read again. The other extensions keep their package.
            let mut packages = inner.unloaded_packages();
            packages.remove(id);
            packages.extend(scan.packages.remove_entry(id));
            let mut unloaded = Vec::from_iter(old.map(|entry| (id.clone(), entry)));
            unloaded.extend(self.reconcile(&mut inner, packages));
            unloaded
        };
        self.drop_instances(unloaded).await;

        let order: Vec<ExtensionId> = {
            let inner = self.inner();
            match inner.entries.get(id) {
                None => {
                    return Err(Error::user(format!(
                        "extension `{id}` is not in a discovery directory"
                    )));
                }
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
        match report.not_activated.remove(id) {
            Some(error) => Err(error),
            None => Ok(report),
        }
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
    /// - An `internal` error if a dependency is not active. This counts as
    ///   a failed restart.
    /// - The error of the `load` or `activate` call. The extension stays
    ///   `Failed`, and the failure counts as a failed restart.
    pub async fn restart(&self, id: &ExtensionId) -> Result<()> {
        let id = id.clone();
        self.operation(|host| async move { host.restart_one(&id).await })
            .await
    }

    /// Handles a crash of the active extension `id`, for example a WASM
    /// trap outside a lifecycle call. The runtime of the extension calls
    /// it. `error` is the reason; it must not contain secrets.
    ///
    /// The host deactivates the active dependents first, puts `id` in the
    /// state `Failed`, releases what it owns (§5.2) and drops its instance.
    /// It does not call the crashed instance. Then the automatic restart
    /// applies ([`HostConfig`]). A successful restart activates the
    /// dependents again.
    ///
    /// # Errors
    ///
    /// - A `user` error if the host does not know `id`.
    /// - A `policy` error if the extension is not `Active`.
    pub async fn report_crash(&self, id: &ExtensionId, error: Error) -> Result<()> {
        let id = id.clone();
        self.operation(|host| async move { host.crash(&id, &error).await })
            .await
    }

    /// The body of [`report_crash`](Self::report_crash).
    async fn crash(&self, id: &ExtensionId, error: &Error) -> Result<()> {
        let dependents = {
            let inner = self.inner();
            let entry = inner.entries.get(id).ok_or_else(|| unknown(id))?;
            if entry.state != ExtensionState::Active {
                return Err(Error::policy(format!(
                    "extension `{id}` cannot crash in the state {:?}",
                    entry.state
                )));
            }
            inner.active_dependents(id)
        };
        for dependent in dependents.iter().rev() {
            // A dependent that fails here stays `Failed`.
            if let Err(error) = self.deactivate_one(dependent).await {
                tracing::warn!(extension = %dependent, %error, "deactivation after a crash failed");
            }
        }
        {
            let mut inner = self.inner();
            let inactive = |dependent: &ExtensionId| {
                let entry = inner.entries.get(dependent);
                entry.is_some_and(|entry| entry.state == ExtensionState::Inactive)
            };
            let revive: Vec<ExtensionId> = dependents.into_iter().filter(inactive).collect();
            if let Some(entry) = inner.entries.get_mut(id) {
                entry.revive = revive;
            }
        }
        self.fail(id, error, true).await
    }

    /// Disables the failed extension `id` and stops its pending restart. A
    /// disabled extension does not activate again.
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
    /// (§5.7). A failure does not stop the shutdown. Returns the extensions
    /// whose `deactivate` call failed, each with the error.
    ///
    /// The shutdown stops all pending restarts. After it, the host does not
    /// activate or restart an extension: each attempt is a `policy` error.
    ///
    /// The shutdown waits for the lifecycle operation that runs. The time
    /// limit of a call into an extension ([`HostConfig::call_timeout`])
    /// ends that wait.
    pub async fn shutdown(&self) -> BTreeMap<ExtensionId, Error> {
        self.operation(|host| async move { host.shutdown_locked().await })
            .await
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
        failures
    }

    /// Runs one lifecycle operation in its own task, which holds the
    /// lifecycle lock. Thus a caller that drops its future does not stop
    /// the operation between two steps.
    async fn operation<T, F, Fut>(&self, body: F) -> T
    where
        T: Send + 'static,
        F: FnOnce(Arc<Self>) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send,
    {
        let host = self.this.upgrade();
        let host = host.expect("a host that is in use is not dropped");
        let task = tokio::spawn(async move {
            let _lifecycle = host.lifecycle.lock().await;
            body(Arc::clone(&host)).await
        });
        match task.await.map_err(tokio::task::JoinError::try_into_panic) {
            Ok(result) => result,
            // A panic of the host itself, not of an extension.
            Err(Ok(panic)) => std::panic::resume_unwind(panic),
            Err(Err(_)) => panic!("the Tokio runtime stopped during a lifecycle operation"),
        }
    }

    /// Unloads the instance of `id`: drops it in a blocking task, with the
    /// time limit and the containment of each call into extension code.
    async fn drop_instance(&self, id: &ExtensionId, instance: Option<Arc<dyn ExtensionInstance>>) {
        let Some(instance) = instance else {
            return;
        };
        let unload = tokio::task::spawn_blocking(move || {
            drop(instance);
            Ok(())
        });
        if let Err(error) = joined(id, "unload", self.config.call_timeout, unload).await {
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
        tokio::task::spawn_blocking(move || scan(&directories))
            .await
            .map_err(|error| Error::internal("extension discovery panicked").with_source(error))
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

    /// Releases everything that `owner` registered (§5.2).
    ///
    /// It waits until the jobs of `owner` have ended. The job scheduler
    /// limits this wait: it aborts a job that ignores the cancel request.
    async fn release(&self, owner: &Owner) {
        self.services.registry.unregister_owner(owner);
        self.services.commands.unregister_owner(owner);
        self.services.jobs.stop_owner(owner).await;
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
            // A dependent that fails is `Failed` and has its own restart.
            if let Err(error) = self.activate_one(&dependent, Lifecycle::Activate).await {
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
                    Err(Error::internal(refuse(&reason)))
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

        let limit = self.config.call_timeout;

        let result = async {
            let instance = match instance {
                Some(instance) => instance,
                None => {
                    let runtime = Arc::clone(&self.runtime);
                    let load = async move { runtime.load(&manifest, &directory).await };
                    let instance: Arc<dyn ExtensionInstance> =
                        contained(id, "load", limit, load).await?.into();
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
            let activate = async move { instance.activate(context).await };
            contained(id, "activate", limit, activate).await
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
                let deactivate = async move { instance.deactivate().await };
                contained(id, "deactivate", self.config.call_timeout, deactivate).await
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
    fn drop(&mut self) {
        let inner = self.inner.get_mut();
        let inner = inner.unwrap_or_else(PoisonError::into_inner);
        for (id, entry) in &mut inner.entries {
            entry.cancel_restart(id, "the host is dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::{Received, Subscription};
    use crate::jobs::JobHandle;
    use rivet_sdk::error::ErrorCategory;
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
    }

    /// The record of the fake runtime: what the host called, and what must
    /// fail.
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<String>>,
        modes: Mutex<BTreeMap<String, Mode>>,
        jobs: Mutex<BTreeMap<String, JobHandle<()>>>,
        gate: tokio::sync::Notify,
    }

    impl Fake {
        fn log(&self, call: &str) {
            self.calls.lock().unwrap().push(call.to_owned());
        }

        /// Records `call`, then fails, panics or hangs if the test asked
        /// for it.
        async fn call(&self, call: &str) -> Result<()> {
            self.log(call);
            match self.mode(call) {
                None => Ok(()),
                Some(Mode::Fail) => Err(Error::connectivity(format!("{call} failed"))),
                Some(Mode::Panic) => panic!("{call} panicked"),
                Some(Mode::Hang) => std::future::pending().await,
                Some(Mode::Wait) => {
                    self.gate.notified().await;
                    Ok(())
                }
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
        /// Registers the service `<id>.service` and the command
        /// `<id>.command`, and starts a job that runs until it is cancelled.
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
                // `job <id>` = `Hang`: the job ignores the cancel request.
                let stubborn = self.fake.mode(&format!("job {owner}")).is_some();
                let job = services
                    .jobs
                    .spawn(owner.clone(), "work", move |job| async move {
                        if stubborn {
                            std::future::pending::<()>().await;
                        }
                        job.cancelled().await;
                        Err(Error::cancelled("stopped"))
                    })?;
                self.fake
                    .jobs
                    .lock()
                    .unwrap()
                    .insert(owner.to_string(), job);
                // Gives a concurrent activation the chance to run.
                tokio::task::yield_now().await;
                self.fake.call(&format!("activate {owner}")).await
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
            let end = ExtensionStateChanged {
                id: id("end"),
                from: None,
                to: None,
                reason: None,
            };
            self.services.events.publish(end.clone());
            let mut changes = Vec::new();
            loop {
                match self.events.recv().await {
                    Some(Received::Event(event)) if event == end => return changes,
                    Some(Received::Event(event)) => changes.push(line(&event)),
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
        let f = fixture(true);
        f.add("a", &[]);
        f.host.discover().await.unwrap();
        f.fake.set("load a@1.0.0", Some(Mode::Panic));

        let report = f.go("a").await;

        let error = &report.not_activated[&id("a")];
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert_eq!(f.state("a"), Some(Failed));
        assert_eq!(f.fake.take_calls(), ["load a@1.0.0"]);
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
        f.host.reload(&id("a")).await.unwrap_err();
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
    async fn reload_to_an_invalid_manifest_fails_and_leaves_a_consistent_host() {
        let f = fixture(true);
        f.add("a", &[]);
        f.add("b", &["a"]);
        f.host.discover().await.unwrap();
        f.go("b").await;
        f.fake.take_calls();
        f.write(USER, "a", "id = \"a\"\nversion = \"not a version\"\n");

        let error = f.host.reload(&id("a")).await.unwrap_err();

        assert_eq!(error.category(), ErrorCategory::User);
        assert!(error.message().contains("invalid extension manifest"));
        assert_eq!(f.state("a"), Some(Rejected));
        assert_eq!(f.reason("a"), error.message());
        assert_eq!(f.state("b"), Some(Rejected));
        // An invalid manifest is not an input of the resolver.
        assert!(f.reason("b").contains("`a` is not present"));
        // Nothing is half active.
        assert_eq!(
            f.fake.take_calls(),
            ["deactivate b", "deactivate a", "unload a", "unload b"]
        );
        for owner in ["a", "b"] {
            assert_eq!(f.registered(owner).await, (false, false));
        }
        assert!(f.go("b").await.activated.is_empty());

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

        // A removed package fails the reload.
        std::fs::remove_dir_all(f.roots[USER].path().join("a")).unwrap();
        let error = f.host.reload(&id("a")).await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::User);
        assert_eq!(f.state("a"), None);
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

        assert_eq!(
            f.fake.take_calls(),
            ["deactivate c", "deactivate b", "unload b", "deactivate a"]
        );
        assert_eq!(failures.keys().collect::<Vec<_>>(), [&id("b")]);
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
            // The instance is dropped when the runtime removed the aborted
            // call, which holds it. It is not called again.
            if call == "activate a" {
                assert_eq!(f.job_end("a").await, ErrorCategory::Cancelled);
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
        assert_eq!(
            f.fake.take_calls(),
            ["deactivate b", "unload b", "deactivate a"]
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

        // Only an active extension can crash.
        for (extension, category) in [
            ("idle", ErrorCategory::Policy),
            ("unknown", ErrorCategory::User),
        ] {
            let crash = Error::internal("trap");
            let error = f.host.report_crash(&id(extension), crash).await;
            assert_eq!(error.unwrap_err().category(), category);
        }
        assert_eq!(f.state("idle"), Some(Resolved));
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
}
