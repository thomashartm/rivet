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
//! An activation that fails goes from its start state to `Active` and then
//! immediately to `Failed`, because the diagram reaches `Failed` only from
//! `Active`.
//!
//! # Concurrency
//!
//! Lifecycle operations run one after the other. Thus two activation events
//! for the same extension activate it one time, and a reload is not mixed
//! with an activation. [`ExtensionHost::extensions`] does not wait for a
//! lifecycle operation.
//!
//! ```
//! use rivet_core::bus::{CommandBus, EventBus};
//! use rivet_core::host::{ExtensionHost, ExtensionInstance, ExtensionRuntime, Services};
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
//! let host = ExtensionHost::new(Arc::new(NoRuntime), services, sdk, directories, true);
//! host.discover().await?;
//! assert!(host.extensions().is_empty());
//! # Ok::<(), Error>(())
//! # }).unwrap();
//! ```

use crate::Owner;
use crate::bus::{CommandBus, EventBus};
use crate::jobs::JobScheduler;
use crate::registry::ServiceRegistry;
use crate::resolve::{ActivationIndex, ActivationTrigger, Outcome, Resolution, resolve};
use rivet_sdk::error::{Error, Result};
use rivet_sdk::extension::BoxFuture;
use rivet_sdk::manifest::{ExtensionId, Manifest, Version};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

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
    /// The host unloads an instance by dropping it. Dropping must release
    /// everything the instance holds (§5.2). There is no `unload` method,
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
/// The host calls each method in a separate task. A panic in a method puts
/// the extension in the state `Failed` (§5.6).
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
    /// The activation or the deactivation failed. See
    /// [`ExtensionHost::restart`] and [`ExtensionHost::disable`].
    Failed,
    /// The extension was disabled after a failure. It stays disabled.
    Disabled,
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
    /// Why the extension is `Rejected` or `Failed`.
    pub reason: Option<String>,
}

/// One entry of [`ExtensionHost::extensions`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionStatus {
    /// The extension.
    pub id: ExtensionId,
    /// The state.
    pub state: ExtensionState,
    /// Why the extension is `Rejected` or `Failed`.
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
        (Active, Lifecycle::Fail) => Some(Failed),
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
}

impl Entry {
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
/// the call is an `internal` error and not a panic of the host (§5.6).
async fn contained<T: Send + 'static>(
    id: &ExtensionId,
    what: &str,
    call: impl Future<Output = Result<T>> + Send + 'static,
) -> Result<T> {
    tokio::spawn(call).await.unwrap_or_else(|error| {
        Err(Error::internal(format!("extension `{id}` panicked in `{what}`")).with_source(error))
    })
}

fn unknown(id: &ExtensionId) -> Error {
    Error::user(format!("extension `{id}` is not known to the host"))
}

struct Inner {
    entries: BTreeMap<ExtensionId, Entry>,
    invalid: Vec<(PathBuf, String)>,
    resolution: Resolution,
    index: ActivationIndex,
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
/// All methods take `&self`. Share the host in an [`Arc`].
pub struct ExtensionHost {
    runtime: Arc<dyn ExtensionRuntime>,
    services: Services,
    sdk_version: Version,
    directories: Vec<PathBuf>,
    headless: bool,
    /// Held for the whole of each lifecycle operation.
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
    pub fn new(
        runtime: Arc<dyn ExtensionRuntime>,
        services: Services,
        sdk_version: Version,
        directories: Vec<PathBuf>,
        headless: bool,
    ) -> Self {
        let resolution = Resolution::default();
        Self {
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
            }),
        }
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
        let _lifecycle = self.lifecycle.lock().await;
        let scan = self.scan().await?;
        let unloaded = {
            let mut inner = self.inner();
            inner.invalid = scan.invalid;
            self.reconcile(&mut inner, scan.packages)
        };
        drop(unloaded);
        Ok(())
    }

    /// Activates the extensions that `trigger` selects, each after its
    /// dependencies (§4.4). An extension is loaded on its first activation.
    ///
    /// A failing or panicking activation puts that extension in the state
    /// `Failed` and removes what it registered. The other extensions still
    /// activate, but not the dependents of the failed extension. The report
    /// gives the reason for each extension that did not activate.
    pub async fn trigger(&self, trigger: ActivationTrigger<'_>) -> ActivationReport {
        let _lifecycle = self.lifecycle.lock().await;
        let plan = self.inner().index.plan(trigger, self.headless);
        let mut report = ActivationReport {
            activated: Vec::new(),
            not_activated: plan.blocked,
        };
        self.activate_all(plan.activate, &mut report).await;
        report
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
    ///   The other extensions are deactivated nevertheless.
    pub async fn deactivate(&self, id: &ExtensionId) -> Result<()> {
        let _lifecycle = self.lifecycle.lock().await;
        self.deactivate_tree(id).await
    }

    /// Unloads the inactive extension `id`: drops its instance and removes
    /// it from the host. A later [`discover`](Self::discover) finds it
    /// again. Extensions that depend on it become `Rejected` until then.
    ///
    /// # Errors
    ///
    /// - A `user` error if the host does not know `id`.
    /// - A `policy` error if the extension is not `Inactive`.
    pub async fn unload(&self, id: &ExtensionId) -> Result<()> {
        let _lifecycle = self.lifecycle.lock().await;
        let unloaded = {
            let mut inner = self.inner();
            let entry = self.apply(&mut inner, id, Lifecycle::Unload, None)?;
            let packages = inner.unloaded_packages();
            (entry, self.reconcile(&mut inner, packages))
        };
        drop(unloaded);
        Ok(())
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
    /// - The error of its `deactivate` call. The extension is `Failed`.
    /// - A `user` error if the package is not on disk any more, or if the
    ///   new manifest is invalid or does not resolve.
    /// - The error of its `load` or `activate` call. The extension is
    ///   `Failed`.
    pub async fn reload(&self, id: &ExtensionId) -> Result<ActivationReport> {
        let _lifecycle = self.lifecycle.lock().await;
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
            (old, self.reconcile(&mut inner, packages))
        };
        drop(unloaded);

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

    /// Activates the failed extension `id` again. The host does not restart
    /// an extension automatically.
    ///
    /// # Errors
    ///
    /// - A `user` error if the host does not know `id`.
    /// - A `policy` error if the extension is not `Failed`, or if it has
    ///   `requires_ui = true` in a headless host.
    /// - An `internal` error if a dependency is not active.
    /// - The error of the `load` or `activate` call. The extension is
    ///   `Failed` again.
    pub async fn restart(&self, id: &ExtensionId) -> Result<()> {
        let _lifecycle = self.lifecycle.lock().await;
        self.activate_one(id, Lifecycle::Restart).await.map(drop)
    }

    /// Disables the failed extension `id`. A disabled extension does not
    /// activate again.
    ///
    /// # Errors
    ///
    /// - A `user` error if the host does not know `id`.
    /// - A `policy` error if the extension is not `Failed`.
    pub async fn disable(&self, id: &ExtensionId) -> Result<()> {
        let _lifecycle = self.lifecycle.lock().await;
        self.apply(&mut self.inner(), id, Lifecycle::Disable, None)
            .map(drop)
    }

    /// Deactivates all active extensions in reverse dependency order
    /// (§5.7). A failure does not stop the shutdown. Returns the extensions
    /// whose `deactivate` call failed, each with the error.
    pub async fn shutdown(&self) -> BTreeMap<ExtensionId, Error> {
        let _lifecycle = self.lifecycle.lock().await;
        let order: Vec<ExtensionId> = {
            let inner = self.inner();
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
    /// the entry if the change removed the extension. The caller drops it
    /// after it released the lock, because the drop runs extension code.
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
    /// removed, for the caller to drop after it released the lock.
    fn reconcile(
        &self,
        inner: &mut Inner,
        mut packages: BTreeMap<ExtensionId, Package>,
    ) -> Vec<Entry> {
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
                removed.extend(self.apply(inner, &id, event, None).ok().flatten());
            }
            let Some((package, rejected)) = wanted else {
                continue;
            };
            let entry = Entry {
                package,
                state: ExtensionState::Discovered,
                reason: None,
                instance: None,
            };
            inner.entries.insert(id.clone(), entry);
            self.publish(&id, None, Some(ExtensionState::Discovered), None);
            let event = match rejected {
                Some(_) => Lifecycle::Reject,
                None => Lifecycle::Resolve,
            };
            // `Discovered` permits both events.
            removed.extend(self.apply(inner, &id, event, rejected).ok().flatten());
        }
        inner.index = ActivationIndex::new(&resolution);
        inner.resolution = resolution;
        removed
    }

    /// Releases everything that `owner` registered (§5.2).
    fn release(&self, owner: &Owner) {
        self.services.registry.unregister_owner(owner);
        self.services.commands.unregister_owner(owner);
        self.services.jobs.cancel_owner(owner);
    }

    /// Puts the active extension `id` in the state `Failed` and unloads its
    /// instance.
    fn fail(&self, id: &ExtensionId, error: &Error) -> Result<()> {
        self.release(id);
        let instance = {
            let mut inner = self.inner();
            let reason = Some(error.message().to_owned());
            self.apply(&mut inner, id, Lifecycle::Fail, reason)?;
            let entry = inner.entries.get_mut(id);
            entry.and_then(|entry| entry.instance.take())
        };
        drop(instance);
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
    // shortcut: if the caller drops the future during the call into the
    // extension, that call still completes but the state does not change;
    // run the operation in its own task when a caller needs to cancel it.
    async fn activate_one(&self, id: &ExtensionId, event: Lifecycle) -> Result<bool> {
        let (instance, manifest, directory) = {
            let inner = self.inner();
            let entry = inner.entries.get(id).ok_or_else(|| unknown(id))?;
            if entry.state == ExtensionState::Active && event == Lifecycle::Activate {
                return Ok(false);
            }
            let refuse = |reason: &str| format!("extension `{id}` cannot activate: {reason}");
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
            if let Some(dependency) = manifest.dependencies.keys().find(inactive) {
                let reason = format!("its dependency `{dependency}` is not active");
                return Err(Error::internal(refuse(&reason)));
            }
            let directory = entry.package.directory.clone();
            (entry.instance.clone(), manifest, directory)
        };

        let result = async {
            let instance = match instance {
                Some(instance) => instance,
                None => {
                    let runtime = Arc::clone(&self.runtime);
                    let load = async move { runtime.load(&manifest, &directory).await };
                    let instance: Arc<dyn ExtensionInstance> =
                        contained(id, "load", load).await?.into();
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
            contained(id, "activate", activate).await
        }
        .await;

        self.apply(&mut self.inner(), id, event, None)?;
        match result {
            Ok(()) => Ok(true),
            Err(error) => {
                self.fail(id, &error)?;
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
                contained(id, "deactivate", deactivate).await
            }
            None => Ok(()),
        };
        match result {
            Ok(()) => {
                self.release(id);
                self.apply(&mut self.inner(), id, Lifecycle::Deactivate, None)
                    .map(drop)
            }
            Err(error) => {
                self.fail(id, &error)?;
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
    }

    /// The record of the fake runtime: what the host called, and what must
    /// fail.
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<String>>,
        modes: Mutex<BTreeMap<String, Mode>>,
        jobs: Mutex<BTreeMap<String, JobHandle<()>>>,
    }

    impl Fake {
        fn log(&self, call: &str) {
            self.calls.lock().unwrap().push(call.to_owned());
        }

        /// Records `call`, then fails or panics if the test asked for it.
        fn call(&self, call: &str) -> Result<()> {
            self.log(call);
            let mode = self.modes.lock().unwrap().get(call).copied();
            match mode {
                None => Ok(()),
                Some(Mode::Fail) => Err(Error::connectivity(format!("{call} failed"))),
                Some(Mode::Panic) => panic!("{call} panicked"),
            }
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
                    .call(&format!("load {}@{}", manifest.id, manifest.version))?;
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
                let job = services
                    .jobs
                    .spawn(owner.clone(), "work", |job| async move {
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
                self.fake.call(&format!("activate {owner}"))
            })
        }

        fn deactivate(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async move { self.fake.call(&format!("deactivate {}", self.id)) })
        }
    }

    impl Drop for FakeInstance {
        fn drop(&mut self) {
            self.fake.log(&format!("unload {}", self.id));
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
        roots: [TempDir; 3],
    }

    fn fixture(headless: bool) -> Fixture {
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
        );
        Fixture {
            fake,
            events: services.events.subscribe(),
            services,
            host: Arc::new(host),
            roots,
        }
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
            let name = |state: Option<ExtensionState>| {
                state.map_or("none".to_owned(), |state| format!("{state:?}"))
            };
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
                    Some(Received::Event(event)) => {
                        let (from, to) = (name(event.from), name(event.to));
                        changes.push(format!("{}: {from} -> {to}", event.id));
                    }
                    other => panic!("unexpected {other:?}"),
                }
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
            assert_eq!(
                f.changes().await,
                ["a: Resolved -> Active", "a: Active -> Failed"]
            );
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
}
