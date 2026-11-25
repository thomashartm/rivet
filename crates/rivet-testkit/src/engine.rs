//! The mock engine: the real core services and the real extension host, with
//! extensions that are Rust test code.

use rivet_core::bus::{CommandBus, EventBus, Received, Subscription};
use rivet_core::host::{
    ExtensionContext, ExtensionHost, ExtensionInstance, ExtensionRuntime, ExtensionStateChanged,
    HostConfig, MANIFEST_FILE, Services,
};
use rivet_core::jobs::JobScheduler;
use rivet_core::registry::ServiceRegistry;
use rivet_core::secrets::SecretStore;
use rivet_sdk::error::{Error, Result};
use rivet_sdk::extension::BoxFuture;
use rivet_sdk::manifest::{ExtensionId, Manifest, Version};
use std::collections::BTreeMap;
use std::future::Future;
use std::num::{NonZeroU16, NonZeroUsize};
use std::path::Path;
use std::pin::pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use tempfile::TempDir;

type Activate = dyn Fn(ExtensionContext) -> BoxFuture<'static, Result<()>> + Send + Sync;
type Deactivate = dyn Fn() -> BoxFuture<'static, Result<()>> + Send + Sync;

/// What a test extension does when the host activates and deactivates it.
///
/// Without a closure, the call does nothing and succeeds. The closures run
/// again after each load, for example after a reload.
///
/// ```
/// use rivet_testkit::Behaviour;
///
/// let behaviour = Behaviour::new()
///     .on_activate(|context| async move {
///         let greet = |name: String| async move { Ok(format!("hello {name}")) };
///         context.services.commands.register(context.owner, "acme.greet", greet)
///     })
///     .on_deactivate(|| async { Ok(()) });
/// # drop(behaviour);
/// ```
#[derive(Default)]
pub struct Behaviour {
    activate: Option<Box<Activate>>,
    deactivate: Option<Box<Deactivate>>,
}

impl Behaviour {
    /// Creates a behaviour that does nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets what the extension does when it activates. The closure gets the
    /// real [`ExtensionContext`]: it registers services, command handlers
    /// and jobs with `context.owner` as the owner.
    #[must_use]
    pub fn on_activate<F, Fut>(mut self, activate: F) -> Self
    where
        F: Fn(ExtensionContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        self.activate = Some(Box::new(move |context| Box::pin(activate(context))));
        self
    }

    /// Sets what the extension does when it deactivates.
    #[must_use]
    pub fn on_deactivate<F, Fut>(mut self, deactivate: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        self.deactivate = Some(Box::new(move || Box::pin(deactivate())));
        self
    }
}

/// Returns the text of a minimal valid `extension.toml`.
///
/// - The SDK range accepts the SDK version of the [`TestEngine`].
/// - Each dependency accepts every version.
/// - The extension activates on the command that has the name `id`:
///   `ActivationTrigger::Command(id)`.
///
/// The function does not validate its input. [`TestEngine::add_extension`]
/// does.
pub fn manifest(id: &str, version: &str, dependencies: &[&str]) -> String {
    let dependencies: String = dependencies
        .iter()
        .map(|dependency| format!("\"{dependency}\" = \"*\"\n"))
        .collect();
    format!(
        "id = \"{id}\"\nversion = \"{version}\"\nsdk = \"={SDK_VERSION}\"\n\n\
         [dependencies]\n{dependencies}\n\
         [[activation]]\non = \"command\"\ncommand = \"{id}\"\n"
    )
}

/// The SDK version of the test engine. All workspace crates have one version.
const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// What the test runtime shares with its instances.
#[derive(Default)]
struct Shared {
    behaviours: Mutex<BTreeMap<ExtensionId, Arc<Behaviour>>>,
    calls: Mutex<Vec<String>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shared {
    fn record(&self, call: String) {
        lock(&self.calls).push(call);
    }
}

/// The in-process runtime: an instance runs the [`Behaviour`] of its id.
struct TestRuntime(Arc<Shared>);

impl ExtensionRuntime for TestRuntime {
    fn load<'a>(
        &'a self,
        manifest: &'a Manifest,
        _directory: &'a Path,
    ) -> BoxFuture<'a, Result<Box<dyn ExtensionInstance>>> {
        Box::pin(async move {
            let id = manifest.id.clone();
            self.0.record(format!("load {id}@{}", manifest.version));
            let behaviour = lock(&self.0.behaviours).get(&id).cloned().ok_or_else(|| {
                Error::internal(format!(
                    "extension `{id}` has no behaviour: add it with `TestEngine::add_extension`"
                ))
            })?;
            let shared = Arc::clone(&self.0);
            let instance = TestInstance {
                id,
                behaviour,
                shared,
            };
            Ok(Box::new(instance) as Box<dyn ExtensionInstance>)
        })
    }
}

struct TestInstance {
    id: ExtensionId,
    behaviour: Arc<Behaviour>,
    shared: Arc<Shared>,
}

impl ExtensionInstance for TestInstance {
    fn activate(&self, context: ExtensionContext) -> BoxFuture<'_, Result<()>> {
        self.shared.record(format!("activate {}", self.id));
        match &self.behaviour.activate {
            Some(activate) => activate(context),
            None => Box::pin(async { Ok(()) }),
        }
    }

    fn deactivate(&self) -> BoxFuture<'_, Result<()>> {
        self.shared.record(format!("deactivate {}", self.id));
        match &self.behaviour.deactivate {
            Some(deactivate) => deactivate(),
            None => Box::pin(async { Ok(()) }),
        }
    }
}

impl Drop for TestInstance {
    fn drop(&mut self) {
        self.shared.record(format!("unload {}", self.id));
    }
}

/// A test engine: the real core services and the real extension host, in a
/// temporary directory. See the [crate documentation](crate) for a complete
/// test.
///
/// The engine has no logic of its own. A test drives the lifecycle through
/// [`host`](Self::host) and uses the services through
/// [`services`](Self::services). The host is headless.
///
/// When the engine is dropped, it asks every job that is not finished to
/// stop, and the temporary directory is deleted. The drop does not wait for
/// the jobs and does not call `deactivate`: call `host().shutdown().await`
/// for that.
pub struct TestEngine {
    host: Arc<ExtensionHost>,
    services: Services,
    shared: Arc<Shared>,
    events: Mutex<Subscription<ExtensionStateChanged>>,
    directory: TempDir,
}

impl TestEngine {
    /// Builds the engine: service registry, command bus, event bus, job
    /// scheduler and an extension host that discovers extensions in a new
    /// temporary directory.
    ///
    /// # Errors
    ///
    /// Returns an `internal` error if the temporary directory cannot be
    /// created.
    pub fn new() -> Result<Self> {
        let directory = tempfile::tempdir().map_err(|error| {
            Error::internal("cannot create the temporary extension directory").with_source(error)
        })?;
        let services = Services {
            registry: Arc::new(ServiceRegistry::new()),
            commands: Arc::new(CommandBus::new()),
            events: Arc::new(EventBus::new(NonZeroU16::MAX)),
            jobs: JobScheduler::new(NonZeroUsize::MAX, 64),
        };
        let shared = Arc::new(Shared::default());
        // Subscribed before the host exists, so no state change is missed.
        let events = Mutex::new(services.events.subscribe());
        let sdk_version = SDK_VERSION.parse::<Version>().map_err(|error| {
            Error::internal("the crate version is not a semantic version").with_source(error)
        })?;
        let host = ExtensionHost::new(
            Arc::new(TestRuntime(Arc::clone(&shared))),
            services.clone(),
            Arc::new(SecretStore::new()),
            sdk_version,
            vec![directory.path().to_owned()],
            true,
            HostConfig::default(),
        );
        Ok(Self {
            host,
            services,
            shared,
            events,
            directory,
        })
    }

    /// Adds an extension: writes `manifest` as
    /// `<directory>/<id>/extension.toml` and keeps `behaviour` for the id.
    /// Returns the id.
    ///
    /// `manifest` is the text of an `extension.toml` file, for example from
    /// [`manifest`]. The host does not know the extension until the test
    /// calls `host().discover()`.
    ///
    /// A second call with the same id replaces the manifest and the
    /// behaviour. A loaded extension keeps its old manifest and behaviour
    /// until `host().reload(&id)`.
    ///
    /// # Errors
    ///
    /// - The `user` error of [`Manifest::parse`] if `manifest` is invalid.
    /// - An `internal` error if the file cannot be written.
    pub fn add_extension(&self, manifest: &str, behaviour: Behaviour) -> Result<ExtensionId> {
        let id = Manifest::parse(manifest)?.id;
        let folder = self.directory.path().join(id.as_str());
        std::fs::create_dir_all(&folder)
            .and_then(|()| std::fs::write(folder.join(MANIFEST_FILE), manifest))
            .map_err(|error| {
                let message = format!("cannot write the manifest of extension `{id}`");
                Error::internal(message).with_source(error)
            })?;
        lock(&self.shared.behaviours).insert(id.clone(), Arc::new(behaviour));
        Ok(id)
    }

    /// The real extension host. Drive the lifecycle with it: `discover`,
    /// `trigger`, `deactivate`, `unload`, `reload`, `restart`, `disable`,
    /// `shutdown`.
    pub fn host(&self) -> &Arc<ExtensionHost> {
        &self.host
    }

    /// The real core services: registry, command bus, event bus, jobs.
    pub fn services(&self) -> &Services {
        &self.services
    }

    /// The temporary discovery directory of the host.
    pub fn directory(&self) -> &Path {
        self.directory.path()
    }

    /// Returns the calls that the host made into the test runtime since the
    /// last call of this method, in order.
    ///
    /// | Entry | Meaning |
    /// | --- | --- |
    /// | `load <id>@<version>` | The host loaded the package. |
    /// | `activate <id>` | The host called `activate`. |
    /// | `deactivate <id>` | The host called `deactivate`. |
    /// | `unload <id>` | The host dropped the instance. |
    pub fn take_calls(&self) -> Vec<String> {
        std::mem::take(&mut lock(&self.shared.calls))
    }

    /// Returns the [`ExtensionStateChanged`] events that the host published
    /// since the last call of this method, in order.
    ///
    /// # Errors
    ///
    /// Returns an `internal` error if more events were published than the
    /// event bus buffers (65 535). Call the method more frequently.
    pub fn take_state_changes(&self) -> Result<Vec<ExtensionStateChanged>> {
        let mut events = lock(&self.events);
        let mut changes = Vec::new();
        // The host publishes synchronously, so each event is ready now. One
        // poll without a waker, and without the Tokio task budget, reads it.
        let mut context = Context::from_waker(Waker::noop());
        loop {
            let next = pin!(tokio::task::unconstrained(events.recv())).poll(&mut context);
            match next {
                Poll::Ready(Some(Received::Event(change))) => changes.push(change),
                Poll::Ready(Some(Received::Missed(missed))) => {
                    return Err(Error::internal(format!(
                        "the test engine missed {missed} state changes"
                    )));
                }
                Poll::Ready(None) | Poll::Pending => return Ok(changes),
            }
        }
    }
}

impl Drop for TestEngine {
    /// A test that fails early does not call `shutdown`. Its jobs must not
    /// continue after the temporary directory is deleted.
    fn drop(&mut self) {
        let jobs = &self.services.jobs;
        for job in jobs.jobs() {
            if !job.state.is_finished() {
                jobs.cancel_owner(&job.owner);
            }
        }
    }
}
