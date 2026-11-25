//! The mock engine: real services, real host, recorded calls and events.

use rivet_sdk::error::{Error, ErrorCategory, Result};
use rivet_sdk::manifest::{ExtensionId, Version, VersionReq};
use rivet_testkit::ExtensionState::{self, Active, Failed, Inactive, Rejected, Resolved};
use rivet_testkit::{
    ActivationTrigger, Behaviour, ExtensionStateChanged, JobContext, MANIFEST_FILE, Received,
    TestEngine, manifest,
};
use std::sync::Arc;
use std::time::Duration;

fn state(engine: &TestEngine, id: &ExtensionId) -> Option<ExtensionState> {
    let mut all = engine.host().extensions().into_iter();
    all.find(|status| &status.id == id)
        .map(|status| status.state)
}

/// The state changes since the last call, as `id: from -> to`.
fn changes(engine: &TestEngine) -> Vec<String> {
    let name = |state: Option<ExtensionState>| {
        state.map_or("none".to_owned(), |state| format!("{state:?}"))
    };
    let changes = engine.take_state_changes().unwrap();
    let text = |change: ExtensionStateChanged| {
        format!(
            "{}: {} -> {}",
            change.id,
            name(change.from),
            name(change.to)
        )
    };
    changes.into_iter().map(text).collect()
}

#[tokio::test]
async fn one_call_builds_the_real_services_and_a_host_in_a_temporary_directory() -> Result<()> {
    let engine = TestEngine::new()?;
    let owner: ExtensionId = "acme.test".parse()?;
    let services = engine.services();

    let version = Version::new(1, 0, 0);
    let service: Arc<str> = Arc::from("service");
    services
        .registry
        .register(owner.clone(), "acme.service", version, service)?;
    let found: Arc<str> = services
        .registry
        .lookup("acme.service", &VersionReq::STAR)?;
    assert_eq!(&*found, "service");

    let double = |number: u32| async move { Ok(number * 2) };
    services
        .commands
        .register(owner.clone(), "acme.double", double)?;
    assert_eq!(
        services
            .commands
            .execute::<_, u32>("acme.double", 21u32)
            .await?,
        42
    );

    let mut subscription = services.events.subscribe::<u8>();
    assert_eq!(services.events.publish(7u8), 1);
    assert_eq!(subscription.recv().await, Some(Received::Event(7)));

    let job = services.jobs.spawn(owner, "work", |_job| async { Ok(5) })?;
    assert_eq!(job.join().await?, 5);

    assert!(engine.directory().is_dir());
    engine.host().discover().await?;
    assert!(engine.host().extensions().is_empty());

    let directory = engine.directory().to_owned();
    drop(engine);
    assert!(!directory.exists(), "the temporary directory is deleted");
    Ok(())
}

#[tokio::test]
async fn lifecycle_discover_trigger_deactivate_reload_shutdown_is_recorded() -> Result<()> {
    let engine = TestEngine::new()?;
    let host = engine.host();
    let base = engine.add_extension(&manifest("acme.base", "1.0.0", &[]), Behaviour::new())?;
    let app = engine.add_extension(
        &manifest("acme.app", "1.0.0", &["acme.base"]),
        Behaviour::new(),
    )?;
    assert!(
        engine
            .directory()
            .join("acme.app")
            .join(MANIFEST_FILE)
            .is_file()
    );

    // Discover: the real resolver runs. Nothing is loaded.
    host.discover().await?;
    assert_eq!(state(&engine, &app), Some(Resolved));
    assert_eq!(engine.take_calls(), Vec::<String>::new());
    assert_eq!(
        changes(&engine),
        [
            "acme.app: none -> Discovered",
            "acme.app: Discovered -> Resolved",
            "acme.base: none -> Discovered",
            "acme.base: Discovered -> Resolved",
        ]
    );

    // Trigger: the dependency activates first.
    let report = host.trigger(ActivationTrigger::Command("acme.app")).await;
    assert_eq!(report.activated, [base.clone(), app.clone()]);
    assert_eq!(
        engine.take_calls(),
        [
            "load acme.base@1.0.0",
            "activate acme.base",
            "load acme.app@1.0.0",
            "activate acme.app",
        ]
    );
    assert_eq!(
        changes(&engine),
        [
            "acme.base: Resolved -> Active",
            "acme.app: Resolved -> Active"
        ]
    );

    // Deactivate.
    host.deactivate(&app).await?;
    assert_eq!(state(&engine, &app), Some(Inactive));
    assert_eq!(engine.take_calls(), ["deactivate acme.app"]);
    assert_eq!(changes(&engine), ["acme.app: Active -> Inactive"]);

    // Reload: a new manifest and a new behaviour replace the old ones.
    let reloaded = Behaviour::new().on_activate(|context| async move {
        let handler = |(): ()| async { Ok("version 2") };
        let commands = &context.services.commands;
        commands.register(context.owner, "acme.base.version", handler)
    });
    engine.add_extension(&manifest("acme.base", "2.0.0", &[]), reloaded)?;
    host.trigger(ActivationTrigger::Command("acme.app")).await;
    engine.take_calls();
    let report = host.reload(&base).await?;
    assert_eq!(report.activated, [base.clone(), app.clone()]);
    assert_eq!(
        engine.take_calls(),
        [
            "deactivate acme.app",
            "deactivate acme.base",
            "unload acme.base",
            "load acme.base@2.0.0",
            "activate acme.base",
            "activate acme.app",
        ]
    );
    let commands = &engine.services().commands;
    let version: &str = commands.execute("acme.base.version", ()).await?;
    assert_eq!(version, "version 2");

    // Shutdown: reverse dependency order.
    engine.take_state_changes()?;
    assert!(host.shutdown().await.is_empty());
    assert_eq!(
        engine.take_calls(),
        ["deactivate acme.app", "deactivate acme.base"]
    );
    assert_eq!(
        changes(&engine),
        [
            "acme.app: Active -> Inactive",
            "acme.base: Active -> Inactive"
        ]
    );
    // The records were taken: they are empty now.
    assert!(engine.take_calls().is_empty());
    assert!(engine.take_state_changes()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn raw_manifest_text_and_deactivate_behaviour_are_used() -> Result<()> {
    let engine = TestEngine::new()?;
    let text = "id = \"acme.driver\"\nversion = \"0.3.0\"\nsdk = \"^0.1\"\n\n\
                [[activation]]\non = \"connection\"\ntype = \"postgres\"\n";
    let behaviour = Behaviour::new()
        .on_deactivate(|| async { Err(Error::connectivity("the pool did not close")) });
    let id = engine.add_extension(text, behaviour)?;
    let host = engine.host();

    host.discover().await?;
    let report = host
        .trigger(ActivationTrigger::Connection("postgres"))
        .await;
    assert_eq!(report.activated, std::slice::from_ref(&id));

    // The failure of the test code arrives unchanged, in the SDK error model.
    let error = host.deactivate(&id).await.unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Connectivity);
    assert_eq!(error.message(), "the pool did not close");
    assert_eq!(state(&engine, &id), Some(Failed));
    Ok(())
}

#[tokio::test]
async fn failing_activation_is_recorded_as_calls_and_events() -> Result<()> {
    let engine = TestEngine::new()?;
    let behaviour = Behaviour::new().on_activate(|_context| async { Err(Error::auth("no token")) });
    let id = engine.add_extension(&manifest("acme.auth", "1.0.0", &[]), behaviour)?;
    engine.host().discover().await?;
    engine.take_state_changes()?;

    let trigger = ActivationTrigger::Command("acme.auth");
    let report = engine.host().trigger(trigger).await;
    assert_eq!(report.not_activated[&id].category(), ErrorCategory::Auth);
    assert_eq!(
        engine.take_calls(),
        [
            "load acme.auth@1.0.0",
            "activate acme.auth",
            "unload acme.auth"
        ]
    );
    let changes = engine.take_state_changes()?;
    let last = changes.last().unwrap();
    assert_eq!((last.to, last.id.clone()), (Some(Failed), id));
    assert!(last.reason.as_deref().unwrap().contains("no token"));
    Ok(())
}

#[tokio::test]
async fn invalid_manifest_is_a_user_error_and_writes_nothing() -> Result<()> {
    let engine = TestEngine::new()?;
    let error = engine
        .add_extension("id = \"Not Valid\"", Behaviour::new())
        .unwrap_err();
    assert_eq!(error.category(), ErrorCategory::User);
    assert_eq!(std::fs::read_dir(engine.directory()).unwrap().count(), 0);
    Ok(())
}

#[tokio::test]
async fn extension_without_behaviour_fails_with_an_internal_error() -> Result<()> {
    let engine = TestEngine::new()?;
    // Written by hand, not with `add_extension`.
    let folder = engine.directory().join("acme.manual");
    std::fs::create_dir(&folder).unwrap();
    let text = manifest("acme.manual", "1.0.0", &[]);
    std::fs::write(folder.join(MANIFEST_FILE), text).unwrap();
    let id: ExtensionId = "acme.manual".parse()?;

    engine.host().discover().await?;
    let trigger = ActivationTrigger::Command("acme.manual");
    let report = engine.host().trigger(trigger).await;
    let error = &report.not_activated[&id];
    assert_eq!(error.category(), ErrorCategory::Internal);
    assert!(error.message().contains("TestEngine::add_extension"));
    Ok(())
}

#[tokio::test]
async fn dependency_that_is_missing_rejects_the_extension() -> Result<()> {
    let engine = TestEngine::new()?;
    let manifest = manifest("acme.app", "1.0.0", &["acme.absent"]);
    let id = engine.add_extension(&manifest, Behaviour::new())?;
    engine.host().discover().await?;
    assert_eq!(state(&engine, &id), Some(Rejected));
    assert_eq!(state(&engine, &id).filter(|state| *state == Active), None);
    Ok(())
}

/// R-38 (c): a test that fails early drops the engine without `shutdown`.
#[tokio::test]
async fn dropping_the_engine_cancels_the_jobs_of_its_extensions() -> Result<()> {
    let engine = TestEngine::new()?;
    let behaviour = Behaviour::new().on_activate(|context| async move {
        let until_cancelled = |job: JobContext| async move {
            job.cancelled().await;
            Ok(())
        };
        let jobs = &context.services.jobs;
        jobs.spawn(context.owner, "acme.poll", until_cancelled)?;
        Ok(())
    });
    engine.add_extension(&manifest("acme.poller", "1.0.0", &[]), behaviour)?;
    engine.host().discover().await?;
    let trigger = ActivationTrigger::Command("acme.poller");
    assert_eq!(engine.host().trigger(trigger).await.activated.len(), 1);
    let jobs = engine.services().jobs.clone();

    drop(engine);

    let finished = async {
        while jobs.jobs().iter().any(|job| !job.state.is_finished()) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    let finished = tokio::time::timeout(Duration::from_secs(5), finished).await;
    assert!(finished.is_ok(), "jobs still run: {:?}", jobs.jobs());
    Ok(())
}
