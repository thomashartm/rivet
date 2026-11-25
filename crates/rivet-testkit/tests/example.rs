use rivet_sdk::error::Result;
use rivet_testkit::ExtensionState::{Active, Discovered, Inactive, Resolved};
use rivet_testkit::{ActivationTrigger, Behaviour, TestEngine, manifest};

#[tokio::test]
async fn greeter_registers_its_command_and_releases_it() -> Result<()> {
    let engine = TestEngine::new()?;
    let greeter = Behaviour::new().on_activate(|context| async move {
        let greet = |name: String| async move { Ok(format!("hello {name}")) };
        let commands = &context.services.commands;
        commands.register(context.owner, "acme.greet", greet)
    });
    let id = engine.add_extension(&manifest("acme.greeter", "1.0.0", &[]), greeter)?;
    let host = engine.host();
    let commands = &engine.services().commands;

    // `manifest` activates the extension on the command with the name of its id.
    host.discover().await?;
    let report = host
        .trigger(ActivationTrigger::Command("acme.greeter"))
        .await;
    assert_eq!(report.activated, std::slice::from_ref(&id));
    let greeting: String = commands.execute("acme.greet", "Ada".to_owned()).await?;
    assert_eq!(greeting, "hello Ada");

    // The host removes the command when the extension deactivates.
    host.deactivate(&id).await?;
    let gone = commands.execute::<_, String>("acme.greet", "Ada".to_owned());
    assert!(gone.await.is_err());

    let calls = [
        "load acme.greeter@1.0.0",
        "activate acme.greeter",
        "deactivate acme.greeter",
    ];
    assert_eq!(engine.take_calls(), calls);
    let states: Vec<_> = engine.take_state_changes()?;
    let states: Vec<_> = states.into_iter().filter_map(|change| change.to).collect();
    assert_eq!(states, [Discovered, Resolved, Active, Inactive]);
    Ok(())
}
