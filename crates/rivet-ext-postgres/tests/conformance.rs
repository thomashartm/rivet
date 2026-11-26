//! The conformance suite of `rivet-testkit` against the PostgreSQL container.
//! Skipped (and says so) unless `RIVET_TEST_CONTAINERS=1`.

use rivet_ext_postgres::PostgresDriver;
use rivet_testkit::conformance::{self, Sql};
use rivet_testkit::database;

#[tokio::test(flavor = "multi_thread")]
async fn postgres_driver_passes_the_conformance_suite() {
    if !database::containers_enabled() {
        return;
    }
    let fixture = database::postgres();
    fixture.ensure_reachable().await.unwrap();
    conformance::run_all(&PostgresDriver, &fixture, &Sql::postgres())
        .await
        .unwrap();
}

/// A role default of `bytea_output = escape` must not break `bytea`: the
/// driver asks for the hex format at login. The role default is removed at
/// the end, also if the checks fail.
#[tokio::test(flavor = "multi_thread")]
async fn bytea_reads_with_a_role_default_of_escape() {
    use std::future::poll_fn;
    use std::pin::Pin;

    use arrow_array::{Array, BinaryArray, RecordBatch, StringArray};
    use futures_core::Stream;
    use rivet_sdk::extension::{ConnectRequest, Connection, Credential, Credentials, Driver};
    use rivet_sdk::secret::Secret;

    if !database::containers_enabled() {
        return;
    }
    let fixture = database::postgres();
    fixture.ensure_reachable().await.unwrap();
    async fn connect(fixture: &database::DatabaseFixture) -> Box<dyn Connection> {
        let credential = Credential::Password(Secret::from(fixture.password.expose().to_owned()));
        let credentials = Credentials::new(credential).with_user(fixture.user.clone());
        PostgresDriver
            .connect(ConnectRequest::new(fixture.profile.clone(), credentials))
            .await
            .unwrap()
    }
    async fn batch(connection: &dyn Connection, sql: &str) -> Option<RecordBatch> {
        let mut result = connection.execute(sql.to_owned()).await.unwrap();
        let batch = poll_fn(|cx| Pin::new(&mut result).poll_next(cx)).await;
        batch.map(Result::unwrap)
    }
    let role = format!("\"{}\"", fixture.user.replace('"', "\"\""));
    let fixture = std::sync::Arc::new(fixture);
    let admin = connect(&fixture).await;
    batch(
        &*admin,
        &format!("alter role {role} set bytea_output = 'escape'"),
    )
    .await;
    let checked = tokio::spawn({
        let fixture = std::sync::Arc::clone(&fixture);
        async move {
            let connection = connect(&fixture).await;
            batch(
                &*connection,
                "select current_setting('bytea_output'), '\\x0001ff'::bytea",
            )
            .await
        }
    })
    .await;
    batch(&*admin, &format!("alter role {role} reset bytea_output")).await;
    let checked = checked.unwrap().unwrap();
    let setting = checked
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(setting.value(0), "hex");
    let bytes = checked
        .column(1)
        .as_any()
        .downcast_ref::<BinaryArray>()
        .unwrap();
    assert_eq!(bytes.value(0), [0u8, 1, 255]);
}

/// A statement without result columns waits inside `execute` for its end.
/// `cancel` stops that wait with `cancelled`, and a dropped `execute` future
/// stops the statement too. Each time the connection runs the next statement.
#[tokio::test(flavor = "multi_thread")]
async fn wait_for_a_statement_without_columns_stays_cancellable() {
    use std::time::Duration;

    use rivet_sdk::error::ErrorCategory;
    use rivet_sdk::extension::{ConnectRequest, Connection, Credential, Credentials, Driver};
    use rivet_sdk::secret::Secret;

    const SLOW: &str = "do $$ begin perform pg_sleep(30); end $$";
    const LIMIT: Duration = Duration::from_secs(10);
    if !database::containers_enabled() {
        return;
    }
    let fixture = database::postgres();
    fixture.ensure_reachable().await.unwrap();
    let credential = Credential::Password(Secret::from(fixture.password.expose().to_owned()));
    let credentials = Credentials::new(credential).with_user(fixture.user.clone());
    let connection = PostgresDriver
        .connect(ConnectRequest::new(fixture.profile.clone(), credentials))
        .await
        .unwrap();
    async fn ping(connection: &dyn Connection) {
        let result = tokio::time::timeout(LIMIT, connection.execute("select 1".to_owned()));
        assert!(result.await.unwrap().unwrap().rows_affected().is_none());
    }

    let cancel = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        connection.cancel().await.unwrap();
    };
    let both = async { tokio::join!(connection.execute(SLOW.to_owned()), cancel) };
    let (outcome, ()) = tokio::time::timeout(LIMIT, both).await.unwrap();
    assert_eq!(outcome.unwrap_err().category(), ErrorCategory::Cancelled);
    ping(&*connection).await;

    // The future is dropped after 300 ms: the cancel request goes in the background.
    let dropped = tokio::time::timeout(
        Duration::from_millis(300),
        connection.execute(SLOW.to_owned()),
    );
    assert!(dropped.await.is_err());
    ping(&*connection).await;
}
