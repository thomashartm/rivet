//! The driver conformance suite of `rivet-testkit` against the MySQL
//! container, and MySQL-only cases. Skipped, with a message, unless
//! `RIVET_TEST_CONTAINERS=1`.

use std::time::Duration;

use rivet_ext_mysql::MysqlDriver;
use rivet_sdk::error::ErrorCategory;
use rivet_sdk::extension::{ConnectRequest, Credential, Credentials, Driver};
use rivet_sdk::secret::Secret;
use rivet_testkit::conformance::{self, Sql};
use rivet_testkit::database;

#[tokio::test(flavor = "multi_thread")]
async fn mysql_driver_passes_the_conformance_suite() {
    if !database::containers_enabled() {
        return;
    }
    let fixture = database::mysql();
    fixture.ensure_reachable().await.unwrap();
    conformance::run_all(&MysqlDriver, &fixture, &Sql::mysql())
        .await
        .unwrap();
}

/// An `execute` future dropped before the answer: the next statement must
/// not read that answer. The connection is closed instead.
#[tokio::test(flavor = "multi_thread")]
async fn dropped_execute_closes_the_connection() {
    if !database::containers_enabled() {
        return;
    }
    let fixture = database::mysql();
    let password = Credential::Password(Secret::from(fixture.password.expose().to_owned()));
    let credentials = Credentials::new(password).with_user(fixture.user.clone());
    let request = ConnectRequest::new(fixture.profile.clone(), credentials);
    let connection = MysqlDriver.connect(request).await.unwrap();

    let slow = connection.execute(Sql::mysql().slow);
    let dropped = tokio::time::timeout(Duration::from_millis(300), slow).await;
    assert!(dropped.is_err(), "the slow statement must still run");

    let error = connection.execute("select 1".to_owned()).await.unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Connectivity, "{error:?}");
}

/// Two statements in one call are refused and the second never runs.
#[tokio::test(flavor = "multi_thread")]
async fn second_statement_in_one_call_is_refused() {
    if !database::containers_enabled() {
        return;
    }
    let fixture = database::mysql();
    let password = Credential::Password(Secret::from(fixture.password.expose().to_owned()));
    let credentials = Credentials::new(password).with_user(fixture.user.clone());
    let request = ConnectRequest::new(fixture.profile.clone(), credentials);
    let connection = MysqlDriver.connect(request).await.unwrap();

    let table = "rivet_multi_statement_probe";
    connection
        .execute(format!("drop table if exists {table}"))
        .await
        .unwrap();
    let error = connection
        .execute(format!("create table {table} (a int); select 2"))
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(error.category(), ErrorCategory::User, "{error:?}");
    // A `;` inside a string is one statement, and the connection still works.
    connection.execute("select 'a;b'".to_owned()).await.unwrap();
    let probe = connection
        .execute(format!("select * from {table}"))
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(probe.category(), ErrorCategory::User, "{probe:?}");
}
