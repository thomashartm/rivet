//! TLS against the `mysql-tls` container, which refuses plaintext: the
//! whole conformance suite (with `cancels`, so the `KILL QUERY` connection
//! uses TLS too), and a wrong CA and a wrong host name are refused. The
//! user `rivet_cert` logs in only with the right client certificate.
//! Skipped (and says so) unless `RIVET_TEST_CONTAINERS=1`.

use std::future::poll_fn;
use std::pin::Pin;

use futures_util::Stream;
use rivet_ext_mysql::MysqlDriver;
use rivet_sdk::error::{Error, ErrorCategory};
use rivet_sdk::extension::{ConnectRequest, Credential, Credentials, Driver};
use rivet_sdk::model::TlsSettings;
use rivet_sdk::secret::Secret;
use rivet_testkit::conformance::{self, Sql};
use rivet_testkit::database::{self, DatabaseFixture};

async fn connect_error(fixture: &DatabaseFixture) -> Error {
    let credential = Credential::Password(Secret::from(fixture.password.expose().to_owned()));
    let credentials = Credentials::new(credential).with_user(fixture.user.clone());
    let request = ConnectRequest::new(fixture.profile.clone(), credentials);
    MysqlDriver.connect(request).await.err().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn conformance_suite_passes_over_tls() {
    if !database::containers_enabled() {
        return;
    }
    let fixture = database::mysql_tls();
    fixture.ensure_reachable().await.unwrap();
    conformance::run_all(&MysqlDriver, &fixture, &Sql::mysql())
        .await
        .unwrap();
}

/// The server refuses plaintext: a passing suite above was TLS.
#[tokio::test(flavor = "multi_thread")]
async fn server_refuses_plaintext() {
    if !database::containers_enabled() {
        return;
    }
    let mut fixture = database::mysql_tls();
    fixture.profile.tls = TlsSettings::new().with_enabled(false);
    let error = connect_error(&fixture).await;
    assert!(error.message().contains("secure transport"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_ca_is_refused() {
    if !database::containers_enabled() {
        return;
    }
    let mut fixture = database::mysql_tls();
    let other = database::test_certs_dir().join("other-ca.pem");
    fixture.profile.tls = TlsSettings::new().with_ca_certificate(other);
    let error = connect_error(&fixture).await;
    assert_eq!(error.category(), ErrorCategory::Connectivity, "{error}");
    assert!(error.message().contains("UnknownIssuer"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_host_name_is_refused() {
    if !database::containers_enabled() {
        return;
    }
    // The certificate names `localhost`, not the address.
    let mut fixture = database::mysql_tls();
    fixture.profile.endpoint.host = "127.0.0.1".to_owned();
    let error = connect_error(&fixture).await;
    assert_eq!(error.category(), ErrorCategory::Connectivity, "{error}");
    assert!(error.message().contains("not valid for name"), "{error}");
}

/// `rivet_cert` is `REQUIRE SUBJECT '/CN=rivet_cert'`: the login works with
/// the client certificate. The suite's `cancels` step needs the `KILL QUERY`
/// connection, which logs in with the same certificate.
#[tokio::test(flavor = "multi_thread")]
async fn client_certificate_logs_in_and_cancels() {
    if !database::containers_enabled() {
        return;
    }
    let request = ConnectRequest::new(
        database::mysql_tls().profile,
        database::client_certificate("client"),
    );
    let connection = std::sync::Arc::new(MysqlDriver.connect(request).await.unwrap());
    let mut result = connection
        .execute("select current_user()".to_owned())
        .await
        .unwrap();
    let batch = poll_fn(|cx| Pin::new(&mut result).poll_next(cx))
        .await
        .unwrap()
        .unwrap();
    drop(result);
    let user = batch
        .column(0)
        .as_any()
        .downcast_ref::<arrow_array::StringArray>()
        .unwrap()
        .value(0)
        .to_owned();
    assert_eq!(user, "rivet_cert@%");

    let running = tokio::spawn({
        let connection = std::sync::Arc::clone(&connection);
        async move {
            let mut result = connection.execute(Sql::mysql().slow).await?;
            poll_fn(|cx| Pin::new(&mut result).poll_next(cx))
                .await
                .transpose()
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    connection.cancel().await.unwrap();
    let error = running.await.unwrap().err().unwrap();
    assert_eq!(error.category(), ErrorCategory::Cancelled, "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn cert_user_without_a_certificate_is_refused() {
    if !database::containers_enabled() {
        return;
    }
    let credentials = Credentials::new(Credential::Password(Secret::from(String::new())))
        .with_user(database::CERT_USER);
    let request = ConnectRequest::new(database::mysql_tls().profile, credentials);
    let error = MysqlDriver.connect(request).await.err().unwrap();
    assert_eq!(error.category(), ErrorCategory::Auth, "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn client_certificate_of_another_ca_is_refused() {
    if !database::containers_enabled() {
        return;
    }
    let request = ConnectRequest::new(
        database::mysql_tls().profile,
        database::client_certificate("other-client"),
    );
    let error = MysqlDriver.connect(request).await.err().unwrap();
    // The server sends the TLS alert `unknown_ca`.
    assert_eq!(error.category(), ErrorCategory::Connectivity, "{error}");
    assert!(error.message().contains("UnknownCA"), "{error}");
}
