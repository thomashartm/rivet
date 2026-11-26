//! TLS against the `mysql-tls` container, which refuses plaintext: the
//! whole conformance suite (with `cancels`, so the `KILL QUERY` connection
//! uses TLS too), and a wrong CA and a wrong host name are refused.
//! Skipped (and says so) unless `RIVET_TEST_CONTAINERS=1`.

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
