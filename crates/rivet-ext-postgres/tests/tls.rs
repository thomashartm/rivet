//! TLS against the `postgres-tls` container: the whole conformance suite
//! (with `cancels`, so the cancel request runs over TLS), the session is
//! really TLS, and a wrong CA and a wrong host name are refused. The user
//! `rivet_cert` logs in only with the right client certificate. Skipped
//! (and says so) unless `RIVET_TEST_CONTAINERS=1`.

use std::future::poll_fn;
use std::pin::Pin;

use arrow_array::{Array, BooleanArray};
use futures_core::Stream;
use rivet_ext_postgres::PostgresDriver;
use rivet_sdk::error::{ErrorCategory, Result};
use rivet_sdk::extension::{ConnectRequest, Connection, Credential, Credentials, Driver};
use rivet_sdk::model::TlsSettings;
use rivet_sdk::secret::Secret;
use rivet_testkit::conformance::{self, Sql};
use rivet_testkit::database::{self, DatabaseFixture};

async fn connect(fixture: &DatabaseFixture) -> Result<Box<dyn Connection>> {
    let credential = Credential::Password(Secret::from(fixture.password.expose().to_owned()));
    let credentials = Credentials::new(credential).with_user(fixture.user.clone());
    PostgresDriver
        .connect(ConnectRequest::new(fixture.profile.clone(), credentials))
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn conformance_suite_passes_over_tls() {
    if !database::containers_enabled() {
        return;
    }
    let fixture = database::postgres_tls();
    fixture.ensure_reachable().await.unwrap();
    conformance::run_all(&PostgresDriver, &fixture, &Sql::postgres())
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn session_is_tls() {
    if !database::containers_enabled() {
        return;
    }
    let connection = connect(&database::postgres_tls()).await.unwrap();
    let mut result = connection
        .execute("select ssl from pg_stat_ssl where pid = pg_backend_pid()".to_owned())
        .await
        .unwrap();
    let batch = poll_fn(|cx| Pin::new(&mut result).poll_next(cx))
        .await
        .unwrap()
        .unwrap();
    let ssl = batch.column(0).as_any().downcast_ref::<BooleanArray>();
    assert!(ssl.unwrap().value(0), "the server sees no TLS");
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_ca_is_refused() {
    if !database::containers_enabled() {
        return;
    }
    let mut fixture = database::postgres_tls();
    let other = database::test_certs_dir().join("other-ca.pem");
    fixture.profile.tls = TlsSettings::new().with_ca_certificate(other);
    let error = connect(&fixture).await.err().unwrap();
    assert_eq!(error.category(), ErrorCategory::Connectivity, "{error}");
    assert!(error.message().contains("UnknownIssuer"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_host_name_is_refused() {
    if !database::containers_enabled() {
        return;
    }
    // The certificate names `localhost`, not the address.
    let mut fixture = database::postgres_tls();
    fixture.profile.endpoint.host = "127.0.0.1".to_owned();
    let error = connect(&fixture).await.err().unwrap();
    assert_eq!(error.category(), ErrorCategory::Connectivity, "{error}");
    assert!(error.message().contains("not valid for name"), "{error}");
}

/// PostgreSQL accepts a plaintext cancel request even from a TLS session,
/// so the server cannot tell. A proxy records the first bytes of each
/// connection: the login and the cancel must both start with `SSLRequest`.
#[tokio::test(flavor = "multi_thread")]
async fn cancel_request_uses_tls() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F];

    if !database::containers_enabled() {
        return;
    }
    let mut fixture = database::postgres_tls();
    let server = ("127.0.0.1", fixture.profile.endpoint.port.unwrap());
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    fixture.profile.endpoint.port = Some(proxy.local_addr().unwrap().port());
    let (starts, mut seen) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut client, _) = proxy.accept().await.unwrap();
            let starts = starts.clone();
            tokio::spawn(async move {
                let mut start = [0; 8];
                client.read_exact(&mut start).await.unwrap();
                starts.send(start).unwrap();
                let mut upstream = tokio::net::TcpStream::connect(server).await.unwrap();
                upstream.write_all(&start).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });

    let connection = std::sync::Arc::new(connect(&fixture).await.unwrap());
    let running = tokio::spawn({
        let connection = std::sync::Arc::clone(&connection);
        async move {
            let mut result = connection.execute(Sql::postgres().slow).await?;
            poll_fn(|cx| Pin::new(&mut result).poll_next(cx))
                .await
                .transpose()
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    connection.cancel().await.unwrap();
    let error = running.await.unwrap().err().unwrap();
    assert_eq!(error.category(), ErrorCategory::Cancelled, "{error}");
    assert_eq!(seen.recv().await.unwrap(), SSL_REQUEST, "login");
    assert_eq!(seen.recv().await.unwrap(), SSL_REQUEST, "cancel request");
}

/// `rivet_cert` may log in only with `cert` (pg_hba `hostssl … cert`): the
/// login works with the client certificate, and the cancel request (which
/// runs on its own TLS connection) works too.
#[tokio::test(flavor = "multi_thread")]
async fn client_certificate_logs_in_and_cancels() {
    if !database::containers_enabled() {
        return;
    }
    let request = ConnectRequest::new(
        database::postgres_tls().profile,
        database::client_certificate("client"),
    );
    let connection = std::sync::Arc::new(PostgresDriver.connect(request).await.unwrap());
    let mut result = connection
        .execute(
            "select current_user || ' ' || client_dn from pg_stat_ssl \
             where pid = pg_backend_pid()"
                .to_owned(),
        )
        .await
        .unwrap();
    let batch = poll_fn(|cx| Pin::new(&mut result).poll_next(cx))
        .await
        .unwrap()
        .unwrap();
    drop(result);
    let seen = batch
        .column(0)
        .as_any()
        .downcast_ref::<arrow_array::StringArray>()
        .unwrap()
        .value(0)
        .to_owned();
    assert_eq!(seen, "rivet_cert /CN=rivet_cert");

    let running = tokio::spawn({
        let connection = std::sync::Arc::clone(&connection);
        async move {
            let mut result = connection.execute(Sql::postgres().slow).await?;
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
    let request = ConnectRequest::new(database::postgres_tls().profile, credentials);
    let error = PostgresDriver.connect(request).await.err().unwrap();
    assert_eq!(error.category(), ErrorCategory::Auth, "{error}");
    assert!(error.message().contains("certificate"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn client_certificate_of_another_ca_is_refused() {
    if !database::containers_enabled() {
        return;
    }
    let request = ConnectRequest::new(
        database::postgres_tls().profile,
        database::client_certificate("other-client"),
    );
    let error = PostgresDriver.connect(request).await.err().unwrap();
    // The server sends the TLS alert `unknown_ca`.
    assert_eq!(error.category(), ErrorCategory::Connectivity, "{error}");
    assert!(format!("{error:?}").contains("UnknownCA"), "{error:?}");
}
