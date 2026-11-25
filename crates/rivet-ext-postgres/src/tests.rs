//! Tests that need no container. A scripted PostgreSQL server talks to the
//! driver over an in-memory transport.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rivet_sdk::extension::ByteStream;
use rivet_sdk::manifest::{ExtensionPoint, Manifest};
use rivet_sdk::model::{Endpoint, ProviderRef, TlsSettings};
use rivet_sdk::secret::Secret;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

use super::*;

const PASSWORD: &str = "pw-that-must-not-leak";
/// A limit for each test: a driver that opened a socket to the
/// unreachable endpoint would hang.
const LIMIT: Duration = Duration::from_secs(10);

/// A profile whose endpoint is not reachable (TEST-NET-1, RFC 5737).
fn profile(tls: bool) -> ConnectionProfile {
    ConnectionProfile::new(
        ProviderRef::new("postgres"),
        Endpoint::new("192.0.2.1").with_port(9),
        ProviderRef::new("password"),
    )
    .with_tls(TlsSettings::new().with_enabled(tls))
}

fn password() -> Credentials {
    Credentials::new(Credential::Password(Secret::from(PASSWORD.to_owned()))).with_user("app")
}

async fn connect_over(
    transport: Box<dyn ByteStream>,
    credentials: Credentials,
    tls: bool,
) -> Result<Box<dyn Connection>> {
    let request = ConnectRequest::new(profile(tls), credentials).with_transport(transport);
    tokio::time::timeout(LIMIT, PostgresDriver.connect(request))
        .await
        .expect("the driver used the transport, not a socket")
}

/// One end of an in-memory pipe.
struct Pipe {
    reader: Mutex<ReadHalf<DuplexStream>>,
    writer: Mutex<WriteHalf<DuplexStream>>,
}

impl ByteStream for Pipe {
    fn read(&self, max: usize) -> BoxFuture<'_, Result<Vec<u8>>> {
        Box::pin(async move {
            let mut buffer = vec![0; max];
            let count = self.reader.lock().await.read(&mut buffer).await;
            buffer.truncate(count.map_err(|e| Error::connectivity("pipe").with_source(e))?);
            Ok(buffer)
        })
    }

    fn write(&self, data: Vec<u8>) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let mut writer = self.writer.lock().await;
            let written = writer.write_all(&data).await;
            written.map_err(|e| Error::connectivity("pipe").with_source(e))
        })
    }
}

/// The scripted server at the other end of a [`Pipe`].
struct Peer(DuplexStream);

fn pipe() -> (Box<dyn ByteStream>, Peer) {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let (reader, writer) = tokio::io::split(client);
    let pipe = Pipe {
        reader: Mutex::new(reader),
        writer: Mutex::new(writer),
    };
    (Box::new(pipe), Peer(server))
}

impl Peer {
    /// Reads the startup message and returns its body.
    async fn startup(&mut self) -> Vec<u8> {
        let length = self.0.read_i32().await.unwrap();
        let mut body = vec![0; usize::try_from(length - 4).unwrap()];
        self.0.read_exact(&mut body).await.unwrap();
        body
    }

    /// Reads one message: its type byte and its body.
    async fn message(&mut self) -> (u8, Vec<u8>) {
        let tag = self.0.read_u8().await.unwrap();
        let length = self.0.read_i32().await.unwrap();
        let mut body = vec![0; usize::try_from(length - 4).unwrap()];
        self.0.read_exact(&mut body).await.unwrap();
        (tag, body)
    }

    async fn send(&mut self, tag: u8, body: &[u8]) {
        let length = i32::try_from(body.len() + 4).unwrap();
        let mut message = vec![tag];
        message.extend(length.to_be_bytes());
        message.extend(body);
        self.0.write_all(&message).await.unwrap();
    }

    async fn error(&mut self, code: &str, message: &str) {
        let mut body = Vec::new();
        for (field, value) in [(b'S', "ERROR"), (b'C', code), (b'M', message)] {
            body.push(field);
            body.extend(value.as_bytes());
            body.push(0);
        }
        body.push(0);
        self.send(b'E', &body).await;
    }

    /// Accepts the login without a password and reports an idle server.
    async fn accept_login(&mut self) {
        self.startup().await;
        self.send(b'R', &0i32.to_be_bytes()).await; // AuthenticationOk
        self.send(b'K', &[0, 0, 0, 7, 0, 0, 0, 9]).await; // BackendKeyData
        self.send(b'Z', b"I").await; // ReadyForQuery
    }
}

/// A transport that records any use and then fails.
struct Untouched(Arc<AtomicBool>);

impl ByteStream for Untouched {
    fn read(&self, _: usize) -> BoxFuture<'_, Result<Vec<u8>>> {
        self.0.store(true, Ordering::SeqCst);
        Box::pin(async { Err(Error::internal("the transport must not be read")) })
    }

    fn write(&self, _: Vec<u8>) -> BoxFuture<'_, Result<()>> {
        self.0.store(true, Ordering::SeqCst);
        Box::pin(async { Err(Error::internal("the transport must not be written")) })
    }
}

fn untouched() -> (Box<dyn ByteStream>, Arc<AtomicBool>) {
    let used = Arc::new(AtomicBool::new(false));
    (Box::new(Untouched(Arc::clone(&used))), used)
}

#[tokio::test]
async fn profile_with_tls_is_refused_before_any_io() {
    let (transport, used) = untouched();
    let error = connect_over(transport, password(), true)
        .await
        .err()
        .unwrap();
    assert_eq!(error.category(), ErrorCategory::User);
    assert!(error.message().contains("TLS"), "{error}");
    assert!(error.message().contains("#19"), "{error}");
    assert!(!used.load(Ordering::SeqCst));
}

#[tokio::test]
async fn credentials_without_user_or_password_are_refused() {
    let token = Credentials::new(Credential::Token(Secret::from(PASSWORD.to_owned())));
    let no_user = Credentials::new(Credential::Password(Secret::from(PASSWORD.to_owned())));
    for credentials in [token.with_user("app"), no_user] {
        let (transport, used) = untouched();
        let error = connect_over(transport, credentials, false)
            .await
            .err()
            .unwrap();
        assert_eq!(error.category(), ErrorCategory::Auth, "{error}");
        assert!(!format!("{error:?}").contains(PASSWORD));
        assert!(!used.load(Ordering::SeqCst));
    }
}

#[test]
fn login_settings_hide_the_password_in_debug() {
    let config = config(&profile(false), &password()).unwrap();
    assert!(!format!("{config:?}").contains(PASSWORD));
    assert!(!format!("{:?}", password()).contains(PASSWORD));
}

#[tokio::test]
async fn login_runs_over_the_transport_with_the_credentials_and_hides_the_password() {
    let (transport, mut peer) = pipe();
    let server = tokio::spawn(async move {
        let startup = peer.startup().await;
        let has = |text: &[u8]| startup.windows(text.len()).any(|window| window == text);
        assert!(has(b"user\0app\0"), "the startup message names the user");
        peer.send(b'R', &3i32.to_be_bytes()).await; // AuthenticationCleartextPassword
        let (tag, body) = peer.message().await;
        assert_eq!(tag, b'p');
        assert_eq!(body, format!("{PASSWORD}\0").as_bytes());
        let refusal = "password authentication failed for user \"app\"";
        peer.error("28P01", refusal).await;
    });
    let error = connect_over(transport, password(), false)
        .await
        .err()
        .unwrap();
    server.await.unwrap();
    assert_eq!(error.category(), ErrorCategory::Auth, "{error}");
    assert!(error.message().contains("28P01"), "{error}");
    for text in [format!("{error}"), format!("{error:?}")] {
        assert!(!text.contains(PASSWORD), "{text}");
    }
}

#[tokio::test]
async fn transport_that_closes_gives_connectivity() {
    let (transport, peer) = pipe();
    drop(peer);
    let error = connect_over(transport, password(), false)
        .await
        .err()
        .unwrap();
    assert_eq!(error.category(), ErrorCategory::Connectivity, "{error}");
}

#[tokio::test]
async fn connection_over_a_transport_maps_sql_errors_and_refuses_cancel() {
    let (transport, mut peer) = pipe();
    let server = tokio::spawn(async move {
        peer.accept_login().await;
        // The prepare step: Parse, Describe, Sync.
        while peer.message().await.0 != b'S' {}
        peer.error("42601", "syntax error at or near \"this\"")
            .await;
        peer.send(b'Z', b"I").await;
        peer
    });
    let connection = connect_over(transport, password(), false).await.unwrap();

    let error = connection.cancel().await.unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Connectivity);
    assert!(error.message().contains("tunnel"), "{error}");

    let error = connection
        .execute("this is not sql".to_owned())
        .await
        .unwrap_err();
    assert_eq!(error.category(), ErrorCategory::User, "{error}");
    assert!(error.message().contains("42601"), "{error}");
    drop(server.await.unwrap());
}

#[test]
fn sqlstate_gives_the_category_of_the_driver_contract() {
    let cases = [
        ("28P01", ErrorCategory::Auth),
        ("28000", ErrorCategory::Auth),
        ("57014", ErrorCategory::Cancelled),
        ("08006", ErrorCategory::Connectivity),
        ("57P01", ErrorCategory::Connectivity),
        ("42601", ErrorCategory::User),
        ("42P01", ErrorCategory::User),
        ("22012", ErrorCategory::User),
        ("23505", ErrorCategory::User),
        ("53200", ErrorCategory::Database),
        ("XX000", ErrorCategory::Database),
    ];
    for (code, expected) in cases {
        assert_eq!(category(code), expected, "{code}");
    }
}

#[test]
fn dialect_is_postgresql_with_double_quotes() {
    let dialect = PostgresDriver.dialect();
    assert_eq!(dialect.name, "postgresql");
    assert_eq!(dialect.identifier_quote, '"');
}

#[test]
fn manifest_contributes_the_driver_point() {
    let manifest = Manifest::parse(include_str!("../extension.toml")).unwrap();
    assert_eq!(manifest.id.as_str(), "rivet.postgres");
    assert_eq!(manifest.version.to_string(), env!("CARGO_PKG_VERSION"));
    assert_eq!(manifest.contributes.len(), 1);
    assert_eq!(manifest.contributes[0].kind, ExtensionPoint::Driver);
}
