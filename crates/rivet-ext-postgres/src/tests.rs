//! Tests that need no container. A scripted PostgreSQL server talks to the
//! driver over an in-memory transport.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rivet_sdk::extension::ByteStream;
use rivet_sdk::manifest::{ExtensionPoint, Manifest};
use rivet_sdk::model::{ClientCertificate, Endpoint, ProviderRef, TlsSettings};
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

/// Connects over an untouched transport with `tls` and returns the error.
async fn refused_before_any_io(tls: TlsSettings) -> Error {
    let (transport, used) = untouched();
    let request =
        ConnectRequest::new(profile(true).with_tls(tls), password()).with_transport(transport);
    let error = PostgresDriver.connect(request).await.err().unwrap();
    assert!(!used.load(Ordering::SeqCst), "{error}");
    error
}

#[tokio::test]
async fn client_certificate_is_refused_before_any_io() {
    let key = "keychain://rivet/client-key".parse().unwrap();
    let tls = TlsSettings::new().with_client_certificate(ClientCertificate::new("c.pem", key));
    let error = refused_before_any_io(tls).await;
    assert_eq!(error.category(), ErrorCategory::User);
    assert!(error.message().contains("client certificate"), "{error}");
}

/// The text of a key that must appear in no error.
const KEY: &str =
    "-----BEGIN PRIVATE KEY-----\nkey-text-that-must-not-leak\n-----END PRIVATE KEY-----\n";

#[tokio::test]
async fn bad_client_certificate_is_refused_before_any_io() {
    let certificate = "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n";
    for (tls, certificate, says) in [
        (false, certificate, "needs TLS"),
        (true, "no PEM here", "no PEM certificate"),
        (true, certificate, "not a PEM private key"),
    ] {
        let credential = Credential::ClientCertificate {
            certificate: certificate.to_owned(),
            private_key: Secret::from(KEY.to_owned()),
        };
        let (transport, used) = untouched();
        let error = connect_over(
            transport,
            Credentials::new(credential).with_user("app"),
            tls,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.category(), ErrorCategory::User, "{error:?}");
        assert!(error.message().contains(says), "{error:?}");
        assert!(!format!("{error:?}").contains("must-not-leak"), "{error:?}");
        assert!(!used.load(Ordering::SeqCst));
    }
}

#[test]
fn client_certificate_login_has_no_password() {
    let credential = Credential::ClientCertificate {
        certificate: String::new(),
        private_key: Secret::from(KEY.to_owned()),
    };
    let config = config(
        &profile(true),
        &Credentials::new(credential).with_user("app"),
    )
    .unwrap();
    assert_eq!(config.get_password(), None);
    assert_eq!(config.get_user(), Some("app"));
}

#[tokio::test]
async fn unusable_ca_file_is_refused_before_any_io() {
    let dir = std::env::temp_dir().join(format!("rivet-pg-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let empty = dir.join("empty.pem");
    std::fs::write(&empty, "no certificate here\n").unwrap();
    for path in [dir.join("missing.pem"), empty] {
        let error =
            refused_before_any_io(TlsSettings::new().with_ca_certificate(path.clone())).await;
        assert_eq!(error.category(), ErrorCategory::User, "{error}");
        assert!(
            error.message().contains(&*path.to_string_lossy()),
            "{error}"
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn server_without_tls_is_refused_not_used_in_plaintext() {
    let (transport, mut peer) = pipe();
    let server = async move {
        let mut request = [0; 8];
        peer.0.read_exact(&mut request).await.unwrap();
        peer.0.write_all(b"N").await.unwrap(); // no TLS here
        // A client that falls back sends the startup message next.
        let mut rest = Vec::new();
        let _ = peer.0.read_to_end(&mut rest).await;
        (request, rest)
    };
    let (connected, (request, rest)) = tokio::join!(
        async {
            let connected = connect_over(transport, password(), true).await;
            // Dropping the error closes the transport: the server read ends.
            connected.err().unwrap()
        },
        server
    );
    assert_eq!(request, [0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F], "SSLRequest");
    assert_eq!(
        connected.category(),
        ErrorCategory::Connectivity,
        "{connected}"
    );
    assert!(
        connected.message().contains("does not support TLS"),
        "{connected}"
    );
    assert!(
        rest.is_empty(),
        "the driver sent {} bytes in plaintext",
        rest.len()
    );
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

/// The answers of the server to one `execute` of `select 1 as n` whose
/// rows never end: the prepare step, the close of the prepared statement and
/// then [`BATCH_ROWS`] rows of the simple query, with no CommandComplete.
async fn answer_endless_select(peer: &mut Peer) {
    let mut columns = 1i16.to_be_bytes().to_vec();
    columns.extend(b"n\0");
    columns.extend(0i32.to_be_bytes()); // table
    columns.extend(0i16.to_be_bytes()); // column number
    columns.extend(23i32.to_be_bytes()); // int4
    columns.extend(4i16.to_be_bytes()); // size
    columns.extend((-1i32).to_be_bytes()); // modifier
    columns.extend(0i16.to_be_bytes()); // text format
    let mut prepared = false;
    loop {
        match peer.message().await.0 {
            b'S' if !prepared => {
                prepared = true;
                peer.send(b'1', &[]).await; // ParseComplete
                peer.send(b't', &0i16.to_be_bytes()).await; // ParameterDescription
                peer.send(b'T', &columns).await; // RowDescription
                peer.send(b'Z', b"I").await;
            }
            b'S' => {
                peer.send(b'3', &[]).await; // CloseComplete
                peer.send(b'Z', b"I").await;
            }
            b'Q' => break,
            _ => {}
        }
    }
    peer.send(b'T', &columns).await;
    let mut row = 1i16.to_be_bytes().to_vec();
    row.extend(1i32.to_be_bytes());
    row.push(b'1');
    for _ in 0..BATCH_ROWS {
        peer.send(b'D', &row).await; // DataRow
    }
}

#[tokio::test]
async fn dropped_result_over_a_transport_closes_the_connection() {
    let (transport, mut peer) = pipe();
    let server = tokio::spawn(async move {
        peer.accept_login().await;
        answer_endless_select(&mut peer).await;
        // The driver must close the stream: the read sees its end.
        let mut rest = Vec::new();
        peer.0.read_to_end(&mut rest).await.unwrap();
    });
    let connection = connect_over(transport, password(), false).await.unwrap();

    let mut result = connection
        .execute("select 1 as n".to_owned())
        .await
        .unwrap();
    let next = std::future::poll_fn(|cx| Pin::new(&mut result).poll_next(cx));
    let batch = tokio::time::timeout(LIMIT, next).await.unwrap();
    assert_eq!(batch.unwrap().unwrap().num_rows(), BATCH_ROWS);
    drop(result);
    tokio::time::timeout(LIMIT, server)
        .await
        .expect("the driver closed the transport stream")
        .unwrap();

    let error = tokio::time::timeout(LIMIT, connection.execute("select 1".to_owned()))
        .await
        .expect("the closed connection answers at once")
        .unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Connectivity, "{error}");
    assert!(error.message().contains("closed"), "{error}");
    assert!(error.message().contains("tunnel"), "{error}");
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

#[tokio::test(start_paused = true)]
async fn login_that_never_gets_an_answer_fails_with_connectivity() {
    // `_peer` stays open and silent: the server accepted and says nothing.
    let (transport, _peer) = pipe();
    let request = ConnectRequest::new(profile(false), password()).with_transport(transport);
    let error = PostgresDriver.connect(request).await.err().unwrap();
    assert_eq!(error.category(), ErrorCategory::Connectivity, "{error}");
    assert!(error.message().contains("login"), "{error}");
    assert!(!format!("{error:?}").contains(PASSWORD));
}

#[tokio::test(start_paused = true)]
async fn cancel_that_never_ends_frees_the_busy_lock() {
    // A real login over a pipe gives a cancel token.
    let (transport, mut peer) = pipe();
    let config = config(&profile(false), &password()).unwrap();
    let (login, _) = tokio::join!(
        start(&config, Transport::new(transport), None),
        peer.accept_login()
    );
    let (client, _task) = login.unwrap();
    // The cancel socket is accepted and never closed.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let held = tokio::spawn(async move {
        let socket = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
        drop(socket);
    });
    let cancel = Canceller {
        token: client.cancel_token(),
        target: Some((address.ip().to_string(), address.port())),
        tls: None,
    };
    let busy = Arc::new(Mutex::new(()));
    let running = Running {
        _busy: Arc::clone(&busy).lock_owned().await,
        cancel,
        tunnel: None,
    };
    running.stop();
    // The lock comes free after the cancel limit, not never.
    let lock = tokio::time::timeout(CANCEL_TIMEOUT * 2, busy.lock()).await;
    assert!(lock.is_ok(), "the busy lock stayed held");
    held.abort();
}
