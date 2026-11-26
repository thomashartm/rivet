//! Database fixtures: the PostgreSQL and MySQL containers of
//! `docker/compose.test.yml`.
//!
//! The fixtures contain no database client. A driver test takes the
//! [`ConnectionProfile`] and the test credentials and connects with its own
//! code.
//!
//! # Container tests
//!
//! A test that needs the containers starts with [`containers_enabled`]:
//!
//! ```
//! # async fn test() -> rivet_sdk::error::Result<()> {
//! if !rivet_testkit::database::containers_enabled() {
//!     return Ok(());
//! }
//! let postgres = rivet_testkit::database::postgres();
//! postgres.ensure_reachable().await?;
//! # Ok(())
//! # }
//! ```
//!
//! | Step | Command |
//! | --- | --- |
//! | Start the containers | `docker compose -f docker/compose.test.yml up -d --wait` |
//! | Run the container tests | `RIVET_TEST_CONTAINERS=1 cargo test -p rivet-testkit` |
//! | Stop the containers | `docker compose -f docker/compose.test.yml down -v` |
//!
//! | Value of `RIVET_TEST_CONTAINERS` | Result |
//! | --- | --- |
//! | not set, empty or `0` | The container tests are skipped. |
//! | `1` | The container tests run. |
//! | any other value | The container tests fail. |

use rivet_sdk::error::{Error, Result};
use rivet_sdk::model::{ConnectionProfile, Endpoint, ExtensionValue, ProviderRef, TlsSettings};
use rivet_sdk::secret::Secret;
use std::io::Write;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The switch for container tests: they run only when this environment
/// variable is `1`. See [`containers_enabled`] for the other values.
pub const CONTAINERS_SWITCH: &str = "RIVET_TEST_CONTAINERS";

/// The command that starts the containers, from the repository root.
pub const START_COMMAND: &str = "docker compose -f docker/compose.test.yml up -d --wait";

/// The user of both test databases. Test-only: it is public.
pub const TEST_USER: &str = "rivet_test";

/// The password of both test databases. Test-only: it is public and protects
/// nothing. It is not a secret.
pub const TEST_ONLY_PASSWORD: &str = "test-only-not-a-secret";

const HOST: &str = "127.0.0.1";
const DATABASE: &str = "rivet_test";
const POSTGRES_PORT: u16 = 54329;
const MYSQL_PORT: u16 = 33069;
const POSTGRES_TLS_PORT: u16 = 54330;
const MYSQL_TLS_PORT: u16 = 33070;

/// The host name in the certificate of the TLS test servers.
pub const TLS_HOST: &str = "localhost";

/// The directory with the test TLS files that `docker/test-certs.sh`
/// writes when the containers start: `ca.pem` (the CA of the TLS test
/// servers) and `other-ca.pem` (a CA that signed nothing).
pub fn test_certs_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docker/test-certs")
}
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a PostgreSQL server must stay silent after its answer to the
/// `SSLRequest`.
const POSTGRES_SILENCE: Duration = Duration::from_millis(100);

/// Decides from the value of [`CONTAINERS_SWITCH`] if the container tests
/// run. `None` means that the variable is not set.
fn switch(value: Option<&str>) -> std::result::Result<bool, String> {
    match value {
        None | Some("" | "0") => Ok(false),
        Some("1") => Ok(true),
        Some(other) => Err(format!(
            "{CONTAINERS_SWITCH} has the value `{other}`; the permitted values are \
             `1` (run the container tests) and `0`, empty or not set (skip them)"
        )),
    }
}

/// Returns `true` when the container tests are switched on
/// ([`CONTAINERS_SWITCH`] is `1`). If the variable is not set, empty or `0`,
/// it writes one line to the standard error output that says the test is
/// skipped, and returns `false`.
///
/// # Panics
///
/// Panics if the variable has another value, for example `true`. The test
/// fails: a typing error must not skip the container tests silently.
pub fn containers_enabled() -> bool {
    let value = match std::env::var(CONTAINERS_SWITCH) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(value)) => Some(value.to_string_lossy().into_owned()),
    };
    let enabled = switch(value.as_deref()).unwrap_or_else(|message| panic!("{message}"));
    if !enabled {
        let test = std::thread::current();
        let test = test.name().unwrap_or("test");
        // Written to the stream itself: the test harness captures `eprintln!`.
        // A failed write to the standard error output cannot be reported.
        let _ = writeln!(
            std::io::stderr(),
            "skipped `{test}`: container tests are off; run `{START_COMMAND}` and set {CONTAINERS_SWITCH}=1"
        );
    }
    enabled
}

/// The PostgreSQL `SSLRequest` message: length 8, request code 80877103.
const POSTGRES_SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F];
/// The protocol version in the first packet of a MySQL server.
const MYSQL_PROTOCOL_VERSION: u8 = 10;

/// Reads the first answer of the server and checks that it is the answer of
/// a PostgreSQL server (`postgres` is `true`) or of a MySQL server. Returns
/// what is wrong, if anything.
async fn probe(postgres: bool, stream: &mut TcpStream) -> std::io::Result<Option<String>> {
    let wrong = if postgres {
        stream.write_all(&POSTGRES_SSL_REQUEST).await?;
        // `S`: the server accepts TLS. `N`: it does not. Both are PostgreSQL.
        let answer = stream.read_u8().await?;
        if matches!(answer, b'S' | b'N') {
            // PostgreSQL now waits for the client. A server that sends more
            // is of another type: an SSH banner starts with `S` too.
            match tokio::time::timeout(POSTGRES_SILENCE, stream.read_u8()).await {
                Err(_silent) => None,
                Ok(more) => Some(format!(
                    "the server sent byte {} after the answer to SSLRequest",
                    more?
                )),
            }
        } else {
            Some(format!(
                "the answer to SSLRequest was byte {answer}, not `S` or `N`"
            ))
        }
    } else {
        // Packet header (3 bytes length, 1 byte sequence), then the payload.
        let mut header = [0; 4];
        stream.read_exact(&mut header).await?;
        let version = stream.read_u8().await?;
        let [length @ .., sequence] = header;
        if version != MYSQL_PROTOCOL_VERSION {
            Some(format!(
                "the first packet has protocol version {version}, not {MYSQL_PROTOCOL_VERSION}"
            ))
        } else if sequence != 0 {
            Some(format!(
                "the first packet has sequence number {sequence}, not 0"
            ))
        } else {
            (length == [0; 3]).then(|| "the first packet has an empty payload".to_owned())
        }
    };
    Ok(wrong)
}

/// One test database: how to reach it, and the test credentials.
///
/// The fields are public: a test can change the profile. Create a fixture
/// with [`postgres`] or [`mysql`].
#[derive(Debug)]
#[non_exhaustive]
pub struct DatabaseFixture {
    /// The profile of the database. The engine id is `postgres` or `mysql`.
    /// TLS is off: the containers accept plaintext on the loopback address.
    pub profile: ConnectionProfile,
    /// The test user ([`TEST_USER`]).
    pub user: String,
    /// The test-only password ([`TEST_ONLY_PASSWORD`]).
    pub password: Secret,
}

impl DatabaseFixture {
    fn new(engine: &str, port: u16) -> Self {
        let mut auth = ProviderRef::new("password");
        let user = ExtensionValue::Text(TEST_USER.to_owned());
        auth.settings.insert("user".to_owned(), user);
        Self {
            profile: ConnectionProfile::new(
                ProviderRef::new(engine),
                Endpoint::new(HOST).with_port(port).with_database(DATABASE),
                auth,
            )
            .with_tls(TlsSettings::new().with_enabled(false))
            .with_environment("test"),
            user: TEST_USER.to_owned(),
            password: Secret::from(TEST_ONLY_PASSWORD.to_owned()),
        }
    }

    /// Checks that a database server of the correct type answers. The check
    /// waits two seconds at most.
    ///
    /// | Engine | Check |
    /// | --- | --- |
    /// | `postgres` | The server answers an `SSLRequest` with `S` or `N` and then sends nothing. |
    /// | `mysql` | The first packet of the server has sequence number 0, a payload and protocol version 10. |
    ///
    /// The check does not log in: it does not prove the user, the password
    /// or the database name. A real login is a part-2 item; it needs a
    /// database client, and the testkit has none.
    ///
    /// # Errors
    ///
    /// - A `connectivity` error if the connection fails, takes too long or
    ///   the answer is not from a database of the correct type. The message
    ///   contains [`START_COMMAND`].
    /// - A `user` error if the endpoint of the profile has no port, or if
    ///   the engine of the profile is not `postgres` or `mysql`.
    pub async fn ensure_reachable(&self) -> Result<()> {
        let Endpoint { host, port, .. } = &self.profile.endpoint;
        let port = port.ok_or_else(|| Error::user("the endpoint of the profile has no port"))?;
        let engine = &self.profile.engine.id;
        let postgres = match engine.as_str() {
            "postgres" => true,
            "mysql" => false,
            other => {
                let message = format!("the testkit has no check for the engine `{other}`");
                return Err(Error::user(message));
            }
        };
        let unreachable = |reason: &str| {
            Error::connectivity(format!(
                "the {engine} test database at {host}:{port} is not reachable ({reason}); \
                 start the containers from the repository root: `{START_COMMAND}`"
            ))
        };
        let check = async {
            let mut stream = TcpStream::connect((host.as_str(), port)).await?;
            probe(postgres, &mut stream).await
        };
        match tokio::time::timeout(CONNECT_TIMEOUT, check).await {
            Ok(Ok(None)) => Ok(()),
            Ok(Ok(Some(wrong))) => Err(unreachable(&wrong)),
            Ok(Err(error)) => Err(unreachable("connection failed").with_source(error)),
            Err(elapsed) => Err(unreachable("timeout").with_source(elapsed)),
        }
    }
}

/// The PostgreSQL test database of `docker/compose.test.yml`.
pub fn postgres() -> DatabaseFixture {
    DatabaseFixture::new("postgres", POSTGRES_PORT)
}

/// The MySQL test database of `docker/compose.test.yml`.
pub fn mysql() -> DatabaseFixture {
    DatabaseFixture::new("mysql", MYSQL_PORT)
}

/// The same database as the fixture, on its TLS server: the host is
/// [`TLS_HOST`] and TLS is on, with only the test CA trusted.
fn with_tls(mut fixture: DatabaseFixture, port: u16) -> DatabaseFixture {
    fixture.profile.endpoint.host = TLS_HOST.to_owned();
    fixture.profile.endpoint.port = Some(port);
    fixture.profile.tls = TlsSettings::new().with_ca_certificate(test_certs_dir().join("ca.pem"));
    fixture
}

/// The PostgreSQL TLS test database (`postgres-tls`).
pub fn postgres_tls() -> DatabaseFixture {
    with_tls(postgres(), POSTGRES_TLS_PORT)
}

/// The MySQL TLS test database (`mysql-tls`). It refuses plaintext.
pub fn mysql_tls() -> DatabaseFixture {
    with_tls(mysql(), MYSQL_TLS_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rivet_sdk::error::ErrorCategory;

    const COMPOSE: &str = include_str!("../../../docker/compose.test.yml");

    /// The lines of one service in the Compose file.
    fn service(name: &str) -> String {
        let start = COMPOSE.find(&format!("\n  {name}:\n")).unwrap();
        let rest = &COMPOSE[start + 1..];
        let lines = rest.lines().skip(1);
        let body = lines.take_while(|line| line.is_empty() || line.starts_with("    "));
        body.collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn compose_file_pins_images_checks_health_and_binds_loopback_only() {
        for (name, image, port) in [
            ("postgres", "image: postgres:18.7\n", "127.0.0.1:54329:5432"),
            ("mysql", "image: mysql:8.4.13\n", "127.0.0.1:33069:3306"),
        ] {
            let service = service(name);
            assert!(service.contains(image), "{name}: pinned image");
            assert!(service.contains("healthcheck:"), "{name}: health check");
            let ports: Vec<&str> = service
                .lines()
                .skip_while(|line| line.trim() != "ports:")
                .skip(1)
                .take_while(|line| line.trim().starts_with("- "))
                .collect();
            assert_eq!(ports, [format!("      - \"{port}\"")], "{name}: ports");
            assert!(!service.contains("volumes:"), "{name}: no persistent data");
            assert!(service.contains("tmpfs:"), "{name}: data in memory");
        }
        for (name, port) in [
            ("postgres-tls", "127.0.0.1:54330:5432"),
            ("mysql-tls", "127.0.0.1:33070:3306"),
        ] {
            let service = service(name);
            assert!(service.contains(&format!("- \"{port}\"")), "{name}: port");
            assert!(service.contains("./test-certs:/certs:ro"), "{name}: certs");
            assert!(service.contains("tmpfs:"), "{name}: data in memory");
        }
        assert!(!COMPOSE.contains("latest"));
        assert!(!COMPOSE.contains("\nvolumes:"));
    }

    #[test]
    fn compose_file_marks_the_credentials_as_test_only() {
        assert!(COMPOSE.contains("TEST-ONLY CREDENTIALS"));
        assert!(TEST_ONLY_PASSWORD.contains("test-only"));
        // Every password in the file is the marked test password.
        let passwords: Vec<&str> = COMPOSE
            .lines()
            .filter_map(|line| line.trim().split_once("PASSWORD: "))
            .map(|(_, value)| value)
            .collect();
        assert_eq!(passwords, [TEST_ONLY_PASSWORD; 3]);
        assert!(COMPOSE.contains(&format!("--password={TEST_ONLY_PASSWORD}\"")));
        assert_eq!(COMPOSE.matches("USER: rivet_test\n").count(), 2);
        assert!(COMPOSE.contains(START_COMMAND));
        assert!(COMPOSE.contains(CONTAINERS_SWITCH));
    }

    #[test]
    fn fixtures_give_the_profile_and_the_test_credentials() {
        for (fixture, engine, port) in [(postgres(), "postgres", 54329), (mysql(), "mysql", 33069)]
        {
            assert_eq!(fixture.profile.engine, ProviderRef::new(engine));
            let endpoint = &fixture.profile.endpoint;
            assert_eq!(endpoint.host, "127.0.0.1");
            assert_eq!(endpoint.port, Some(port));
            assert_eq!(endpoint.database.as_deref(), Some("rivet_test"));
            assert!(COMPOSE.contains(&format!("_DB: {DATABASE}\n")));
            assert!(COMPOSE.contains(&format!("_DATABASE: {DATABASE}\n")));
            assert!(!fixture.profile.tls.enabled);
            assert_eq!(fixture.user, TEST_USER);
            assert_eq!(fixture.password.expose(), TEST_ONLY_PASSWORD);
            // The password is not in the profile, and not in the debug text.
            assert!(!format!("{fixture:?}").contains(TEST_ONLY_PASSWORD));
        }
    }

    #[test]
    fn tls_fixtures_trust_only_the_test_ca() {
        for (fixture, port) in [(postgres_tls(), 54330), (mysql_tls(), 33070)] {
            assert_eq!(fixture.profile.endpoint.host, TLS_HOST);
            assert_eq!(fixture.profile.endpoint.port, Some(port));
            assert!(fixture.profile.tls.enabled);
            let ca = fixture.profile.tls.ca_certificate.unwrap();
            assert_eq!(ca, test_certs_dir().join("ca.pem"));
        }
        assert!(COMPOSE.contains("./test-certs:/certs\n"));
    }

    #[tokio::test]
    async fn unreachable_database_says_how_to_start_the_containers() {
        // A port that was free a moment ago: nothing listens on it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut fixture = postgres();
        fixture.profile.endpoint.port = Some(port);

        let error = fixture.ensure_reachable().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Connectivity);
        assert!(error.message().contains(START_COMMAND), "{error:?}");
        assert!(error.message().contains(&format!("127.0.0.1:{port}")));
    }

    #[tokio::test]
    async fn profile_without_port_is_a_user_error() {
        let mut fixture = mysql();
        fixture.profile.endpoint.port = None;
        let error = fixture.ensure_reachable().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::User);
    }

    #[test]
    fn switch_is_off_on_or_an_error() {
        for off in [None, Some(""), Some("0")] {
            assert_eq!(switch(off), Ok(false), "{off:?}");
        }
        assert_eq!(switch(Some("1")), Ok(true));
        for wrong in ["true", "TRUE", "yes", "on", "2", " 1", "1 ", "01"] {
            let message = switch(Some(wrong)).unwrap_err();
            assert!(message.contains(CONTAINERS_SWITCH), "{message}");
            assert!(message.contains(&format!("`{wrong}`")), "{message}");
            assert!(
                message.contains("`1`") && message.contains("`0`"),
                "{message}"
            );
        }
    }

    /// A server that accepts one connection, reads `request` bytes and
    /// writes `answer`. Returns the fixture that points at it.
    async fn server(engine: &str, request: usize, answer: &'static [u8]) -> DatabaseFixture {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = vec![0; request];
            stream.read_exact(&mut received).await.unwrap();
            stream.write_all(answer).await.unwrap();
            // Keep the connection open until the client closes it.
            let _ = stream.read_u8().await;
        });
        DatabaseFixture::new(engine, port)
    }

    #[tokio::test]
    async fn server_that_speaks_the_protocol_is_reachable() {
        for (engine, request, answer) in [
            ("postgres", 8, &b"N"[..]),
            ("postgres", 8, b"S"),
            ("mysql", 0, b"\x4a\x00\x00\x00\x0a8.4.13\x00"),
        ] {
            let fixture = server(engine, request, answer).await;
            fixture.ensure_reachable().await.unwrap();
        }
    }

    #[tokio::test]
    async fn postgres_check_sends_an_ssl_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fixture = DatabaseFixture::new("postgres", listener.local_addr().unwrap().port());
        let request = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 8];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(b"N").await.unwrap();
            // PostgreSQL keeps the connection open after the answer.
            let _ = stream.read_u8().await;
            request
        };
        let (request, reachable) = tokio::join!(request, fixture.ensure_reachable());
        reachable.unwrap();
        assert_eq!(request[..4], 8u32.to_be_bytes());
        assert_eq!(request[4..], 80_877_103u32.to_be_bytes());
    }

    #[tokio::test]
    async fn server_of_another_type_is_not_reachable() {
        for (engine, request, answer, reason) in [
            // PostgreSQL answers with an error message (`E`) to a bad start.
            ("postgres", 8, &b"E"[..], "byte 69, not `S` or `N`"),
            (
                "postgres",
                0,
                b"HTTP/1.1 400 Bad Request\r\n\r\n",
                "byte 72",
            ),
            // A MySQL error packet, for example "too many connections".
            (
                "mysql",
                0,
                b"\x17\x00\x00\x00\xff\x10\x04Too many",
                "version 255, not 10",
            ),
            ("mysql", 0, b"HTTP/1.1 400 Bad Request\r\n\r\n", "not 10"),
        ] {
            let fixture = server(engine, request, answer).await;
            let error = fixture.ensure_reachable().await.unwrap_err();
            assert_eq!(error.category(), ErrorCategory::Connectivity);
            assert!(error.message().contains(reason), "{error:?}");
            assert!(error.message().contains(START_COMMAND), "{error:?}");
        }
    }

    /// R-56: one correct byte at the correct place is not enough.
    #[tokio::test]
    async fn server_with_one_matching_byte_is_not_reachable() {
        let mut wrongly_reachable = Vec::new();
        for (engine, answer, reason) in [
            // An SSH banner starts with `S`.
            (
                "postgres",
                &b"SSH-2.0-OpenSSH_9.9\r\n"[..],
                "byte 83 after the answer to SSLRequest",
            ),
            // The fifth byte of each answer is 10, the MySQL protocol version.
            ("mysql", b"+OK\r\n", "sequence number 13, not 0"),
            ("mysql", b"PING\n", "sequence number 71, not 0"),
            ("mysql", b"\x00\x00\x00\x00\x0a", "an empty payload"),
        ] {
            let fixture = server(engine, 0, answer).await;
            let Err(error) = fixture.ensure_reachable().await else {
                wrongly_reachable.push((engine, answer));
                continue;
            };
            assert_eq!(error.category(), ErrorCategory::Connectivity);
            assert!(error.message().contains(reason), "{error:?}");
        }
        assert_eq!(wrongly_reachable, []);
    }

    #[tokio::test]
    async fn engine_without_a_check_is_a_user_error() {
        let error = DatabaseFixture::new("oracle", 1).ensure_reachable().await;
        let error = error.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::User);
        assert!(error.message().contains("`oracle`"), "{error:?}");
    }

    #[tokio::test]
    async fn server_that_closes_the_connection_is_not_reachable() {
        for engine in ["postgres", "mysql"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let fixture = DatabaseFixture::new(engine, listener.local_addr().unwrap().port());
            let close = async { drop(listener.accept().await.unwrap()) };
            let (error, ()) = tokio::join!(fixture.ensure_reachable(), close);
            let error = error.unwrap_err();
            assert_eq!(error.category(), ErrorCategory::Connectivity);
            assert!(error.message().contains("connection failed"), "{error:?}");
        }
    }

    /// R-36: a listener that is not a database is not a reachable database.
    #[tokio::test]
    async fn plain_listener_is_not_a_reachable_database() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = Some(listener.local_addr().unwrap().port());
        let (mut postgres, mut mysql) = (postgres(), mysql());
        postgres.profile.endpoint.port = port;
        mysql.profile.endpoint.port = port;

        let (postgres, mysql) = tokio::join!(postgres.ensure_reachable(), mysql.ensure_reachable());
        for error in [postgres.unwrap_err(), mysql.unwrap_err()] {
            assert_eq!(error.category(), ErrorCategory::Connectivity);
            assert!(error.message().contains("timeout"), "{error:?}");
        }
    }
}
