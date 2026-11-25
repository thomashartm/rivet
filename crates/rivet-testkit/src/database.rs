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
//! | Run the container tests | `RIVET_TEST_CONTAINERS=1 cargo test --workspace` |
//! | Stop the containers | `docker compose -f docker/compose.test.yml down -v` |

use rivet_sdk::error::{Error, Result};
use rivet_sdk::model::{ConnectionProfile, Endpoint, ExtensionValue, ProviderRef, TlsSettings};
use rivet_sdk::secret::Secret;
use std::io::Write;
use std::time::Duration;
use tokio::net::TcpStream;

/// The switch for container tests: they run only when this environment
/// variable is `1`.
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
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Returns `true` when the container tests are switched on
/// ([`CONTAINERS_SWITCH`] is `1`). If not, it writes one line to the standard
/// error output that says the test is skipped, and returns `false`.
pub fn containers_enabled() -> bool {
    let enabled = std::env::var(CONTAINERS_SWITCH).is_ok_and(|value| value == "1");
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

/// One test database: how to reach it, and the test credentials.
#[derive(Debug)]
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
            profile: ConnectionProfile {
                engine: ProviderRef::new(engine),
                endpoint: Endpoint {
                    host: HOST.to_owned(),
                    port: Some(port),
                    database: Some(DATABASE.to_owned()),
                },
                auth,
                credential_source: None,
                tunnels: Vec::new(),
                tls: TlsSettings {
                    enabled: false,
                    ..TlsSettings::default()
                },
                read_only: false,
                confirm_on_write: false,
                environment: Some("test".to_owned()),
            },
            user: TEST_USER.to_owned(),
            password: Secret::from(TEST_ONLY_PASSWORD.to_owned()),
        }
    }

    /// Checks that the database accepts a TCP connection. The check waits
    /// two seconds at most. It does not speak the database protocol.
    ///
    /// # Errors
    ///
    /// - A `connectivity` error if the connection fails or takes too long.
    ///   The message contains [`START_COMMAND`].
    /// - A `user` error if the endpoint of the profile has no port.
    pub async fn ensure_reachable(&self) -> Result<()> {
        let Endpoint { host, port, .. } = &self.profile.endpoint;
        let port = port.ok_or_else(|| Error::user("the endpoint of the profile has no port"))?;
        let engine = &self.profile.engine.id;
        let unreachable = |reason: &str| {
            Error::connectivity(format!(
                "the {engine} test database at {host}:{port} is not reachable ({reason}); \
                 start the containers from the repository root: `{START_COMMAND}`"
            ))
        };
        let connect = TcpStream::connect((host.as_str(), port));
        match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
            Ok(Ok(_stream)) => Ok(()),
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

    #[tokio::test]
    async fn reachable_database_passes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut fixture = postgres();
        fixture.profile.endpoint.port = Some(listener.local_addr().unwrap().port());
        fixture.ensure_reachable().await.unwrap();
    }
}
