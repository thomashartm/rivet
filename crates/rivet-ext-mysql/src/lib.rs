//! The MySQL driver extension (ARCHITECTURE.md §4.2, ticket #15).
//!
//! [`MysqlDriver`] implements the [`Driver`] contract of the SDK with the
//! crate `mysql_async`. Every use of `mysql_async` stays in this crate.
//!
//! | Rule | How |
//! | --- | --- |
//! | Bounded reads (§5.5) | The result set reads [`BATCH_ROWS`] rows from the socket for each batch it gives. |
//! | Drop of a result set | `KILL QUERY` on a second connection, then the rest of the result is read and discarded. An endless result is not read to its end. |
//! | Drop of a result set, the kill fails | For example when the server refuses the second connection. The socket is closed without a read of the rest of the result, at most [`CLOSE_TIMEOUT`] later, and the lock is freed. The next `execute` gives a `connectivity` error. The server stops the statement when it next writes to the closed socket: a statement that sends no rows (for example a long `count(*)`) runs to its end. |
//! | Drop of an `execute` future before the answer | `KILL QUERY`, and the connection is closed: the next statement would read the old answer. The next `execute` gives a `connectivity` error. |
//! | `cancel` | `KILL QUERY <connection id>` on a second connection. |
//! | One statement for each `execute` | `mysql_async` cannot turn multi-statements off. The statement is prepared first: the server refuses a second statement (`user` error, code 1064) and runs none. A statement that cannot be prepared (code 1295, for example `LOCK TABLES`) is run as it is: the server had parsed it as one statement. |
//! | TLS | On if `tls.enabled` (the default): rustls, the server certificate and the host name of the endpoint are verified, also for the `KILL QUERY` connection. The trust store is the system store, or only the `tls.ca_certificate` file; the built-in Mozilla roots of `mysql_async` are off. A server without TLS is refused. |
//! | Client certificate | A [`Credential::ClientCertificate`] is shown in the TLS handshake, also of the `KILL QUERY` connection; it replaces the password. With TLS off it is refused with `user`. A `tls.client_certificate` in the profile is refused with `user`: the host resolves its key and passes the credential. |
//! | Tunnel transport | Not supported: `mysql_async` opens its own socket. A request with a transport is refused. |
//!
//! The password and the key are in no error and no debug text of this crate.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arrow_array::RecordBatch;
use arrow_schema::{Schema, SchemaRef};
use mysql_async::prelude::Queryable;
use mysql_async::{
    ClientIdentity, Conn, Opts, OptsBuilder, QueryResult, SslOpts, TextProtocol, Value,
};
use rivet_sdk::error::{Error, Result};
use rivet_sdk::extension::{BoxFuture, ConnectRequest, Connection, Credential, Dialect, Driver};
use rivet_sdk::model::{ResultSet, TlsSettings};
use rivet_sdk::secret::Secret;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::{Mutex, OwnedMutexGuard};

mod types;

use types::Kind;

/// The number of rows in each record batch, at most.
pub const BATCH_ROWS: usize = 1024;

/// The port of a profile that does not set one.
const DEFAULT_PORT: u16 = 3306;

/// The longest wait for the `KILL QUERY` of a dropped result.
const KILL_TIMEOUT: Duration = Duration::from_secs(10);

/// The longest wait for a polite close (`COM_QUIT`) of a connection that is
/// given up. After it, the socket is closed without one.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// MySQL error codes (`ER_*`) with their own error category.
mod code {
    /// `ER_DBACCESS_DENIED_ERROR`.
    pub const DATABASE_ACCESS_DENIED: u16 = 1044;
    /// `ER_ACCESS_DENIED_ERROR`: wrong user or password.
    pub const ACCESS_DENIED: u16 = 1045;
    /// `ER_HOST_NOT_PRIVILEGED`.
    pub const HOST_NOT_PRIVILEGED: u16 = 1130;
    /// `ER_UNSUPPORTED_PS`: the statement cannot be prepared.
    pub const UNSUPPORTED_PS: u16 = 1295;
    /// `ER_QUERY_INTERRUPTED`: `KILL QUERY` stopped the statement.
    pub const QUERY_INTERRUPTED: u16 = 1317;
    /// `ER_ACCESS_DENIED_NO_PASSWORD_ERROR`.
    pub const ACCESS_DENIED_NO_PASSWORD: u16 = 1698;
}

/// The MySQL driver. It has no state: each [`Driver::connect`] opens one
/// connection.
#[derive(Debug, Default, Clone, Copy)]
pub struct MysqlDriver;

impl Driver for MysqlDriver {
    fn dialect(&self) -> Dialect {
        Dialect::new("mysql", '`')
    }

    fn connect(&self, request: ConnectRequest) -> BoxFuture<'_, Result<Box<dyn Connection>>> {
        Box::pin(async move {
            let opts = opts(&request)?;
            let conn = Conn::new(opts.clone()).await.map_err(error)?;
            let killer = Arc::new(Killer {
                opts,
                id: conn.id(),
            });
            Ok(Box::new(MysqlConnection {
                conn: Arc::new(Mutex::new(Some(conn))),
                busy: Arc::new(AtomicBool::new(false)),
                killer,
            }) as Box<dyn Connection>)
        })
    }
}

/// The connection options of a request. Refuses what the driver cannot do
/// safely, before any I/O.
fn opts(request: &ConnectRequest) -> Result<Opts> {
    if request.transport.is_some() {
        return Err(Error::user(
            "the MySQL driver cannot connect through a tunnel yet: its client library opens \
             its own socket. Remove the tunnels from the profile",
        ));
    }
    let credentials = &request.credentials;
    let ssl = ssl_opts(&request.profile.tls, &credentials.credential)?;
    let user = credentials
        .user
        .clone()
        .ok_or_else(|| Error::user("the MySQL driver needs a user name in the credentials"))?;
    let password = match &credentials.credential {
        Credential::Password(password) => Some(password.expose().to_owned()),
        // shortcut: a client certificate replaces the password; both together
        // need an SDK decision (#19). Add the password here once it is made.
        Credential::ClientCertificate { .. } => None,
        _ => {
            return Err(Error::user(
                "the MySQL driver accepts only a password or a client certificate credential",
            ));
        }
    };
    let endpoint = &request.profile.endpoint;
    Ok(OptsBuilder::default()
        .ip_or_hostname(endpoint.host.clone())
        .tcp_port(endpoint.port.unwrap_or(DEFAULT_PORT))
        .db_name(endpoint.database.clone())
        .user(Some(user))
        .pass(password)
        // Else the client switches to the Unix socket that the server names.
        .prefer_socket(false)
        .ssl_opts(ssl)
        .into())
}

/// The TLS options of `tls`, or `None` if the profile turns TLS off. A
/// client certificate `credential` is the identity of the client.
fn ssl_opts(tls: &TlsSettings, credential: &Credential) -> Result<Option<SslOpts>> {
    let identity = match credential {
        Credential::ClientCertificate {
            certificate,
            private_key,
        } => Some((certificate, private_key)),
        _ => None,
    };
    if !tls.enabled {
        if identity.is_some() {
            return Err(Error::user(
                "a client certificate needs TLS; the profile turns TLS off",
            ));
        }
        return Ok(None);
    }
    // Its key is a secret URI that only the host can resolve.
    if tls.client_certificate.is_some() {
        return Err(Error::user(
            "the MySQL driver cannot read `tls.client_certificate`: the host resolves its key \
             and passes a client certificate credential",
        ));
    }
    let roots: Vec<_> = match &tls.ca_certificate {
        // `mysql_async` reads PEM or DER and fails the connect on a bad file.
        Some(path) => vec![
            std::fs::read(path)
                .map_err(|error| {
                    Error::user(format!(
                        "cannot read the CA certificate file {}",
                        path.display()
                    ))
                    .with_source(error)
                })?
                .into(),
        ],
        None => rustls_native_certs::load_native_certs()
            .certs
            .into_iter()
            .map(|certificate| certificate.to_vec().into())
            .collect(),
    };
    if roots.is_empty() {
        return Err(Error::user(
            "the system trust store has no certificate; set `tls.ca_certificate` to the CA \
             file of the server",
        ));
    }
    let identity = match identity {
        Some((certificate, key)) => Some(client_identity(certificate, key)?),
        None => None,
    };
    Ok(Some(
        SslOpts::default()
            .with_root_certs(roots)
            .with_disable_built_in_roots(true)
            .with_client_identity(identity),
    ))
}

/// The identity of a client certificate credential. `mysql_async` parses
/// the PEM only at connect; this check gives a `user` error before any I/O.
/// An error names no part of the key.
fn client_identity(certificate: &str, key: &Secret) -> Result<ClientIdentity> {
    let chain = CertificateDer::pem_slice_iter(certificate.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| {
            Error::user("the client certificate is not valid PEM").with_source(error)
        })?;
    if chain.is_empty() {
        return Err(Error::user("the client certificate has no PEM certificate"));
    }
    // No source: a PEM error can quote a line of the key.
    PrivateKeyDer::from_pem_slice(key.expose().as_bytes())
        .map_err(|_| Error::user("the key of the client certificate is not a PEM private key"))?;
    Ok(ClientIdentity::new(
        certificate.as_bytes().to_vec().into(),
        key.expose().as_bytes().to_vec().into(),
    ))
}

/// Maps an error of `mysql_async` to the categories of the [`Driver`] doc.
/// The message is the text of the error. No `mysql_async` error contains
/// the connection options, so it has no password.
fn error(error: mysql_async::Error) -> Error {
    let message = format!("MySQL: {error}");
    match &error {
        mysql_async::Error::Server(server) => match server.code {
            code::ACCESS_DENIED
            | code::DATABASE_ACCESS_DENIED
            | code::HOST_NOT_PRIVILEGED
            | code::ACCESS_DENIED_NO_PASSWORD => Error::auth(message),
            code::QUERY_INTERRUPTED => Error::cancelled(message),
            _ => Error::user(message),
        },
        mysql_async::Error::Io(_)
        | mysql_async::Error::Driver(
            mysql_async::DriverError::ConnectionClosed
            | mysql_async::DriverError::NoClientSslFlagFromServer,
        ) => Error::connectivity(message),
        _ => Error::internal(message),
    }
}

/// Stops the statement that runs on one connection, from a second
/// connection. Holds the options of the first connection, with the
/// password: it has no `Debug`.
struct Killer {
    opts: Opts,
    id: u32,
}

impl Killer {
    async fn kill(&self) -> Result<()> {
        let mut conn = Conn::new(self.opts.clone()).await.map_err(error)?;
        let killed = conn
            .query_drop(format!("KILL QUERY {}", self.id))
            .await
            .map_err(error);
        // The kill has worked or failed; a failed close changes nothing.
        let _ = conn.disconnect().await;
        killed
    }
}

/// One open MySQL connection. `None` in the slot: the connection is closed.
struct MysqlConnection {
    conn: Arc<Mutex<Option<Conn>>>,
    /// `true` while a statement has a result that is not read to its end.
    busy: Arc<AtomicBool>,
    killer: Arc<Killer>,
}

impl Connection for MysqlConnection {
    fn execute(&self, statement: String) -> BoxFuture<'_, Result<ResultSet>> {
        Box::pin(async move {
            let mut lease = Lease {
                slot: Some(Arc::clone(&self.conn).lock_owned().await),
                busy: Arc::clone(&self.busy),
                killer: Arc::clone(&self.killer),
                querying: false,
            };
            if self.busy.load(Ordering::SeqCst) {
                // A result was dropped where no runtime could stop it.
                stop(lease.slot(), &self.killer).await;
                self.busy.store(false, Ordering::SeqCst);
            }
            lease.querying = true;
            let conn = lease
                .slot()
                .as_mut()
                .ok_or_else(|| Error::connectivity("the MySQL connection is closed"))?;
            self.busy.store(true, Ordering::SeqCst);
            // `mysql_async` always enables multi-statements and has no switch for it. The
            // server parses a prepared statement as exactly one statement, so a second one
            // is refused here, before anything runs.
            let single = match conn.prep(statement.as_str()).await {
                Ok(prepared) => conn.close(prepared).await,
                // The server parsed the text as one statement before it refused to prepare it
                // (a text with two statements fails earlier, with 1064), so it may run.
                Err(mysql_async::Error::Server(server)) if server.code == code::UNSUPPORTED_PS => {
                    Ok(())
                }
                Err(error) => Err(error),
            };
            let columns = match single {
                Ok(()) => conn
                    .query_iter(statement)
                    .await
                    .map(|result| result.columns()),
                Err(error) => Err(error),
            };
            lease.querying = false;
            let columns = match columns {
                Ok(Some(columns)) if !columns.is_empty() => columns,
                // No result set, for example `create table`, or an error.
                other => {
                    self.busy.store(false, Ordering::SeqCst);
                    other.map_err(error)?;
                    let empty: RecordBatchStream = Box::pin(futures_util::stream::empty());
                    return ResultSet::new(Arc::new(Schema::empty()), Vec::new(), empty);
                }
            };
            let (mut fields, mut metadata, mut kinds) = (Vec::new(), Vec::new(), Vec::new());
            for column in columns.iter() {
                let (field, column, kind) = types::describe(column);
                fields.push(field);
                metadata.push(column);
                kinds.push(kind);
            }
            let reader = Reader {
                lease,
                schema: Arc::new(Schema::new(fields)),
                kinds,
            };
            let schema = Arc::clone(&reader.schema);
            let batches = futures_util::stream::unfold(Some(reader), |reader| async move {
                let mut reader = reader?;
                match reader.next_batch().await {
                    Ok(Some((batch, more))) => Some((Ok(batch), more.then_some(reader))),
                    Ok(None) => None,
                    Err(error) => Some((Err(error), None)),
                }
            });
            ResultSet::new(schema, metadata, Box::pin(batches))
        })
    }

    fn cancel(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            if self.busy.load(Ordering::SeqCst) {
                self.killer.kill().await
            } else {
                Ok(())
            }
        })
    }
}

type RecordBatchStream = rivet_sdk::model::RecordBatchStream;

/// The lock on the connection for one statement. If it is dropped before
/// the result is read to its end, it stops the statement.
struct Lease {
    slot: Option<OwnedMutexGuard<Option<Conn>>>,
    busy: Arc<AtomicBool>,
    killer: Arc<Killer>,
    /// `true` while the driver waits for the first answer to a statement.
    querying: bool,
}

impl Lease {
    fn slot(&mut self) -> &mut Option<Conn> {
        // Only `drop` takes the guard.
        self.slot
            .as_mut()
            .expect("the lease holds the lock until drop")
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if !self.busy.load(Ordering::SeqCst) {
            return;
        }
        if self.querying
            && let Some(slot) = self.slot.as_mut()
        {
            // The answer to the statement is not read: the next statement
            // would read it. The connection cannot be used again.
            slot.take();
        }
        // Without a runtime, the next `execute` stops the statement.
        let (Some(mut slot), Ok(runtime)) =
            (self.slot.take(), tokio::runtime::Handle::try_current())
        else {
            return;
        };
        let (busy, killer) = (Arc::clone(&self.busy), Arc::clone(&self.killer));
        runtime.spawn(async move {
            stop(&mut slot, &killer).await;
            busy.store(false, Ordering::SeqCst);
        });
    }
}

/// Stops the statement whose result is not read to its end, and reads the
/// rest of the result. If the kill fails, it closes the connection: to read
/// an endless result to its end would never finish.
async fn stop(slot: &mut Option<Conn>, killer: &Killer) {
    let killed = matches!(
        tokio::time::timeout(KILL_TIMEOUT, killer.kill()).await,
        Ok(Ok(()))
    );
    if killed && let Some(conn) = slot.as_mut() {
        let rest = QueryResult::<'_, '_, TextProtocol>::new(conn);
        // `KILL QUERY` ends the result with an error: the connection is good.
        match rest.drop_result().await {
            Ok(()) => return,
            Err(error) if !error.is_fatal() => return,
            Err(_) => {}
        }
    }
    if let Some(conn) = slot.take() {
        // shortcut: in mysql_async 0.37 `disconnect` marks the `Conn` as closed before it
        // reads the rest of the result; dropped at the timeout, the `Conn` then closes its
        // socket and reads nothing. A plain drop would read the rest in a spawned task,
        // forever for an endless result. Check it when mysql_async is updated (test
        // `failed_kill_frees_the_lock_and_closes_the_socket`).
        // The connection is given up; a failed or late close changes nothing.
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, conn.disconnect()).await;
    }
}

/// Reads the rows of one result, one batch at a time.
struct Reader {
    lease: Lease,
    schema: SchemaRef,
    kinds: Vec<Kind>,
}

impl Reader {
    /// Reads up to [`BATCH_ROWS`] rows. Gives the batch and `true` if more
    /// rows can follow, or `None` at the end.
    async fn next_batch(&mut self) -> Result<Option<(RecordBatch, bool)>> {
        let busy = Arc::clone(&self.lease.busy);
        let conn = self
            .lease
            .slot()
            .as_mut()
            .ok_or_else(|| Error::connectivity("the MySQL connection is closed"))?;
        let mut columns: Vec<Vec<Value>> = vec![Vec::with_capacity(BATCH_ROWS); self.kinds.len()];
        let mut rows = 0;
        let mut more = true;
        while rows < BATCH_ROWS {
            // shortcut: `QueryResult::next` is public but hidden in the docs of
            // mysql_async 0.37; it is the one row-by-row read on an owned `Conn`.
            // Check it when mysql_async is updated.
            let row = QueryResult::<'_, '_, TextProtocol>::new(&mut *conn)
                .next()
                .await;
            match row {
                Ok(Some(row)) => {
                    for (column, value) in columns.iter_mut().zip(row.unwrap()) {
                        column.push(value);
                    }
                    rows += 1;
                }
                Ok(None) => {
                    busy.store(false, Ordering::SeqCst);
                    more = false;
                    break;
                }
                Err(failure) => {
                    // The server ended the result with an error.
                    busy.store(false, Ordering::SeqCst);
                    return Err(error(failure));
                }
            }
        }
        if rows == 0 {
            return Ok(None);
        }
        let arrays = self
            .kinds
            .iter()
            .zip(columns)
            .zip(self.schema.fields())
            .map(|((kind, values), field)| kind.array(field.name(), values))
            .collect::<Result<Vec<_>>>()?;
        let batch = RecordBatch::try_new(Arc::clone(&self.schema), arrays)
            .map_err(|failure| Error::internal(format!("a MySQL record batch: {failure}")))?;
        Ok(Some((batch, more)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rivet_sdk::error::ErrorCategory;
    use rivet_sdk::extension::{ByteStream, Credentials};
    use rivet_sdk::manifest::{ExtensionPoint, Manifest};
    use rivet_sdk::model::{ConnectionProfile, Endpoint, ProviderRef, TlsSettings};
    use rivet_sdk::secret::Secret;
    use std::time::Duration;
    use tokio::net::TcpListener;

    const PASSWORD: &str = "unit-test-password-9f3a";

    fn request(port: u16, tls: bool) -> ConnectRequest {
        let profile = ConnectionProfile::new(
            ProviderRef::new("mysql"),
            Endpoint::new("127.0.0.1").with_port(port),
            ProviderRef::new("password"),
        )
        .with_tls(TlsSettings::new().with_enabled(tls));
        let password = Credential::Password(Secret::from(PASSWORD.to_owned()));
        ConnectRequest::new(profile, Credentials::new(password).with_user("app"))
    }

    async fn connect_error(request: ConnectRequest) -> Error {
        match MysqlDriver.connect(request).await {
            Ok(_) => panic!("the connection must fail"),
            Err(error) => error,
        }
    }

    /// A port where a listener waits. Returns the listener, to check that
    /// nobody connected.
    async fn listener() -> (TcpListener, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    async fn assert_no_connection(listener: &TcpListener) {
        let accepted = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(accepted.is_err(), "the driver opened a socket");
    }

    fn assert_no_password(error: &Error) {
        assert!(!format!("{error:?}").contains(PASSWORD), "{error:?}");
        assert!(!error.to_string().contains(PASSWORD), "{error}");
    }

    #[test]
    fn manifest_contributes_the_driver_point() {
        let manifest = Manifest::parse(include_str!("../extension.toml")).unwrap();
        assert_eq!(manifest.id.as_str(), "rivet.mysql");
        assert_eq!(manifest.contributes.len(), 1);
        assert_eq!(manifest.contributes[0].kind, ExtensionPoint::Driver);
        assert_eq!(manifest.contributes[0].id.as_str(), "mysql");
        assert_eq!(manifest.version.to_string(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn dialect_is_mysql_with_backtick() {
        let dialect = MysqlDriver.dialect();
        assert_eq!(
            (dialect.name.as_str(), dialect.identifier_quote),
            ("mysql", '`')
        );
    }

    #[tokio::test]
    async fn client_certificate_is_refused_without_a_connection() {
        let (listener, port) = listener().await;
        let mut request = request(port, true);
        let key = "keychain://rivet/client-key".parse().unwrap();
        request.profile.tls = TlsSettings::new()
            .with_client_certificate(rivet_sdk::model::ClientCertificate::new("c.pem", key));
        let error = connect_error(request).await;
        assert_eq!(error.category(), ErrorCategory::User);
        assert!(error.message().contains("client certificate"), "{error:?}");
        assert_no_password(&error);
        assert_no_connection(&listener).await;
    }

    fn password() -> Credential {
        Credential::Password(Secret::from(PASSWORD.to_owned()))
    }

    /// The text of a key that must appear in no error.
    const KEY: &str =
        "-----BEGIN PRIVATE KEY-----\nkey-text-that-must-not-leak\n-----END PRIVATE KEY-----\n";

    fn client_certificate(certificate: &str) -> Credential {
        Credential::ClientCertificate {
            certificate: certificate.to_owned(),
            private_key: Secret::from(KEY.to_owned()),
        }
    }

    #[tokio::test]
    async fn bad_client_certificate_is_refused_without_a_connection() {
        let certificate = "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n";
        for (tls, certificate, says) in [
            (false, certificate, "needs TLS"),
            (true, "no PEM here", "no PEM certificate"),
            (true, certificate, "not a PEM private key"),
        ] {
            let (listener, port) = listener().await;
            let mut request = request(port, tls);
            request.credentials.credential = client_certificate(certificate);
            let error = connect_error(request).await;
            assert_eq!(error.category(), ErrorCategory::User, "{error:?}");
            assert!(error.message().contains(says), "{error:?}");
            assert!(!format!("{error:?}").contains("must-not-leak"), "{error:?}");
            assert_no_connection(&listener).await;
        }
    }

    #[tokio::test]
    async fn missing_ca_file_is_refused_without_a_connection() {
        let (listener, port) = listener().await;
        let mut request = request(port, true);
        let path = std::env::temp_dir().join("rivet-mysql-no-such-ca.pem");
        request.profile.tls = TlsSettings::new().with_ca_certificate(path.clone());
        let error = connect_error(request).await;
        assert_eq!(error.category(), ErrorCategory::User);
        assert!(
            error.message().contains(&*path.to_string_lossy()),
            "{error:?}"
        );
        assert_no_connection(&listener).await;
    }

    #[test]
    fn tls_uses_only_the_chosen_roots() {
        assert!(
            ssl_opts(&TlsSettings::new().with_enabled(false), &password())
                .unwrap()
                .is_none()
        );
        let system = ssl_opts(&TlsSettings::new(), &password()).unwrap().unwrap();
        assert!(system.disable_built_in_roots());
        assert!(!system.root_certs().is_empty());
        assert!(!system.accept_invalid_certs() && !system.skip_domain_validation());
        let path = std::env::temp_dir().join(format!("rivet-mysql-ca-{}.pem", std::process::id()));
        std::fs::write(&path, "pinned").unwrap();
        let pinned = ssl_opts(
            &TlsSettings::new().with_ca_certificate(path.clone()),
            &password(),
        );
        std::fs::remove_file(&path).unwrap();
        let pinned = pinned.unwrap().unwrap();
        assert!(pinned.disable_built_in_roots());
        assert_eq!(pinned.root_certs().len(), 1, "only the pinned CA");
    }

    struct NoStream;

    impl ByteStream for NoStream {
        fn read(&self, _max: usize) -> BoxFuture<'_, Result<Vec<u8>>> {
            panic!("the driver must not read the transport")
        }

        fn write(&self, _data: Vec<u8>) -> BoxFuture<'_, Result<()>> {
            panic!("the driver must not write the transport")
        }
    }

    #[tokio::test]
    async fn request_with_transport_is_refused_without_a_socket() {
        let (listener, port) = listener().await;
        let request = request(port, false).with_transport(Box::new(NoStream));
        let error = connect_error(request).await;
        assert_eq!(error.category(), ErrorCategory::User);
        assert!(error.message().contains("tunnel"), "{error:?}");
        assert_no_password(&error);
        assert_no_connection(&listener).await;
    }

    #[tokio::test]
    async fn credentials_without_user_or_password_are_refused() {
        let mut no_user = request(1, false);
        no_user.credentials.user = None;
        let error = connect_error(no_user).await;
        assert_eq!(error.category(), ErrorCategory::User);
        assert!(error.message().contains("user name"), "{error:?}");

        let mut token = request(1, false);
        token.credentials.credential = Credential::Token(Secret::from(PASSWORD.to_owned()));
        let error = connect_error(token).await;
        assert_eq!(error.category(), ErrorCategory::User);
        assert_no_password(&error);
    }

    #[tokio::test]
    async fn unreachable_server_is_connectivity_without_the_password() {
        let (listener, port) = listener().await;
        drop(listener);
        let error = connect_error(request(port, false)).await;
        assert_eq!(error.category(), ErrorCategory::Connectivity, "{error:?}");
        assert_no_password(&error);
    }

    /// A dropped endless result whose `KILL QUERY` fails (the killer points
    /// at a closed port): the lock is freed, the next `execute` fails with
    /// `connectivity`, and the server sees the socket closed.
    #[tokio::test(flavor = "multi_thread")]
    async fn failed_kill_frees_the_lock_and_closes_the_socket() {
        use futures_util::StreamExt;
        use rivet_testkit::{conformance::Sql, database};
        if !database::containers_enabled() {
            return;
        }
        let fixture = database::mysql();
        let password = Credential::Password(Secret::from(fixture.password.expose().to_owned()));
        let credentials = Credentials::new(password).with_user(fixture.user.clone());
        let opts = opts(&ConnectRequest::new(fixture.profile.clone(), credentials)).unwrap();
        let conn = Conn::new(opts.clone()).await.unwrap();
        let id = conn.id();
        let (closed, port) = listener().await;
        drop(closed);
        let connection = MysqlConnection {
            conn: Arc::new(Mutex::new(Some(conn))),
            busy: Arc::new(AtomicBool::new(false)),
            killer: Arc::new(Killer {
                opts: OptsBuilder::from_opts(opts.clone()).tcp_port(port).into(),
                id,
            }),
        };

        let mut result = connection.execute(Sql::mysql().endless).await.unwrap();
        result.next().await.unwrap().unwrap();
        drop(result);
        let next = connection.execute("select 1".to_owned());
        let error = tokio::time::timeout(Duration::from_secs(5), next)
            .await
            .expect("the lock must be freed")
            .map(|_| ())
            .unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Connectivity, "{error:?}");

        let mut observer = Conn::new(opts).await.unwrap();
        let alive = format!("select count(*) from information_schema.processlist where id = {id}");
        for _ in 0..50 {
            let count: Option<u64> = observer.query_first(alive.as_str()).await.unwrap();
            if count == Some(0) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the server still runs connection {id}");
    }

    #[test]
    fn maps_mysql_errors_to_the_categories_of_the_driver_doc() {
        let server = |code| {
            mysql_async::Error::Server(mysql_async::ServerError {
                code,
                message: "server text".to_owned(),
                state: "HY000".to_owned(),
            })
        };
        let io = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        for (failure, category) in [
            (server(1045), ErrorCategory::Auth),
            (server(1044), ErrorCategory::Auth),
            (server(1130), ErrorCategory::Auth),
            (server(1698), ErrorCategory::Auth),
            (server(1317), ErrorCategory::Cancelled),
            (server(1064), ErrorCategory::User),
            (server(1146), ErrorCategory::User),
            (
                mysql_async::Error::Io(io.into()),
                ErrorCategory::Connectivity,
            ),
            (
                mysql_async::DriverError::ConnectionClosed.into(),
                ErrorCategory::Connectivity,
            ),
            (
                mysql_async::DriverError::NoClientSslFlagFromServer.into(),
                ErrorCategory::Connectivity,
            ),
            (
                mysql_async::DriverError::UnexpectedPacket {
                    payload: Vec::new(),
                }
                .into(),
                ErrorCategory::Internal,
            ),
        ] {
            let text = failure.to_string();
            let mapped = error(failure);
            assert_eq!(mapped.category(), category, "{text}");
            assert_eq!(mapped.message(), format!("MySQL: {text}"));
        }
    }
}
