//! The MySQL driver extension (ARCHITECTURE.md §4.2, ticket #15).
//!
//! [`MysqlDriver`] implements the [`Driver`] contract of the SDK with the
//! crate `mysql_async`. Every use of `mysql_async` stays in this crate.
//!
//! | Rule | How |
//! | --- | --- |
//! | Bounded reads (§5.5) | The result set reads [`BATCH_ROWS`] rows from the socket for each batch it gives. |
//! | Drop of a result set | `KILL QUERY` on a second connection, then the rest of the result is read and discarded. An endless result is not read to its end. |
//! | Drop of an `execute` future before the answer | `KILL QUERY`, and the connection is closed: the next statement would read the old answer. The next `execute` gives a `connectivity` error. |
//! | `cancel` | `KILL QUERY <connection id>` on a second connection. |
//! | One statement for each `execute` | `mysql_async` cannot turn multi-statements off. The statement is prepared first: the server refuses a second statement (`user` error, code 1064) and runs none. A statement that cannot be prepared (code 1295) is refused as well. |
//! | TLS | Not supported yet (#19): a profile with TLS on is refused. |
//! | Tunnel transport | Not supported: `mysql_async` opens its own socket. A request with a transport is refused. |
//!
//! The password is in no error and no debug text of this crate.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arrow_array::RecordBatch;
use arrow_schema::{Schema, SchemaRef};
use mysql_async::prelude::Queryable;
use mysql_async::{Conn, Opts, OptsBuilder, QueryResult, TextProtocol, Value};
use rivet_sdk::error::{Error, Result};
use rivet_sdk::extension::{BoxFuture, ConnectRequest, Connection, Credential, Dialect, Driver};
use rivet_sdk::model::ResultSet;
use tokio::sync::{Mutex, OwnedMutexGuard};

mod types;

use types::Kind;

/// The number of rows in each record batch, at most.
pub const BATCH_ROWS: usize = 1024;

/// The port of a profile that does not set one.
const DEFAULT_PORT: u16 = 3306;

/// MySQL error codes (`ER_*`) with their own error category.
mod code {
    /// `ER_DBACCESS_DENIED_ERROR`.
    pub const DATABASE_ACCESS_DENIED: u16 = 1044;
    /// `ER_ACCESS_DENIED_ERROR`: wrong user or password.
    pub const ACCESS_DENIED: u16 = 1045;
    /// `ER_HOST_NOT_PRIVILEGED`.
    pub const HOST_NOT_PRIVILEGED: u16 = 1130;
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
    if request.profile.tls.enabled {
        return Err(Error::user(
            "the MySQL driver does not support TLS yet (ticket #19). To connect in plain \
             text, set `tls.enabled = false` in the profile",
        ));
    }
    let credentials = &request.credentials;
    let user = credentials
        .user
        .clone()
        .ok_or_else(|| Error::user("the MySQL driver needs a user name in the credentials"))?;
    let Credential::Password(password) = &credentials.credential else {
        return Err(Error::user(
            "the MySQL driver accepts only a password credential",
        ));
    };
    let endpoint = &request.profile.endpoint;
    Ok(OptsBuilder::default()
        .ip_or_hostname(endpoint.host.clone())
        .tcp_port(endpoint.port.unwrap_or(DEFAULT_PORT))
        .db_name(endpoint.database.clone())
        .user(Some(user))
        .pass(Some(password.expose().to_owned()))
        // Else the client switches to the Unix socket that the server names.
        .prefer_socket(false)
        .into())
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
        | mysql_async::Error::Driver(mysql_async::DriverError::ConnectionClosed) => {
            Error::connectivity(message)
        }
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
    let killed = killer.kill().await.is_ok();
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
        // The connection is given up; a failed close changes nothing.
        let _ = conn.disconnect().await;
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
    async fn profile_with_tls_is_refused_without_a_connection() {
        let (listener, port) = listener().await;
        let error = connect_error(request(port, true)).await;
        assert_eq!(error.category(), ErrorCategory::User);
        assert!(error.message().contains("TLS"), "{error:?}");
        assert!(error.message().contains("#19"), "{error:?}");
        assert_no_password(&error);
        assert_no_connection(&listener).await;
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
