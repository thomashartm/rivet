//! The PostgreSQL driver of rivet: [`PostgresDriver`] implements the
//! [`Driver`] contract of `rivet-sdk` on top of the `tokio-postgres` crate.
//! No other crate sees `tokio-postgres`.
//!
//! The driver needs a Tokio runtime: each connection runs a background task.
//!
//! | Topic | Behaviour |
//! | --- | --- |
//! | Login | The user and the password come from the [`Credentials`] of the request. Other credentials are refused with `auth`. |
//! | TLS | Not supported yet (#19). A profile with `tls.enabled = true` is refused with `user`; the driver does not connect. |
//! | Transport | If the request has a transport, the protocol runs over it and the driver opens no socket. |
//! | Types | See the table on [`PostgresDriver`]. |
//! | Rows | Read in batches of [`BATCH_ROWS`] rows, only as fast as the [`ResultSet`] is read. |
//!
//! # Cancel and drop
//!
//! PostgreSQL stops a running statement only with a cancel request on a
//! second connection. Without a transport the driver opens that connection
//! to the host and port of the profile. With a transport it cannot: it has
//! one stream only. Then:
//!
//! - [`Connection::cancel`] fails with `connectivity` and does nothing.
//! - To drop an unfinished [`ResultSet`] closes the connection: the driver
//!   drops the transport stream. The server ends the statement when it sees
//!   the closed stream. Each later [`Connection::execute`] fails with
//!   `connectivity`; the caller opens a new connection.
//!
//! Without a transport, to drop an unfinished [`ResultSet`] sends the cancel
//! request, and the connection stays usable.

mod transport;
mod types;

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use arrow_array::{RecordBatch, RecordBatchOptions};
use arrow_schema::{Field, Schema, SchemaRef};
use futures_core::Stream;
use rivet_sdk::error::{Error, ErrorCategory, Result};
use rivet_sdk::extension::{
    BoxFuture, ConnectRequest, Connection, Credential, Credentials, Dialect, Driver,
};
use rivet_sdk::model::{ColumnMetadata, ConnectionProfile, ResultSet};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio::task::AbortHandle;
use tokio_postgres::config::SslMode;
use tokio_postgres::{CancelToken, Client, NoTls, SimpleQueryMessage, SimpleQueryStream};

use crate::transport::Transport;
use crate::types::ColumnBuilder;

/// The number of rows in each record batch. The last batch can have fewer.
pub const BATCH_ROWS: usize = 1024;

/// The port of PostgreSQL if the endpoint has none.
const DEFAULT_PORT: u16 = 5432;

/// The time limit of the login. The SDK has no connect timeout; without a
/// limit a server that accepts the socket and never answers hangs the caller.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(30);

/// The time limit of the whole cancel request. The background task of a
/// dropped result holds the `busy` lock until the cancel ends.
const CANCEL_TIMEOUT: Duration = Duration::from_secs(10);

/// The PostgreSQL driver.
///
/// [`Connection::execute`] gives these Arrow types. Each column can be NULL.
///
/// | PostgreSQL type | Arrow type |
/// | --- | --- |
/// | `boolean` | `Boolean` |
/// | `smallint`, `integer`, `bigint` | `Int16`, `Int32`, `Int64` |
/// | `real`, `double precision` | `Float32`, `Float64` |
/// | `bytea` | `Binary` |
/// | each other type, also `text` and `varchar` | `Utf8`: the text form of PostgreSQL |
///
/// [`ColumnMetadata::source_type`] has the PostgreSQL type name, for
/// example `numeric`.
///
/// One call of `execute` runs one statement; it has no parameters.
#[derive(Debug, Default, Clone, Copy)]
pub struct PostgresDriver;

impl Driver for PostgresDriver {
    fn dialect(&self) -> Dialect {
        Dialect::new("postgresql", '"')
    }

    fn connect(&self, request: ConnectRequest) -> BoxFuture<'_, Result<Box<dyn Connection>>> {
        Box::pin(connect(request))
    }
}

async fn connect(request: ConnectRequest) -> Result<Box<dyn Connection>> {
    let ConnectRequest {
        profile,
        credentials,
        transport,
        ..
    } = request;
    if profile.tls.enabled {
        return Err(Error::user(
            "the PostgreSQL driver cannot use TLS yet (ticket #19); the profile asks for \
             TLS, so the driver does not connect",
        ));
    }
    let config = config(&profile, &credentials)?;
    let (client, target, tunnel) = match transport {
        Some(transport) => {
            let (client, task) = start(&config, Transport::new(transport)).await?;
            let tunnel = Tunnel {
                task,
                closed: Arc::new(AtomicBool::new(false)),
            };
            (client, None, Some(tunnel))
        }
        None => {
            let target = (
                profile.endpoint.host.clone(),
                profile.endpoint.port.unwrap_or(DEFAULT_PORT),
            );
            let (client, _) = start(&config, open_socket(&target).await?).await?;
            (client, Some(target), None)
        }
    };
    let cancel = Canceller {
        token: client.cancel_token(),
        target,
    };
    Ok(Box::new(PostgresConnection {
        client,
        cancel,
        tunnel,
        busy: Arc::new(Mutex::new(())),
    }))
}

/// The settings of the login. The password is only in the returned value.
fn config(
    profile: &ConnectionProfile,
    credentials: &Credentials,
) -> Result<tokio_postgres::Config> {
    let user = credentials
        .user
        .as_deref()
        .ok_or_else(|| Error::auth("the credentials have no user; PostgreSQL needs one"))?;
    let Credential::Password(password) = &credentials.credential else {
        return Err(Error::auth(
            "the PostgreSQL driver accepts only a password credential",
        ));
    };
    let mut config = tokio_postgres::Config::new();
    config
        .user(user)
        .password(password.expose())
        .ssl_mode(SslMode::Disable)
        // The decoder of `bytea` reads only the hex format; a role or database
        // default of `escape` must not change that.
        .options("-c bytea_output=hex");
    if let Some(database) = &profile.endpoint.database {
        config.dbname(database);
    }
    Ok(config)
}

async fn open_socket((host, port): &(String, u16)) -> Result<TcpStream> {
    TcpStream::connect((host.as_str(), *port))
        .await
        .map_err(|error| {
            Error::connectivity(format!("cannot reach PostgreSQL at {host}:{port}"))
                .with_source(error)
        })
}

/// Logs in over `stream` and starts the background task of the connection.
/// To abort the task drops `stream`.
async fn start<S>(config: &tokio_postgres::Config, stream: S) -> Result<(Client, AbortHandle)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (client, connection) =
        tokio::time::timeout(LOGIN_TIMEOUT, config.connect_raw(stream, NoTls))
            .await
            .map_err(|elapsed| {
                Error::connectivity(format!(
                    "PostgreSQL did not finish the login in {} seconds",
                    LOGIN_TIMEOUT.as_secs()
                ))
                .with_source(elapsed)
            })?
            .map_err(map_error)?;
    // The task ends when the client is dropped or the stream fails. A failure
    // reaches the caller as a `closed` error of the next call.
    let task = tokio::spawn(connection).abort_handle();
    Ok((client, task))
}

/// Returns the category of a PostgreSQL error code (SQLSTATE).
fn category(code: &str) -> ErrorCategory {
    match code {
        "57014" => ErrorCategory::Cancelled,
        // admin_shutdown, crash_shutdown, cannot_connect_now, database_dropped, idle_session_timeout
        "57P01" | "57P02" | "57P03" | "57P04" | "57P05" => ErrorCategory::Connectivity,
        _ => match &code[..code.len().min(2)] {
            // invalid_authorization_specification, invalid_password
            "28" => ErrorCategory::Auth,
            "08" => ErrorCategory::Connectivity,
            // insufficient_resources, program_limit_exceeded, system_error, internal_error
            "53" | "54" | "58" | "XX" => ErrorCategory::Database,
            _ => ErrorCategory::User,
        },
    }
}

/// Converts an error of `tokio-postgres` to an SDK error. The texts come
/// from the server or the client library; neither has the password.
fn map_error(error: tokio_postgres::Error) -> Error {
    if let Some(db) = error.as_db_error() {
        let code = db.code().code();
        let message = format!("PostgreSQL: {} (SQLSTATE {code})", db.message());
        return Error::new(category(code), message).with_source(error);
    }
    let io = std::error::Error::source(&error).is_some_and(|source| source.is::<std::io::Error>());
    let category = if error.is_closed() || io {
        ErrorCategory::Connectivity
    } else {
        ErrorCategory::Internal
    };
    Error::new(category, format!("PostgreSQL client: {error}")).with_source(error)
}

/// Sends the cancel request of PostgreSQL on a second connection.
#[derive(Clone)]
struct Canceller {
    token: CancelToken,
    /// The host and port of the server. `None` if the connection runs over a
    /// transport: then no second connection is possible.
    target: Option<(String, u16)>,
}

impl Canceller {
    async fn send(&self) -> Result<()> {
        let Some(target) = &self.target else {
            return Err(Error::connectivity(
                "cancel is not possible through a tunnel transport: PostgreSQL cancels on a \
                 second connection, and the driver has only the one stream",
            ));
        };
        let cancel = async {
            let mut socket = open_socket(target).await?;
            self.token
                .cancel_query_raw(&mut socket, NoTls)
                .await
                .map_err(map_error)?;
            // The server closes the socket after it has passed the request on.
            // A later statement thus cannot get the cancel.
            let _ = socket.read_to_end(&mut Vec::new()).await;
            Ok(())
        };
        tokio::time::timeout(CANCEL_TIMEOUT, cancel)
            .await
            .map_err(|elapsed| {
                Error::connectivity(format!(
                    "the cancel request took more than {} seconds",
                    CANCEL_TIMEOUT.as_secs()
                ))
                .with_source(elapsed)
            })?
    }
}

/// The background task of a connection over a transport.
#[derive(Clone)]
struct Tunnel {
    task: AbortHandle,
    /// Set when a dropped result closed the connection.
    closed: Arc<AtomicBool>,
}

impl Tunnel {
    /// Closes the connection: aborting the task drops the transport stream.
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.task.abort();
    }
}

struct PostgresConnection {
    client: Client,
    cancel: Canceller,
    /// `Some` if the connection runs over a transport.
    tunnel: Option<Tunnel>,
    /// Held by the result of the running statement, until it ends or its
    /// cancel request is sent.
    busy: Arc<Mutex<()>>,
}

impl Connection for PostgresConnection {
    fn execute(&self, statement: String) -> BoxFuture<'_, Result<ResultSet>> {
        Box::pin(async move {
            let busy = Arc::clone(&self.busy).lock_owned().await;
            if self
                .tunnel
                .as_ref()
                .is_some_and(|t| t.closed.load(Ordering::SeqCst))
            {
                return Err(Error::connectivity(
                    "the connection is closed: a result over the tunnel transport stopped \
                     before its statement ended, and PostgreSQL cannot cancel through a tunnel; \
                     open a new connection",
                ));
            }
            // The extended protocol gives the column types; the simple protocol
            // gives each value as text and runs the statement.
            let prepared = self.client.prepare(&statement).await.map_err(map_error)?;
            let (fields, columns): (Vec<Field>, Vec<ColumnMetadata>) = prepared
                .columns()
                .iter()
                .map(|column| {
                    let source = column.type_();
                    let field = Field::new(column.name(), types::data_type(source), true);
                    (field, ColumnMetadata::new(source.name(), true))
                })
                .unzip();
            let builders = prepared
                .columns()
                .iter()
                .map(|column| ColumnBuilder::new(column.type_()))
                .collect();
            drop(prepared);
            let rows = self
                .client
                .simple_query_raw(&statement)
                .await
                .map_err(map_error)?;
            let batches = Batches {
                rows: Box::pin(rows),
                schema: Arc::new(Schema::new(fields)),
                type_names: columns.iter().map(|c| c.source_type.clone()).collect(),
                builders,
                count: 0,
                running: Some(Running {
                    _busy: busy,
                    cancel: self.cancel.clone(),
                    tunnel: self.tunnel.clone(),
                }),
            };
            ResultSet::new(Arc::clone(&batches.schema), columns, Box::pin(batches))
        })
    }

    fn cancel(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(self.cancel.send())
    }
}

/// A statement whose result is not read to its end.
struct Running {
    _busy: OwnedMutexGuard<()>,
    cancel: Canceller,
    tunnel: Option<Tunnel>,
}

impl Running {
    /// Stops the statement and then frees the connection. Over a transport
    /// it closes the connection (see the crate doc); else it sends the
    /// cancel request in the background.
    fn stop(self) {
        if let Some(tunnel) = &self.tunnel {
            tunnel.close();
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = self.cancel.send().await;
                drop(self);
            });
        }
    }
}

/// The record batches of one statement, made only when they are read.
struct Batches {
    rows: Pin<Box<SimpleQueryStream>>,
    schema: SchemaRef,
    type_names: Vec<String>,
    builders: Vec<ColumnBuilder>,
    /// The rows in the builders.
    count: usize,
    /// `None` when the statement has ended.
    running: Option<Running>,
}

impl Batches {
    fn finish(&mut self) -> Result<RecordBatch> {
        let columns = self
            .builders
            .iter_mut()
            .map(ColumnBuilder::finish)
            .collect();
        // The row count is needed for a statement with no columns (`select;`).
        let options = RecordBatchOptions::new().with_row_count(Some(self.count));
        self.count = 0;
        RecordBatch::try_new_with_options(Arc::clone(&self.schema), columns, &options).map_err(
            |error| Error::internal("the driver made a wrong record batch").with_source(error),
        )
    }

    fn append(&mut self, row: &tokio_postgres::SimpleQueryRow) -> Result<()> {
        if row.len() != self.builders.len() {
            return Err(Error::internal(format!(
                "PostgreSQL sent a row with {} columns, not {}",
                row.len(),
                self.builders.len()
            )));
        }
        for (index, builder) in self.builders.iter_mut().enumerate() {
            builder.append(row.get(index), &self.type_names[index])?;
        }
        self.count += 1;
        Ok(())
    }
}

impl Stream for Batches {
    type Item = Result<RecordBatch>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        while this.running.is_some() {
            match this.rows.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(SimpleQueryMessage::Row(row)))) => {
                    if let Err(error) = this.append(&row) {
                        if let Some(running) = this.running.take() {
                            running.stop();
                        }
                        return Poll::Ready(Some(Err(error)));
                    }
                    if this.count == BATCH_ROWS {
                        return Poll::Ready(Some(this.finish()));
                    }
                }
                Poll::Ready(Some(Ok(_))) => {}
                Poll::Ready(Some(Err(error))) => {
                    // The statement failed: it has ended.
                    this.running = None;
                    return Poll::Ready(Some(Err(map_error(error))));
                }
                Poll::Ready(None) => {
                    this.running = None;
                    if this.count > 0 {
                        return Poll::Ready(Some(this.finish()));
                    }
                }
            }
        }
        Poll::Ready(None)
    }
}

impl Drop for Batches {
    fn drop(&mut self) {
        if let Some(running) = self.running.take() {
            running.stop();
        }
    }
}

#[cfg(test)]
mod tests;
