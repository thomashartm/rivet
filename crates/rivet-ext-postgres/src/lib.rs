//! The PostgreSQL driver of rivet: [`PostgresDriver`] implements the
//! [`Driver`] contract of `rivet-sdk` on top of the `tokio-postgres` crate.
//! No other crate sees `tokio-postgres`.
//!
//! The driver needs a Tokio runtime: each connection runs a background task.
//!
//! | Topic | Behaviour |
//! | --- | --- |
//! | Login | The user comes from the [`Credentials`] of the request, with a password or a client certificate credential. Other credentials are refused with `auth`. |
//! | TLS | On if `tls.enabled` (the default): rustls, TLS 1.2 or 1.3, the server certificate and the host name of the endpoint are verified. The trust store is the system store, or only the `tls.ca_certificate` file. The cancel request uses TLS too. A server without TLS is refused. |
//! | Client certificate | A [`Credential::ClientCertificate`] is shown in the TLS handshake of the login and of the cancel request; it replaces the password. With TLS off it is refused with `user`. A `tls.client_certificate` in the profile is refused with `user`: the host resolves its key and passes the credential. |
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
use rivet_sdk::secret::Secret;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio::task::AbortHandle;
use tokio_postgres::config::SslMode;
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};
use tokio_postgres::{CancelToken, Client, NoTls, SimpleQueryMessage, SimpleQueryStream};
use tokio_postgres_rustls::MakeRustlsConnect;

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
    let tls = tls(&profile, &credentials.credential)?;
    let config = config(&profile, &credentials)?;
    let (client, target, tunnel) = match transport {
        Some(transport) => {
            let (client, task) = start(&config, Transport::new(transport), tls.as_ref()).await?;
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
            let (client, _) = start(&config, open_socket(&target).await?, tls.as_ref()).await?;
            (client, Some(target), None)
        }
    };
    let cancel = Canceller {
        token: client.cancel_token(),
        target,
        tls,
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
    let mut config = tokio_postgres::Config::new();
    match &credentials.credential {
        Credential::Password(password) => {
            config.password(password.expose());
        }
        // shortcut: a client certificate replaces the password; both together
        // need an SDK decision (#19). Add the password here once it is made.
        Credential::ClientCertificate { .. } => {}
        _ => {
            return Err(Error::auth(
                "the PostgreSQL driver accepts only a password or a client certificate \
                 credential",
            ));
        }
    }
    config
        .user(user)
        // `Require` with a verifying connector: no fallback to plaintext.
        .ssl_mode(if profile.tls.enabled {
            SslMode::Require
        } else {
            SslMode::Disable
        })
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

/// The TLS of a connection: the connector and the host name that the server
/// certificate must have.
#[derive(Clone)]
struct Tls {
    connector: MakeRustlsConnect,
    host: String,
}

impl Tls {
    fn connect<S>(&self) -> <MakeRustlsConnect as MakeTlsConnect<S>>::TlsConnect
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        match MakeTlsConnect::<S>::make_tls_connect(&mut self.connector.clone(), &self.host) {
            Ok(connect) => connect,
            Err(never) => match never {},
        }
    }
}

/// The TLS of `profile`, or `None` if the profile turns TLS off. A
/// client certificate `credential` is the identity of the client.
fn tls(profile: &ConnectionProfile, credential: &Credential) -> Result<Option<Tls>> {
    let settings = &profile.tls;
    let identity = match credential {
        Credential::ClientCertificate {
            certificate,
            private_key,
        } => Some((certificate, private_key)),
        _ => None,
    };
    if !settings.enabled {
        if identity.is_some() {
            return Err(Error::user(
                "a client certificate needs TLS; the profile turns TLS off",
            ));
        }
        return Ok(None);
    }
    // Its key is a secret URI that only the host can resolve.
    if settings.client_certificate.is_some() {
        return Err(Error::user(
            "the PostgreSQL driver cannot read `tls.client_certificate`: the host resolves \
             its key and passes a client certificate credential",
        ));
    }
    let mut roots = rustls::RootCertStore::empty();
    match &settings.ca_certificate {
        Some(path) => {
            let unreadable = |error: rustls::pki_types::pem::Error| {
                Error::user(format!(
                    "cannot read the CA certificate file {}",
                    path.display()
                ))
                .with_source(error)
            };
            for certificate in CertificateDer::pem_file_iter(path).map_err(unreadable)? {
                roots
                    .add(certificate.map_err(unreadable)?)
                    .map_err(|error| {
                        Error::user(format!(
                            "{} has a certificate that is not a valid CA certificate",
                            path.display()
                        ))
                        .with_source(error)
                    })?;
            }
            if roots.is_empty() {
                return Err(Error::user(format!(
                    "{} has no PEM certificate",
                    path.display()
                )));
            }
        }
        None => {
            let (added, _) =
                roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
            if added == 0 {
                return Err(Error::user(
                    "the system trust store has no certificate; set `tls.ca_certificate` to \
                     the CA file of the server",
                ));
            }
        }
    }
    // The provider is explicit: the process default depends on crate features.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| Error::internal("the TLS provider is not usable").with_source(error))?
        .with_root_certificates(roots);
    let config = match identity {
        Some((certificate, key)) => {
            let (chain, key) = client_identity(certificate, key)?;
            config.with_client_auth_cert(chain, key).map_err(|error| {
                Error::user("the client certificate and its key are not usable").with_source(error)
            })?
        }
        None => config.with_no_client_auth(),
    };
    Ok(Some(Tls {
        connector: MakeRustlsConnect::new(config),
        host: profile.endpoint.host.clone(),
    }))
}

/// The certificate chain and the key of a client certificate credential,
/// from PEM. An error names no part of the key.
fn client_identity(
    certificate: &str,
    key: &Secret,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let chain = CertificateDer::pem_slice_iter(certificate.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| {
            Error::user("the client certificate is not valid PEM").with_source(error)
        })?;
    if chain.is_empty() {
        return Err(Error::user("the client certificate has no PEM certificate"));
    }
    // No source: a PEM error can quote a line of the key.
    let key = PrivateKeyDer::from_pem_slice(key.expose().as_bytes())
        .map_err(|_| Error::user("the key of the client certificate is not a PEM private key"))?;
    Ok((chain, key))
}

/// Two handles of one socket. The cancel request consumes the first (also
/// inside TLS); the second waits for the server to close the socket.
fn twin(socket: TcpStream) -> std::io::Result<(TcpStream, TcpStream)> {
    let socket = socket.into_std()?;
    let watch = socket.try_clone()?;
    Ok((TcpStream::from_std(socket)?, TcpStream::from_std(watch)?))
}

/// Logs in over `stream` and starts the background task of the connection.
/// To abort the task drops `stream`. `tls` is `None` for plaintext.
async fn start<S>(
    config: &tokio_postgres::Config,
    stream: S,
    tls: Option<&Tls>,
) -> Result<(Client, AbortHandle)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match tls {
        Some(tls) => login(config, stream, tls.connect::<S>()).await,
        None => login(config, stream, NoTls).await,
    }
}

async fn login<S, T>(
    config: &tokio_postgres::Config,
    stream: S,
    tls: T,
) -> Result<(Client, AbortHandle)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    T: TlsConnect<S>,
    T::Stream: Send + 'static,
{
    let (client, connection) = tokio::time::timeout(LOGIN_TIMEOUT, config.connect_raw(stream, tls))
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
    // `tokio-postgres` has no TLS test and its text leaves out the cause (for
    // example a wrong certificate); the unit and container tests pin the text.
    if error.to_string() == "error performing TLS handshake" {
        let cause = std::error::Error::source(&error).map_or(String::new(), |c| format!(": {c}"));
        let message = format!("PostgreSQL: the TLS connection failed{cause}");
        return Error::connectivity(message).with_source(error);
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
    /// The TLS of the connection; the cancel request uses it too.
    tls: Option<Tls>,
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
            let (socket, mut watch) = twin(open_socket(target).await?).map_err(|error| {
                Error::connectivity("cannot prepare the cancel socket").with_source(error)
            })?;
            let sent = match &self.tls {
                Some(tls) => {
                    self.token
                        .cancel_query_raw(socket, tls.connect::<TcpStream>())
                        .await
                }
                None => self.token.cancel_query_raw(socket, NoTls).await,
            };
            sent.map_err(map_error)?;
            // The server closes the socket after it has passed the request on.
            // A later statement thus cannot get the cancel.
            let _ = watch.read_to_end(&mut Vec::new()).await;
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
