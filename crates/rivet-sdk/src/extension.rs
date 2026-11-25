//! The extension point contracts (ARCHITECTURE.md §4.2): one trait for each
//! headless extension point. The UI extension points are in `rivet-ui-sdk`.
//!
//! The module contains contracts and plain data only (§3.3). It contains no
//! implementation and no database-specific, dialect-specific or
//! cloud-specific code.
//!
//! # Rules that apply to every contract
//!
//! - Each trait is `Send + Sync` and is used as a trait object.
//! - An operation that can do I/O returns a [`BoxFuture`]. Rust 1.100 does
//!   not permit `async fn` in a trait that is used as a trait object.
//! - Parameters and results are owned plain data, so each trait can be
//!   mirrored as a WIT interface and in the C ABI (§4.1).
//! - Every failure is an [`Error`](crate::error::Error) of the SDK error
//!   model (§5.6).
//! - The host owns every resource (§5.2). To drop a trait object or a
//!   returned future releases what it holds.
//! - [`Contract`] links each trait to its
//!   [`ExtensionPoint`] in the manifest.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;

use futures_core::Stream;

use crate::error::Result;
use crate::manifest::ExtensionPoint;
use crate::model::{
    Catalog, CatalogObject, ConnectionProfile, ExtensionFields, ProviderRef, ResultSet,
};
use crate::secret::Secret;

/// The future that an asynchronous contract method returns.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A stream of byte chunks, for example the content of a file (§5.5). An
/// `Err` item ends the stream.
pub type ByteChunkStream = Pin<Box<dyn Stream<Item = Result<Vec<u8>>> + Send>>;

/// Links the trait object type of a contract to its extension point, for
/// example `<dyn Driver as Contract>::POINT`.
///
/// Each [`ExtensionPoint`] has exactly one contract. Only `rivet-sdk` and
/// `rivet-ui-sdk` implement this trait.
pub trait Contract {
    /// The extension point of the contract.
    const POINT: ExtensionPoint;
}

/// A two-way byte stream, for example a TCP connection or a tunnel channel.
///
/// The SDK defines this trait itself because it must be free of I/O and of
/// an async runtime, and because owned buffers map directly to WIT and to
/// the C ABI.
///
/// One `read` and one `write` can run at the same time. Two calls of the
/// same method must not run at the same time. To drop the stream closes it.
pub trait ByteStream: Send + Sync {
    /// Reads up to `max` bytes. `max` is 1 or more. An empty result means
    /// the other side closed the stream.
    fn read(&self, max: usize) -> BoxFuture<'_, Result<Vec<u8>>>;

    /// Writes all of `data`.
    fn write(&self, data: Vec<u8>) -> BoxFuture<'_, Result<()>>;
}

/// What a [`Driver`] reports about the SQL dialect of its database.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Dialect {
    /// The name of the dialect, for example `postgresql`.
    pub name: String,
    /// The character that quotes an identifier, for example `"`.
    pub identifier_quote: char,
    /// Details that only some clients of the driver understand. The key
    /// starts with the id of the extension that owns it.
    pub extensions: ExtensionFields,
}

impl Dialect {
    /// Creates a dialect with no extension fields.
    ///
    /// ```
    /// use rivet_sdk::extension::Dialect;
    ///
    /// let dialect = Dialect::new("postgresql", '"');
    /// assert!(dialect.extensions.is_empty());
    /// ```
    pub fn new(name: impl Into<String>, identifier_quote: char) -> Self {
        Self {
            name: name.into(),
            identifier_quote,
            extensions: ExtensionFields::new(),
        }
    }

    /// Sets the details that only some clients of the driver understand.
    #[must_use]
    pub fn with_extensions(mut self, extensions: ExtensionFields) -> Self {
        self.extensions = extensions;
        self
    }
}

/// The input of [`Driver::connect`].
#[non_exhaustive]
pub struct ConnectRequest {
    /// The profile of the database. The driver uses `engine`, `endpoint`
    /// and `tls`.
    pub profile: ConnectionProfile,
    /// The credentials from the [`AuthProvider`] of the profile.
    pub credentials: Credentials,
    /// The stream from the last [`TunnelProvider`] of the profile. `None`
    /// means the driver opens the network connection itself.
    pub transport: Option<Box<dyn ByteStream>>,
}

impl ConnectRequest {
    /// Creates a request with no transport: the driver opens the network
    /// connection itself.
    ///
    /// ```
    /// use rivet_sdk::extension::{ConnectRequest, Credential, Credentials};
    /// use rivet_sdk::model::{ConnectionProfile, Endpoint, ProviderRef};
    /// use rivet_sdk::secret::Secret;
    ///
    /// let profile = ConnectionProfile::new(
    ///     ProviderRef::new("postgres"),
    ///     Endpoint::new("db.example.com"),
    ///     ProviderRef::new("password"),
    /// );
    /// let password = Credential::Password(Secret::from("example".to_owned()));
    /// let request = ConnectRequest::new(profile, Credentials::new(password).with_user("app"));
    /// assert!(request.transport.is_none());
    /// ```
    pub fn new(profile: ConnectionProfile, credentials: Credentials) -> Self {
        Self {
            profile,
            credentials,
            transport: None,
        }
    }

    /// Sets the stream from the last tunnel of the profile.
    #[must_use]
    pub fn with_transport(mut self, transport: Box<dyn ByteStream>) -> Self {
        self.transport = Some(transport);
        self
    }
}

/// The contract of [`ExtensionPoint::Driver`]: connects to a database and
/// describes its dialect.
pub trait Driver: Send + Sync {
    /// Describes the SQL dialect of the database.
    fn dialect(&self) -> Dialect;

    /// Opens one connection to the database.
    fn connect(&self, request: ConnectRequest) -> BoxFuture<'_, Result<Box<dyn Connection>>>;
}

/// One open database connection, made by [`Driver::connect`]. To drop it
/// closes the connection.
pub trait Connection: Send + Sync {
    /// Runs one statement. The rows arrive as a stream of Arrow record
    /// batches. The driver reads from the database only as fast as the
    /// caller reads the stream (§5.5).
    fn execute(&self, statement: String) -> BoxFuture<'_, Result<ResultSet>>;

    /// Cancels the statement that runs on this connection, in the database
    /// (§5.4). The cancelled statement fails with a `cancelled` error. It is
    /// not an error if no statement runs.
    fn cancel(&self) -> BoxFuture<'_, Result<()>>;
}

/// The secret part of [`Credentials`].
#[derive(Debug)]
#[non_exhaustive]
pub enum Credential {
    /// A password.
    Password(Secret),
    /// A token, for example a short-lived access token.
    Token(Secret),
    /// A client certificate for mutual TLS.
    ClientCertificate {
        /// The certificate chain in PEM format. A certificate is public.
        certificate: String,
        /// The private key in PEM format.
        private_key: Secret,
    },
}

/// The credentials for one connection attempt.
#[derive(Debug)]
#[non_exhaustive]
pub struct Credentials {
    /// The database user. `None` if the credential names the user itself.
    pub user: Option<String>,
    /// The secret.
    pub credential: Credential,
    /// The time after which the credentials are not valid. The host gets new
    /// credentials before this time (§5.3). `None` means no expiry.
    pub expires_at: Option<SystemTime>,
}

impl Credentials {
    /// Creates credentials with no user and no expiry.
    pub fn new(credential: Credential) -> Self {
        Self {
            user: None,
            credential,
            expires_at: None,
        }
    }

    /// Sets the database user.
    #[must_use]
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Sets the time after which the credentials are not valid.
    #[must_use]
    pub fn with_expires_at(mut self, expires_at: SystemTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
}

/// The input of [`AuthProvider::credentials`].
#[derive(Debug)]
#[non_exhaustive]
pub struct AuthRequest {
    /// The profile of the database. The auth provider uses `auth` and
    /// `endpoint`.
    pub profile: ConnectionProfile,
    /// The identity from the [`CredentialSource`] of the profile, if the
    /// profile has one.
    pub identity: Option<Identity>,
}

impl AuthRequest {
    /// Creates a request with no identity.
    pub fn new(profile: ConnectionProfile) -> Self {
        Self {
            profile,
            identity: None,
        }
    }

    /// Sets the identity from the credential source of the profile.
    #[must_use]
    pub fn with_identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }
}

/// The contract of [`ExtensionPoint::AuthProvider`]: produces the
/// credentials for a connection attempt.
pub trait AuthProvider: Send + Sync {
    /// Produces the credentials for one connection attempt, with their
    /// expiry.
    fn credentials(&self, request: AuthRequest) -> BoxFuture<'_, Result<Credentials>>;
}

/// An identity that a [`CredentialSource`] resolved. The SDK does not
/// interpret the content. The auth provider that uses the identity does.
#[derive(Debug)]
#[non_exhaustive]
pub struct Identity {
    /// The name of the identity, for example an account or a role.
    pub principal: String,
    /// The parts of the identity that are not secret, by name.
    pub attributes: ExtensionFields,
    /// The secret parts of the identity, by name.
    pub secrets: BTreeMap<String, Secret>,
    /// The time after which the identity is not valid. `None` means no
    /// expiry.
    pub expires_at: Option<SystemTime>,
}

impl Identity {
    /// Creates an identity with no attributes, no secrets and no expiry.
    ///
    /// ```
    /// use rivet_sdk::extension::Identity;
    /// use rivet_sdk::secret::Secret;
    ///
    /// let secrets = [("token".to_owned(), Secret::from("example".to_owned()))];
    /// let identity = Identity::new("role/reader").with_secrets(secrets.into());
    /// assert_eq!(identity.principal, "role/reader");
    /// assert!(identity.expires_at.is_none());
    /// ```
    pub fn new(principal: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
            attributes: ExtensionFields::new(),
            secrets: BTreeMap::new(),
            expires_at: None,
        }
    }

    /// Sets the parts of the identity that are not secret.
    #[must_use]
    pub fn with_attributes(mut self, attributes: ExtensionFields) -> Self {
        self.attributes = attributes;
        self
    }

    /// Sets the secret parts of the identity.
    #[must_use]
    pub fn with_secrets(mut self, secrets: BTreeMap<String, Secret>) -> Self {
        self.secrets = secrets;
        self
    }

    /// Sets the time after which the identity is not valid.
    #[must_use]
    pub fn with_expires_at(mut self, expires_at: SystemTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
}

/// The contract of [`ExtensionPoint::CredentialSource`]: resolves an
/// identity.
pub trait CredentialSource: Send + Sync {
    /// Resolves the identity that `source` describes. `source` is the
    /// `credential_source` of a profile. Its settings select the identity,
    /// for example a role to assume or an account to impersonate.
    fn resolve(&self, source: ProviderRef) -> BoxFuture<'_, Result<Identity>>;
}

/// The input of [`TunnelProvider::open`].
#[non_exhaustive]
pub struct TunnelRequest {
    /// The tunnel entry of the profile, with its settings.
    pub tunnel: ProviderRef,
    /// The host to reach through the tunnel.
    pub target_host: String,
    /// The port to reach on `target_host`.
    pub target_port: u16,
    /// The stream from the tunnel before this one in the profile. `None`
    /// means this tunnel opens its own network connection.
    pub transport: Option<Box<dyn ByteStream>>,
}

impl TunnelRequest {
    /// Creates a request with no transport: the tunnel opens its own network
    /// connection.
    ///
    /// ```
    /// use rivet_sdk::extension::TunnelRequest;
    /// use rivet_sdk::model::ProviderRef;
    ///
    /// let request = TunnelRequest::new(ProviderRef::new("ssh"), "db.internal", 5432);
    /// assert!(request.transport.is_none());
    /// ```
    pub fn new(tunnel: ProviderRef, target_host: impl Into<String>, target_port: u16) -> Self {
        Self {
            tunnel,
            target_host: target_host.into(),
            target_port,
            transport: None,
        }
    }

    /// Sets the stream from the tunnel before this one in the profile.
    #[must_use]
    pub fn with_transport(mut self, transport: Box<dyn ByteStream>) -> Self {
        self.transport = Some(transport);
        self
    }
}

/// The contract of [`ExtensionPoint::TunnelProvider`]: opens a byte stream
/// to a target through a tunnel or a proxy.
pub trait TunnelProvider: Send + Sync {
    /// Opens a byte stream to the target. To drop the stream closes the
    /// tunnel channel.
    fn open(&self, request: TunnelRequest) -> BoxFuture<'_, Result<Box<dyn ByteStream>>>;
}

/// The contract of [`ExtensionPoint::MetadataProvider`]: reads catalog
/// objects, generates DDL and computes diffs.
pub trait MetadataProvider: Send + Sync {
    /// Reads the catalog of the database behind `connection`.
    fn introspect(&self, connection: Arc<dyn Connection>) -> BoxFuture<'_, Result<Catalog>>;

    /// Generates the statement that creates `object`, in the dialect of the
    /// database.
    fn generate_ddl(&self, object: CatalogObject) -> BoxFuture<'_, Result<String>>;

    /// Computes the statements that change `source` into `target`, in the
    /// order to run them. An empty result means the catalogs are equal.
    fn diff(&self, source: Catalog, target: Catalog) -> BoxFuture<'_, Result<Vec<String>>>;
}

/// The contract of [`ExtensionPoint::ResultSink`]: consumes a result
/// stream, for example into a grid, a file or a network target.
pub trait ResultSink: Send + Sync {
    /// Reads `result` to its end. The sink reads only as fast as it can
    /// process the batches (§5.5).
    fn consume(&self, result: ResultSet) -> BoxFuture<'_, Result<()>>;
}

/// The contract of [`ExtensionPoint::Importer`]: converts an external format
/// to a result stream.
pub trait Importer: Send + Sync {
    /// Converts `source`, the bytes of the external format, to a result set.
    fn import(&self, source: ByteChunkStream) -> BoxFuture<'_, Result<ResultSet>>;
}

/// The contract of [`ExtensionPoint::Exporter`]: converts a result stream to
/// an external format.
pub trait Exporter: Send + Sync {
    /// Converts `result` to the bytes of the external format.
    fn export(&self, result: ResultSet) -> BoxFuture<'_, Result<ByteChunkStream>>;
}

/// The contract of [`ExtensionPoint::ModelProvider`]: sends a prompt to a
/// model and returns the response.
///
/// The engine applies the data policy and the redaction before the call
/// (§7.6). The contract gives a model provider only the prompt. It gives no
/// access to a connection.
pub trait ModelProvider: Send + Sync {
    /// Sends `prompt` to the model and returns the response.
    fn complete(&self, prompt: String) -> BoxFuture<'_, Result<String>>;
}

/// The access of a script to the engine.
///
/// This trait is a placeholder with no methods. The Engine API surface for
/// scripts (ADR-0007) is not defined yet. It is added here when
/// `rivet-engine-api` exists.
pub trait EngineHandle: Send + Sync {}

/// The contract of [`ExtensionPoint::ScriptEngine`]: runs scripts in one
/// language against the Engine API (ADR-0007).
pub trait ScriptEngine: Send + Sync {
    /// Runs `script`, the source text. The script reaches the engine only
    /// through `engine`.
    fn run(&self, script: String, engine: Arc<dyn EngineHandle>) -> BoxFuture<'_, Result<()>>;
}

/// The type of an [`Argument`]. Each type is one variant of
/// [`ExtensionValue`](crate::model::ExtensionValue).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ArgumentType {
    /// A boolean.
    Bool,
    /// A signed integer.
    Integer,
    /// A floating-point number.
    Float,
    /// A text.
    Text,
}

/// One argument of a [`Signature`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Argument {
    /// The name of the argument.
    pub name: String,
    /// One line that tells the user what the argument is.
    pub summary: String,
    /// The type of the value.
    pub value_type: ArgumentType,
    /// `true` if the caller must give the argument.
    pub required: bool,
}

impl Argument {
    /// Creates an argument that the caller can omit.
    pub fn new(
        name: impl Into<String>,
        summary: impl Into<String>,
        value_type: ArgumentType,
    ) -> Self {
        Self {
            name: name.into(),
            summary: summary.into(),
            value_type,
            required: false,
        }
    }

    /// Sets `required`. `true` means the caller must give the argument.
    #[must_use]
    pub fn with_required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }
}

/// The name and the typed arguments of a [`CliCommand`] or an
/// [`ApiEndpoint`]. The host uses it to register the contribution and to
/// validate the arguments before the call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Signature {
    /// The name of the subcommand or of the control API method.
    pub name: String,
    /// One line that tells the user what it does.
    pub summary: String,
    /// The arguments.
    pub arguments: Vec<Argument>,
}

impl Signature {
    /// Creates a signature with no arguments.
    ///
    /// ```
    /// use rivet_sdk::extension::{Argument, ArgumentType, Signature};
    ///
    /// let signature = Signature::new("export", "Exports a table to a file.").with_arguments([
    ///     Argument::new("table", "The table to export.", ArgumentType::Text).with_required(true),
    /// ]);
    /// assert!(signature.arguments[0].required);
    /// ```
    pub fn new(name: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            summary: summary.into(),
            arguments: Vec::new(),
        }
    }

    /// Sets the arguments.
    #[must_use]
    pub fn with_arguments(mut self, arguments: impl IntoIterator<Item = Argument>) -> Self {
        self.arguments = arguments.into_iter().collect();
        self
    }
}

/// The contract of [`ExtensionPoint::CliCommand`]: a CLI subcommand with
/// typed arguments.
pub trait CliCommand: Send + Sync {
    /// Describes the subcommand.
    fn signature(&self) -> Signature;

    /// Runs the subcommand. `arguments` has the values by argument name.
    /// Returns the text that the CLI prints.
    fn run(&self, arguments: ExtensionFields) -> BoxFuture<'_, Result<String>>;
}

/// The contract of [`ExtensionPoint::ApiEndpoint`]: a control API method.
pub trait ApiEndpoint: Send + Sync {
    /// Describes the method.
    fn signature(&self) -> Signature;

    /// Calls the method. `arguments` has the values by argument name.
    /// Returns the fields of the response.
    fn call(&self, arguments: ExtensionFields) -> BoxFuture<'_, Result<ExtensionFields>>;
}

impl Contract for dyn Driver {
    const POINT: ExtensionPoint = ExtensionPoint::Driver;
}
impl Contract for dyn AuthProvider {
    const POINT: ExtensionPoint = ExtensionPoint::AuthProvider;
}
impl Contract for dyn CredentialSource {
    const POINT: ExtensionPoint = ExtensionPoint::CredentialSource;
}
impl Contract for dyn TunnelProvider {
    const POINT: ExtensionPoint = ExtensionPoint::TunnelProvider;
}
impl Contract for dyn MetadataProvider {
    const POINT: ExtensionPoint = ExtensionPoint::MetadataProvider;
}
impl Contract for dyn ResultSink {
    const POINT: ExtensionPoint = ExtensionPoint::ResultSink;
}
impl Contract for dyn Importer {
    const POINT: ExtensionPoint = ExtensionPoint::Importer;
}
impl Contract for dyn Exporter {
    const POINT: ExtensionPoint = ExtensionPoint::Exporter;
}
impl Contract for dyn ModelProvider {
    const POINT: ExtensionPoint = ExtensionPoint::ModelProvider;
}
impl Contract for dyn ScriptEngine {
    const POINT: ExtensionPoint = ExtensionPoint::ScriptEngine;
}
impl Contract for dyn CliCommand {
    const POINT: ExtensionPoint = ExtensionPoint::CliCommand;
}
impl Contract for dyn ApiEndpoint {
    const POINT: ExtensionPoint = ExtensionPoint::ApiEndpoint;
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use arrow_array::{ArrayRef, Int64Array, RecordBatch};
    use arrow_schema::{DataType, Field, Schema};

    use super::*;
    use crate::error::{Error, ErrorCategory};
    use crate::model::{CatalogObjectKind, ColumnMetadata, Endpoint, ExtensionValue, TlsSettings};

    /// Runs a future that is always ready, without an async runtime.
    fn block_on<T>(mut future: BoxFuture<'_, T>) -> T {
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("the mock future is always ready"),
        }
    }

    /// A stream over a fixed list of items.
    struct Fixed<T>(VecDeque<T>);

    impl<T: Unpin> Stream for Fixed<T> {
        type Item = T;

        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<T>> {
            Poll::Ready(self.0.pop_front())
        }
    }

    fn drain<S: Stream + Unpin>(mut stream: S) -> Vec<S::Item> {
        let mut context = Context::from_waker(Waker::noop());
        let mut items = Vec::new();
        while let Poll::Ready(Some(item)) = Pin::new(&mut stream).poll_next(&mut context) {
            items.push(item);
        }
        items
    }

    /// A result set with one `bigint` column `n` and one batch.
    fn result_set(values: &[i64]) -> ResultSet {
        let schema = Arc::new(Schema::new(vec![Field::new("n", DataType::Int64, false)]));
        let column: ArrayRef = Arc::new(Int64Array::from(values.to_vec()));
        let batch = RecordBatch::try_new(schema.clone(), vec![column]).unwrap();
        let columns = vec![ColumnMetadata {
            source_type: "bigint".into(),
            nullable: false,
            extensions: ExtensionFields::new(),
        }];
        ResultSet::new(schema, columns, Box::pin(Fixed([Ok(batch)].into()))).unwrap()
    }

    fn row_count(result: ResultSet) -> usize {
        drain(result)
            .into_iter()
            .map(|batch| batch.unwrap().num_rows())
            .sum()
    }

    fn profile() -> ConnectionProfile {
        ConnectionProfile {
            engine: ProviderRef::new("test.engine"),
            endpoint: Endpoint {
                host: "db.example".into(),
                port: Some(5432),
                database: None,
            },
            auth: ProviderRef::new("test.token"),
            credential_source: Some(ProviderRef::new("test.chain")),
            tunnels: vec![ProviderRef::new("test.tunnel")],
            tls: TlsSettings::default(),
            read_only: false,
            confirm_on_write: false,
            environment: None,
        }
    }

    /// Returns to the reader what was written.
    #[derive(Default)]
    struct Loopback(Mutex<VecDeque<u8>>);

    impl ByteStream for Loopback {
        fn read(&self, max: usize) -> BoxFuture<'_, Result<Vec<u8>>> {
            Box::pin(async move {
                let mut buffer = self.0.lock().unwrap();
                let count = max.min(buffer.len());
                Ok(buffer.drain(..count).collect())
            })
        }

        fn write(&self, data: Vec<u8>) -> BoxFuture<'_, Result<()>> {
            Box::pin(async move {
                self.0.lock().unwrap().extend(data);
                Ok(())
            })
        }
    }

    struct MockDriver;

    #[derive(Default)]
    struct MockConnection {
        cancelled: AtomicBool,
    }

    impl Driver for MockDriver {
        fn dialect(&self) -> Dialect {
            Dialect {
                name: "mock".into(),
                identifier_quote: '"',
                extensions: ExtensionFields::new(),
            }
        }

        fn connect(&self, request: ConnectRequest) -> BoxFuture<'_, Result<Box<dyn Connection>>> {
            Box::pin(async move {
                match request.credentials.credential {
                    Credential::Token(_) => {
                        Ok(Box::new(MockConnection::default()) as Box<dyn Connection>)
                    }
                    _ => Err(Error::auth("the mock driver accepts only a token")),
                }
            })
        }
    }

    impl Connection for MockConnection {
        fn execute(&self, _statement: String) -> BoxFuture<'_, Result<ResultSet>> {
            Box::pin(async move {
                if self.cancelled.load(Ordering::SeqCst) {
                    return Err(Error::cancelled("the statement was cancelled"));
                }
                Ok(result_set(&[1, 2, 3]))
            })
        }

        fn cancel(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async move {
                self.cancelled.store(true, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    fn token(expires_at: Option<SystemTime>) -> Credentials {
        Credentials {
            user: Some("app".into()),
            credential: Credential::Token(String::from("t0k3n").into()),
            expires_at,
        }
    }

    fn connect(credentials: Credentials) -> Result<Box<dyn Connection>> {
        let driver: Box<dyn Driver> = Box::new(MockDriver);
        block_on(driver.connect(ConnectRequest {
            profile: profile(),
            credentials,
            transport: Some(Box::new(Loopback::default())),
        }))
    }

    #[test]
    fn driver_connects_executes_streams_cancels_and_describes_its_dialect() {
        let driver: Box<dyn Driver> = Box::new(MockDriver);
        assert_eq!(driver.dialect().name, "mock");
        assert_eq!(driver.dialect().identifier_quote, '"');

        let connection: Arc<dyn Connection> = connect(token(None)).unwrap().into();
        let result = block_on(connection.execute("select n".into())).unwrap();
        assert_eq!(result.columns()[0].source_type, "bigint");
        assert_eq!(row_count(result), 3);

        block_on(connection.cancel()).unwrap();
        let error = block_on(connection.execute("select n".into())).unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Cancelled);
    }

    #[test]
    fn driver_failure_uses_the_sdk_error_model() {
        let password = Credentials {
            credential: Credential::Password(String::from("pw").into()),
            ..token(None)
        };
        let error = connect(password).err().unwrap();
        assert_eq!(error.category(), ErrorCategory::Auth);
    }

    struct MockAuth;

    impl AuthProvider for MockAuth {
        fn credentials(&self, request: AuthRequest) -> BoxFuture<'_, Result<Credentials>> {
            Box::pin(async move {
                let identity = request
                    .identity
                    .ok_or_else(|| Error::auth("the mock auth provider needs an identity"))?;
                Ok(Credentials {
                    user: Some(identity.principal),
                    credential: Credential::Token(String::from("t0k3n").into()),
                    expires_at: identity.expires_at,
                })
            })
        }
    }

    struct MockSource;

    impl CredentialSource for MockSource {
        fn resolve(&self, source: ProviderRef) -> BoxFuture<'_, Result<Identity>> {
            Box::pin(async move {
                Ok(Identity {
                    principal: format!("identity-of-{}", source.id),
                    attributes: ExtensionFields::new(),
                    secrets: BTreeMap::from([(
                        "access_key".to_owned(),
                        String::from("k3y").into(),
                    )]),
                    expires_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(900)),
                })
            })
        }
    }

    #[test]
    fn credential_source_resolves_an_identity() {
        let source: Box<dyn CredentialSource> = Box::new(MockSource);
        let identity = block_on(source.resolve(ProviderRef::new("test.chain"))).unwrap();
        assert_eq!(identity.principal, "identity-of-test.chain");
        assert_eq!(identity.secrets["access_key"].expose(), "k3y");
        assert!(!format!("{identity:?}").contains("k3y"));
    }

    #[test]
    fn auth_provider_produces_secret_credentials_with_expiry() {
        let source: Box<dyn CredentialSource> = Box::new(MockSource);
        let identity = block_on(source.resolve(ProviderRef::new("test.chain"))).unwrap();
        let auth: Box<dyn AuthProvider> = Box::new(MockAuth);
        let credentials = block_on(auth.credentials(AuthRequest {
            profile: profile(),
            identity: Some(identity),
        }))
        .unwrap();

        assert_eq!(credentials.user.as_deref(), Some("identity-of-test.chain"));
        assert_eq!(
            credentials.expires_at,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(900))
        );
        assert!(!format!("{credentials:?}").contains("t0k3n"));
        let Credential::Token(secret) = credentials.credential else {
            panic!("the mock produces a token");
        };
        assert_eq!(secret.expose(), "t0k3n");

        let request = AuthRequest {
            profile: profile(),
            identity: None,
        };
        let error = block_on(auth.credentials(request)).unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Auth);
    }

    struct MockTunnel;

    impl TunnelProvider for MockTunnel {
        fn open(&self, request: TunnelRequest) -> BoxFuture<'_, Result<Box<dyn ByteStream>>> {
            Box::pin(async move {
                if request.target_port == 0 {
                    return Err(Error::connectivity("port 0 is not reachable"));
                }
                // A chained tunnel talks through the stream of the tunnel before it.
                Ok(request
                    .transport
                    .unwrap_or_else(|| Box::new(Loopback::default())))
            })
        }
    }

    fn tunnel_request(port: u16, transport: Option<Box<dyn ByteStream>>) -> TunnelRequest {
        TunnelRequest {
            tunnel: ProviderRef::new("test.tunnel"),
            target_host: "db.example".into(),
            target_port: port,
            transport,
        }
    }

    #[test]
    fn tunnel_provider_opens_a_byte_stream_to_a_target() {
        let tunnel: Box<dyn TunnelProvider> = Box::new(MockTunnel);
        let first = block_on(tunnel.open(tunnel_request(22, None))).unwrap();
        let stream = block_on(tunnel.open(tunnel_request(5432, Some(first)))).unwrap();

        block_on(stream.write(b"hello".to_vec())).unwrap();
        assert_eq!(block_on(stream.read(2)).unwrap(), b"he");
        assert_eq!(block_on(stream.read(16)).unwrap(), b"llo");
        assert!(block_on(stream.read(16)).unwrap().is_empty());

        let error = block_on(tunnel.open(tunnel_request(0, None)))
            .err()
            .unwrap();
        assert_eq!(error.category(), ErrorCategory::Connectivity);
    }

    struct MockMetadata;

    fn table(name: &str) -> CatalogObject {
        CatalogObject {
            kind: CatalogObjectKind::Table,
            name: name.into(),
            definition: None,
            extensions: ExtensionFields::new(),
            children: Vec::new(),
        }
    }

    impl MetadataProvider for MockMetadata {
        fn introspect(&self, connection: Arc<dyn Connection>) -> BoxFuture<'_, Result<Catalog>> {
            Box::pin(async move {
                let tables = row_count(connection.execute("list tables".into()).await?);
                Ok(Catalog {
                    objects: (0..tables).map(|n| table(&format!("t{n}"))).collect(),
                })
            })
        }

        fn generate_ddl(&self, object: CatalogObject) -> BoxFuture<'_, Result<String>> {
            Box::pin(async move { Ok(format!("create table {}", object.name)) })
        }

        fn diff(&self, source: Catalog, target: Catalog) -> BoxFuture<'_, Result<Vec<String>>> {
            Box::pin(async move {
                Ok(target
                    .objects
                    .iter()
                    .filter(|object| !source.objects.contains(object))
                    .map(|object| format!("create table {}", object.name))
                    .collect())
            })
        }
    }

    #[test]
    fn metadata_provider_introspects_generates_ddl_and_diffs() {
        let metadata: Box<dyn MetadataProvider> = Box::new(MockMetadata);
        let connection: Arc<dyn Connection> = connect(token(None)).unwrap().into();

        let catalog = block_on(metadata.introspect(connection)).unwrap();
        assert_eq!(catalog.objects.len(), 3);
        let ddl = block_on(metadata.generate_ddl(table("orders"))).unwrap();
        assert_eq!(ddl, "create table orders");
        let changes = block_on(metadata.diff(Catalog::default(), catalog.clone())).unwrap();
        assert_eq!(changes.len(), 3);
        assert!(
            block_on(metadata.diff(catalog.clone(), catalog))
                .unwrap()
                .is_empty()
        );
    }

    #[derive(Default)]
    struct CountingSink(Mutex<usize>);

    impl ResultSink for CountingSink {
        fn consume(&self, result: ResultSet) -> BoxFuture<'_, Result<()>> {
            Box::pin(async move {
                *self.0.lock().unwrap() += row_count(result);
                Ok(())
            })
        }
    }

    #[test]
    fn result_sink_consumes_a_result_set() {
        let counting = Arc::new(CountingSink::default());
        let sink: Arc<dyn ResultSink> = counting.clone();
        block_on(sink.consume(result_set(&[7, 8]))).unwrap();
        assert_eq!(*counting.0.lock().unwrap(), 2);
    }

    /// The mock format: one byte for each row.
    struct MockFormat;

    impl Importer for MockFormat {
        fn import(&self, source: ByteChunkStream) -> BoxFuture<'_, Result<ResultSet>> {
            Box::pin(async move {
                let mut values = Vec::new();
                for chunk in drain(source) {
                    values.extend(chunk?.into_iter().map(i64::from));
                }
                Ok(result_set(&values))
            })
        }
    }

    impl Exporter for MockFormat {
        fn export(&self, result: ResultSet) -> BoxFuture<'_, Result<ByteChunkStream>> {
            Box::pin(async move {
                let chunk = vec![0u8; row_count(result)];
                Ok(Box::pin(Fixed([Ok(chunk)].into())) as ByteChunkStream)
            })
        }
    }

    #[test]
    fn importer_converts_bytes_to_a_result_set() {
        let importer: Box<dyn Importer> = Box::new(MockFormat);
        let source = Fixed([Ok(vec![1, 2]), Ok(vec![3])].into());
        let result = block_on(importer.import(Box::pin(source))).unwrap();
        assert_eq!(row_count(result), 3);

        let broken = Fixed([Err(Error::user("the file is damaged"))].into());
        let error = block_on(importer.import(Box::pin(broken))).unwrap_err();
        assert_eq!(error.category(), ErrorCategory::User);
    }

    #[test]
    fn exporter_converts_a_result_set_to_bytes() {
        let exporter: Box<dyn Exporter> = Box::new(MockFormat);
        let bytes = block_on(exporter.export(result_set(&[4, 5]))).unwrap();
        let chunks: Vec<Vec<u8>> = drain(bytes).into_iter().map(Result::unwrap).collect();
        assert_eq!(chunks, [vec![0, 0]]);
    }

    struct MockModel;

    impl ModelProvider for MockModel {
        fn complete(&self, prompt: String) -> BoxFuture<'_, Result<String>> {
            Box::pin(async move {
                if prompt.is_empty() {
                    return Err(Error::user("the prompt is empty"));
                }
                Ok(format!("echo: {prompt}"))
            })
        }
    }

    #[test]
    fn model_provider_gets_only_a_prompt() {
        let model: Box<dyn ModelProvider> = Box::new(MockModel);
        let response = block_on(model.complete("list the tables".into())).unwrap();
        assert_eq!(response, "echo: list the tables");
        let error = block_on(model.complete(String::new())).unwrap_err();
        assert_eq!(error.category(), ErrorCategory::User);
    }

    struct MockEngine;

    impl EngineHandle for MockEngine {}

    struct MockScripts;

    impl ScriptEngine for MockScripts {
        fn run(&self, script: String, _: Arc<dyn EngineHandle>) -> BoxFuture<'_, Result<()>> {
            Box::pin(async move {
                if script.contains("syntax error") {
                    return Err(Error::user("the script has a syntax error"));
                }
                Ok(())
            })
        }
    }

    #[test]
    fn script_engine_runs_a_script() {
        let scripts: Box<dyn ScriptEngine> = Box::new(MockScripts);
        let engine: Arc<dyn EngineHandle> = Arc::new(MockEngine);
        block_on(scripts.run("let x = 1;".into(), engine.clone())).unwrap();
        let error = block_on(scripts.run("syntax error".into(), engine)).unwrap_err();
        assert_eq!(error.category(), ErrorCategory::User);
    }

    /// The mock is a CLI subcommand and a control API method.
    struct Greet;

    fn greet_signature() -> Signature {
        Signature {
            name: "greet".into(),
            summary: "Greets a user.".into(),
            arguments: vec![Argument {
                name: "name".into(),
                summary: "The user to greet.".into(),
                value_type: ArgumentType::Text,
                required: true,
            }],
        }
    }

    fn greeting(arguments: &ExtensionFields) -> Result<String> {
        match arguments.get("name") {
            Some(ExtensionValue::Text(name)) => Ok(format!("hello {name}")),
            _ => Err(Error::user("the argument `name` must be a text")),
        }
    }

    impl CliCommand for Greet {
        fn signature(&self) -> Signature {
            greet_signature()
        }

        fn run(&self, arguments: ExtensionFields) -> BoxFuture<'_, Result<String>> {
            Box::pin(async move { greeting(&arguments) })
        }
    }

    impl ApiEndpoint for Greet {
        fn signature(&self) -> Signature {
            greet_signature()
        }

        fn call(&self, arguments: ExtensionFields) -> BoxFuture<'_, Result<ExtensionFields>> {
            Box::pin(async move {
                let text = ExtensionValue::Text(greeting(&arguments)?);
                Ok(ExtensionFields::from([("greeting".to_owned(), text)]))
            })
        }
    }

    fn name_argument() -> ExtensionFields {
        ExtensionFields::from([("name".to_owned(), ExtensionValue::Text("ada".into()))])
    }

    #[test]
    fn cli_command_describes_itself_and_runs() {
        let command: Box<dyn CliCommand> = Box::new(Greet);
        assert_eq!(command.signature(), greet_signature());
        assert_eq!(block_on(command.run(name_argument())).unwrap(), "hello ada");
        let error = block_on(command.run(ExtensionFields::new())).unwrap_err();
        assert_eq!(error.category(), ErrorCategory::User);
    }

    #[test]
    fn api_endpoint_describes_itself_and_answers() {
        let endpoint: Box<dyn ApiEndpoint> = Box::new(Greet);
        assert_eq!(
            endpoint.signature().arguments[0].value_type,
            ArgumentType::Text
        );
        let response = block_on(endpoint.call(name_argument())).unwrap();
        assert_eq!(
            response["greeting"],
            ExtensionValue::Text("hello ada".into())
        );
        let error = block_on(endpoint.call(ExtensionFields::new())).unwrap_err();
        assert_eq!(error.category(), ErrorCategory::User);
    }

    #[test]
    fn every_headless_extension_point_has_exactly_one_contract() {
        const MAPPED: [ExtensionPoint; 12] = [
            <dyn Driver as Contract>::POINT,
            <dyn AuthProvider as Contract>::POINT,
            <dyn CredentialSource as Contract>::POINT,
            <dyn TunnelProvider as Contract>::POINT,
            <dyn MetadataProvider as Contract>::POINT,
            <dyn ResultSink as Contract>::POINT,
            <dyn Importer as Contract>::POINT,
            <dyn Exporter as Contract>::POINT,
            <dyn ModelProvider as Contract>::POINT,
            <dyn ScriptEngine as Contract>::POINT,
            <dyn CliCommand as Contract>::POINT,
            <dyn ApiEndpoint as Contract>::POINT,
        ];
        let mut contracts = [0; MAPPED.len()];
        for point in MAPPED {
            // No wildcard arm: a new `ExtensionPoint` variant does not compile
            // until it gets a contract here or in `rivet-ui-sdk`.
            let index = match point {
                ExtensionPoint::Driver => 0,
                ExtensionPoint::AuthProvider => 1,
                ExtensionPoint::CredentialSource => 2,
                ExtensionPoint::TunnelProvider => 3,
                ExtensionPoint::MetadataProvider => 4,
                ExtensionPoint::ResultSink => 5,
                ExtensionPoint::Importer => 6,
                ExtensionPoint::Exporter => 7,
                ExtensionPoint::ModelProvider => 8,
                ExtensionPoint::ScriptEngine => 9,
                ExtensionPoint::CliCommand => 10,
                ExtensionPoint::ApiEndpoint => 11,
                ExtensionPoint::UiView | ExtensionPoint::UiCommand | ExtensionPoint::UiPanel => {
                    panic!("{point:?} is a UI extension point; its contract is in rivet-ui-sdk")
                }
            };
            assert!(!point.is_ui());
            contracts[index] += 1;
        }
        assert_eq!(contracts, [1; MAPPED.len()]);
    }

    #[test]
    fn every_contract_is_a_send_and_sync_trait_object() {
        fn assert_send_sync<T: ?Sized + Send + Sync>() {}
        assert_send_sync::<dyn ByteStream>();
        assert_send_sync::<dyn Driver>();
        assert_send_sync::<dyn Connection>();
        assert_send_sync::<dyn AuthProvider>();
        assert_send_sync::<dyn CredentialSource>();
        assert_send_sync::<dyn TunnelProvider>();
        assert_send_sync::<dyn MetadataProvider>();
        assert_send_sync::<dyn ResultSink>();
        assert_send_sync::<dyn Importer>();
        assert_send_sync::<dyn Exporter>();
        assert_send_sync::<dyn ModelProvider>();
        assert_send_sync::<dyn EngineHandle>();
        assert_send_sync::<dyn ScriptEngine>();
        assert_send_sync::<dyn CliCommand>();
        assert_send_sync::<dyn ApiEndpoint>();
    }
}
