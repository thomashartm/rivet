//! Canonical data types shared by the host and all extensions
//! (ARCHITECTURE.md §6.1): connection profile, catalog and result set.
//!
//! The types are plain data. They contain no database-specific,
//! dialect-specific or cloud-specific code and do no I/O (§3.3). Details that
//! only one extension understands travel in [`ExtensionFields`].

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use arrow_array::RecordBatch;
use arrow_schema::SchemaRef;
use futures_core::Stream;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::secret::SecretUri;

/// A value of an extension field.
///
/// In a configuration file it is written as a plain boolean, integer, float
/// or string.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum ExtensionValue {
    /// A boolean.
    Bool(bool),
    /// A signed integer.
    Integer(i64),
    /// A floating-point number.
    Float(f64),
    /// A text.
    Text(String),
}

/// Details that only one extension understands, as typed values by key
/// (§6.1). This is the only mechanism for such details; the core models get
/// no dialect-specific fields.
///
/// On a [`CatalogObject`] and a [`ColumnMetadata`] the key starts with the id
/// of the extension that owns it, for example `acme.postgres.oid`. In the
/// settings of a [`ProviderRef`] the provider already owns every key, so the
/// key has no prefix.
pub type ExtensionFields = BTreeMap<String, ExtensionValue>;

/// A reference to an implementation that an extension provides: an engine, an
/// auth method, a credential source or a tunnel.
///
/// The SDK does not know the implementations. The host looks up `id` in the
/// service registry, and the implementation validates `settings` and
/// `secrets`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ProviderRef {
    /// The id under which the extension registered the implementation.
    pub id: String,
    /// The settings of this implementation. They MUST NOT contain secret
    /// values; a secret goes in `secrets`.
    #[serde(default)]
    pub settings: ExtensionFields,
    /// The secrets this implementation needs, by name, as references.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretUri>,
}

impl ProviderRef {
    /// Creates a reference with no settings and no secrets.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            settings: ExtensionFields::new(),
            secrets: BTreeMap::new(),
        }
    }

    /// Sets the settings.
    #[must_use]
    pub fn with_settings(mut self, settings: ExtensionFields) -> Self {
        self.settings = settings;
        self
    }

    /// Sets the secret references.
    #[must_use]
    pub fn with_secrets(mut self, secrets: BTreeMap<String, SecretUri>) -> Self {
        self.secrets = secrets;
        self
    }
}

/// The network address of a database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Endpoint {
    /// The host name or IP address.
    pub host: String,
    /// The port. `None` means the default port of the engine.
    #[serde(default)]
    pub port: Option<u16>,
    /// The database to open. `None` means the default database of the engine.
    #[serde(default)]
    pub database: Option<String>,
}

impl Endpoint {
    /// Creates an endpoint with the default port and the default database of
    /// the engine.
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: None,
            database: None,
        }
    }

    /// Sets the port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Sets the database to open.
    #[must_use]
    pub fn with_database(mut self, database: impl Into<String>) -> Self {
        self.database = Some(database.into());
        self
    }
}

/// A client certificate for mutual TLS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ClientCertificate {
    /// The path of the certificate file. A certificate is public.
    pub certificate: PathBuf,
    /// The reference to the private key.
    pub private_key: SecretUri,
}

impl ClientCertificate {
    /// Creates a client certificate from the path of the certificate file and
    /// the reference to the private key.
    pub fn new(certificate: impl Into<PathBuf>, private_key: SecretUri) -> Self {
        Self {
            certificate: certificate.into(),
            private_key,
        }
    }
}

/// The TLS settings of a profile (§7.5). TLS is on unless `enabled` is set to
/// `false` explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TlsSettings {
    /// `false` permits a plaintext connection. Every interface shows such a
    /// profile as insecure.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// The path of a CA certificate file. If set, only this CA is trusted
    /// (CA pinning).
    #[serde(default)]
    pub ca_certificate: Option<PathBuf>,
    /// The client certificate, if the server requires one.
    #[serde(default)]
    pub client_certificate: Option<ClientCertificate>,
}

fn enabled_by_default() -> bool {
    true
}

impl Default for TlsSettings {
    /// TLS on, system trust store, no client certificate.
    fn default() -> Self {
        Self {
            enabled: enabled_by_default(),
            ca_certificate: None,
            client_certificate: None,
        }
    }
}

impl TlsSettings {
    /// Creates the default settings: TLS on, system trust store, no client
    /// certificate.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets `enabled`. `false` permits a plaintext connection.
    #[must_use]
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Sets the CA certificate file. Only this CA is trusted then.
    #[must_use]
    pub fn with_ca_certificate(mut self, ca_certificate: impl Into<PathBuf>) -> Self {
        self.ca_certificate = Some(ca_certificate.into());
        self
    }

    /// Sets the client certificate.
    #[must_use]
    pub fn with_client_certificate(mut self, client_certificate: ClientCertificate) -> Self {
        self.client_certificate = Some(client_certificate);
        self
    }
}

/// How to reach and open one database (§5.3, §6.1).
///
/// A profile contains no secret values. Each secret is a [`SecretUri`], so a
/// profile can be stored as a plain file and committed (§6.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ConnectionProfile {
    /// The database driver.
    pub engine: ProviderRef,
    /// The address of the database.
    pub endpoint: Endpoint,
    /// The auth method.
    pub auth: ProviderRef,
    /// The credential source that the auth method uses, if it needs one.
    #[serde(default)]
    pub credential_source: Option<ProviderRef>,
    /// The tunnels to pass through, in order from the client to the database.
    #[serde(default)]
    pub tunnels: Vec<ProviderRef>,
    /// The TLS settings.
    #[serde(default)]
    pub tls: TlsSettings,
    /// If `true`, the engine rejects statements that write.
    #[serde(default)]
    pub read_only: bool,
    /// If `true`, the engine asks for confirmation before a statement that
    /// writes.
    #[serde(default)]
    pub confirm_on_write: bool,
    /// The environment tag, for example `production`.
    #[serde(default)]
    pub environment: Option<String>,
}

impl ConnectionProfile {
    /// Creates a profile with the required fields. The other fields have the
    /// same values as in a profile file that does not set them: no credential
    /// source, no tunnels, TLS on, writes permitted without confirmation, no
    /// environment tag.
    ///
    /// ```
    /// use rivet_sdk::model::{ConnectionProfile, Endpoint, ProviderRef, TlsSettings};
    ///
    /// let profile = ConnectionProfile::new(
    ///     ProviderRef::new("postgres"),
    ///     Endpoint::new("db.example.com").with_port(5432),
    ///     ProviderRef::new("password"),
    /// )
    /// .with_read_only(true)
    /// .with_environment("production");
    ///
    /// assert_eq!(profile.endpoint.port, Some(5432));
    /// assert_eq!(profile.tls, TlsSettings::new());
    /// assert!(profile.read_only);
    /// ```
    pub fn new(engine: ProviderRef, endpoint: Endpoint, auth: ProviderRef) -> Self {
        Self {
            engine,
            endpoint,
            auth,
            credential_source: None,
            tunnels: Vec::new(),
            tls: TlsSettings::default(),
            read_only: false,
            confirm_on_write: false,
            environment: None,
        }
    }

    /// Sets the credential source that the auth method uses.
    #[must_use]
    pub fn with_credential_source(mut self, credential_source: ProviderRef) -> Self {
        self.credential_source = Some(credential_source);
        self
    }

    /// Sets the tunnels, in order from the client to the database.
    #[must_use]
    pub fn with_tunnels(mut self, tunnels: impl IntoIterator<Item = ProviderRef>) -> Self {
        self.tunnels = tunnels.into_iter().collect();
        self
    }

    /// Sets the TLS settings.
    #[must_use]
    pub fn with_tls(mut self, tls: TlsSettings) -> Self {
        self.tls = tls;
        self
    }

    /// Sets `read_only`. `true` makes the engine reject statements that
    /// write.
    #[must_use]
    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// Sets `confirm_on_write`. `true` makes the engine ask for confirmation
    /// before a statement that writes.
    #[must_use]
    pub fn with_confirm_on_write(mut self, confirm_on_write: bool) -> Self {
        self.confirm_on_write = confirm_on_write;
        self
    }

    /// Sets the environment tag.
    #[must_use]
    pub fn with_environment(mut self, environment: impl Into<String>) -> Self {
        self.environment = Some(environment.into());
        self
    }
}

/// The kind of a [`CatalogObject`] (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CatalogObjectKind {
    /// A schema (namespace).
    Schema,
    /// A table.
    Table,
    /// A view.
    View,
    /// A materialized view.
    MaterializedView,
    /// A function or a procedure.
    Routine,
    /// A sequence.
    Sequence,
    /// An index.
    Index,
    /// A constraint.
    Constraint,
    /// A trigger.
    Trigger,
    /// A role (user or group).
    Role,
    /// An extension of the database.
    Extension,
}

/// One object in the catalog of a database, with the objects it contains.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CatalogObject {
    /// The kind of the object.
    pub kind: CatalogObjectKind,
    /// The name of the object, without the names of its parents.
    pub name: String,
    /// The statement that creates the object, in the dialect of the database.
    #[serde(default)]
    pub definition: Option<String>,
    /// Details that only the engine extension understands.
    #[serde(default)]
    pub extensions: ExtensionFields,
    /// The objects inside this object, for example the tables of a schema.
    #[serde(default)]
    pub children: Vec<CatalogObject>,
}

impl CatalogObject {
    /// Creates an object with no definition, no extension fields and no
    /// children.
    ///
    /// ```
    /// use rivet_sdk::model::{Catalog, CatalogObject, CatalogObjectKind};
    ///
    /// let schema = CatalogObject::new(CatalogObjectKind::Schema, "public")
    ///     .with_children([CatalogObject::new(CatalogObjectKind::Table, "users")]);
    /// let catalog = Catalog::new([schema]);
    /// assert_eq!(catalog.objects[0].children[0].name, "users");
    /// ```
    pub fn new(kind: CatalogObjectKind, name: impl Into<String>) -> Self {
        Self {
            kind,
            name: name.into(),
            definition: None,
            extensions: ExtensionFields::new(),
            children: Vec::new(),
        }
    }

    /// Sets the statement that creates the object.
    #[must_use]
    pub fn with_definition(mut self, definition: impl Into<String>) -> Self {
        self.definition = Some(definition.into());
        self
    }

    /// Sets the details that only the engine extension understands.
    #[must_use]
    pub fn with_extensions(mut self, extensions: ExtensionFields) -> Self {
        self.extensions = extensions;
        self
    }

    /// Sets the objects inside this object.
    #[must_use]
    pub fn with_children(mut self, children: impl IntoIterator<Item = CatalogObject>) -> Self {
        self.children = children.into_iter().collect();
        self
    }
}

/// The catalog of a database: a tree of [`CatalogObject`]s.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Catalog {
    /// The objects at the top level.
    #[serde(default)]
    pub objects: Vec<CatalogObject>,
}

impl Catalog {
    /// Creates a catalog from the objects at the top level.
    pub fn new(objects: impl IntoIterator<Item = CatalogObject>) -> Self {
        Self {
            objects: objects.into_iter().collect(),
        }
    }
}

/// What the database reports about one column of a result set.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ColumnMetadata {
    /// The type name in the database, for example `varchar(40)`.
    pub source_type: String,
    /// `true` if the database permits NULL in this column.
    pub nullable: bool,
    /// Details that only the engine extension understands.
    pub extensions: ExtensionFields,
}

impl ColumnMetadata {
    /// Creates the metadata of a column with no extension fields.
    pub fn new(source_type: impl Into<String>, nullable: bool) -> Self {
        Self {
            source_type: source_type.into(),
            nullable,
            extensions: ExtensionFields::new(),
        }
    }

    /// Sets the details that only the engine extension understands.
    #[must_use]
    pub fn with_extensions(mut self, extensions: ExtensionFields) -> Self {
        self.extensions = extensions;
        self
    }
}

/// A stream of Arrow record batches (§5.5). An `Err` item ends the result.
pub type RecordBatchStream = Pin<Box<dyn Stream<Item = Result<RecordBatch>> + Send>>;

/// The result of a statement: an Arrow schema, metadata for each column and a
/// stream of record batches.
///
/// A `ResultSet` is itself the stream of its batches. It is not serializable.
pub struct ResultSet {
    schema: SchemaRef,
    columns: Vec<ColumnMetadata>,
    batches: RecordBatchStream,
}

impl ResultSet {
    /// Creates a result set. `columns` has one entry for each field of
    /// `schema`, in the same order.
    ///
    /// Fails with an `internal` error if the two counts are different.
    pub fn new(
        schema: SchemaRef,
        columns: Vec<ColumnMetadata>,
        batches: RecordBatchStream,
    ) -> Result<Self> {
        let (fields, metadata) = (schema.fields().len(), columns.len());
        if fields != metadata {
            return Err(Error::internal(format!(
                "the result set has {fields} schema fields but metadata for {metadata} columns"
            )));
        }
        Ok(Self {
            schema,
            columns,
            batches,
        })
    }

    /// Returns the Arrow schema of every batch.
    pub fn schema(&self) -> &SchemaRef {
        &self.schema
    }

    /// Returns the metadata of the columns, in schema order.
    pub fn columns(&self) -> &[ColumnMetadata] {
        &self.columns
    }
}

impl Stream for ResultSet {
    type Item = Result<RecordBatch>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.batches.as_mut().poll_next(cx)
    }
}

impl fmt::Debug for ResultSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResultSet")
            .field("schema", &self.schema)
            .field("columns", &self.columns)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::pin::pin;
    use std::sync::Arc;
    use std::task::Waker;

    use arrow_array::{ArrayRef, Int64Array, StringArray};
    use arrow_schema::{DataType, Field, Schema};

    use super::*;
    use crate::error::ErrorCategory;

    fn fields(entries: &[(&str, ExtensionValue)]) -> ExtensionFields {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect()
    }

    fn full_profile() -> ConnectionProfile {
        ConnectionProfile {
            engine: ProviderRef {
                id: "test.engine".into(),
                settings: fields(&[
                    ("application_name", ExtensionValue::Text("rivet".into())),
                    ("statement_timeout_ms", ExtensionValue::Integer(30_000)),
                    ("sample_ratio", ExtensionValue::Float(0.5)),
                    ("prefer_binary", ExtensionValue::Bool(true)),
                ]),
                secrets: BTreeMap::new(),
            },
            endpoint: Endpoint {
                host: "db.internal.example".into(),
                port: Some(5432),
                database: Some("orders".into()),
            },
            auth: ProviderRef {
                id: "test.password".into(),
                settings: fields(&[("user", ExtensionValue::Text("app".into()))]),
                secrets: BTreeMap::from([(
                    "password".to_owned(),
                    "keychain://rivet/orders".parse().unwrap(),
                )]),
            },
            credential_source: Some(ProviderRef::new("test.credential-chain")),
            tunnels: vec![
                ProviderRef {
                    id: "test.ssh".into(),
                    settings: fields(&[("host", ExtensionValue::Text("bastion".into()))]),
                    secrets: BTreeMap::from([(
                        "private_key".to_owned(),
                        "aws-sm://ops/bastion-key".parse().unwrap(),
                    )]),
                },
                ProviderRef::new("test.socks"),
            ],
            tls: TlsSettings {
                enabled: true,
                ca_certificate: Some("certs/ca.pem".into()),
                client_certificate: Some(ClientCertificate {
                    certificate: "certs/client.pem".into(),
                    private_key: "gcp-sm://projects/p/secrets/client-key".parse().unwrap(),
                }),
            },
            read_only: true,
            confirm_on_write: true,
            environment: Some("production".into()),
        }
    }

    #[test]
    fn profile_round_trips_through_toml() {
        let profile = full_profile();
        let text = toml::to_string(&profile).unwrap();
        assert_eq!(toml::from_str::<ConnectionProfile>(&text).unwrap(), profile);
    }

    #[test]
    fn minimal_profile_gets_safe_defaults() {
        let profile: ConnectionProfile = toml::from_str(
            r#"
            [engine]
            id = "test.engine"
            [endpoint]
            host = "localhost"
            [auth]
            id = "test.password"
            "#,
        )
        .unwrap();
        assert!(profile.tls.enabled, "TLS must be on by default");
        assert_eq!(profile.tls, TlsSettings::default());
        assert!(!profile.read_only);
        assert!(!profile.confirm_on_write);
        assert_eq!(profile.environment, None);
        assert_eq!(profile.credential_source, None);
        assert!(profile.tunnels.is_empty());
        assert_eq!(profile.auth, ProviderRef::new("test.password"));
        let text = toml::to_string(&profile).unwrap();
        assert_eq!(toml::from_str::<ConnectionProfile>(&text).unwrap(), profile);
    }

    #[test]
    fn tls_opt_out_is_explicit() {
        let tls: TlsSettings = toml::from_str("enabled = false").unwrap();
        assert!(!tls.enabled);
    }

    #[test]
    fn profile_rejects_unknown_fields_and_secret_values() {
        let base = r#"
            [engine]
            id = "test.engine"
            [endpoint]
            host = "localhost"
            [auth]
            id = "test.password"
        "#;
        let unknown = format!("password = \"hunter2\"\n{base}");
        assert!(toml::from_str::<ConnectionProfile>(&unknown).is_err());
        let plain_secret = format!("{base}[auth.secrets]\npassword = \"hunter2\"\n");
        assert!(toml::from_str::<ConnectionProfile>(&plain_secret).is_err());
    }

    #[test]
    fn catalog_round_trips_through_toml() {
        let leaf = |kind, name: &str| CatalogObject {
            kind,
            name: name.into(),
            definition: Some(format!("definition of {name}")),
            extensions: fields(&[("test.engine.oid", ExtensionValue::Integer(42))]),
            children: Vec::new(),
        };
        use CatalogObjectKind::*;
        let catalog = Catalog {
            objects: vec![
                CatalogObject {
                    kind: Schema,
                    name: "public".into(),
                    definition: None,
                    extensions: ExtensionFields::new(),
                    children: vec![
                        CatalogObject {
                            children: vec![
                                leaf(Index, "orders_pkey"),
                                leaf(Constraint, "orders_total_check"),
                                leaf(Trigger, "orders_audit"),
                            ],
                            ..leaf(Table, "orders")
                        },
                        leaf(View, "open_orders"),
                        leaf(MaterializedView, "daily_totals"),
                        leaf(Routine, "close_order"),
                        leaf(Sequence, "orders_id_seq"),
                    ],
                },
                leaf(Role, "app"),
                leaf(Extension, "fuzzy_match"),
            ],
        };
        let text = toml::to_string(&catalog).unwrap();
        assert_eq!(toml::from_str::<Catalog>(&text).unwrap(), catalog);
        assert!(text.contains("kind = \"materialized_view\""), "{text}");
    }

    /// A stream over a fixed list of items; it stands in for a driver.
    struct FixedStream(std::collections::VecDeque<Result<RecordBatch>>);

    impl Stream for FixedStream {
        type Item = Result<RecordBatch>;

        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.pop_front())
        }
    }

    /// Reads a stream that is always ready, without an async runtime.
    fn drain(result_set: ResultSet) -> Vec<Result<RecordBatch>> {
        let mut result_set = pin!(result_set);
        let mut context = Context::from_waker(Waker::noop());
        let mut items = Vec::new();
        loop {
            match result_set.as_mut().poll_next(&mut context) {
                Poll::Ready(Some(item)) => items.push(item),
                Poll::Ready(None) => return items,
                Poll::Pending => panic!("the test stream is always ready"),
            }
        }
    }

    fn schema() -> SchemaRef {
        Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("name", DataType::Utf8, true),
        ]))
    }

    fn columns() -> Vec<ColumnMetadata> {
        vec![
            ColumnMetadata {
                source_type: "bigint".into(),
                nullable: false,
                extensions: fields(&[("test.engine.type_oid", ExtensionValue::Integer(20))]),
            },
            ColumnMetadata {
                source_type: "varchar(40)".into(),
                nullable: true,
                extensions: ExtensionFields::new(),
            },
        ]
    }

    fn batch(ids: &[i64], names: &[Option<&str>]) -> RecordBatch {
        let id: ArrayRef = Arc::new(Int64Array::from(ids.to_vec()));
        let name: ArrayRef = Arc::new(StringArray::from(names.to_vec()));
        RecordBatch::try_new(schema(), vec![id, name]).unwrap()
    }

    #[test]
    fn result_set_yields_its_batches_and_column_metadata() {
        let batches = [
            batch(&[1, 2], &[Some("a"), None]),
            batch(&[3], &[Some("c")]),
        ];
        let stream = FixedStream(batches.iter().cloned().map(Ok).collect());
        let result_set = ResultSet::new(schema(), columns(), Box::pin(stream)).unwrap();

        assert_eq!(result_set.schema(), &schema());
        assert_eq!(result_set.columns(), columns());
        assert_eq!(result_set.columns()[0].source_type, "bigint");
        assert!(!result_set.columns()[0].nullable);
        assert!(format!("{result_set:?}").contains("bigint"));

        let read: Vec<RecordBatch> = drain(result_set).into_iter().map(Result::unwrap).collect();
        assert_eq!(read, batches);
        assert_eq!(read.iter().map(RecordBatch::num_rows).sum::<usize>(), 3);
    }

    #[test]
    fn result_set_passes_stream_errors_to_the_reader() {
        let stream = FixedStream(
            [
                Ok(batch(&[1], &[None])),
                Err(Error::connectivity("connection lost")),
            ]
            .into(),
        );
        let items = drain(ResultSet::new(schema(), columns(), Box::pin(stream)).unwrap());
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        let error = items[1].as_ref().unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Connectivity);
    }

    #[test]
    fn result_set_rejects_a_column_count_mismatch() {
        let stream = FixedStream(Default::default());
        let one_column = columns().into_iter().take(1).collect();
        let error = ResultSet::new(schema(), one_column, Box::pin(stream)).unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Internal);
    }

    #[test]
    fn result_set_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ResultSet>();
    }
}
