//! Extension manifest schema: the typed form of an `extension.toml` file
//! (ARCHITECTURE.md §4.4, §4.5, §4.7, ADR-0008).
//!
//! [`Manifest::parse`] takes the text of the file. This module does no file or
//! network I/O (§3.3). Unknown fields are rejected. A failure is an
//! [`Error`] of the category `user`.
//!
//! A manifest is untrusted input. Thus:
//!
//! - Each of the lists `contributes`, `activation`, `capabilities.network`,
//!   `capabilities.filesystem` and `capabilities.secrets` has a maximum of
//!   [`LIST_MAX_ENTRIES`] entries.
//! - An error message repeats a maximum of 128 characters of a value of the
//!   manifest and shows a control character as an escape (for example
//!   `\u{1b}`). It does not contain a line break.
//!
//! # Extension id rules
//!
//! An [`ExtensionId`] is valid when all of these are true:
//!
//! - It has 1 to 128 characters.
//! - It has one or more segments, separated by `.`.
//! - Each segment has one or more of: ASCII lowercase letters, digits, `-`.
//! - A segment does not start or end with `-`.
//!
//! Examples: `postgres`, `acme.postgres`, `acme.aws-auth`.
//!
//! The `id` of a contribution, the `command` of an activation event and the
//! `type` of an activation event obey the same rules.
//!
//! # Capability scope rules
//!
//! A manifest is untrusted input. A scope that is not in the forms below is
//! rejected. The text of a valid scope is kept as written.
//!
//! A network `host` is one of:
//!
//! - An IP address literal, for example `10.0.0.5`, `::1` or `[::1]`. The
//!   `[]` are permitted only for IPv6.
//! - A DNS name of 1 to 253 characters: labels separated by `.`. Each label
//!   has 1 to 63 ASCII letters, digits, `-` or `_`, and does not start or
//!   end with `-`. Upper case is permitted. The last label is not a number
//!   (only digits, or `0x` and hexadecimal digits), because some resolvers
//!   read such a name as an address.
//!
//! A port, a scheme, a path, a wildcard, whitespace and a `.` at the end
//! (`db.example.com.`) are not permitted.
//! Each host has one table. Two hosts are the same when [`same_host`] says
//! so: their text is equal (ASCII case ignored) or they are the same IP
//! address. A port is in the `ports` list one time only.
//!
//! A filesystem `path` obeys these rules. They are the same on each operating
//! system; the permission service decides at run time if the path exists on
//! this one.
//!
//! - It does not start or end with whitespace.
//! - It is `~`, or it starts with `~/`, with `/`, with a Windows drive
//!   (`C:\` or `C:/`) or with `\\` (UNC). A relative path and `~user` are not
//!   permitted.
//! - It has no control character (for example NUL, a line feed or ESC).
//! - It has no `.` or `..` component. Components are separated by `/` or `\`.
//! - It has one spelling: no empty component (`/a//b`) and no separator at
//!   the end (`/a/`, `~/`). A root (`/`, `C:\`) and the `\\` at the start of
//!   a UNC path are permitted.
//! - A `path` is declared one time only, whatever the `access`. Two paths are
//!   the same when their text is equal.
//!
//! A secret namespace has one or more segments, separated by `/`. A segment
//! has one or more ASCII letters, digits, `.`, `_` or `-`, and is not `.` or
//! `..`. Thus `://`, `%` and whitespace are not permitted. A namespace is
//! declared one time only. Case is significant. Known limit: a secret whose
//! first path segments have other characters (for example `+`, `=`, `@`)
//! cannot be named by a namespace.
//!
//! # Example
//!
//! ```
//! use rivet_sdk::manifest::{ExtensionPoint, Manifest};
//!
//! let manifest = Manifest::parse(
//!     r#"
//!     id = "acme.postgres"
//!     version = "1.4.0"
//!     sdk = ">=0.1.0, <0.2.0"
//!
//!     [[contributes]]
//!     kind = "driver"
//!     id = "postgres"
//!     "#,
//! )?;
//! assert_eq!(manifest.id.as_str(), "acme.postgres");
//! assert_eq!(manifest.contributes[0].kind, ExtensionPoint::Driver);
//! assert!(!manifest.requires_ui);
//! # Ok::<(), rivet_sdk::error::Error>(())
//! ```

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

pub use semver::{Version, VersionReq};
use serde::Deserialize;

use crate::error::{Error, Result};

/// The maximum length of an [`ExtensionId`] in characters.
pub const EXTENSION_ID_MAX_LEN: usize = 128;

/// The maximum number of entries in each of the lists `contributes`,
/// `activation`, `capabilities.network`, `capabilities.filesystem` and
/// `capabilities.secrets`.
pub const LIST_MAX_ENTRIES: usize = 256;

/// The maximum number of characters of a manifest value that an error message
/// repeats.
const ERROR_VALUE_MAX_CHARS: usize = 128;

/// The maximum number of characters of a TOML parser message that an error
/// message repeats.
const PARSE_MESSAGE_MAX_CHARS: usize = 512;

/// The validated id of an extension. See the [module documentation](self) for
/// the rules.
///
/// ```
/// use rivet_sdk::manifest::ExtensionId;
///
/// let id: ExtensionId = "acme.aws-auth".parse()?;
/// assert_eq!(id.as_str(), "acme.aws-auth");
/// assert!("Acme".parse::<ExtensionId>().is_err());
/// # Ok::<(), rivet_sdk::error::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtensionId(String);

impl<'de> Deserialize<'de> for ExtensionId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // `message()`, not `Display`: the category prefix must not be nested.
        Self::try_from(String::deserialize(deserializer)?)
            .map_err(|error| serde::de::Error::custom(error.message()))
    }
}

impl ExtensionId {
    /// Returns the id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ExtensionId {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        match id_rule_violation(&value) {
            Some(reason) => Err(Error::user(format!(
                "invalid extension id `{}`: {reason}",
                shown(&value, ERROR_VALUE_MAX_CHARS)
            ))),
            None => Ok(Self(value)),
        }
    }
}

/// Returns the first [extension id rule](self#extension-id-rules) that
/// `value` breaks. A contribution id, an activation command and a connection
/// type obey the same rules.
fn id_rule_violation(value: &str) -> Option<&'static str> {
    if value.is_empty() {
        return Some("it is empty");
    }
    if value.len() > EXTENSION_ID_MAX_LEN {
        return Some("it has more than 128 characters");
    }
    for segment in value.split('.') {
        if segment.is_empty() {
            return Some("a segment between `.` is empty");
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Some("only lowercase letters, digits, `-` and `.` are permitted");
        }
        if segment.starts_with('-') || segment.ends_with('-') {
            return Some("a segment starts or ends with `-`");
        }
    }
    None
}

/// Returns `value` in the form that an error message can show: a maximum of
/// `max` characters, and no character that changes the line or the direction
/// of the text in a terminal or in a log. A manifest is untrusted input.
fn shown(value: &str, max: usize) -> String {
    let mut text = String::new();
    for character in value.chars().take(max) {
        // Control characters, line separators and direction controls.
        let unsafe_to_show = character.is_control()
            || matches!(character, '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        if unsafe_to_show {
            text.extend(character.escape_default());
        } else {
            text.push(character);
        }
    }
    if value.chars().nth(max).is_some() {
        text.push_str("...");
    }
    text
}

/// Parses an IP address literal. An IPv6 address can have the `[]` of a
/// URL; an IPv4 address in `[]` is not an address.
fn ip_literal(host: &str) -> Option<IpAddr> {
    match host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        Some(inner) => inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6),
        None => host.parse().ok(),
    }
}

/// The form of a host in which two equal hosts are equal values.
#[derive(PartialEq, Eq, Hash)]
enum HostKey {
    Address(IpAddr),
    Name(String),
}

fn host_key(host: &str) -> HostKey {
    match ip_literal(host) {
        Some(address) => HostKey::Address(address),
        None => HostKey::Name(host.to_ascii_lowercase()),
    }
}

/// `true` if `host` obeys the [network host rules](self#capability-scope-rules).
fn is_network_host(host: &str) -> bool {
    if ip_literal(host).is_some() {
        return true;
    }
    let is_number = |label: &str| {
        let digits = label
            .strip_prefix("0x")
            .or_else(|| label.strip_prefix("0X"));
        digits.is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
            || label.bytes().all(|b| b.is_ascii_digit())
    };
    host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
        && !host.rsplit('.').next().is_some_and(is_number)
}

/// Returns `true` if the two hosts are the same host (ADR-0020). This is the
/// one comparison of hosts: the manifest validation and the permission
/// service use it.
///
/// - Two IP address literals are the same when they are the same address. An
///   IPv6 address can have the `[]` of a URL.
/// - All other texts are the same when they are equal, ASCII case ignored.
///
/// There is no name resolution, no wildcard and no conversion between IPv4
/// and IPv6. The function does not validate: a text that is not a valid host
/// is the same only as an equal text.
///
/// ```
/// use rivet_sdk::manifest::same_host;
///
/// assert!(same_host("db.example.com", "DB.Example.com"));
/// assert!(same_host("::1", "[0:0:0:0:0:0:0:1]"));
/// assert!(!same_host("localhost", "127.0.0.1"));
/// ```
pub fn same_host(left: &str, right: &str) -> bool {
    host_key(left) == host_key(right)
}

/// `true` if `namespace` obeys the
/// [secret namespace rules](self#capability-scope-rules).
fn is_secret_namespace(namespace: &str) -> bool {
    namespace.split('/').all(|segment| {
        !matches!(segment, "" | "." | "..")
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    })
}

/// `true` if `path` starts like a path below the home directory or like an
/// absolute path of an operating system. A text rule: the result does not
/// depend on the operating system of this process.
fn is_scope_path_start(path: &str) -> bool {
    path == "~"
        || path.starts_with("~/")
        || path.starts_with('/')
        || path.starts_with(r"\\")
        || matches!(path.as_bytes(), [drive, b':', b'/' | b'\\', ..] if drive.is_ascii_alphabetic())
}

/// `true` if the valid-start `path` has an empty component or ends with a
/// separator. A root (`/`, `C:\`) and the `\\` of a UNC path are not empty
/// components.
fn has_empty_component(path: &str) -> bool {
    let separators = ['/', '\\'];
    match path.strip_prefix(r"\\") {
        Some(unc) => unc.split(separators).any(str::is_empty),
        None => {
            path == "~/"
                || path.split_once(separators).is_some_and(|(_, rest)| {
                    !rest.is_empty() && rest.split(separators).any(str::is_empty)
                })
        }
    }
}

impl FromStr for ExtensionId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::try_from(value.to_owned())
    }
}

impl fmt::Display for ExtensionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An extension point that an extension can contribute to (§4.2).
///
/// The name in the manifest is the variant name in kebab case, for example
/// `auth-provider`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ExtensionPoint {
    /// Connects to a database and runs statements.
    Driver,
    /// Produces credentials for a connection attempt.
    AuthProvider,
    /// Resolves cloud identities.
    CredentialSource,
    /// Opens a byte stream to a target through a tunnel or a proxy.
    TunnelProvider,
    /// Reads catalog objects and generates DDL.
    MetadataProvider,
    /// Consumes a result stream.
    ResultSink,
    /// Converts an external format to a result stream.
    Importer,
    /// Converts a result stream to an external format.
    Exporter,
    /// Sends a prompt to a model and returns the response.
    ModelProvider,
    /// Runs scripts in one language.
    ScriptEngine,
    /// A CLI subcommand.
    CliCommand,
    /// A control API method.
    ApiEndpoint,
    /// A UI view. Requires `requires_ui = true`.
    UiView,
    /// A UI command. Requires `requires_ui = true`.
    UiCommand,
    /// A UI panel. Requires `requires_ui = true`.
    UiPanel,
}

impl ExtensionPoint {
    /// Returns `true` for the UI extension points. An extension that
    /// contributes one of them must set `requires_ui = true`.
    pub fn is_ui(self) -> bool {
        matches!(self, Self::UiView | Self::UiCommand | Self::UiPanel)
    }
}

/// One contribution of an extension to an extension point: a `[[contributes]]`
/// table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Contribution {
    /// The extension point.
    pub kind: ExtensionPoint,
    /// The name of the contribution inside the extension.
    pub id: String,
}

impl Contribution {
    /// Creates a contribution.
    ///
    /// The id is not validated here. [`Manifest::parse`] validates the
    /// contributions of a manifest.
    ///
    /// ```
    /// use rivet_sdk::manifest::{Contribution, ExtensionPoint};
    ///
    /// let contribution = Contribution::new(ExtensionPoint::Driver, "postgres");
    /// assert_eq!(contribution.id, "postgres");
    /// ```
    pub fn new(kind: ExtensionPoint, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
        }
    }
}

/// An event that activates an extension (§4.4): an `[[activation]]` table.
/// The field `on` selects the event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(tag = "on", rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ActivationEvent {
    /// `on = "extension-point"`: the first use of an extension point that the
    /// extension contributes.
    ExtensionPoint,
    /// `on = "command"`: the command is invoked.
    Command {
        /// The name of the command on the command bus.
        command: String,
    },
    /// `on = "connection"`: a connection of the type is opened.
    Connection {
        /// The connection type, for example `postgres`.
        #[serde(rename = "type")]
        connection_type: String,
    },
}

/// One entry of the network allowlist: a `[[capabilities.network]]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct NetworkScope {
    /// The host the extension may connect to.
    pub host: String,
    /// The ports on the host the extension may connect to.
    pub ports: Vec<u16>,
}

impl NetworkScope {
    /// Creates a scope for `ports` on `host`.
    ///
    /// The values are not validated here. [`Manifest::parse`] validates the
    /// scopes of a manifest.
    ///
    /// ```
    /// use rivet_sdk::manifest::NetworkScope;
    ///
    /// let scope = NetworkScope::new("db.example.com", [5432]);
    /// assert_eq!(scope.ports, [5432]);
    /// ```
    pub fn new(host: impl Into<String>, ports: impl IntoIterator<Item = u16>) -> Self {
        Self {
            host: host.into(),
            ports: ports.into_iter().collect(),
        }
    }
}

/// The access an extension has to a filesystem path.
///
/// This enum is exhaustive on purpose: it decides a permission. A new variant
/// is a breaking change of the SDK, so the core cannot ignore it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemAccess {
    /// `read`: read only.
    Read,
    /// `read-write`: read and write.
    ReadWrite,
}

/// One filesystem scope: a `[[capabilities.filesystem]]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct FilesystemScope {
    /// The path the extension may access. The host interprets it (#7).
    pub path: String,
    /// The access to the path.
    pub access: FilesystemAccess,
}

impl FilesystemScope {
    /// Creates a scope for `path` with `access`.
    ///
    /// The values are not validated here. [`Manifest::parse`] validates the
    /// scopes of a manifest.
    ///
    /// ```
    /// use rivet_sdk::manifest::{FilesystemAccess, FilesystemScope};
    ///
    /// let scope = FilesystemScope::new("~/.postgresql", FilesystemAccess::Read);
    /// assert_eq!(scope.access, FilesystemAccess::Read);
    /// ```
    pub fn new(path: impl Into<String>, access: FilesystemAccess) -> Self {
        Self {
            path: path.into(),
            access,
        }
    }
}

/// The access an extension has to the clipboard.
///
/// This enum is exhaustive on purpose: it decides a permission. A new variant
/// is a breaking change of the SDK, so the core cannot ignore it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClipboardAccess {
    /// `read`: read the clipboard.
    Read,
    /// `write`: write the clipboard.
    Write,
}

/// The capabilities an extension requires, with their scopes (§4.7): the
/// `[capabilities]` table. An empty list means the capability is not required.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct Capabilities {
    /// The hosts and ports the extension may connect to.
    pub network: Vec<NetworkScope>,
    /// The paths the extension may access.
    pub filesystem: Vec<FilesystemScope>,
    /// The secret namespaces the extension may read.
    pub secrets: Vec<String>,
    /// The clipboard operations the extension may do.
    pub clipboard: Vec<ClipboardAccess>,
}

impl Capabilities {
    /// Creates capabilities that require nothing. Add scopes with the
    /// `with_*` methods.
    ///
    /// The values are not validated here. [`Manifest::parse`] validates the
    /// capabilities of a manifest.
    ///
    /// ```
    /// use rivet_sdk::manifest::{Capabilities, ClipboardAccess, NetworkScope};
    ///
    /// assert!(Capabilities::new().is_empty());
    ///
    /// let capabilities = Capabilities::new()
    ///     .with_network([NetworkScope::new("db.example.com", [5432])])
    ///     .with_secrets(["keychain://prod".to_owned()])
    ///     .with_clipboard([ClipboardAccess::Write]);
    /// assert!(!capabilities.is_empty());
    /// assert_eq!(capabilities.network[0].host, "db.example.com");
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the hosts and ports the extension may connect to.
    #[must_use]
    pub fn with_network(mut self, network: impl IntoIterator<Item = NetworkScope>) -> Self {
        self.network = network.into_iter().collect();
        self
    }

    /// Sets the paths the extension may access.
    #[must_use]
    pub fn with_filesystem(
        mut self,
        filesystem: impl IntoIterator<Item = FilesystemScope>,
    ) -> Self {
        self.filesystem = filesystem.into_iter().collect();
        self
    }

    /// Sets the secret namespaces the extension may read.
    #[must_use]
    pub fn with_secrets(mut self, secrets: impl IntoIterator<Item = String>) -> Self {
        self.secrets = secrets.into_iter().collect();
        self
    }

    /// Sets the clipboard operations the extension may do.
    #[must_use]
    pub fn with_clipboard(mut self, clipboard: impl IntoIterator<Item = ClipboardAccess>) -> Self {
        self.clipboard = clipboard.into_iter().collect();
        self
    }

    /// Returns `true` if no capability is required: all lists are empty.
    pub fn is_empty(&self) -> bool {
        // The pattern has no `..`: a new field does not compile until it is
        // added here.
        let Self {
            network,
            filesystem,
            secrets,
            clipboard,
        } = self;
        network.is_empty() && filesystem.is_empty() && secrets.is_empty() && clipboard.is_empty()
    }
}

/// A parsed and validated `extension.toml` (§4.4).
///
/// Create one with [`Manifest::parse`]. See `docs/examples/extension.toml`
/// for a documented example of the file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Manifest {
    /// The id of the extension. Required.
    pub id: ExtensionId,
    /// The version of the extension. Required.
    pub version: Version,
    /// The SDK versions the extension supports (§4.5). Required.
    pub sdk: VersionReq,
    /// The extensions this extension depends on, with the permitted versions.
    #[serde(default)]
    pub dependencies: BTreeMap<ExtensionId, VersionReq>,
    /// The extension points the extension contributes to.
    #[serde(default)]
    pub contributes: Vec<Contribution>,
    /// The capabilities the extension requires.
    #[serde(default)]
    pub capabilities: Capabilities,
    /// The events that activate the extension.
    #[serde(default)]
    pub activation: Vec<ActivationEvent>,
    /// `true` when the extension needs a UI process. Default `false`.
    #[serde(default)]
    pub requires_ui: bool,
}

impl Manifest {
    /// Parses and validates the text of an `extension.toml` file.
    ///
    /// # Errors
    ///
    /// Returns an error of the category `user` that names the field and the
    /// reason when:
    ///
    /// - the text is not valid TOML;
    /// - a required field (`id`, `version`, `sdk`) is missing;
    /// - the id, the version or a version range is invalid;
    /// - a field, an extension point or a capability is unknown;
    /// - a dependency is declared more than once, or names the extension itself;
    /// - a contribution `id`, an activation `command` or `type`, a network
    ///   `host`, a filesystem `path` or a secret namespace is empty or has only
    ///   whitespace;
    /// - a contribution `id`, an activation `command` or `type` breaks the
    ///   [extension id rules](self#extension-id-rules);
    /// - a network `host`, a filesystem `path` or a secret namespace breaks the
    ///   [capability scope rules](self#capability-scope-rules);
    /// - a network scope has an empty `ports` list, contains port 0 or contains
    ///   a port more than once;
    /// - two contributions have the same `kind` and `id`;
    /// - an activation event, a network host, a filesystem path, a secret
    ///   namespace or a clipboard access is declared more than once;
    /// - a list has more than [`LIST_MAX_ENTRIES`] entries;
    /// - an activation event is `on = "extension-point"` and there is no
    ///   `[[contributes]]` table;
    /// - a UI extension point is contributed and `requires_ui` is not `true`.
    pub fn parse(text: &str) -> Result<Self> {
        // The line of the manifest names the field. The parser error is not
        // the source: its text repeats the manifest with no limit.
        let manifest: Self = toml::from_str(text).map_err(|error| {
            let place = error
                .span()
                .and_then(|span| text.get(..span.start))
                .map(|before| {
                    let line_start = before.rfind('\n').map_or(0, |end| end + 1);
                    format!(
                        "line {}, column {} (`{}`): ",
                        before.matches('\n').count() + 1,
                        before[line_start..].chars().count() + 1,
                        shown(
                            text[line_start..].lines().next().unwrap_or(""),
                            ERROR_VALUE_MAX_CHARS
                        )
                    )
                })
                .unwrap_or_default();
            Error::user(format!(
                "invalid extension manifest: {place}{}",
                shown(error.message(), PARSE_MESSAGE_MAX_CHARS)
            ))
        })?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// The rules that span fields or that the types do not express.
    fn validate(&self) -> Result<()> {
        let invalid =
            |reason: String| Err(Error::user(format!("invalid extension manifest: {reason}")));
        // The text of a value in a message.
        let shown = |value: &str| shown(value, ERROR_VALUE_MAX_CHARS);
        let not_blank = |field: String, value: &str| {
            if value.trim().is_empty() {
                return invalid(format!("field `{field}` must not be empty"));
            }
            Ok(())
        };
        // After `not_blank`, for a text with the extension id rules.
        let valid_id = |field: String, value: &str| match id_rule_violation(value) {
            Some(reason) => invalid(format!(
                "field `{field}` (`{}`) is invalid: {reason}",
                shown(value)
            )),
            None => Ok(()),
        };
        let capabilities = &self.capabilities;
        for (field, entries) in [
            ("contributes", self.contributes.len()),
            ("activation", self.activation.len()),
            ("capabilities.network", capabilities.network.len()),
            ("capabilities.filesystem", capabilities.filesystem.len()),
            ("capabilities.secrets", capabilities.secrets.len()),
        ] {
            if entries > LIST_MAX_ENTRIES {
                return invalid(format!(
                    "field `{field}` has {entries} entries; the maximum is {LIST_MAX_ENTRIES}"
                ));
            }
        }

        if self.dependencies.contains_key(&self.id) {
            return invalid(format!(
                "field `dependencies`: the extension `{}` must not depend on itself",
                self.id
            ));
        }
        // Each `seen` map gives the index of the first entry with a key, so a
        // duplicate check does not compare an entry with each earlier entry.
        let mut seen = HashMap::new();
        for (index, contribution) in self.contributes.iter().enumerate() {
            not_blank(format!("contributes[{index}].id"), &contribution.id)?;
            valid_id(format!("contributes[{index}].id"), &contribution.id)?;
            if let Some(first) = seen.insert((contribution.kind, &contribution.id), index) {
                return invalid(format!(
                    "field `contributes[{index}]` has the same `kind` and `id` (`{}`) as \
                     `contributes[{first}]`",
                    shown(&contribution.id)
                ));
            }
            if contribution.kind.is_ui() && !self.requires_ui {
                return invalid(format!(
                    "field `requires_ui` must be `true` because the UI contribution `{}` \
                     is declared in `contributes`",
                    shown(&contribution.id)
                ));
            }
        }
        let mut seen = HashMap::new();
        for (index, event) in self.activation.iter().enumerate() {
            match event {
                ActivationEvent::ExtensionPoint => {
                    if self.contributes.is_empty() {
                        return invalid(format!(
                            "field `activation[{index}]`: `on = \"extension-point\"` needs at \
                             least one `[[contributes]]` table"
                        ));
                    }
                }
                ActivationEvent::Command { command } => {
                    not_blank(format!("activation[{index}].command"), command)?;
                    valid_id(format!("activation[{index}].command"), command)?;
                }
                ActivationEvent::Connection { connection_type } => {
                    not_blank(format!("activation[{index}].type"), connection_type)?;
                    valid_id(format!("activation[{index}].type"), connection_type)?;
                }
            }
            if let Some(first) = seen.insert(event, index) {
                return invalid(format!(
                    "field `activation[{index}]` is the same as `activation[{first}]`"
                ));
            }
        }
        let mut seen = HashMap::new();
        for (index, scope) in capabilities.network.iter().enumerate() {
            not_blank(format!("capabilities.network[{index}].host"), &scope.host)?;
            if scope.host.strip_suffix('.').is_some_and(is_network_host) {
                return invalid(format!(
                    "field `capabilities.network[{index}].host` (`{}`) must not end with `.`; \
                     remove the `.` at the end",
                    shown(&scope.host)
                ));
            }
            if !is_network_host(&scope.host) {
                return invalid(format!(
                    "field `capabilities.network[{index}].host` (`{}`) must be a DNS name or an \
                     IP address. A DNS name has labels of ASCII letters, digits, `-` and `_`, \
                     separated by `.`; a label does not start or end with `-` and the last \
                     label is not a number. A port, a scheme, a path, a wildcard and \
                     whitespace are not permitted",
                    shown(&scope.host)
                ));
            }
            // The key of `same_host`.
            if let Some(first) = seen.insert(host_key(&scope.host), index) {
                return invalid(format!(
                    "field `capabilities.network[{index}].host` (`{}`) is the same host as \
                     `capabilities.network[{first}].host`; put all ports of a host in one table",
                    shown(&scope.host)
                ));
            }
            if scope.ports.is_empty() {
                return invalid(format!(
                    "field `capabilities.network[{index}].ports` must list at least one port"
                ));
            }
            if scope.ports.contains(&0) {
                return invalid(format!(
                    "field `capabilities.network[{index}].ports` must not contain port 0"
                ));
            }
            let mut ports = HashSet::new();
            if let Some(port) = scope.ports.iter().find(|&port| !ports.insert(port)) {
                return invalid(format!(
                    "field `capabilities.network[{index}].ports` contains port {port} more than \
                     once"
                ));
            }
        }
        let mut seen = HashMap::new();
        for (index, scope) in capabilities.filesystem.iter().enumerate() {
            not_blank(
                format!("capabilities.filesystem[{index}].path"),
                &scope.path,
            )?;
            if scope.path != scope.path.trim() {
                return invalid(format!(
                    "field `capabilities.filesystem[{index}].path` (`{}`) must not start or end \
                     with whitespace",
                    shown(&scope.path)
                ));
            }
            if !is_scope_path_start(&scope.path) {
                return invalid(format!(
                    "field `capabilities.filesystem[{index}].path` (`{}`) must be an absolute \
                     path, `~` or a path that starts with `~/`",
                    shown(&scope.path)
                ));
            }
            if scope.path.split(['/', '\\']).any(|part| part == "..") {
                return invalid(format!(
                    "field `capabilities.filesystem[{index}].path` (`{}`) must not contain a \
                     `..` component",
                    shown(&scope.path)
                ));
            }
            if scope.path.contains(char::is_control) {
                return invalid(format!(
                    "field `capabilities.filesystem[{index}].path` (`{}`) must not contain a \
                     control character",
                    shown(&scope.path)
                ));
            }
            if scope.path.split(['/', '\\']).any(|part| part == ".") {
                return invalid(format!(
                    "field `capabilities.filesystem[{index}].path` (`{}`) must not contain a \
                     `.` component",
                    shown(&scope.path)
                ));
            }
            if has_empty_component(&scope.path) {
                return invalid(format!(
                    "field `capabilities.filesystem[{index}].path` (`{}`) must not contain an \
                     empty component or end with a separator",
                    shown(&scope.path)
                ));
            }
            // Exact text, as the update review compares paths (ADR-0020).
            if let Some(first) = seen.insert(&scope.path, index) {
                return invalid(format!(
                    "field `capabilities.filesystem[{index}].path` (`{}`) is the same path as \
                     `capabilities.filesystem[{first}].path`; declare a path one time, with \
                     the access it needs",
                    shown(&scope.path)
                ));
            }
        }
        let mut seen = HashMap::new();
        for (index, namespace) in capabilities.secrets.iter().enumerate() {
            not_blank(format!("capabilities.secrets[{index}]"), namespace)?;
            if !is_secret_namespace(namespace) {
                return invalid(format!(
                    "field `capabilities.secrets[{index}]` (`{}`) must be segments \
                     separated by `/`; a segment has one or more ASCII letters, digits, `.`, \
                     `_` or `-` and is not `.` or `..`",
                    shown(namespace)
                ));
            }
            if let Some(first) = seen.insert(namespace, index) {
                return invalid(format!(
                    "field `capabilities.secrets[{index}]` (`{}`) is the same as \
                     `capabilities.secrets[{first}]`",
                    shown(namespace)
                ));
            }
        }
        let mut seen = HashMap::new();
        for (index, access) in capabilities.clipboard.iter().enumerate() {
            if let Some(first) = seen.insert(access, index) {
                return invalid(format!(
                    "field `capabilities.clipboard[{index}]` is the same as \
                     `capabilities.clipboard[{first}]`"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCategory;

    const MINIMAL: &str = "id = \"acme.postgres\"\nversion = \"1.0.0\"\nsdk = \"^0.1\"\n";

    /// Parses a manifest that must be rejected. Checks the category and that
    /// the message contains each expected part (the field and the reason).
    fn rejected(text: &str, parts: &[&str]) {
        let error = Manifest::parse(text).expect_err("manifest must be rejected");
        assert_eq!(error.category(), ErrorCategory::User);
        for part in parts {
            assert!(
                error.message().contains(part),
                "`{part}` is not in the message:\n{}",
                error.message()
            );
        }
    }

    #[test]
    fn minimal_manifest_uses_defaults() {
        let manifest = Manifest::parse(MINIMAL).unwrap();
        assert_eq!(manifest.id.as_str(), "acme.postgres");
        assert_eq!(manifest.version, Version::new(1, 0, 0));
        assert_eq!(manifest.sdk, VersionReq::parse("^0.1").unwrap());
        assert!(manifest.dependencies.is_empty());
        assert!(manifest.contributes.is_empty());
        assert_eq!(manifest.capabilities, Capabilities::default());
        assert!(manifest.activation.is_empty());
        assert!(!manifest.requires_ui);
    }

    #[test]
    fn example_manifest_is_parsed_in_full() {
        let manifest =
            Manifest::parse(include_str!("../../../docs/examples/extension.toml")).unwrap();
        assert_eq!(manifest.id.to_string(), "acme.postgres");
        assert_eq!(manifest.version, Version::new(1, 4, 0));
        assert_eq!(manifest.sdk, VersionReq::parse(">=0.1.0, <0.2.0").unwrap());
        assert!(manifest.requires_ui);
        assert_eq!(
            manifest.dependencies,
            BTreeMap::from([(
                "acme.aws-auth".parse().unwrap(),
                VersionReq::parse("^2.1").unwrap()
            )])
        );
        let contribution = |kind, id: &str| Contribution {
            kind,
            id: id.to_owned(),
        };
        assert_eq!(
            manifest.contributes,
            [
                contribution(ExtensionPoint::Driver, "postgres"),
                contribution(ExtensionPoint::CliCommand, "pg-vacuum"),
                contribution(ExtensionPoint::UiPanel, "pg-activity"),
            ]
        );
        assert_eq!(
            manifest.activation,
            [
                ActivationEvent::ExtensionPoint,
                ActivationEvent::Command {
                    command: "pg.vacuum".to_owned()
                },
                ActivationEvent::Connection {
                    connection_type: "postgres".to_owned()
                },
            ]
        );
        let filesystem = |path: &str, access| FilesystemScope {
            path: path.to_owned(),
            access,
        };
        assert_eq!(
            manifest.capabilities,
            Capabilities {
                network: vec![NetworkScope {
                    host: "db.example.com".to_owned(),
                    ports: vec![5432, 6432],
                }],
                filesystem: vec![
                    filesystem("~/.postgresql", FilesystemAccess::Read),
                    filesystem("~/.cache/acme-postgres", FilesystemAccess::ReadWrite),
                ],
                secrets: vec!["acme-postgres".to_owned()],
                clipboard: vec![ClipboardAccess::Read, ClipboardAccess::Write],
            }
        );
    }

    #[test]
    fn every_extension_point_name_is_accepted() {
        let names = [
            ("driver", ExtensionPoint::Driver),
            ("auth-provider", ExtensionPoint::AuthProvider),
            ("credential-source", ExtensionPoint::CredentialSource),
            ("tunnel-provider", ExtensionPoint::TunnelProvider),
            ("metadata-provider", ExtensionPoint::MetadataProvider),
            ("result-sink", ExtensionPoint::ResultSink),
            ("importer", ExtensionPoint::Importer),
            ("exporter", ExtensionPoint::Exporter),
            ("model-provider", ExtensionPoint::ModelProvider),
            ("script-engine", ExtensionPoint::ScriptEngine),
            ("cli-command", ExtensionPoint::CliCommand),
            ("api-endpoint", ExtensionPoint::ApiEndpoint),
            ("ui-view", ExtensionPoint::UiView),
            ("ui-command", ExtensionPoint::UiCommand),
            ("ui-panel", ExtensionPoint::UiPanel),
        ];
        for (name, point) in names {
            let text = format!(
                "{MINIMAL}requires_ui = true\n[[contributes]]\nkind = \"{name}\"\nid = \"x\"\n"
            );
            assert_eq!(Manifest::parse(&text).unwrap().contributes[0].kind, point);
        }
    }

    #[test]
    fn rejects_missing_required_field() {
        for field in ["id", "version", "sdk"] {
            let text: String = MINIMAL
                .lines()
                .filter(|line| !line.starts_with(field))
                .map(|line| format!("{line}\n"))
                .collect();
            rejected(&text, &[&format!("missing field `{field}`")]);
        }
    }

    #[test]
    fn rejects_invalid_id() {
        let cases = [
            ("", "it is empty"),
            ("Acme.postgres", "only lowercase letters"),
            ("acme_postgres", "only lowercase letters"),
            ("acme..postgres", "a segment between `.` is empty"),
            (".acme", "a segment between `.` is empty"),
            ("acme.-postgres", "a segment starts or ends with `-`"),
            ("acme-", "a segment starts or ends with `-`"),
        ];
        for (id, reason) in cases {
            let text = MINIMAL.replace("acme.postgres", id);
            rejected(
                &text,
                &["line 1, column 6", "id = ", "invalid extension id", reason],
            );
        }
        let long = "a".repeat(EXTENSION_ID_MAX_LEN + 1);
        rejected(
            &MINIMAL.replace("acme.postgres", &long),
            &["more than 128 characters"],
        );
        assert!(
            "a".repeat(EXTENSION_ID_MAX_LEN)
                .parse::<ExtensionId>()
                .is_ok()
        );
    }

    #[test]
    fn rejects_invalid_version() {
        rejected(&MINIMAL.replace("1.0.0", "1.0"), &["version = \"1.0\""]);
    }

    #[test]
    fn rejects_invalid_sdk_range() {
        rejected(
            &MINIMAL.replace("^0.1", "not-a-range"),
            &["sdk = \"not-a-range\""],
        );
    }

    #[test]
    fn rejects_invalid_dependency_range_and_id() {
        rejected(
            &format!("{MINIMAL}[dependencies]\n\"acme.auth\" = \">>1\"\n"),
            &["\"acme.auth\" = \">>1\""],
        );
        rejected(
            &format!("{MINIMAL}[dependencies]\n\"Acme\" = \"^1\"\n"),
            &["invalid extension id `Acme`"],
        );
    }

    #[test]
    fn rejects_unknown_field() {
        rejected(
            &format!("{MINIMAL}colour = \"red\"\n"),
            &["unknown field `colour`"],
        );
        rejected(
            &format!("{MINIMAL}[[contributes]]\nkind = \"driver\"\nid = \"x\"\nextra = 1\n"),
            &["unknown field `extra`"],
        );
        rejected(
            &format!("{MINIMAL}[[activation]]\non = \"command\"\ncommand = \"x\"\nextra = 1\n"),
            &["unknown field `extra`"],
        );
        rejected(
            &format!("{MINIMAL}[[capabilities.network]]\nhost = \"h\"\nports = [1]\nextra = 1\n"),
            &["unknown field `extra`"],
        );
    }

    #[test]
    fn rejects_unknown_extension_point() {
        rejected(
            &format!("{MINIMAL}[[contributes]]\nkind = \"teleporter\"\nid = \"x\"\n"),
            &["kind = \"teleporter\"", "unknown variant `teleporter`"],
        );
    }

    #[test]
    fn rejects_unknown_capability() {
        rejected(
            &format!("{MINIMAL}[capabilities]\ncamera = true\n"),
            &["unknown field `camera`", "network", "clipboard"],
        );
    }

    #[test]
    fn rejects_unknown_capability_scope_value() {
        rejected(
            &format!("{MINIMAL}[capabilities]\nclipboard = [\"paste\"]\n"),
            &["unknown variant `paste`"],
        );
        rejected(
            &format!("{MINIMAL}[[capabilities.filesystem]]\npath = \"/tmp\"\naccess = \"write\"\n"),
            &["access = \"write\"", "unknown variant `write`"],
        );
        rejected(
            &format!("{MINIMAL}[[capabilities.network]]\nhost = \"h\"\nports = [70000]\n"),
            &["ports = [70000]"],
        );
    }

    #[test]
    fn rejects_duplicate_dependency() {
        rejected(
            &format!("{MINIMAL}[dependencies]\n\"acme.auth\" = \"^1\"\n\"acme.auth\" = \"^2\"\n"),
            &["duplicate key", "acme.auth"],
        );
    }

    #[test]
    fn rejects_ui_contribution_without_requires_ui() {
        for kind in ["ui-view", "ui-command", "ui-panel"] {
            rejected(
                &format!("{MINIMAL}[[contributes]]\nkind = \"{kind}\"\nid = \"my-ui\"\n"),
                &["`requires_ui` must be `true`", "my-ui"],
            );
        }
    }

    #[test]
    fn rejects_blank_contribution_id() {
        for id in ["", " \t"] {
            rejected(
                &format!("{MINIMAL}[[contributes]]\nkind = \"driver\"\nid = \"{id}\"\n"),
                &["field `contributes[0].id` must not be empty"],
            );
        }
    }

    #[test]
    fn rejects_blank_activation_command() {
        for command in ["", "  "] {
            rejected(
                &format!("{MINIMAL}[[activation]]\non = \"command\"\ncommand = \"{command}\"\n"),
                &["field `activation[0].command` must not be empty"],
            );
        }
    }

    #[test]
    fn rejects_blank_activation_connection_type() {
        for connection_type in ["", "  "] {
            rejected(
                &format!(
                    "{MINIMAL}[[activation]]\non = \"connection\"\ntype = \"{connection_type}\"\n"
                ),
                &["field `activation[0].type` must not be empty"],
            );
        }
    }

    #[test]
    fn rejects_blank_network_host() {
        for host in ["", "  "] {
            rejected(
                &format!("{MINIMAL}[[capabilities.network]]\nhost = \"{host}\"\nports = [1]\n"),
                &["field `capabilities.network[0].host` must not be empty"],
            );
        }
    }

    #[test]
    fn rejects_empty_network_ports() {
        rejected(
            &format!("{MINIMAL}[[capabilities.network]]\nhost = \"h\"\nports = []\n"),
            &["field `capabilities.network[0].ports` must list at least one port"],
        );
    }

    #[test]
    fn rejects_network_port_zero() {
        rejected(
            &format!("{MINIMAL}[[capabilities.network]]\nhost = \"h\"\nports = [5432, 0]\n"),
            &["field `capabilities.network[0].ports` must not contain port 0"],
        );
    }

    #[test]
    fn rejects_blank_filesystem_path() {
        for path in ["", "  "] {
            rejected(
                &format!(
                    "{MINIMAL}[[capabilities.filesystem]]\npath = \"{path}\"\naccess = \"read\"\n"
                ),
                &["field `capabilities.filesystem[0].path` must not be empty"],
            );
        }
    }

    #[test]
    fn rejects_blank_secret_namespace() {
        for namespace in ["", "  "] {
            rejected(
                &format!("{MINIMAL}[capabilities]\nsecrets = [\"aws\", \"{namespace}\"]\n"),
                &["field `capabilities.secrets[1]` must not be empty"],
            );
        }
    }

    #[test]
    fn rejects_duplicate_contribution() {
        let driver = "[[contributes]]\nkind = \"driver\"\nid = \"pg\"\n";
        rejected(
            &format!("{MINIMAL}{driver}{driver}"),
            &[
                "field `contributes[1]`",
                "same `kind` and `id` (`pg`) as `contributes[0]`",
            ],
        );
        // The same id under a different kind is a different contribution.
        let exporter = "[[contributes]]\nkind = \"exporter\"\nid = \"pg\"\n";
        assert!(Manifest::parse(&format!("{MINIMAL}{driver}{exporter}")).is_ok());
    }

    /// A manifest with one network scope for `host`.
    fn network(host: &str, ports: &str) -> String {
        format!("[[capabilities.network]]\nhost = \"{host}\"\nports = {ports}\n")
    }

    #[test]
    fn accepts_dns_names_and_ip_literals_as_network_host() {
        for host in [
            "h",
            "localhost",
            "DB.example.com",
            "xn--bcher-kva.example",
            "3com.example",
            "10.0.0.5",
            "::1",
            "[::1]",
            "[2001:db8::1]",
        ] {
            let manifest = Manifest::parse(&format!("{MINIMAL}{}", network(host, "[1]")))
                .unwrap_or_else(|error| panic!("{host}: {error}"));
            // The text is kept as written.
            assert_eq!(manifest.capabilities.network[0].host, host);
        }
    }

    #[test]
    fn rejects_invalid_network_host() {
        let long_label = "a".repeat(64);
        let long_name = ["a".repeat(63).as_str(); 4].join(".");
        for host in [
            " db.example.com ",
            "db.example.com\\t",
            "db.example.com:5432",
            "[::1]:5432",
            "*",
            "*.example.com",
            "https://db.example.com",
            "db.example.com/path",
            "db..example.com",
            ".example.com",
            "-db.example.com",
            "db-.example.com",
            "user@db.example.com",
            "b\u{fc}cher.example",
            "[db.example.com]",
            "[10.0.0.5]",
            "[::1",
            "::1]",
            "127.1",
            "256.1.1.1",
            "0x7f.1",
            "0x7f000001",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            rejected(
                &format!("{MINIMAL}{}", network(host, "[1]")),
                &[
                    "field `capabilities.network[0].host`",
                    "must be a DNS name or an IP address",
                ],
            );
        }
    }

    #[test]
    fn rejects_duplicate_network_host() {
        for (first, second) in [
            ("db.example.com", "db.example.com"),
            // The permission service ignores ASCII case and compares addresses.
            ("db.example.com", "DB.Example.com"),
            ("::1", "[0:0:0:0:0:0:0:1]"),
        ] {
            for ports in ["[5432]", "[6432]"] {
                rejected(
                    &format!(
                        "{MINIMAL}{}{}",
                        network(first, "[5432]"),
                        network(second, ports)
                    ),
                    &[
                        "field `capabilities.network[1].host`",
                        "is the same host as `capabilities.network[0].host`",
                    ],
                );
            }
        }
        let two_hosts = format!(
            "{MINIMAL}{}{}",
            network("db.example.com", "[5432]"),
            network("replica.example.com", "[5432]")
        );
        assert!(Manifest::parse(&two_hosts).is_ok());
    }

    #[test]
    fn rejects_duplicate_network_port() {
        rejected(
            &format!("{MINIMAL}{}", network("h", "[5432, 22, 5432]")),
            &["field `capabilities.network[0].ports` contains port 5432 more than once"],
        );
    }

    #[test]
    fn rejects_duplicate_clipboard_access() {
        rejected(
            &format!("{MINIMAL}[capabilities]\nclipboard = [\"read\", \"read\"]\n"),
            &["field `capabilities.clipboard[1]` is the same as `capabilities.clipboard[0]`"],
        );
    }

    #[test]
    fn rejects_duplicate_filesystem_scope() {
        let scope = |access: &str| {
            format!("[[capabilities.filesystem]]\npath = \"~/.pg\"\naccess = \"{access}\"\n")
        };
        rejected(
            &format!("{MINIMAL}{}{}", scope("read"), scope("read")),
            &[
                "field `capabilities.filesystem[1].path` (`~/.pg`)",
                "is the same path as `capabilities.filesystem[0].path`",
            ],
        );
    }

    #[test]
    fn rejects_filesystem_path_with_surrounding_whitespace() {
        for path in [" ~/.pg", "~/.pg ", "~/.pg\\n"] {
            rejected(
                &format!(
                    "{MINIMAL}[[capabilities.filesystem]]\npath = \"{path}\"\naccess = \"read\"\n"
                ),
                &[
                    "field `capabilities.filesystem[0].path`",
                    "must not start or end with whitespace",
                ],
            );
        }
        // Whitespace inside a path is permitted.
        let inside = "[[capabilities.filesystem]]\npath = \"~/my files\"\naccess = \"read\"\n";
        assert!(Manifest::parse(&format!("{MINIMAL}{inside}")).is_ok());
    }

    #[test]
    fn rejects_filesystem_path_with_parent_component() {
        for path in [
            "~/../outside",
            "~/..",
            "/data/../etc",
            "/data/..",
            "C:\\\\data\\\\..\\\\x",
        ] {
            rejected(
                &format!(
                    "{MINIMAL}[[capabilities.filesystem]]\npath = \"{path}\"\naccess = \"read\"\n"
                ),
                &[
                    "field `capabilities.filesystem[0].path`",
                    "must not contain a `..` component",
                ],
            );
        }
        // `..` inside a name is not a component.
        let name = "[[capabilities.filesystem]]\npath = \"~/a..b/..c\"\naccess = \"read\"\n";
        assert!(Manifest::parse(&format!("{MINIMAL}{name}")).is_ok());
    }

    #[test]
    fn rejects_filesystem_path_that_is_not_absolute_or_below_home() {
        // TOML literal strings (`'`): a `\` is not an escape.
        let scope = |path: &str| {
            format!("{MINIMAL}[[capabilities.filesystem]]\npath = '{path}'\naccess = \"read\"\n")
        };
        for path in [
            "relative/dir",
            "relative",
            "~other/.ssh",
            "./x",
            "C:",
            "C:x",
            r"~\x",
            r"\x",
        ] {
            rejected(
                &scope(path),
                &[
                    "field `capabilities.filesystem[0].path`",
                    "must be an absolute path, `~` or a path that starts with `~/`",
                ],
            );
        }
        for path in [
            "~",
            "~/.pg",
            "/",
            "/var/lib",
            r"C:\data",
            "c:/data",
            r"\\host\share",
        ] {
            Manifest::parse(&scope(path)).unwrap_or_else(|error| panic!("{path}: {error}"));
        }
    }

    #[test]
    fn rejects_invalid_secret_namespace() {
        for namespace in [
            " aws",
            "aws ",
            "prod db",
            "aws\\n",
            "/aws",
            "aws/",
            "prod//db",
            "keychain://aws",
            ".",
            "prod/../db",
            "prod/./db",
            "prod%2Fdb",
            "aws:prod",
            "prod+db",
            "pr\u{f6}d",
        ] {
            rejected(
                &format!("{MINIMAL}[capabilities]\nsecrets = [\"{namespace}\"]\n"),
                &[
                    "field `capabilities.secrets[0]`",
                    "must be segments separated by `/`",
                ],
            );
        }
        let valid = "[capabilities]\nsecrets = [\"acme-postgres\", \"prod/db\", \"Prod/db\"]\n";
        assert!(Manifest::parse(&format!("{MINIMAL}{valid}")).is_ok());
    }

    #[test]
    fn rejects_duplicate_secret_namespace() {
        rejected(
            &format!("{MINIMAL}[capabilities]\nsecrets = [\"aws\", \"prod/db\", \"aws\"]\n"),
            &["field `capabilities.secrets[2]` (`aws`) is the same as `capabilities.secrets[0]`"],
        );
    }

    #[test]
    fn rejects_duplicate_activation_event() {
        let driver = "[[contributes]]\nkind = \"driver\"\nid = \"pg\"\n";
        for event in [
            "[[activation]]\non = \"extension-point\"\n",
            "[[activation]]\non = \"command\"\ncommand = \"pg.vacuum\"\n",
            "[[activation]]\non = \"connection\"\ntype = \"postgres\"\n",
        ] {
            rejected(
                &format!("{MINIMAL}{driver}{event}{event}"),
                &["field `activation[1]` is the same as `activation[0]`"],
            );
        }
    }

    #[test]
    fn rejects_extension_point_activation_without_contribution() {
        rejected(
            &format!("{MINIMAL}[[activation]]\non = \"extension-point\"\n"),
            &[
                "field `activation[0]`",
                "`on = \"extension-point\"` needs at least one `[[contributes]]` table",
            ],
        );
    }

    #[test]
    fn rejects_invalid_contribution_id() {
        let cases = [
            ("my id", "only lowercase letters"),
            (" pg", "only lowercase letters"),
            ("pg\\n", "only lowercase letters"),
            ("Pg", "only lowercase letters"),
            ("pg..x", "a segment between `.` is empty"),
            ("-pg", "a segment starts or ends with `-`"),
        ];
        for (id, reason) in cases {
            rejected(
                &format!("{MINIMAL}[[contributes]]\nkind = \"driver\"\nid = \"{id}\"\n"),
                &["field `contributes[0].id`", "is invalid", reason],
            );
        }
        let long = "a".repeat(EXTENSION_ID_MAX_LEN + 1);
        rejected(
            &format!("{MINIMAL}[[contributes]]\nkind = \"driver\"\nid = \"{long}\"\n"),
            &["field `contributes[0].id`", "more than 128 characters"],
        );
    }

    #[test]
    fn rejects_invalid_activation_command_and_connection_type() {
        for name in [
            " pg.vacuum",
            "pg.vacuum ",
            "pg vacuum",
            "Pg.Vacuum",
            "pg..vacuum",
        ] {
            rejected(
                &format!("{MINIMAL}[[activation]]\non = \"command\"\ncommand = \"{name}\"\n"),
                &["field `activation[0].command`", "is invalid"],
            );
            rejected(
                &format!("{MINIMAL}[[activation]]\non = \"connection\"\ntype = \"{name}\"\n"),
                &["field `activation[0].type`", "is invalid"],
            );
        }
    }

    #[test]
    fn rejects_dependency_on_itself() {
        rejected(
            &format!("{MINIMAL}[dependencies]\n\"acme.postgres\" = \"^1\"\n"),
            &[
                "field `dependencies`",
                "`acme.postgres` must not depend on itself",
            ],
        );
    }

    #[test]
    fn rejects_invalid_toml() {
        rejected("id = ", &["invalid extension manifest"]);
    }

    // R-54: each list has a maximum number of entries.
    #[test]
    fn rejects_list_with_more_than_the_maximum_number_of_entries() {
        // One entry of each list. `secrets` is an array in one line.
        type Entry = fn(usize) -> String;
        let lists: [(&str, Entry); 5] = [
            ("contributes", |n| {
                format!("[[contributes]]\nkind = \"driver\"\nid = \"d{n}\"\n")
            }),
            ("activation", |n| {
                format!("[[activation]]\non = \"command\"\ncommand = \"c{n}\"\n")
            }),
            ("capabilities.network", |n| {
                network(&format!("2001:db8::{n:x}"), "[1]")
            }),
            ("capabilities.filesystem", |n| {
                format!("[[capabilities.filesystem]]\npath = \"/d{n}\"\naccess = \"read\"\n")
            }),
            ("capabilities.secrets", |n| format!("\"s{n}\",")),
        ];
        for (field, entry) in lists {
            let manifest = |count: usize| {
                let entries: String = (0..count).map(entry).collect();
                if field == "capabilities.secrets" {
                    return format!("{MINIMAL}[capabilities]\nsecrets = [{entries}]\n");
                }
                format!("{MINIMAL}{entries}")
            };
            Manifest::parse(&manifest(LIST_MAX_ENTRIES))
                .unwrap_or_else(|error| panic!("{field}: {error}"));
            rejected(
                &manifest(LIST_MAX_ENTRIES + 1),
                &[
                    &format!("field `{field}` has 257 entries"),
                    "the maximum is 256",
                ],
            );
        }
    }

    // R-54: a port is a `u16`, so the list needs no limit; the check is linear.
    #[test]
    fn accepts_every_port_and_rejects_a_duplicate_after_them() {
        let all: Vec<String> = (1..=u16::MAX).map(|port| port.to_string()).collect();
        let ports = format!("[{}]", all.join(","));
        let manifest = Manifest::parse(&format!("{MINIMAL}{}", network("h", &ports))).unwrap();
        assert_eq!(manifest.capabilities.network[0].ports.len(), 65535);
        let ports = format!("[{},65535]", all.join(","));
        rejected(
            &format!("{MINIMAL}{}", network("h", &ports)),
            &["contains port 65535 more than once"],
        );
    }

    // R-55a: an error message cuts and escapes the text of the manifest.
    #[test]
    fn error_message_cuts_and_escapes_untrusted_text() {
        let long = "a".repeat(1_000_000);
        // TOML escapes: the parsed value has ESC, a line feed, a line
        // separator and a right-to-left override.
        let hostile = "a\\u001b[31mX\\nfake line\\u2028\\u202e";
        let raw_escape = format!("{MINIMAL}x = \"a\u{1b}[31m\"\n");
        let mut manifests = vec![raw_escape, format!("{MINIMAL}{long} = 1\n")];
        for value in [long.as_str(), hostile] {
            manifests.extend([
                MINIMAL.replace("acme.postgres", value),
                MINIMAL.replace("1.0.0", value),
                format!("{MINIMAL}[dependencies]\n\"{value}\" = \"1\"\n"),
                format!("{MINIMAL}[[contributes]]\nkind = \"{value}\"\nid = \"x\"\n"),
                format!("{MINIMAL}[[contributes]]\nkind = \"driver\"\nid = \"{value}\"\n"),
                format!("{MINIMAL}[[activation]]\non = \"command\"\ncommand = \"{value}\"\n"),
                format!("{MINIMAL}[[activation]]\non = \"connection\"\ntype = \"{value}\"\n"),
                format!("{MINIMAL}{}", network(value, "[1]")),
                format!("{MINIMAL}{}", network(&format!("{value}."), "[1]")),
                format!(
                    "{MINIMAL}[[capabilities.filesystem]]\npath = \"{value}\"\naccess = \"read\"\n"
                ),
                format!(
                    "{MINIMAL}[[capabilities.filesystem]]\npath = \"/{value}/..\"\naccess = \"read\"\n"
                ),
                format!(
                    "{MINIMAL}[[capabilities.filesystem]]\npath = \"/{value}/.\"\naccess = \"read\"\n"
                ),
                format!(
                    "{MINIMAL}[[capabilities.filesystem]]\npath = \"/{value}//\"\naccess = \"read\"\n"
                ),
                format!(
                    "{MINIMAL}[[capabilities.filesystem]]\npath = \"/{value}\\u0000\"\naccess = \"read\"\n"
                ),
                // `%`: a long namespace is valid.
                format!("{MINIMAL}[capabilities]\nsecrets = [\"{value}%\"]\n"),
            ]);
        }
        // Duplicates: the value is valid for the first rules of its field.
        let path = format!("/{long}");
        let scope = format!("[[capabilities.filesystem]]\npath = \"{path}\"\naccess = \"read\"\n");
        manifests.push(format!("{MINIMAL}{scope}{scope}"));
        for manifest in manifests {
            let error = Manifest::parse(&manifest).expect_err("manifest must be rejected");
            let message = error.message();
            let head: String = message.chars().take(200).collect();
            assert!(message.len() <= 1024, "{} bytes: {head}", message.len());
            assert!(
                !message.chars().any(|c| c.is_control()
                    || matches!(c, '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')),
                "{message:?}"
            );
            // The parser error has the same text with no limit.
            assert!(std::error::Error::source(&error).is_none(), "{head}");
        }
        rejected(
            &format!("{MINIMAL}{}", network(hostile, "[1]")),
            &["(`a\\u{1b}[31mX\\nfake line\\u{2028}\\u{202e}`)"],
        );
        let cut = format!("(`{}...`)", "a".repeat(ERROR_VALUE_MAX_CHARS));
        rejected(&format!("{MINIMAL}{}", network(&long, "[1]")), &[&cut]);
        // A value with the maximum length is not cut.
        let whole = "a".repeat(ERROR_VALUE_MAX_CHARS);
        rejected(
            &format!("{MINIMAL}{}", network(&whole, "[1]")),
            &[&format!("(`{whole}`)")],
        );
    }

    // R-55b: `_` is permitted in a label of a host, not in an id.
    #[test]
    fn accepts_underscore_in_network_host_only() {
        for host in [
            "db_1.example.com",
            "_dmarc.example.com",
            "db_.example.com",
            "a._",
        ] {
            Manifest::parse(&format!("{MINIMAL}{}", network(host, "[1]")))
                .unwrap_or_else(|error| panic!("{host}: {error}"));
        }
        for id in ["pg_vacuum", "PgVacuum"] {
            rejected(
                &format!("{MINIMAL}[[contributes]]\nkind = \"driver\"\nid = \"{id}\"\n"),
                &["field `contributes[0].id`", "only lowercase letters"],
            );
            rejected(
                &format!("{MINIMAL}[[activation]]\non = \"command\"\ncommand = \"{id}\"\n"),
                &["field `activation[0].command`", "only lowercase letters"],
            );
            rejected(
                &format!("{MINIMAL}[[activation]]\non = \"connection\"\ntype = \"{id}\"\n"),
                &["field `activation[0].type`", "only lowercase letters"],
            );
        }
        rejected(
            &format!(
                "{MINIMAL}{}{}",
                network("db_1.example.com", "[1]"),
                network("DB_1.Example.com", "[2]")
            ),
            &["is the same host as `capabilities.network[0].host`"],
        );
    }

    // R-55b: the message for a `.` at the end says what to do.
    #[test]
    fn rejects_network_host_with_dot_at_the_end() {
        for host in ["db.example.com.", "localhost.", "10.0.0.5."] {
            rejected(
                &format!("{MINIMAL}{}", network(host, "[1]")),
                &[
                    "field `capabilities.network[0].host`",
                    "remove the `.` at the end",
                ],
            );
        }
    }

    // R-55d: the one host comparison of the SDK and of the permission service.
    #[test]
    fn same_host_ignores_ascii_case_and_compares_ip_addresses() {
        for (left, right) in [
            ("db.example.com", "DB.Example.COM"),
            ("db_1.example.com", "DB_1.example.com"),
            ("::1", "[::1]"),
            ("::1", "0:0:0:0:0:0:0:1"),
            ("[2001:DB8::1]", "2001:db8:0::1"),
            ("10.0.0.5", "10.0.0.5"),
        ] {
            assert!(same_host(left, right), "{left} {right}");
            assert!(same_host(right, left), "{right} {left}");
        }
        for (left, right) in [
            ("db.example.com", "db.example.org"),
            ("db_1.example.com", "db-1.example.com"),
            ("db_1.example.com", "db1.example.com"),
            ("db.example.com", "db.example.com."),
            ("::1", "::2"),
            ("10.0.0.5", "10.0.0.6"),
            // An IPv4 address in `[]` is not an address.
            ("10.0.0.5", "[10.0.0.5]"),
            // No name resolution and no conversion between address families.
            ("localhost", "127.0.0.1"),
            ("::ffff:10.0.0.5", "10.0.0.5"),
            // Only ASCII case is ignored.
            ("b\u{fc}cher.example", "b\u{dc}cher.example"),
        ] {
            assert!(!same_host(left, right), "{left} {right}");
            assert!(!same_host(right, left), "{right} {left}");
        }
    }

    // R-55c: a path has one spelling.
    #[test]
    fn rejects_filesystem_path_with_a_second_spelling() {
        // TOML literal strings (`'`): a `\` is not an escape.
        let scope = |path: &str| {
            format!("{MINIMAL}[[capabilities.filesystem]]\npath = '{path}'\naccess = \"read\"\n")
        };
        for path in ["/a/./b", "/a/.", "~/.", r"C:\a\.\b"] {
            rejected(
                &scope(path),
                &[
                    "field `capabilities.filesystem[0].path`",
                    "must not contain a `.` component",
                ],
            );
        }
        for path in [
            "/a//b",
            "//host/share",
            "/a/",
            "~/",
            "~/.pg/",
            r"C:\data\",
            r"C:\\data",
            r"\\host\share\",
            r"\\host\\share",
            r"\\",
            r"\\\host",
        ] {
            rejected(
                &scope(path),
                &[
                    "field `capabilities.filesystem[0].path`",
                    "must not contain an empty component or end with a separator",
                ],
            );
        }
        // A root ends with its separator. A name can start with `.`.
        for path in [
            "/",
            r"C:\",
            "C:/",
            "~",
            "~/.pg",
            "/a/.b/c.",
            r"\\host",
            r"\\host\share",
        ] {
            Manifest::parse(&scope(path)).unwrap_or_else(|error| panic!("{path}: {error}"));
        }
    }

    // R-55c
    #[test]
    fn rejects_filesystem_path_with_control_character() {
        for path in [
            "/a\\u0000b",
            "~/\\u0000",
            "/a\\u0000",
            "/a\\nb",
            "/a\\u001b[31mb",
            "/a\\tb",
            "/a\\u007fb",
            "/a\\u0085b",
        ] {
            rejected(
                &format!(
                    "{MINIMAL}[[capabilities.filesystem]]\npath = \"{path}\"\naccess = \"read\"\n"
                ),
                &[
                    "field `capabilities.filesystem[0].path`",
                    "must not contain a control character",
                ],
            );
        }
    }

    // R-55c: a path is declared one time, whatever the access.
    #[test]
    fn rejects_filesystem_path_declared_with_two_accesses() {
        let scope = |access: &str| {
            format!("[[capabilities.filesystem]]\npath = \"~/.pg\"\naccess = \"{access}\"\n")
        };
        for (first, second) in [("read", "read-write"), ("read-write", "read")] {
            rejected(
                &format!("{MINIMAL}{}{}", scope(first), scope(second)),
                &[
                    "field `capabilities.filesystem[1].path` (`~/.pg`)",
                    "is the same path as `capabilities.filesystem[0].path`",
                ],
            );
        }
    }
}
