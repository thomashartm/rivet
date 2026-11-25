//! Extension manifest schema: the typed form of an `extension.toml` file
//! (ARCHITECTURE.md §4.4, §4.5, §4.7, ADR-0008).
//!
//! [`Manifest::parse`] takes the text of the file. This module does no file or
//! network I/O (§3.3). Unknown fields are rejected. A failure is an
//! [`Error`] of the category `user`.
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

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

pub use semver::{Version, VersionReq};
use serde::Deserialize;

use crate::error::{Error, Result};

/// The maximum length of an [`ExtensionId`] in characters.
pub const EXTENSION_ID_MAX_LEN: usize = 128;

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
        let invalid =
            |reason: &str| Error::user(format!("invalid extension id `{value}`: {reason}"));
        if value.is_empty() {
            return Err(invalid("it is empty"));
        }
        if value.len() > EXTENSION_ID_MAX_LEN {
            return Err(invalid("it has more than 128 characters"));
        }
        for segment in value.split('.') {
            if segment.is_empty() {
                return Err(invalid("a segment between `.` is empty"));
            }
            if !segment
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(invalid(
                    "only lowercase letters, digits, `-` and `.` are permitted",
                ));
            }
            if segment.starts_with('-') || segment.ends_with('-') {
                return Err(invalid("a segment starts or ends with `-`"));
            }
        }
        Ok(Self(value))
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

/// An event that activates an extension (§4.4): an `[[activation]]` table.
/// The field `on` selects the event.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

/// The access an extension has to a filesystem path.
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

/// The access an extension has to the clipboard.
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
    /// - a network scope has an empty `ports` list or contains port 0;
    /// - two contributions have the same `kind` and `id`;
    /// - a UI extension point is contributed and `requires_ui` is not `true`.
    pub fn parse(text: &str) -> Result<Self> {
        // The TOML error shows the line of the manifest, so it names the field.
        let manifest: Self = toml::from_str(text).map_err(|error| {
            Error::user(format!("invalid extension manifest: {error}")).with_source(error)
        })?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// The rules that span fields or that the types do not express.
    fn validate(&self) -> Result<()> {
        let invalid =
            |reason: String| Err(Error::user(format!("invalid extension manifest: {reason}")));
        let not_blank = |field: String, value: &str| {
            if value.trim().is_empty() {
                return invalid(format!("field `{field}` must not be empty"));
            }
            Ok(())
        };

        if self.dependencies.contains_key(&self.id) {
            return invalid(format!(
                "field `dependencies`: the extension `{}` must not depend on itself",
                self.id
            ));
        }
        for (index, contribution) in self.contributes.iter().enumerate() {
            not_blank(format!("contributes[{index}].id"), &contribution.id)?;
            if let Some(first) = self.contributes[..index]
                .iter()
                .position(|earlier| earlier == contribution)
            {
                return invalid(format!(
                    "field `contributes[{index}]` has the same `kind` and `id` (`{}`) as \
                     `contributes[{first}]`",
                    contribution.id
                ));
            }
            if contribution.kind.is_ui() && !self.requires_ui {
                return invalid(format!(
                    "field `requires_ui` must be `true` because the UI contribution `{}` \
                     is declared in `contributes`",
                    contribution.id
                ));
            }
        }
        for (index, event) in self.activation.iter().enumerate() {
            match event {
                ActivationEvent::ExtensionPoint => {}
                ActivationEvent::Command { command } => {
                    not_blank(format!("activation[{index}].command"), command)?;
                }
                ActivationEvent::Connection { connection_type } => {
                    not_blank(format!("activation[{index}].type"), connection_type)?;
                }
            }
        }
        for (index, scope) in self.capabilities.network.iter().enumerate() {
            not_blank(format!("capabilities.network[{index}].host"), &scope.host)?;
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
        }
        for (index, scope) in self.capabilities.filesystem.iter().enumerate() {
            not_blank(
                format!("capabilities.filesystem[{index}].path"),
                &scope.path,
            )?;
        }
        for (index, namespace) in self.capabilities.secrets.iter().enumerate() {
            not_blank(format!("capabilities.secrets[{index}]"), namespace)?;
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
            rejected(&text, &["id = ", "\ninvalid extension id", reason]);
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
}
