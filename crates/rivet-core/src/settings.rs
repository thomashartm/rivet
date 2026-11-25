//! Layered settings from TOML files (ARCHITECTURE.md §6.2, §6.3).
//!
//! # Layers
//!
//! There are four layers: default → user → workspace → connection
//! ([`Layer`]). A later layer overrides an earlier layer per key. Tables
//! merge key by key. All other values, arrays included, are replaced whole.
//!
//! # Files
//!
//! - Each file is a TOML document with an integer [`SCHEMA_VERSION_KEY`].
//! - A file with an older version is migrated forward when it is loaded.
//! - A file with a newer version than [`SCHEMA_VERSION`] is an error.
//! - A file that does not exist is an empty layer.
//!
//! # Secrets
//!
//! Settings hold references to secrets ([`SecretUri`]), not secret values.
//! The check at load time is a guard against common mistakes. It is not a
//! proof that a file has no secret value.
//!
//! What the check refuses:
//!
//! - A string under a key whose name marks a secret, if the string is not a
//!   [`SecretUri`]. In an array or a table under such a key, each string is
//!   checked.
//! - A string under any key, if it contains a URL with a password
//!   (`scheme://user:password@host`) or a parameter with a secret name and a
//!   value (`?password=x`, `;Password=x`).
//! - Exception: a secret URI with a built-in scheme (`keychain`, `aws-sm`,
//!   `gcp-sm`) and no second `://` gets no check of its text. Its path can
//!   contain `:`, `@` and `=`.
//!
//! A value that is not a string (integer, float, boolean, date) is accepted
//! under each key: `max_tokens = 4096`, `show_password = true`.
//!
//! Which key names mark a secret:
//!
//! - The name is split into segments at `_`, `-`, `.` and camelCase
//!   boundaries. ASCII case and digits at the end of a segment are ignored.
//! - The key marks a secret if a segment is in [`SECRET_KEY_NAMES`], or if
//!   the name contains the segments `api key`, `private key` or `access key`
//!   (also with `keys`) and the segment `id` does not follow.
//! - Examples: `db_password`, `password2`, `accessToken`, `aws-access-key`,
//!   `api_key_prod`.
//! - Whole segments are compared: `public_key`, `keymap`, `tokenizer` and
//!   `access_key_id` do not mark a secret.
//! - A key that marks a secret cannot hold other text: `password_hint = "pet"`
//!   is refused. Use a key name that does not mark a secret.
//!
//! What the check does not find (examples, not a complete list):
//!
//! - A secret value under a key with another name: `auth`, `pass`, `pw`,
//!   `bearer`, `signing_key`, `ssh_key`, `dbpassword`, `apikey`.
//! - A URL password that contains an unencoded `/`, `?`, `#` or space.
//! - A URL with a secret as the user name and no password
//!   (`https://secret@host`).
//! - A string under a secret key that is a secret value with the form of a
//!   URI and no password part: `password = "x://hunter2"` parses as a secret
//!   URI.
//!
//! What the check refuses although it is not a secret value:
//!
//! - A secret URI of an extension scheme whose path has the form
//!   `user:password@` or a secret parameter: `vault://team:prod@kv/db`.
//!
//! The error of a typed lookup ([`Settings::get`]) never contains the value.
//!
//! # Example
//!
//! ```
//! use rivet_core::settings::{Layer, Settings};
//!
//! let mut settings = Settings::new();
//! settings.set_layer(
//!     Layer::Default,
//!     "built-in defaults",
//!     "schema_version = 1\n[jobs]\nmax_concurrent = 4\n",
//! )?;
//! settings.set_layer(
//!     Layer::User,
//!     "settings.toml",
//!     "schema_version = 1\n[jobs]\nmax_concurrent = 2\n",
//! )?;
//!
//! assert_eq!(settings.get::<usize>("jobs.max_concurrent")?, Some(2));
//! assert_eq!(settings.layer_of("jobs.max_concurrent"), Some(Layer::User));
//! # Ok::<(), rivet_sdk::error::Error>(())
//! ```

use rivet_sdk::error::{Error, Result};
use rivet_sdk::secret::SecretUri;
use serde::de::DeserializeOwned;
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use toml::{Table, Value};

/// The key that holds the schema version in every settings file.
pub const SCHEMA_VERSION_KEY: &str = "schema_version";

/// One migration step: it takes a settings file of version `n` and returns
/// the same file in version `n + 1`.
type Migration = fn(Table) -> Result<Table>;

/// The migration steps in order. Step `i` migrates version `i + 1`.
/// To change the schema, add one step here; [`SCHEMA_VERSION`] follows.
const MIGRATIONS: &[Migration] = &[];

/// The schema version that this host reads and writes.
pub const SCHEMA_VERSION: i64 = MIGRATIONS.len() as i64 + 1;

/// Key-name segments that mark a secret. A string under a key that has one
/// of these segments must be a secret URI, not a secret value: `password`,
/// `db_password`, `dbPassword`, `DB-PASSWORD` and `password2` all have the
/// segment `password`.
///
/// The segments `api key`, `private key` and `access key` (also with `keys`)
/// mark a secret too. See the [module documentation](self#secrets) for how a
/// key name is split, and for what the check does not find.
pub const SECRET_KEY_NAMES: &[&str] = &[
    "password",
    "passwords",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "secrets",
    "token",
    "tokens",
    "credential",
    "credentials",
];

/// The schemes of the built-in secret backends (ADR-0008). The text of a
/// secret URI with one of these schemes is not checked for a password.
const BUILT_IN_SECRET_SCHEMES: [&str; 3] = [crate::secrets::KEYCHAIN_SCHEME, "aws-sm", "gcp-sm"];

/// The segments that mark a secret when `key` or `keys` follows.
/// `secret key` is not here: `secret` alone marks a secret.
const SECRET_KEY_KINDS: [&str; 3] = ["api", "private", "access"];

/// A settings layer. The order of the variants is the override order: a
/// later layer overrides an earlier one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Layer {
    /// Values that ship with the host.
    Default,
    /// The settings file of the user. See [`user_settings_path`].
    User,
    /// The settings file of the open workspace.
    Workspace,
    /// The settings of one connection.
    Connection,
}

impl Layer {
    /// All layers, from the lowest to the highest priority.
    pub const ALL: [Self; 4] = [Self::Default, Self::User, Self::Workspace, Self::Connection];
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Default => "default",
            Self::User => "user",
            Self::Workspace => "workspace",
            Self::Connection => "connection",
        })
    }
}

/// The content of one layer and where it came from.
#[derive(Debug, Clone, Default)]
struct Source {
    /// The file path or another name for error messages.
    name: String,
    table: Table,
}

/// The settings of all four layers and their merged view.
///
/// A key is a path of table keys joined by `.`, for example
/// `jobs.max_concurrent`. A table key that contains a `.` cannot be
/// addressed.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    /// Indexed by `Layer as usize`.
    layers: [Source; 4],
    merged: Table,
}

impl Settings {
    /// Creates settings with four empty layers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces `layer` with the TOML document `text`. `source` names the
    /// document in error messages; for a file, give its path.
    ///
    /// # Errors
    ///
    /// Returns a `user` error that names `source` if:
    ///
    /// - `text` is not valid TOML (the message gives the line),
    /// - [`SCHEMA_VERSION_KEY`] is missing, not a positive integer, or newer
    ///   than [`SCHEMA_VERSION`],
    /// - a migration step fails,
    /// - a key that marks a secret ([`SECRET_KEY_NAMES`]) holds a string that
    ///   is not a secret URI,
    /// - a string under another key contains a URL with a password or a
    ///   parameter with a secret name and a value.
    ///
    /// See the [module documentation](self#secrets) for the limits of this
    /// check.
    ///
    /// The message names the key and never contains the value.
    ///
    /// The layer does not change when an error is returned.
    pub fn set_layer(&mut self, layer: Layer, source: &str, text: &str) -> Result<()> {
        let table = parse_layer(source, text, MIGRATIONS)?;
        self.replace(layer, source.to_owned(), table);
        Ok(())
    }

    /// Reads the file `path` and replaces `layer` with its content. A file
    /// that does not exist makes the layer empty.
    ///
    /// # Errors
    ///
    /// Returns a `user` error that names `path` if the file cannot be read,
    /// or if [`set_layer`](Self::set_layer) refuses its content.
    pub fn load_layer(&mut self, layer: Layer, path: &Path) -> Result<()> {
        let source = path.display().to_string();
        match std::fs::read_to_string(path) {
            Ok(text) => self.set_layer(layer, &source, &text),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.replace(layer, source, Table::new());
                Ok(())
            }
            Err(error) => Err(
                Error::user(format!("{source}: cannot read the settings file")).with_source(error),
            ),
        }
    }

    /// Returns the value of `key` after all layers are merged, or `None` if
    /// no layer sets it. `T` can be a struct to read a whole table.
    ///
    /// # Errors
    ///
    /// Returns a `user` error if the value does not have the type `T`. The
    /// message names the source of the layer that set the key, the key, the
    /// type `T` without module paths (`Vec<String>`) and the TOML type of the
    /// value. It never contains the value.
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let Some(value) = find(&self.merged, key) else {
            return Ok(None);
        };
        // The error of `toml` is dropped: its text quotes the value.
        value.clone().try_into().map(Some).map_err(|_| {
            let source = self
                .layer_of(key)
                .map_or("settings", |layer| &self.layers[layer as usize].name);
            Error::user(format!(
                "{source}: key `{key}` cannot be read as `{}`: the value is a TOML {}",
                short_type_name::<T>(),
                value.type_str()
            ))
        })
    }

    /// Returns the layer that set the value of `key`: the highest layer that
    /// contains the key. Returns `None` if no layer sets it.
    ///
    /// For a table, this is the highest layer that sets a key in the table.
    pub fn layer_of(&self, key: &str) -> Option<Layer> {
        // A key in the merged view is always visible in the highest layer
        // that contains it: a layer above that would hide it has no such key.
        find(&self.merged, key)?;
        Layer::ALL
            .into_iter()
            .rev()
            .find(|layer| find(&self.layers[*layer as usize].table, key).is_some())
    }

    fn replace(&mut self, layer: Layer, name: String, table: Table) {
        self.layers[layer as usize] = Source { name, table };
        self.merged = Table::new();
        for source in &self.layers {
            merge(&mut self.merged, &source.table);
        }
    }
}

/// Returns the name of `T` without module paths: `Vec<String>`, not
/// `alloc::vec::Vec<alloc::string::String>`.
fn short_type_name<T>() -> String {
    let mut name = String::new();
    // Where the current identifier starts in `name`. A `:` shows that the
    // identifier was a module, so it is removed.
    let mut identifier = 0;
    for ch in std::any::type_name::<T>().chars() {
        if ch == ':' {
            name.truncate(identifier);
            continue;
        }
        name.push(ch);
        if !(ch.is_alphanumeric() || ch == '_') {
            identifier = name.len();
        }
    }
    name
}

/// Copies `over` into `base`. Tables merge key by key; other values replace.
fn merge(base: &mut Table, over: &Table) {
    for (key, value) in over {
        match (base.get_mut(key), value) {
            (Some(Value::Table(base)), Value::Table(over)) => merge(base, over),
            _ => {
                base.insert(key.clone(), value.clone());
            }
        }
    }
}

/// Returns the value at the dotted `key`.
fn find<'a>(table: &'a Table, key: &str) -> Option<&'a Value> {
    match key.split_once('.') {
        Some((first, rest)) => find(table.get(first)?.as_table()?, rest),
        None => table.get(key),
    }
}

/// Returns the path of the user settings file: `rivet/settings.toml` in the
/// configuration directory of the platform (§6.2).
///
/// | Platform | Directory |
/// | --- | --- |
/// | Linux and other Unix | `$XDG_CONFIG_HOME`, or `$HOME/.config` |
/// | macOS | `$HOME/Library/Application Support` |
/// | Windows | `%APPDATA%` |
///
/// # Errors
///
/// Returns a `user` error that names the environment variable if the
/// variable that the platform needs is not set.
pub fn user_settings_path() -> Result<PathBuf> {
    let dir = user_config_dir(std::env::consts::OS, |name| std::env::var_os(name))?;
    Ok(dir.join("rivet").join("settings.toml"))
}

/// The pure part of [`user_settings_path`]: `os` is a value of
/// [`std::env::consts::OS`], and `env` reads an environment variable.
fn user_config_dir(os: &str, env: impl Fn(&str) -> Option<OsString>) -> Result<PathBuf> {
    // An empty value counts as not set.
    let var = |name: &str| {
        env(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    let require = |name: &str| {
        var(name).ok_or_else(|| {
            Error::user(format!(
                "the environment variable {name} is not set, so the user settings directory is unknown"
            ))
        })
    };
    Ok(match os {
        "windows" => require("APPDATA")?,
        "macos" => require("HOME")?.join("Library/Application Support"),
        // The XDG specification: a relative XDG_CONFIG_HOME is ignored.
        _ => match var("XDG_CONFIG_HOME").filter(|dir| dir.has_root()) {
            Some(dir) => dir,
            None => require("HOME")?.join(".config"),
        },
    })
}

/// Parses one settings document, migrates it to the newest version of
/// `migrations` and checks it. Returns the content without the version key.
fn parse_layer(source: &str, text: &str, migrations: &[Migration]) -> Result<Table> {
    let mut table: Table = text.parse().map_err(|error: toml::de::Error| {
        // `message()`, not `Display`: `Display` quotes the line of the file,
        // and the line can contain a secret value.
        let line = error
            .span()
            .map(|span| text[..span.start.min(text.len())].matches('\n').count() + 1);
        match line {
            Some(line) => Error::user(format!("{source}: line {line}: {}", error.message())),
            None => Error::user(format!("{source}: {}", error.message())),
        }
    })?;

    let current = migrations.len() as i64 + 1;
    let version = match table.remove(SCHEMA_VERSION_KEY) {
        Some(Value::Integer(version)) if version >= 1 => version,
        Some(_) => {
            return Err(Error::user(format!(
                "{source}: key `{SCHEMA_VERSION_KEY}` must be an integer from 1 to {current}"
            )));
        }
        None => {
            return Err(Error::user(format!(
                "{source}: key `{SCHEMA_VERSION_KEY}` is missing; add `{SCHEMA_VERSION_KEY} = {current}`"
            )));
        }
    };
    if version > current {
        return Err(Error::user(format!(
            "{source}: {SCHEMA_VERSION_KEY} {version} is newer than version {current}, \
             the newest that this version of rivet can read"
        )));
    }

    // `version` is in `1..=current`, so the index is in range.
    for (step, from) in migrations[(version - 1) as usize..].iter().zip(version..) {
        table = step(table).map_err(|error| {
            let message = format!(
                "{source}: migration from {SCHEMA_VERSION_KEY} {from} failed: {}",
                error.message()
            );
            Error::user(message).with_source(error)
        })?;
    }

    reject_secret_values(source, "", &table)?;
    Ok(table)
}

/// Splits a key name into lowercase segments at `_`, `-`, `.` and camelCase
/// boundaries: `dbPassword` and `DB_PASSWORD` give `db`, `password`;
/// `APIKey` gives `api`, `key`.
fn key_segments(key: &str) -> Vec<String> {
    let chars: Vec<char> = key.chars().collect();
    let mut segments = vec![String::new()];
    for (index, &ch) in chars.iter().enumerate() {
        if matches!(ch, '_' | '-' | '.') {
            segments.push(String::new());
            continue;
        }
        let previous = index.checked_sub(1).map(|index| chars[index]);
        let next_is_lower = chars.get(index + 1).is_some_and(char::is_ascii_lowercase);
        // `bP` in `dbPassword`, `2P` in `db2Password`, `IK` in `APIKey`.
        let boundary = ch.is_ascii_uppercase()
            && previous.is_some_and(|previous| {
                previous.is_ascii_lowercase()
                    || previous.is_ascii_digit()
                    || (previous.is_ascii_uppercase() && next_is_lower)
            });
        if boundary {
            segments.push(String::new());
        }
        if let Some(segment) = segments.last_mut() {
            segment.push(ch.to_ascii_lowercase());
        }
    }
    segments.retain(|segment| !segment.is_empty());
    segments
}

/// `true` if the key name marks a secret. See [`SECRET_KEY_NAMES`].
fn is_secret_key(key: &str) -> bool {
    let segments = key_segments(key);
    // `password2` and `token_1` are `password` and `token`.
    let segments: Vec<&str> = segments
        .iter()
        .map(|segment| segment.trim_end_matches(|ch: char| ch.is_ascii_digit()))
        .filter(|segment| !segment.is_empty())
        .collect();
    let is_key_pair = |index: usize| {
        SECRET_KEY_KINDS.contains(&segments[index])
            && matches!(segments.get(index + 1), Some(&("key" | "keys")))
            // `access_key_id` is the public name of a key, not the key.
            && segments.get(index + 2) != Some(&"id")
    };
    segments
        .iter()
        .any(|segment| SECRET_KEY_NAMES.contains(segment))
        || (0..segments.len()).any(is_key_pair)
}

/// `true` if `text` contains a URL with a password:
/// `scheme://user:password@host`. The user can be empty; the password cannot.
fn has_url_password(text: &str) -> bool {
    text.match_indices("://").any(|(index, separator)| {
        let rest = &text[index + separator.len()..];
        // RFC 3986: the authority ends at the first `/`, `?` or `#`, and the
        // user information ends at the last `@` in the authority. A URL in
        // prose also ends at a space.
        // shortcut: a password with an unencoded `/`, `?`, `#` or space is
        // not found; upgrade to a URL parser if settings get typed
        // connection URLs.
        let is_end = |ch: char| matches!(ch, '/' | '?' | '#') || ch.is_whitespace();
        let authority = rest.split(is_end).next().unwrap_or(rest);
        authority
            .rsplit_once('@')
            .and_then(|(user_info, _)| user_info.split_once(':'))
            .is_some_and(|(_, password)| !password.is_empty())
    })
}

/// `true` if `text` contains a parameter `name=value` whose name marks a
/// secret ([`is_secret_key`]) and whose value is not empty. A parameter
/// starts at the start of the text or after `?`, `&`, `#` or `;`: a URL
/// query (`?user=a&password=x`) and a connection string
/// (`Server=h;Password=x`).
fn has_secret_parameter(text: &str) -> bool {
    text.split(['?', '&', '#', ';']).any(|parameter| {
        parameter
            .split_once('=')
            .is_some_and(|(name, value)| is_secret_key(name.trim()) && !value.trim().is_empty())
    })
}

/// Fails if `table` holds a value that the [module documentation](self#secrets)
/// refuses. `path` is the dotted key of `table`; it is empty for the root.
fn reject_secret_values(source: &str, path: &str, table: &Table) -> Result<()> {
    reject_in_table(source, path, table, None)
}

/// `secret_key` is the nearest key on the path whose name marks a secret.
fn reject_in_table(
    source: &str,
    path: &str,
    table: &Table,
    secret_key: Option<&str>,
) -> Result<()> {
    table.iter().try_for_each(|(key, value)| {
        let path = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        let secret_key = if is_secret_key(key) {
            Some(key.as_str())
        } else {
            secret_key
        };
        reject_in_value(source, &path, value, secret_key)
    })
}

/// The messages never contain the value.
fn reject_in_value(
    source: &str,
    path: &str,
    value: &Value,
    secret_key: Option<&str>,
) -> Result<()> {
    let text = match value {
        Value::Table(table) => return reject_in_table(source, path, table, secret_key),
        Value::Array(items) => {
            return items.iter().enumerate().try_for_each(|(index, item)| {
                reject_in_value(source, &format!("{path}[{index}]"), item, secret_key)
            });
        }
        Value::String(text) => text,
        // An integer, a float, a boolean or a date is not a secret value.
        _ => return Ok(()),
    };
    // A built-in secret URI can contain `:`, `@` and `=` in its path. A
    // second `://` shows that the text is more than one URI.
    let is_built_in = text.matches("://").count() == 1
        && text
            .parse::<SecretUri>()
            .is_ok_and(|uri| BUILT_IN_SECRET_SCHEMES.contains(&uri.scheme()));
    let problem = if is_built_in {
        return Ok(());
    } else if has_url_password(text) {
        format!(
            "holds a URL with a password; put the password in a secret store and use a secret \
             URI (for example keychain://). Only a secret URI with the scheme {} can contain \
             `user:password@`",
            BUILT_IN_SECRET_SCHEMES.join(", ")
        )
    } else if has_secret_parameter(text) {
        String::from(
            "holds text with a secret parameter (for example `password=`); put the value in a \
             secret store and use a secret URI (for example keychain://)",
        )
    } else if let Some(name) = secret_key.filter(|_| text.parse::<SecretUri>().is_err()) {
        format!(
            "must hold a secret URI (for example keychain://), because the key name `{name}` \
             marks a secret; settings do not accept a secret value. If the value is not a \
             secret, use a key name that does not mark one"
        )
    } else {
        return Ok(());
    };
    Err(Error::user(format!("{source}: key `{path}` {problem}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rivet_sdk::error::ErrorCategory;
    use serde::Deserialize;

    fn settings(layers: &[(Layer, &str)]) -> Settings {
        let mut settings = Settings::new();
        for (layer, text) in layers {
            settings
                .set_layer(*layer, &format!("{layer}.toml"), text)
                .expect("valid layer");
        }
        settings
    }

    /// Asserts a `user` error whose text contains every part of `parts`.
    fn assert_user_error<T: fmt::Debug>(result: Result<T>, parts: &[&str]) -> String {
        let error = result.expect_err("an error");
        assert_eq!(error.category(), ErrorCategory::User, "{error}");
        let text = error.to_string();
        for part in parts {
            assert!(text.contains(part), "`{part}` is missing in: {text}");
        }
        text
    }

    const DEFAULT: &str = "schema_version = 1\n[editor]\ntab_width = 4\nfont = \"mono\"\n[jobs]\nmax_concurrent = 4\n";
    const USER: &str = "schema_version = 1\n[editor]\ntab_width = 2\n";
    const WORKSPACE: &str = "schema_version = 1\n[editor]\nfont = \"serif\"\n";
    const CONNECTION: &str = "schema_version = 1\n[jobs]\nmax_concurrent = 1\n";

    #[derive(Debug, PartialEq, Deserialize)]
    struct Editor {
        tab_width: u32,
        font: String,
    }

    fn assert_four_layers(settings: &Settings) {
        assert_eq!(settings.get::<u32>("editor.tab_width").unwrap(), Some(2));
        assert_eq!(settings.layer_of("editor.tab_width"), Some(Layer::User));

        let font = settings.get::<String>("editor.font").unwrap();
        assert_eq!(font.as_deref(), Some("serif"));
        assert_eq!(settings.layer_of("editor.font"), Some(Layer::Workspace));

        let limit = settings.get::<usize>("jobs.max_concurrent").unwrap();
        assert_eq!(limit, Some(1));
        assert_eq!(
            settings.layer_of("jobs.max_concurrent"),
            Some(Layer::Connection)
        );
    }

    #[test]
    fn later_layer_overrides_earlier_layer_per_key() {
        let settings = settings(&[
            (Layer::Default, DEFAULT),
            (Layer::User, USER),
            (Layer::Workspace, WORKSPACE),
            (Layer::Connection, CONNECTION),
        ]);
        assert_four_layers(&settings);
    }

    #[test]
    fn override_order_does_not_depend_on_the_load_order() {
        let settings = settings(&[
            (Layer::Connection, CONNECTION),
            (Layer::Workspace, WORKSPACE),
            (Layer::User, USER),
            (Layer::Default, DEFAULT),
        ]);
        assert_four_layers(&settings);
    }

    #[test]
    fn key_set_only_in_the_default_layer_reports_the_default_layer() {
        let settings = settings(&[(Layer::Default, DEFAULT), (Layer::User, USER)]);
        assert_eq!(
            settings.get::<usize>("jobs.max_concurrent").unwrap(),
            Some(4)
        );
        assert_eq!(
            settings.layer_of("jobs.max_concurrent"),
            Some(Layer::Default)
        );
    }

    #[test]
    fn table_lookup_returns_the_merged_table_as_a_typed_value() {
        let settings = settings(&[
            (Layer::Default, DEFAULT),
            (Layer::User, USER),
            (Layer::Workspace, WORKSPACE),
        ]);
        let editor = settings.get::<Editor>("editor").unwrap();
        assert_eq!(
            editor,
            Some(Editor {
                tab_width: 2,
                font: "serif".to_owned()
            })
        );
        assert_eq!(settings.layer_of("editor"), Some(Layer::Workspace));
    }

    #[test]
    fn key_that_no_layer_sets_is_none() {
        let settings = settings(&[(Layer::Default, DEFAULT)]);
        for key in ["editor.theme", "missing", "editor.tab_width.deeper", ""] {
            assert_eq!(settings.get::<String>(key).unwrap(), None, "{key}");
            assert_eq!(settings.layer_of(key), None, "{key}");
        }
        assert_eq!(settings.get::<i64>(SCHEMA_VERSION_KEY).unwrap(), None);
    }

    #[test]
    fn scalar_in_a_later_layer_replaces_a_table() {
        let settings = settings(&[
            (Layer::Default, "schema_version = 1\n[a]\nb = 1\n"),
            (Layer::User, "schema_version = 1\na = 5\n"),
        ]);
        assert_eq!(settings.get::<i64>("a").unwrap(), Some(5));
        assert_eq!(settings.layer_of("a"), Some(Layer::User));
        assert_eq!(settings.get::<i64>("a.b").unwrap(), None);
        assert_eq!(settings.layer_of("a.b"), None);
    }

    #[test]
    fn replacing_a_layer_removes_its_old_keys() {
        let mut settings = settings(&[(Layer::Default, DEFAULT), (Layer::User, USER)]);
        settings
            .set_layer(Layer::User, "user.toml", "schema_version = 1\n")
            .unwrap();
        assert_eq!(settings.get::<u32>("editor.tab_width").unwrap(), Some(4));
        assert_eq!(settings.layer_of("editor.tab_width"), Some(Layer::Default));
    }

    #[test]
    fn lookup_with_the_wrong_type_names_the_file_and_the_key() {
        let settings = settings(&[(Layer::Default, DEFAULT), (Layer::User, USER)]);
        assert_user_error(
            settings.get::<bool>("editor.tab_width"),
            &["user.toml", "`editor.tab_width`"],
        );
    }

    #[test]
    fn missing_or_invalid_schema_version_names_the_file_and_the_key() {
        for text in [
            "",
            "[editor]\ntab_width = 2\n",
            "schema_version = \"1\"\n",
            "schema_version = 1.0\n",
            "schema_version = 0\n",
            "schema_version = -1\n",
        ] {
            let mut settings = Settings::new();
            assert_user_error(
                settings.set_layer(Layer::User, "/cfg/settings.toml", text),
                &["/cfg/settings.toml", "`schema_version`"],
            );
        }
    }

    #[test]
    fn newer_schema_version_is_an_error_that_names_the_file_and_both_versions() {
        let mut settings = settings(&[(Layer::User, USER)]);
        let text = assert_user_error(
            settings.set_layer(Layer::User, "/cfg/settings.toml", "schema_version = 2\n"),
            &["/cfg/settings.toml", "schema_version 2", "version 1"],
        );
        assert!(text.contains("newer"), "{text}");
        // The failed load did not change the layer.
        assert_eq!(settings.get::<u32>("editor.tab_width").unwrap(), Some(2));
    }

    #[test]
    fn current_schema_version_is_one() {
        assert_eq!(SCHEMA_VERSION, 1);
    }

    /// Test-only migration from a fake version 1: `tabs` moves to
    /// `editor.tab_width`.
    fn fake_v1_to_v2(mut table: Table) -> Result<Table> {
        if let Some(tabs) = table.remove("tabs") {
            let mut editor = Table::new();
            editor.insert("tab_width".to_owned(), tabs);
            table.insert("editor".to_owned(), Value::Table(editor));
        }
        Ok(table)
    }

    /// Test-only migration from a fake version 2: it adds `migrated`.
    fn fake_v2_to_v3(mut table: Table) -> Result<Table> {
        table.insert("migrated".to_owned(), Value::Boolean(true));
        Ok(table)
    }

    fn failing_migration(_: Table) -> Result<Table> {
        Err(Error::user("`tabs` must be an integer"))
    }

    const FAKE: &[Migration] = &[fake_v1_to_v2, fake_v2_to_v3];

    #[test]
    fn older_version_is_migrated_forward_through_every_step() {
        let table = parse_layer("old.toml", "schema_version = 1\ntabs = 8\n", FAKE).unwrap();
        let expected: Table = "migrated = true\n[editor]\ntab_width = 8\n"
            .parse()
            .unwrap();
        assert_eq!(table, expected);
    }

    #[test]
    fn migration_starts_at_the_version_of_the_file() {
        // The step from version 1 does not run: `tabs` stays.
        let table = parse_layer("old.toml", "schema_version = 2\ntabs = 8\n", FAKE).unwrap();
        let expected: Table = "tabs = 8\nmigrated = true\n".parse().unwrap();
        assert_eq!(table, expected);

        let table = parse_layer("new.toml", "schema_version = 3\ntabs = 8\n", FAKE).unwrap();
        let expected: Table = "tabs = 8\n".parse().unwrap();
        assert_eq!(table, expected);
    }

    #[test]
    fn version_after_the_last_migration_is_too_new() {
        assert_user_error(
            parse_layer("future.toml", "schema_version = 4\n", FAKE),
            &["future.toml", "schema_version 4", "version 3"],
        );
    }

    #[test]
    fn failed_migration_names_the_file_and_the_version() {
        assert_user_error(
            parse_layer(
                "old.toml",
                "schema_version = 1\ntabs = \"x\"\n",
                &[failing_migration],
            ),
            &["old.toml", "schema_version 1", "`tabs` must be an integer"],
        );
    }

    #[test]
    fn syntax_error_names_the_file_and_the_line_and_hides_the_content() {
        let mut settings = Settings::new();
        let text = assert_user_error(
            settings.set_layer(
                Layer::User,
                "user.toml",
                "schema_version = 1\npassword = \"hunter2\n",
            ),
            &["user.toml", "line 2"],
        );
        assert!(!text.contains("hunter2"), "leaked: {text}");
    }

    #[test]
    fn secret_value_is_refused_with_the_file_and_the_key_and_without_the_value() {
        let cases = [
            ("password = \"hunter2\"\n", "`password`"),
            ("[db]\npassword = \"hunter2\"\n", "`db.password`"),
            ("[db]\nPassword = \"hunter2\"\n", "`db.Password`"),
            ("[db]\nTOKEN = \"hunter2\"\n", "`db.TOKEN`"),
            ("[db]\npassphrase = \"hunter2\"\n", "`db.passphrase`"),
            ("[db]\nsecret = \"hunter2\"\n", "`db.secret`"),
            ("[db]\napi_key = \"hunter2\"\n", "`db.api_key`"),
            ("[db]\nprivate_key = \"hunter2\"\n", "`db.private_key`"),
            ("[db.token]\nvalue = \"hunter2\"\n", "`db.token.value`"),
            ("[db]\ntoken = [\"hunter2\"]\n", "`db.token[0]`"),
            (
                "[[profiles]]\nname = \"a\"\n[[profiles]]\ntoken = \"hunter2\"\n",
                "`profiles[1].token`",
            ),
            ("[db]\npassword = \"Vault://hunter2\"\n", "`db.password`"),
        ];
        for (body, key) in cases {
            let mut settings = Settings::new();
            let text = assert_user_error(
                settings.set_layer(
                    Layer::Workspace,
                    "ws/rivet.toml",
                    &format!("schema_version = 1\n{body}"),
                ),
                &["ws/rivet.toml", key, "secret"],
            );
            assert!(!text.contains("hunter2"), "leaked: {text}");
        }
    }

    #[test]
    fn secret_uri_is_accepted_under_a_secret_key() {
        let settings = settings(&[(
            Layer::Connection,
            "schema_version = 1\n[db]\npassword = \"keychain://rivet/prod-db\"\n",
        )]);
        let uri = settings.get::<SecretUri>("db.password").unwrap().unwrap();
        assert_eq!(uri.as_str(), "keychain://rivet/prod-db");
    }

    #[test]
    fn secret_value_is_refused_under_each_key_with_a_secret_segment() {
        for key in [
            "db_password",
            "access_token",
            "client_secret",
            "secret_key",
            "pwd",
            "passwd",
            "dbPassword",
            "DB_PASSWORD",
            "db-password",
            "APIKey",
            "awsAccessKey",
            "aws_access_key",
            "ssh_private_key",
            "api_keys",
            "credentials",
            "user-credential",
            "refreshTokens",
            "secrets",
        ] {
            let mut settings = Settings::new();
            let text = assert_user_error(
                settings.set_layer(
                    Layer::User,
                    "user.toml",
                    &format!("schema_version = 1\n[db]\n{key} = \"hunter2\"\n"),
                ),
                &["user.toml", &format!("`db.{key}`"), "secret"],
            );
            assert!(!text.contains("hunter2"), "leaked: {text}");
        }
        // A key that contains `.` is one key with two segments.
        let mut settings = Settings::new();
        let text = assert_user_error(
            settings.set_layer(
                Layer::User,
                "user.toml",
                "schema_version = 1\n\"db.password\" = \"hunter2\"\npasswords = [\"hunter2\"]\n",
            ),
            &["user.toml", "secret"],
        );
        assert!(!text.contains("hunter2"), "leaked: {text}");
        assert_user_error(
            settings.set_layer(
                Layer::User,
                "user.toml",
                "schema_version = 1\npasswords = [\"hunter2\"]\n",
            ),
            &["user.toml", "`passwords[0]`"],
        );
    }

    /// R-44: text under a key that marks a secret is refused, and the
    /// message says what to do.
    #[test]
    fn text_that_is_not_a_secret_uri_is_refused_under_a_secret_key() {
        for (body, key, name) in [
            (
                "secret_backend = \"keychain\"\n",
                "`secret_backend`",
                "`secret_backend`",
            ),
            (
                "password_hint = \"pet\"\n",
                "`password_hint`",
                "`password_hint`",
            ),
            (
                "[credentials]\nhelper = \"osxkeychain\"\n",
                "`credentials.helper`",
                "`credentials`",
            ),
        ] {
            let mut settings = Settings::new();
            assert_user_error(
                settings.set_layer(
                    Layer::User,
                    "user.toml",
                    &format!("schema_version = 1\n{body}"),
                ),
                &[
                    "user.toml",
                    key,
                    &format!("key name {name} marks a secret"),
                    "use a key name",
                ],
            );
        }
    }

    #[test]
    fn secret_check_matches_whole_segments_only() {
        let settings = settings(&[(
            Layer::User,
            "schema_version = 1\npublic_key = \"ssh-ed25519 AAAA\"\nkey = \"k\"\n\
             keymap = \"vim\"\ntokenizer = \"simple\"\nsecretary = \"ann\"\n\
             api_key_id = \"AKIA\"\npassport = \"x\"\naws_access_key_id = \"AKIA\"\n",
        )]);
        for key in [
            "aws_access_key_id",
            "public_key",
            "key",
            "keymap",
            "tokenizer",
            "secretary",
            "api_key_id",
            "passport",
        ] {
            assert!(settings.get::<String>(key).unwrap().is_some(), "{key}");
        }
    }

    /// R-44: only a string can be a secret value.
    #[test]
    fn value_that_is_not_a_string_is_accepted_under_a_secret_key() {
        let settings = settings(&[(
            Layer::User,
            "schema_version = 1\ntokens_per_page = 50\nmax_password_length = 12\n\
             show_password = true\nsave_passwords = false\ntoken_limit = 5\n\
             max_tokens = 4096\nmask_secrets = true\nsecret = 1.5\n\
             token = 2026-11-25\npasswords = [1, true]\n[credentials]\nretries = 3\n",
        )]);
        assert_eq!(settings.get::<u32>("max_tokens").unwrap(), Some(4096));
        assert_eq!(settings.get::<bool>("show_password").unwrap(), Some(true));
        assert_eq!(settings.get::<u32>("credentials.retries").unwrap(), Some(3));
    }

    /// R-44: an array or a table under a secret key is checked string by
    /// string.
    #[test]
    fn secret_uris_are_accepted_in_an_array_and_a_table_under_a_secret_key() {
        let settings = settings(&[(
            Layer::User,
            "schema_version = 1\npasswords = [\"keychain://a/b\", \"vault://c/d\"]\n\
             [tokens]\nprod = \"keychain://rivet/prod\"\nttl = 60\n\
             [tokens.nested]\nlist = [\"aws-sm://x/y\"]\n",
        )]);
        let uris = settings.get::<Vec<SecretUri>>("passwords").unwrap();
        assert_eq!(uris.map(|uris| uris.len()), Some(2));

        for (body, key) in [
            (
                "passwords = [\"keychain://a/b\", \"hunter2\"]\n",
                "`passwords[1]`",
            ),
            ("[tokens]\nprod = \"hunter2\"\n", "`tokens.prod`"),
            (
                "[tokens.nested]\nlist = [\"hunter2\"]\n",
                "`tokens.nested.list[0]`",
            ),
        ] {
            let mut settings = Settings::new();
            let text = assert_user_error(
                settings.set_layer(
                    Layer::User,
                    "user.toml",
                    &format!("schema_version = 1\n{body}"),
                ),
                &["user.toml", key, "secret URI"],
            );
            assert!(!text.contains("hunter2"), "leaked: {text}");
        }
    }

    /// R-44: a secret URI can contain `:` and `@`.
    #[test]
    fn secret_uri_with_colon_and_at_sign_is_accepted_under_a_secret_key() {
        let settings = settings(&[(
            Layer::User,
            "schema_version = 1\npassword = \"keychain://team:prod@db/main\"\n\
             token = \"aws-sm://arn:aws:secretsmanager:eu-west-1:1:secret:prod@v2\"\n\
             secret = \"gcp-sm://p/s?token=latest\"\nref = \"keychain://team:prod@db/main\"\n\
             pwd = \"vault://kv/prod/db\"\n",
        )]);
        assert!(settings.get::<SecretUri>("password").unwrap().is_some());
        assert!(settings.get::<SecretUri>("token").unwrap().is_some());
    }

    /// The documented limits of the check. A case that moves out of this
    /// test must move out of the module documentation too.
    #[test]
    fn secret_values_that_the_check_does_not_find_are_accepted() {
        for body in [
            "auth = \"hunter2\"\n",
            "pass = \"hunter2\"\n",
            "db_pass = \"hunter2\"\n",
            "pw = \"hunter2\"\n",
            "bearer = \"hunter2\"\n",
            "signing_key = \"hunter2\"\n",
            "ssh_key = \"hunter2\"\n",
            "dbpassword = \"hunter2\"\n",
            "apikey = \"hunter2\"\n",
            "privatekey = \"hunter2\"\n",
            "secretkey = \"hunter2\"\n",
            "url = \"postgres://app:hun/ter2@db/prod\"\n",
            "url = \"https://hunter2@api.example.com\"\n",
            "password = \"x://hunter2\"\n",
        ] {
            let mut settings = Settings::new();
            let result = settings.set_layer(
                Layer::User,
                "user.toml",
                &format!("schema_version = 1\n{body}"),
            );
            assert!(result.is_ok(), "{body}");
        }
    }

    /// R-2a: the cheap cases of a secret value in a string under a neutral
    /// key, and of a secret key name.
    #[test]
    fn common_spellings_of_a_secret_are_refused() {
        for body in [
            "password2 = \"hunter2\"\n",
            "db_password_1 = \"hunter2\"\n",
            "api_key_prod = \"hunter2\"\n",
            "prodPrivateKeyPem = \"hunter2\"\n",
            "urls = \"postgres://app@a/prod, postgres://app:hunter2@b/prod\"\n",
            "url = \"jdbc:postgresql://h/db?user=a&password=hunter2\"\n",
            "dsn = \"Server=h;User=a;Password=hunter2\"\n",
            "dsn = \"Server=h; User=a; Pwd = hunter2\"\n",
            "endpoint = \"https://api.example.com/?access_token=hunter2\"\n",
            "redirect = \"https://app.example.com/cb#access_token=hunter2\"\n",
        ] {
            let mut settings = Settings::new();
            let text = assert_user_error(
                settings.set_layer(
                    Layer::User,
                    "user.toml",
                    &format!("schema_version = 1\n{body}"),
                ),
                &["user.toml", "`"],
            );
            assert!(!text.contains("hunter2"), "{body} leaked: {text}");
        }
    }

    /// R-44: text that looks like a URL with a password and is not one.
    #[test]
    fn text_without_a_secret_is_accepted_under_a_neutral_key() {
        let settings = settings(&[(
            Layer::User,
            "schema_version = 1\nnote = \"http://example.com: ask bob@corp\"\n\
             query = \"https://h/search?q=a&page=2\"\ndsn = \"Server=h;User=a;Password=\"\n\
             sql = \"select 1; select token = 5\"\n",
        )]);
        for key in ["note", "query", "dsn", "sql"] {
            assert!(settings.get::<String>(key).unwrap().is_some(), "{key}");
        }
    }

    /// R-46: the type is named without module paths.
    #[test]
    fn lookup_with_the_wrong_type_names_the_type_without_module_paths() {
        let settings = settings(&[(Layer::User, USER)]);
        let text = assert_user_error(
            settings.get::<Vec<String>>("editor.tab_width"),
            &["as `Vec<String>`", "integer"],
        );
        assert!(!text.contains("alloc"), "{text}");
        assert_user_error(
            settings.get::<Option<std::collections::BTreeMap<String, bool>>>("editor"),
            &["as `Option<BTreeMap<String, bool>>`"],
        );
    }

    #[test]
    fn url_with_a_password_is_refused_under_any_key() {
        for body in [
            "dsn = \"postgres://app:hunter2@db/prod\"\n",
            "[db]\nurl = \"postgres://app:hunter2@db:5432/prod?sslmode=require\"\n",
            "urls = [\"postgres://app@db/prod\", \"jdbc:postgresql://app:hunter2@db/prod\"]\n",
            "proxy = \"http://:hunter2@proxy\"\n",
            "password = \"postgres://app:hunter2@db/prod\"\n",
            // The documented limit: an extension scheme is checked too.
            "password = \"vault://team:hunter2@kv/db\"\n",
            "mirror = \"keychain://a/b postgres://app:hunter2@db/prod\"\n",
        ] {
            let mut settings = Settings::new();
            let text = assert_user_error(
                settings.set_layer(
                    Layer::User,
                    "user.toml",
                    &format!("schema_version = 1\n{body}"),
                ),
                &["user.toml", "`"],
            );
            assert!(!text.contains("hunter2"), "leaked: {text}");
        }
    }

    #[test]
    fn url_without_a_password_is_accepted() {
        let settings = settings(&[(
            Layer::User,
            "schema_version = 1\na = \"postgres://app@db/prod\"\nb = \"keychain://a/b\"\n\
             c = \"postgres://app:@db/prod\"\nd = \"http://host:8080/path@x\"\n\
             e = \"http://host/a:b@c\"\nf = \"at 10:30 mail a@b\"\n",
        )]);
        for key in ["a", "b", "c", "d", "e", "f"] {
            assert!(settings.get::<String>(key).unwrap().is_some(), "{key}");
        }
    }

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    enum Mode {
        Fast,
    }

    #[test]
    fn lookup_with_the_wrong_type_never_contains_the_value() {
        let settings = settings(&[(
            Layer::User,
            "schema_version = 1\ndb_pass = \"hunter2\"\nmode = \"hunter2\"\n\
             [editor]\ntab_width = \"hunter2\"\nfont = \"mono\"\n",
        )]);
        let text = assert_user_error(
            settings.get::<u32>("db_pass"),
            &["user.toml", "`db_pass`", "u32", "string"],
        );
        assert!(!text.contains("hunter2"), "leaked: {text}");
        // An unknown enum variant, a field in a table and a failed parse.
        for result in [
            settings.get::<Mode>("mode").map(|_| ()),
            settings.get::<Editor>("editor").map(|_| ()),
            settings.get::<SecretUri>("mode").map(|_| ()),
        ] {
            let error = result.expect_err("an error");
            let text = format!("{error} {error:?}");
            assert!(!text.contains("hunter2"), "leaked: {text}");
        }
        assert_user_error(settings.get::<Editor>("editor"), &["`editor`", "table"]);
    }

    #[test]
    fn load_layer_reads_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.toml");
        std::fs::write(&path, USER).unwrap();

        let mut settings = Settings::new();
        settings.load_layer(Layer::User, &path).unwrap();
        assert_eq!(settings.get::<u32>("editor.tab_width").unwrap(), Some(2));
        assert_eq!(settings.layer_of("editor.tab_width"), Some(Layer::User));
    }

    #[test]
    fn load_layer_treats_a_missing_file_as_an_empty_layer() {
        let dir = tempfile::tempdir().unwrap();
        let mut settings = settings(&[(Layer::User, USER)]);
        settings
            .load_layer(Layer::User, &dir.path().join("absent.toml"))
            .unwrap();
        assert_eq!(settings.get::<u32>("editor.tab_width").unwrap(), None);
    }

    #[test]
    fn load_layer_names_the_path_of_an_invalid_or_unreadable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.toml");
        let shown = path.display().to_string();
        let mut settings = Settings::new();

        std::fs::write(&path, "schema_version = 1\n[db]\npassword = \"hunter2\"\n").unwrap();
        let text = assert_user_error(
            settings.load_layer(Layer::User, &path),
            &[&shown, "`db.password`"],
        );
        assert!(!text.contains("hunter2"), "leaked: {text}");

        // A directory cannot be read as a file.
        let shown = dir.path().display().to_string();
        assert_user_error(settings.load_layer(Layer::User, dir.path()), &[&shown]);
    }

    fn env(vars: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
        move |name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        }
    }

    #[test]
    fn linux_uses_xdg_config_home_and_falls_back_to_home_config() {
        let dir = user_config_dir(
            "linux",
            env(&[("XDG_CONFIG_HOME", "/xdg"), ("HOME", "/home/u")]),
        );
        assert_eq!(dir.unwrap(), PathBuf::from("/xdg"));

        // The XDG specification: an unset, empty or relative value is ignored.
        for vars in [
            &[("HOME", "/home/u")][..],
            &[("XDG_CONFIG_HOME", ""), ("HOME", "/home/u")][..],
            &[("XDG_CONFIG_HOME", "relative/dir"), ("HOME", "/home/u")][..],
        ] {
            let dir = user_config_dir("linux", env(vars));
            assert_eq!(dir.unwrap(), PathBuf::from("/home/u/.config"));
        }

        // Other Unix systems use the same convention.
        let dir = user_config_dir("freebsd", env(&[("HOME", "/home/u")]));
        assert_eq!(dir.unwrap(), PathBuf::from("/home/u/.config"));
    }

    #[test]
    fn macos_uses_application_support() {
        let dir = user_config_dir(
            "macos",
            env(&[("XDG_CONFIG_HOME", "/xdg"), ("HOME", "/Users/u")]),
        );
        assert_eq!(
            dir.unwrap(),
            PathBuf::from("/Users/u/Library/Application Support")
        );
    }

    #[test]
    fn windows_uses_appdata() {
        const APPDATA: &str = r"C:\Users\u\AppData\Roaming";
        let dir = user_config_dir("windows", env(&[("APPDATA", APPDATA), ("HOME", "/h")]));
        assert_eq!(dir.unwrap(), PathBuf::from(APPDATA));
    }

    #[test]
    fn missing_environment_variable_is_an_error_that_names_it() {
        assert_user_error(user_config_dir("linux", env(&[])), &["HOME"]);
        assert_user_error(user_config_dir("linux", env(&[("HOME", "")])), &["HOME"]);
        assert_user_error(user_config_dir("macos", env(&[])), &["HOME"]);
        assert_user_error(
            user_config_dir("windows", env(&[("HOME", "/h")])),
            &["APPDATA"],
        );
    }

    #[test]
    fn user_settings_path_ends_with_the_rivet_settings_file() {
        // The test environment sets HOME (Unix) or APPDATA (Windows).
        let path = user_settings_path().unwrap();
        assert!(path.ends_with("rivet/settings.toml"), "{}", path.display());
    }
}
