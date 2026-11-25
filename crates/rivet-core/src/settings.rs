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
//! Settings hold references to secrets, never secret values.
//!
//! - A key whose name marks a secret must hold a [`SecretUri`] string. The
//!   name is split into segments at `_`, `-`, `.` and camelCase boundaries,
//!   and ASCII case is ignored. The key marks a secret if a segment is in
//!   [`SECRET_KEY_NAMES`], or if the name ends with the segments `api key`,
//!   `private key` or `access key` (also with `keys`). Examples:
//!   `db_password`, `accessToken`, `aws-access-key`. Whole segments are
//!   compared, so `public_key`, `keymap` and `tokenizer` are not secret.
//! - A string that is a URL with a password (`scheme://user:password@host`)
//!   is refused under each key.
//! - The error of a typed lookup ([`Settings::get`]) never contains the
//!   value.
//!
//! Limit: the check knows key names and URLs only. It cannot find a secret
//! value under a key with a neutral name, for example `auth = "hunter2"`.
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

/// Key-name segments that mark a secret. A key that has one of these
/// segments must hold a secret URI, not a secret value: `password`,
/// `db_password`, `dbPassword` and `DB-PASSWORD` all have the segment
/// `password`.
///
/// A key that ends with the segments `api key`, `private key` or
/// `access key` (also with `keys`) marks a secret too. See the
/// [module documentation](self#secrets) for how a key name is split.
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

/// The segments that mark a secret when `key` or `keys` follows at the end
/// of the key name. `secret key` is not here: `secret` alone marks a secret.
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
    /// - a key that marks a secret ([`SECRET_KEY_NAMES`]) holds a value that
    ///   is not a secret URI,
    /// - a string value is a URL with a password.
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
    /// type `T` and the TOML type of the value. It never contains the value.
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
                std::any::type_name::<T>(),
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
    let is_key = |kind: &String, last: &String| {
        matches!(last.as_str(), "key" | "keys") && SECRET_KEY_KINDS.contains(&kind.as_str())
    };
    segments
        .iter()
        .any(|segment| SECRET_KEY_NAMES.contains(&segment.as_str()))
        || matches!(&segments[..], [.., kind, last] if is_key(kind, last))
}

/// `true` if `text` is a URL with a password: `scheme://user:password@host`.
/// The user can be empty; the password cannot.
fn has_url_password(text: &str) -> bool {
    let Some((_, rest)) = text.split_once("://") else {
        return false;
    };
    // RFC 3986: the authority ends at the first `/`, `?` or `#`, and the
    // user information ends at the last `@` in the authority.
    // shortcut: a password with an unencoded `/`, `?` or `#` is not found;
    // upgrade to a URL parser if settings get typed connection URLs.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    authority
        .rsplit_once('@')
        .and_then(|(user_info, _)| user_info.split_once(':'))
        .is_some_and(|(_, password)| !password.is_empty())
}

/// Fails if a key that marks a secret holds anything but a secret URI, or if
/// a string under any key is a URL with a password.
/// `path` is the dotted key of `table`; it is empty for the root.
fn reject_secret_values(source: &str, path: &str, table: &Table) -> Result<()> {
    for (key, value) in table {
        let path = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        if is_secret_key(key) {
            let is_uri = value
                .as_str()
                .is_some_and(|text| text.parse::<SecretUri>().is_ok());
            if !is_uri {
                // The message never contains the value.
                return Err(Error::user(format!(
                    "{source}: key `{path}` must hold a secret URI (for example \
                     keychain://); settings do not accept a secret value"
                )));
            }
        }
        reject_in_value(source, &path, value)?;
    }
    Ok(())
}

fn reject_in_value(source: &str, path: &str, value: &Value) -> Result<()> {
    match value {
        Value::Table(table) => reject_secret_values(source, path, table),
        Value::Array(items) => items.iter().enumerate().try_for_each(|(index, item)| {
            reject_in_value(source, &format!("{path}[{index}]"), item)
        }),
        // The message never contains the value.
        Value::String(text) if has_url_password(text) => Err(Error::user(format!(
            "{source}: key `{path}` holds a URL with a password; put the password in a secret \
             store and use a secret URI (for example keychain://)"
        ))),
        _ => Ok(()),
    }
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
            ("[db.token]\nvalue = \"hunter2\"\n", "`db.token`"),
            ("[db]\ntoken = [\"hunter2\"]\n", "`db.token`"),
            ("[db]\nsecret = 12345\n", "`db.secret`"),
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
            assert!(!text.contains("12345"), "leaked: {text}");
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
            &["user.toml", "`passwords`"],
        );
    }

    #[test]
    fn secret_check_matches_whole_segments_only() {
        let settings = settings(&[(
            Layer::User,
            "schema_version = 1\npublic_key = \"ssh-ed25519 AAAA\"\nkey = \"k\"\n\
             keymap = \"vim\"\ntokenizer = \"simple\"\nsecretary = \"ann\"\n\
             api_key_id = \"AKIA\"\npassport = \"x\"\n",
        )]);
        for key in [
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

    #[test]
    fn url_with_a_password_is_refused_under_any_key() {
        for body in [
            "dsn = \"postgres://app:hunter2@db/prod\"\n",
            "[db]\nurl = \"postgres://app:hunter2@db:5432/prod?sslmode=require\"\n",
            "urls = [\"postgres://app@db/prod\", \"jdbc:postgresql://app:hunter2@db/prod\"]\n",
            "proxy = \"http://:hunter2@proxy\"\n",
            "password = \"postgres://app:hunter2@db/prod\"\n",
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
