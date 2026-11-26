//! `rivet`: a minimal SQL prompt for PostgreSQL and MySQL.
//!
//! ```text
//! rivet postgres://user:password@localhost:5432/database
//! rivet mysql://user:password@localhost:3306/database
//! rivet prod                # a saved connection
//! rivet                     # the default connection RIVET_DATABASE_URL
//! rivet pg -f script.sql    # runs a file, stops at the first error
//! sql> select 1 as one;
//! ```
//!
//! # TLS
//!
//! TLS is on: the server certificate and the host name are verified against
//! the system trust store. Parameters of the address change that:
//!
//! - `?tls=off`: plaintext. The connect line says `plaintext, no TLS`.
//! - `?tls_ca=<path>`: trust only the CA in that PEM file.
//!
//! Any other parameter is refused.
//!
//! # Saved connections
//!
//! `rivet <name>` looks in this order:
//!
//! 1. The user settings file (`rivet_core::settings::user_settings_path`):
//!    `[connections.<name>]` with `url` (no password in it), an optional
//!    `password` secret URI (for example `keychain://rivet/prod`), and the
//!    optional guard flags `read_only`, `confirm_on_write` and the label
//!    `environment`.
//! 2. `RIVET_DATABASE_URL_<NAME>` in the environment, then in `./.env`
//!    (the playground; `docker/playground.sh` writes it).
//!
//! # Input
//!
//! A statement ends with `;` at the end of a line. Ctrl-C cancels the
//! running statement; at the prompt it clears the input. `\q` or Ctrl-D
//! quits. At a terminal the prompt has line editing and a history file
//! next to the user settings file. `\d` lists tables, `\?` the commands.
//!
//! Each statement runs as a job of `rivet_core::execute::execute_guarded`
//! and passes the guard of the profile first (`rivet_core::guard`):
//! `read_only` refuses a write, `confirm_on_write` asks at the prompt and
//! refuses in a file or a pipe. The job hands the connection back, so a
//! transaction or a `SET` stays for the next statement.

use std::collections::BTreeMap;
use std::io::{self, IsTerminal};
use std::num::NonZeroUsize;
use std::process::ExitCode;

use rivet_core::jobs::JobScheduler;
use rivet_core::secrets::SecretStore;
use rivet_core::settings::{Layer, Settings, user_settings_path};
use rivet_ext_mysql::MysqlDriver;
use rivet_ext_postgres::PostgresDriver;
use rivet_sdk::error::{Error, Result};
use rivet_sdk::extension::{ConnectRequest, Connection, Credential, Credentials, Driver};
use rivet_sdk::model::{ConnectionProfile, Endpoint, ProviderRef, TlsSettings};
use rivet_sdk::secret::{Secret, SecretUri};
use serde::Deserialize;
use url::Url;

use crate::output::Format;
use crate::repl::{Mode, Session, lines, prompt, repl};

mod output;
mod repl;
mod save;

const USAGE: &str = "\
usage: rivet [postgres://… | mysql://… | <name>] [-f <file.sql>] [--format table|csv|json]
       rivet save <name> <postgres://user@host:port/db | mysql://…>
                  [--read-only] [--confirm-on-write] [--env <label>]

  <name>      a saved connection: [connections.<name>] in the user settings
              file, or RIVET_DATABASE_URL_<NAME> in the environment or ./.env
  no target   RIVET_DATABASE_URL from the environment or ./.env
  ?tls=off    in the address: plaintext; TLS with a verified certificate is the default
  ?tls_ca=<f> in the address: trust only the CA in the PEM file <f>
  -f <file>   run the statements of <file>, stop at the first error
  --format    table (default), csv, or json (one object per row)
  save        ask for the password, check the connection, store the password in
              the keychain and the connection in the user settings file
  --read-only         (save) the saved connection refuses statements that write
  --confirm-on-write  (save) the saved connection asks y/N before a write
  --env <label>       (save) a label such as prod, shown when you connect";

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("save") {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        let saved = tokio::runtime::Runtime::new()
            .map_err(|error| Error::internal("cannot start the runtime").with_source(error))
            .and_then(|runtime| save::run(&runtime, &rest));
        return match saved {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        };
    }
    let mut target = None;
    let mut file = None;
    let mut format = Format::Table;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "-f" | "--file" => match args.next() {
                Some(path) => file = Some(path),
                None => return usage("-f needs a file"),
            },
            "--format" => match args.next().map(|name| name.parse()) {
                Some(Ok(chosen)) => format = chosen,
                Some(Err(error)) => return usage(&error.to_string()),
                None => return usage("--format needs table, csv or json"),
            },
            _ if target.is_none() && !arg.starts_with('-') => target = Some(arg),
            _ => return usage(&format!("unexpected argument `{arg}`")),
        }
    }
    // Opened before the connection, so a wrong path fails fast.
    let file = match file.map(|path| std::fs::File::open(&path).map_err(|error| (path, error))) {
        None => None,
        Some(Ok(file)) => Some(file),
        Some(Err((path, error))) => {
            eprintln!("error: cannot open {path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: cannot start the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let (connection, profile) = match runtime.block_on(connect(target.as_deref())) {
        Ok(connected) => connected,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut session = Session {
        runtime: &runtime,
        // One statement runs at a time; the CLI lists no finished jobs.
        scheduler: JobScheduler::new(NonZeroUsize::MIN, 0),
        connection: Some(connection),
        profile: &profile,
        format,
    };
    let mut stdout = io::stdout().lock();
    let ok = if let Some(file) = file {
        repl(
            &mut session,
            lines(io::BufReader::new(file)),
            &mut stdout,
            Mode::Script,
        )
    } else if io::stdin().is_terminal() {
        eprintln!("End a statement with `;`. Ctrl-C cancels it. `\\?` lists the commands.");
        prompt(&mut session, &mut stdout)
    } else {
        repl(
            &mut session,
            lines(io::stdin().lock()),
            &mut stdout,
            Mode::Pipe,
        )
    };
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn usage(problem: &str) -> ExitCode {
    eprintln!("error: {problem}\n\n{USAGE}");
    ExitCode::from(2)
}

/// Finds the address of `target`, connects and prints where to. Returns the
/// connection and its profile.
async fn connect(target: Option<&str>) -> Result<(Box<dyn Connection>, ConnectionProfile)> {
    let dotenv = std::fs::read_to_string(".env").unwrap_or_default();
    let lookup = |key: &str| {
        std::env::var(key)
            .ok()
            .or_else(|| from_dotenv(&dotenv, key))
    };
    let from_url = |url: String| SavedConnection {
        url,
        ..SavedConnection::default()
    };
    let saved = match target {
        Some(address) if address.contains("://") => from_url(address.to_owned()),
        Some(name) => match saved(&user_settings()?, name)? {
            Some(saved) => saved,
            None => from_url(lookup(&key_of(name)).ok_or_else(|| unknown(name, &dotenv))?),
        },
        None => from_url(lookup(ADDRESS_KEY).ok_or_else(|| {
            Error::user(format!(
                "no target and no {ADDRESS_KEY}; run docker/playground.sh or see --help"
            ))
        })?),
    };
    let (mut request, driver) = parse(&saved.url)?;
    if let Some(uri) = &saved.password {
        let secret = SecretStore::new()
            .resolve(&uri.parse::<SecretUri>()?)
            .await?;
        request.credentials.credential = Credential::Password(secret);
    }
    let profile = &mut request.profile;
    profile.read_only = saved.read_only;
    profile.confirm_on_write = saved.confirm_on_write;
    profile.environment = saved.environment;
    let profile = profile.clone();
    let flags: Vec<&str> = [
        profile.environment.as_deref(),
        profile.read_only.then_some("read-only"),
        profile.confirm_on_write.then_some("confirm writes"),
    ]
    .into_iter()
    .flatten()
    .collect();
    let endpoint = &request.profile.endpoint;
    let shown = format!(
        "{} {}:{}/{}",
        request.profile.engine.id,
        endpoint.host,
        endpoint
            .port
            .map_or("default".to_owned(), |port| port.to_string()),
        endpoint.database.as_deref().unwrap_or("")
    );
    let connection = driver.connect(request).await?;
    let flags = if flags.is_empty() {
        String::new()
    } else {
        format!(" [{}]", flags.join(", "))
    };
    let tls = if profile.tls.enabled {
        "TLS"
    } else {
        "plaintext, no TLS"
    };
    eprintln!("connected to {shown}{flags} ({tls})");
    Ok((connection, profile))
}

/// The user settings, or empty settings if the platform has no user
/// settings directory.
fn user_settings() -> Result<Settings> {
    let mut settings = Settings::new();
    if let Ok(path) = user_settings_path() {
        settings.load_layer(Layer::User, &path)?;
    }
    Ok(settings)
}

/// One `[connections.<name>]` table of the settings.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedConnection {
    /// The address, without a password (the settings check refuses one).
    url: String,
    /// A secret URI, for example `keychain://rivet/prod`.
    password: Option<String>,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    confirm_on_write: bool,
    /// A free label such as `prod` (decision 86.4).
    environment: Option<String>,
}

/// The saved connection `name` in `settings`, or `None` if there is none.
fn saved(settings: &Settings, name: &str) -> Result<Option<SavedConnection>> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::user(format!(
            "`{name}` is not a connection name: use letters, digits, `-` and `_`"
        )));
    }
    let saved = settings.get::<SavedConnection>(&format!("connections.{name}"))?;
    if let Some(uri) = saved.as_ref().and_then(|saved| saved.password.as_deref()) {
        // Fails early on a bad URI, before the address is parsed.
        uri.parse::<SecretUri>()?;
    }
    Ok(saved)
}

/// The error for a connection name that is nowhere.
fn unknown(name: &str, dotenv: &str) -> Error {
    let in_settings = user_settings()
        .and_then(|settings| settings.get::<BTreeMap<String, SavedConnection>>("connections"))
        .ok()
        .flatten()
        .unwrap_or_default()
        .into_keys();
    let known: Vec<String> = in_settings.chain(names(dotenv)).collect();
    Error::user(format!(
        "no connection named `{name}`; known: {}",
        if known.is_empty() {
            "none".to_owned()
        } else {
            known.join(", ")
        }
    ))
}

/// The variable that holds the default database address. A named
/// connection uses this name, `_` and the upper-case name.
// shortcut: .env connections keep plain-text passwords; they serve the local
// playground. Real connections belong in the settings file (keychain).
const ADDRESS_KEY: &str = "RIVET_DATABASE_URL";

/// The variable of the named connection `name`: `my-db` is
/// `RIVET_DATABASE_URL_MY_DB`.
fn key_of(name: &str) -> String {
    format!(
        "{ADDRESS_KEY}_{}",
        name.to_ascii_uppercase().replace('-', "_")
    )
}

/// The `KEY=value` pairs of the text of a `.env` file. `#` comments,
/// `export` and quotes are allowed.
fn dotenv_pairs(text: &str) -> impl Iterator<Item = (&str, &str)> {
    text.lines().filter_map(|line| {
        let line = line.trim();
        let (key, value) = line
            .strip_prefix("export ")
            .unwrap_or(line)
            .split_once('=')?;
        let value = value.trim();
        let unquoted = ['"', '\'']
            .iter()
            .find_map(|quote| value.strip_prefix(*quote)?.strip_suffix(*quote));
        Some((key.trim(), unquoted.unwrap_or(value)))
    })
}

/// Returns the value of `key` in the text of a `.env` file.
fn from_dotenv(text: &str, key: &str) -> Option<String> {
    dotenv_pairs(text)
        .find(|(name, _)| *name == key)
        .map(|(_, value)| value.to_owned())
}

/// The connection names in the text of a `.env` file, in lower case.
fn names(text: &str) -> Vec<String> {
    let prefix = format!("{ADDRESS_KEY}_");
    dotenv_pairs(text)
        .filter_map(|(key, _)| Some(key.strip_prefix(&prefix)?.to_ascii_lowercase()))
        .collect()
}

/// Builds the connect request from a `postgres://` or `mysql://` address,
/// and returns the driver for it.
fn parse(address: &str) -> Result<(ConnectRequest, &'static dyn Driver)> {
    let url = Url::parse(address).map_err(|error| Error::user(format!("bad address: {error}")))?;
    let (engine, driver): (&str, &'static dyn Driver) = match url.scheme() {
        "postgres" | "postgresql" => ("postgres", &PostgresDriver),
        "mysql" => ("mysql", &MysqlDriver),
        _ => {
            return Err(Error::user(
                "the address must start with postgres:// or mysql://",
            ));
        }
    };
    let host = url
        .host_str()
        .ok_or_else(|| Error::user("the address has no host"))?;
    let mut endpoint = Endpoint::new(host);
    if let Some(port) = url.port() {
        endpoint = endpoint.with_port(port);
    }
    let database = url.path().trim_start_matches('/');
    if !database.is_empty() {
        endpoint = endpoint.with_database(decode(database)?);
    }
    let profile = ConnectionProfile::new(
        ProviderRef::new(engine),
        endpoint,
        ProviderRef::new("password"),
    )
    .with_tls(tls(&url)?);
    let password = Credential::Password(Secret::from(decode(url.password().unwrap_or(""))?));
    let mut credentials = Credentials::new(password);
    if !url.username().is_empty() {
        credentials = credentials.with_user(decode(url.username())?);
    }
    Ok((ConnectRequest::new(profile, credentials), driver))
}

/// The TLS settings from the query of the address: TLS is on unless
/// `tls=off`; `tls_ca=<path>` trusts only that CA file. Each other
/// parameter is refused, so a typing error cannot turn TLS off silently.
fn tls(url: &Url) -> Result<TlsSettings> {
    let mut tls = TlsSettings::new();
    let (mut seen_tls, mut seen_ca) = (false, false);
    for (key, value) in url.query_pairs() {
        let seen = match key.as_ref() {
            "tls" => &mut seen_tls,
            "tls_ca" => &mut seen_ca,
            _ => {
                return Err(Error::user(format!(
                    "the address has the unknown parameter `{key}`; rivet knows `tls=on|off` \
                     and `tls_ca=<CA file>`"
                )));
            }
        };
        if std::mem::replace(seen, true) {
            return Err(Error::user(format!(
                "the address has the parameter `{key}` twice"
            )));
        }
        tls = match (key.as_ref(), value.as_ref()) {
            ("tls", "on") => tls.with_enabled(true),
            ("tls", "off") => tls.with_enabled(false),
            ("tls", other) => {
                return Err(Error::user(format!(
                    "`tls={other}` is not known; use `tls=on` or `tls=off`"
                )));
            }
            (_, "") => return Err(Error::user("`tls_ca` needs the path of a CA file")),
            (_, path) => tls.with_ca_certificate(path),
        };
    }
    if !tls.enabled && tls.ca_certificate.is_some() {
        return Err(Error::user(
            "the address has `tls=off` and `tls_ca`; remove one of them",
        ));
    }
    Ok(tls)
}

/// Decodes the `%xx` escapes of one part of the address.
fn decode(part: &str) -> Result<String> {
    percent_encoding::percent_decode_str(part)
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|_| Error::user("the address is not valid UTF-8 after decoding"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reads_every_part_of_the_address() {
        let (request, _) = parse("postgres://app%40x:p%2Bw%20d@db.local:5433/my%20db").unwrap();
        assert_eq!(request.profile.engine.id, "postgres");
        assert_eq!(request.profile.endpoint.host, "db.local");
        assert_eq!(request.profile.endpoint.port, Some(5433));
        assert_eq!(request.profile.endpoint.database.as_deref(), Some("my db"));
        assert!(request.profile.tls.enabled, "TLS is on by default");
        assert_eq!(request.profile.tls.ca_certificate, None);
        assert_eq!(request.credentials.user.as_deref(), Some("app@x"));
        let Credential::Password(password) = &request.credentials.credential else {
            panic!("not a password");
        };
        assert_eq!(password.expose(), "p+w d");
    }

    #[test]
    fn from_dotenv_finds_the_address() {
        let text = "# comment\nPOSTGRES_USER=rivet\n\nexport RIVET_DATABASE_URL = \"postgres://a:b@h/d\"\n";
        assert_eq!(
            from_dotenv(text, ADDRESS_KEY).as_deref(),
            Some("postgres://a:b@h/d")
        );
        assert_eq!(
            from_dotenv("RIVET_DATABASE_URL=postgres://x@h/d", ADDRESS_KEY).as_deref(),
            Some("postgres://x@h/d")
        );
        assert_eq!(
            from_dotenv("# RIVET_DATABASE_URL=x\nOTHER=y", ADDRESS_KEY),
            None
        );
    }

    #[test]
    fn named_connections_map_to_variables() {
        assert_eq!(key_of("my-db"), "RIVET_DATABASE_URL_MY_DB");
        let text = "RIVET_DATABASE_URL=a\nRIVET_DATABASE_URL_PG=b\n# RIVET_DATABASE_URL_OLD=c\nRIVET_DATABASE_URL_MYSQL=d";
        assert_eq!(names(text), ["pg", "mysql"]);
        assert_eq!(from_dotenv(text, &key_of("mysql")).as_deref(), Some("d"));
    }

    fn settings(text: &str) -> Settings {
        let mut settings = Settings::new();
        settings.set_layer(Layer::User, "test", text).unwrap();
        settings
    }

    #[test]
    fn saved_reads_url_and_password_uri() {
        let settings = settings(
            "schema_version = 1\n[connections.prod]\nurl = \"postgres://app@db/x\"\n\
             password = \"keychain://rivet/prod\"\n[connections.local]\nurl = \"mysql://root@h/y\"\n",
        );
        let prod = saved(&settings, "prod").unwrap().unwrap();
        assert_eq!(prod.url, "postgres://app@db/x");
        assert_eq!(prod.password.as_deref(), Some("keychain://rivet/prod"));
        assert!(!prod.read_only && !prod.confirm_on_write);
        assert!(
            saved(&settings, "local")
                .unwrap()
                .unwrap()
                .password
                .is_none()
        );
        assert!(saved(&settings, "other").unwrap().is_none());
    }

    #[test]
    fn saved_refuses_bad_names_and_entries() {
        let empty = settings("schema_version = 1\n");
        assert!(saved(&empty, "a.b").is_err());
        assert!(saved(&empty, "").is_err());
        let no_url =
            settings("schema_version = 1\n[connections.x]\npassword = \"keychain://rivet/x\"\n");
        assert!(saved(&no_url, "x").is_err());
        let typo = settings(
            "schema_version = 1\n[connections.x]\nurl = \"mysql://h/d\"\nread_onyl = true\n",
        );
        assert!(saved(&typo, "x").is_err());
    }

    #[test]
    fn saved_reads_the_guard_flags() {
        let settings = settings(
            "schema_version = 1\n[connections.prod]\nurl = \"postgres://app@db/x\"\n\
             read_only = true\nconfirm_on_write = true\nenvironment = \"prod\"\n",
        );
        let prod = saved(&settings, "prod").unwrap().unwrap();
        assert!(prod.read_only && prod.confirm_on_write);
        assert_eq!(prod.environment.as_deref(), Some("prod"));
    }

    #[test]
    fn parse_reads_the_tls_parameters() {
        let tls = |address: &str| parse(address).map(|(request, _)| request.profile.tls);
        let off = tls("postgres://a@h/d?tls=off").unwrap();
        assert!(!off.enabled);
        assert!(tls("mysql://a@h/d?tls=on").unwrap().enabled);
        let pinned = tls("postgres://a@h/d?tls_ca=%2Fetc%2Fca%20x.pem").unwrap();
        assert!(pinned.enabled);
        assert_eq!(
            pinned.ca_certificate.as_deref(),
            Some(std::path::Path::new("/etc/ca x.pem"))
        );
        let pinned = tls("postgres://a@h/d?tls=on&tls_ca=ca.pem").unwrap();
        assert!(pinned.enabled && pinned.ca_certificate.is_some());
        for (wrong, says) in [
            ("postgres://a@h/d?tls=no", "tls=no"),
            ("postgres://a@h/d?tls=", "tls="),
            ("postgres://a@h/d?sslmode=disable", "sslmode"),
            ("postgres://a@h/d?tls=off&tls=on", "twice"),
            ("postgres://a@h/d?tls_ca=", "tls_ca"),
            ("mysql://a@h/d?tls=off&tls_ca=ca.pem", "tls=off"),
        ] {
            let error = tls(wrong).unwrap_err();
            assert_eq!(error.category(), rivet_sdk::error::ErrorCategory::User);
            assert!(error.message().contains(says), "{wrong}: {error}");
        }
    }

    #[test]
    fn parse_picks_the_driver_by_scheme() {
        let (request, driver) = parse("mysql://root@localhost:3306/x").unwrap();
        assert_eq!(request.profile.engine.id, "mysql");
        assert_eq!(driver.dialect().name, MysqlDriver.dialect().name);
        assert!(parse("sqlite://localhost/x").is_err());
        assert!(parse("not an address").is_err());
    }
}
