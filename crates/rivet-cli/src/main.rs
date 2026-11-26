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
//! # Saved connections
//!
//! `rivet <name>` looks in this order:
//!
//! 1. The user settings file (`rivet_core::settings::user_settings_path`):
//!    `[connections.<name>]` with `url` (no password in it) and an optional
//!    `password` secret URI, for example `keychain://rivet/prod`.
//! 2. `RIVET_DATABASE_URL_<NAME>` in the environment, then in `./.env`
//!    (the playground; `docker/playground.sh` writes it).
//!
//! # Input
//!
//! A statement ends with `;` at the end of a line. Ctrl-C cancels the
//! running statement; at the prompt it clears the input. `\q` or Ctrl-D
//! quits. At a terminal the prompt has line editing and a history file
//! next to the user settings file.

use std::collections::BTreeMap;
use std::future::poll_fn;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::pin::pin;
use std::process::ExitCode;

use arrow_array::cast::AsArray;
use arrow_array::types::{Float32Type, Float64Type, Int8Type, Int16Type, Int32Type, Int64Type};
use arrow_array::{Array, RecordBatch};
use arrow_schema::DataType;
use futures_core::Stream;
use rivet_core::secrets::SecretStore;
use rivet_core::settings::{Layer, Settings, user_settings_path};
use rivet_ext_mysql::MysqlDriver;
use rivet_ext_postgres::PostgresDriver;
use rivet_sdk::error::{Error, Result};
use rivet_sdk::extension::{ConnectRequest, Connection, Credential, Credentials, Driver};
use rivet_sdk::model::{ConnectionProfile, Endpoint, ProviderRef, TlsSettings};
use rivet_sdk::secret::{Secret, SecretUri};
use rustyline::error::ReadlineError;
use url::Url;

const USAGE: &str = "\
usage: rivet [postgres://… | mysql://… | <name>] [-f <file.sql>]

  <name>      a saved connection: [connections.<name>] in the user settings
              file, or RIVET_DATABASE_URL_<NAME> in the environment or ./.env
  no target   RIVET_DATABASE_URL from the environment or ./.env
  -f <file>   run the statements of <file>, stop at the first error";

fn main() -> ExitCode {
    let mut target = None;
    let mut file = None;
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
    let connection = match runtime.block_on(connect(target.as_deref())) {
        Ok(connection) => connection,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut stdout = io::stdout().lock();
    let ok = if let Some(file) = file {
        repl(
            &runtime,
            connection.as_ref(),
            lines(io::BufReader::new(file)),
            &mut stdout,
            true,
        )
    } else if io::stdin().is_terminal() {
        eprintln!("End a statement with `;`. Ctrl-C cancels it. `\\q` or Ctrl-D quits.");
        prompt(&runtime, connection.as_ref(), &mut stdout)
    } else {
        repl(
            &runtime,
            connection.as_ref(),
            lines(io::stdin().lock()),
            &mut stdout,
            false,
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

/// Finds the address of `target`, connects and prints where to.
async fn connect(target: Option<&str>) -> Result<Box<dyn Connection>> {
    let dotenv = std::fs::read_to_string(".env").unwrap_or_default();
    let lookup = |key: &str| {
        std::env::var(key)
            .ok()
            .or_else(|| from_dotenv(&dotenv, key))
    };
    let (address, password) = match target {
        Some(address) if address.contains("://") => (address.to_owned(), None),
        Some(name) => match saved(&user_settings()?, name)? {
            Some(saved) => saved,
            None => (
                lookup(&key_of(name)).ok_or_else(|| unknown(name, &dotenv))?,
                None,
            ),
        },
        None => (
            lookup(ADDRESS_KEY).ok_or_else(|| {
                Error::user(format!(
                    "no target and no {ADDRESS_KEY}; run docker/playground.sh or see --help"
                ))
            })?,
            None,
        ),
    };
    let (mut request, driver) = parse(&address)?;
    if let Some(uri) = password {
        let secret = SecretStore::new().resolve(&uri).await?;
        request.credentials.credential = Credential::Password(secret);
    }
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
    eprintln!("connected to {shown} (plaintext, no TLS)");
    Ok(connection)
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

/// One `[connections.<name>]` table of the settings: `url` and `password`.
type SavedConnection = BTreeMap<String, String>;

/// The address and the password URI of the saved connection `name` in
/// `settings`, or `None` if there is none.
fn saved(settings: &Settings, name: &str) -> Result<Option<(String, Option<SecretUri>)>> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::user(format!(
            "`{name}` is not a connection name: use letters, digits, `-` and `_`"
        )));
    }
    let Some(saved) = settings.get::<SavedConnection>(&format!("connections.{name}"))? else {
        return Ok(None);
    };
    let url = saved
        .get("url")
        .ok_or_else(|| Error::user(format!("connections.{name} has no `url`")))?;
    let password = saved
        .get("password")
        .map(|uri| uri.parse::<SecretUri>())
        .transpose()?;
    Ok(Some((url.clone(), password)))
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
    // shortcut: TLS is always off because the drivers have no TLS yet (#19);
    // honour `sslmode` / `ssl-mode` once they have.
    let profile = ConnectionProfile::new(
        ProviderRef::new(engine),
        endpoint,
        ProviderRef::new("password"),
    )
    .with_tls(TlsSettings::new().with_enabled(false));
    let password = Credential::Password(Secret::from(decode(url.password().unwrap_or(""))?));
    let mut credentials = Credentials::new(password);
    if !url.username().is_empty() {
        credentials = credentials.with_user(decode(url.username())?);
    }
    Ok((ConnectRequest::new(profile, credentials), driver))
}

/// Decodes the `%xx` escapes of one part of the address.
fn decode(part: &str) -> Result<String> {
    percent_encoding::percent_decode_str(part)
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|_| Error::user("the address is not valid UTF-8 after decoding"))
}

/// One input of the statement loop.
enum Input {
    Line(String),
    /// Ctrl-C at the prompt: drop the statement typed so far.
    Clear,
    /// The input cannot be read.
    Failed,
    End,
}

/// The lines of `input`, without a prompt.
fn lines(input: impl BufRead) -> impl FnMut(&str) -> Input {
    let mut lines = input.lines();
    move |_| match lines.next() {
        Some(Ok(line)) => Input::Line(line),
        Some(Err(error)) => {
            eprintln!("error: cannot read the input: {error}");
            Input::Failed
        }
        None => Input::End,
    }
}

/// The interactive prompt: line editing and a history file.
fn prompt(
    runtime: &tokio::runtime::Runtime,
    connection: &dyn Connection,
    output: &mut impl Write,
) -> bool {
    let mut editor = match rustyline::DefaultEditor::new() {
        Ok(editor) => editor,
        Err(error) => {
            eprintln!("error: cannot start the line editor: {error}");
            return false;
        }
    };
    let history: Option<PathBuf> = user_settings_path()
        .ok()
        .map(|path| path.with_file_name("history"));
    if let Some(path) = &history {
        // No history yet is normal.
        let _ = editor.load_history(path);
    }
    let ok = repl(
        runtime,
        connection,
        |prompt| match editor.readline(prompt) {
            Ok(line) => {
                let _ = editor.add_history_entry(line.as_str());
                Input::Line(line)
            }
            Err(ReadlineError::Interrupted) => Input::Clear,
            Err(ReadlineError::Eof) => Input::End,
            Err(error) => {
                eprintln!("error: cannot read the input: {error}");
                Input::Failed
            }
        },
        output,
        false,
    );
    if let Some(path) = &history {
        let saved = path
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .map_err(ReadlineError::from)
            .and_then(|()| editor.save_history(path));
        if let Err(error) = saved {
            eprintln!(
                "warning: cannot save the history to {}: {error}",
                path.display()
            );
        }
    }
    ok
}

/// Runs the statements that `next` gives and writes their results to
/// `output`; errors go to stderr. `next` gets the prompt to show.
///
/// A `script` stops at the first failed statement and also runs a last
/// statement without `;`. Returns `false` if a statement or the input failed.
fn repl(
    runtime: &tokio::runtime::Runtime,
    connection: &dyn Connection,
    mut next: impl FnMut(&str) -> Input,
    output: &mut impl Write,
    script: bool,
) -> bool {
    // shortcut: a statement ends at a line that ends with `;`, so a `;` at a
    // line end inside a function body splits it; the driver splits scripts
    // later (decision 86.2).
    let mut statement = String::new();
    let mut ok = true;
    loop {
        let line = match next(if statement.is_empty() {
            "sql> "
        } else {
            "...> "
        }) {
            Input::Line(line) => line,
            Input::Clear => {
                statement.clear();
                continue;
            }
            Input::Failed => return false,
            Input::End => break,
        };
        if statement.is_empty() && line.trim() == "\\q" {
            return ok;
        }
        if statement.is_empty() && line.trim().is_empty() {
            continue;
        }
        statement.push_str(&line);
        statement.push('\n');
        if !line.trim_end().ends_with(';') {
            continue;
        }
        if !execute(runtime, connection, &std::mem::take(&mut statement), output) {
            ok = false;
            if script {
                return false;
            }
        }
    }
    if script && !statement.trim().is_empty() {
        ok &= execute(runtime, connection, &statement, output);
    }
    ok
}

/// Runs one statement; Ctrl-C cancels it. Returns `false` if it failed.
fn execute(
    runtime: &tokio::runtime::Runtime,
    connection: &dyn Connection,
    statement: &str,
    output: &mut impl Write,
) -> bool {
    let statement = statement.trim().trim_end_matches(';').to_owned();
    let result = runtime.block_on(async {
        let mut query = pin!(run(connection, statement));
        tokio::select! {
            result = &mut query => result,
            _ = tokio::signal::ctrl_c() => {
                // The query then ends with a `cancelled` error.
                if let Err(error) = connection.cancel().await {
                    eprintln!("error: cancel failed: {error}");
                }
                query.await
            }
        }
    });
    match result {
        Ok(text) => {
            let _ = output.write_all(text.as_bytes());
            let _ = output.flush();
            true
        }
        Err(error) => {
            eprintln!("error: {error}");
            false
        }
    }
}

/// Runs one statement and returns its result as a text table.
async fn run(connection: &dyn Connection, statement: String) -> Result<String> {
    let result = connection.execute(statement).await?;
    let header: Vec<String> = result
        .schema()
        .fields()
        .iter()
        .map(|field| field.name().clone())
        .collect();
    let mut result = pin!(result);
    // shortcut: the whole result is held in memory to align the columns;
    // page or stream it when large results matter.
    let mut rows = Vec::new();
    while let Some(batch) = poll_fn(|cx| result.as_mut().poll_next(cx)).await {
        rows.extend(format_batch(&batch?));
    }
    Ok(table(&header, &rows))
}

fn format_batch(batch: &RecordBatch) -> Vec<Vec<String>> {
    (0..batch.num_rows())
        .map(|row| {
            batch
                .columns()
                .iter()
                .map(|column| cell(column.as_ref(), row))
                .collect()
        })
        .collect()
}

/// Formats one value of the type set of the drivers (ADR-0025).
fn cell(column: &dyn Array, row: usize) -> String {
    if column.is_null(row) {
        return "NULL".to_owned();
    }
    match column.data_type() {
        DataType::Boolean => column.as_boolean().value(row).to_string(),
        DataType::Int8 => column.as_primitive::<Int8Type>().value(row).to_string(),
        DataType::Int16 => column.as_primitive::<Int16Type>().value(row).to_string(),
        DataType::Int32 => column.as_primitive::<Int32Type>().value(row).to_string(),
        DataType::Int64 => column.as_primitive::<Int64Type>().value(row).to_string(),
        DataType::Float32 => column.as_primitive::<Float32Type>().value(row).to_string(),
        DataType::Float64 => column.as_primitive::<Float64Type>().value(row).to_string(),
        DataType::Utf8 => column.as_string::<i32>().value(row).to_owned(),
        DataType::Binary => column
            .as_binary::<i32>()
            .value(row)
            .iter()
            .fold("\\x".to_owned(), |hex, byte| hex + &format!("{byte:02x}")),
        other => format!("<{other}>"),
    }
}

/// Aligns `header` and `rows` into columns, with a row count at the end.
fn table(header: &[String], rows: &[Vec<String>]) -> String {
    let widths: Vec<usize> = (0..header.len())
        .map(|i| {
            rows.iter()
                .map(|row| row[i].chars().count())
                .chain([header[i].chars().count()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let line = |cells: &[String]| {
        let padded: Vec<String> = cells
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        padded.join(" | ").trim_end().to_owned() + "\n"
    };
    let mut text = String::new();
    if !header.is_empty() {
        text += &line(header);
        let rule: Vec<String> = widths.iter().map(|width| "-".repeat(*width)).collect();
        text += &rule.join("-+-");
        text += "\n";
        for row in rows {
            text += &line(row);
        }
    }
    text + &format!("({} rows)\n", rows.len())
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
        assert!(!request.profile.tls.enabled);
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
        let (url, password) = saved(&settings, "prod").unwrap().unwrap();
        assert_eq!(url, "postgres://app@db/x");
        assert_eq!(password.unwrap().as_str(), "keychain://rivet/prod");
        assert!(saved(&settings, "local").unwrap().unwrap().1.is_none());
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
    }

    #[test]
    fn parse_picks_the_driver_by_scheme() {
        let (request, driver) = parse("mysql://root@localhost:3306/x").unwrap();
        assert_eq!(request.profile.engine.id, "mysql");
        assert_eq!(driver.dialect().name, MysqlDriver.dialect().name);
        assert!(parse("sqlite://localhost/x").is_err());
        assert!(parse("not an address").is_err());
    }

    #[test]
    fn table_aligns_columns_and_counts_rows() {
        let header = ["id".to_owned(), "name".to_owned()];
        let rows = [
            vec!["1".to_owned(), "alice".to_owned()],
            vec!["22".to_owned(), "NULL".to_owned()],
        ];
        assert_eq!(
            table(&header, &rows),
            "id | name\n---+------\n1  | alice\n22 | NULL\n(2 rows)\n"
        );
    }
}
