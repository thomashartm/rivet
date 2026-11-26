//! `rivet`: a minimal SQL prompt for PostgreSQL and MySQL.
//!
//! ```text
//! rivet postgres://user:password@localhost:5432/database
//! rivet mysql://user:password@localhost:3306/database
//! rivet mysql          # the named connection RIVET_DATABASE_URL_MYSQL
//! rivet                # the default connection RIVET_DATABASE_URL
//! sql> select 1 as one;
//! ```
//!
//! A connection name or no argument reads the address from the environment
//! first, then from a `.env` file in the current directory.
//!
//! A statement ends with `;` at the end of a line. Ctrl-C cancels the
//! running statement. `\q` or end of input (Ctrl-D) quits.

use std::future::poll_fn;
use std::io::{self, BufRead, Write};
use std::pin::pin;
use std::process::ExitCode;

use arrow_array::cast::AsArray;
use arrow_array::types::{Float32Type, Float64Type, Int8Type, Int16Type, Int32Type, Int64Type};
use arrow_array::{Array, RecordBatch};
use arrow_schema::DataType;
use futures_core::Stream;
use rivet_ext_mysql::MysqlDriver;
use rivet_ext_postgres::PostgresDriver;
use rivet_sdk::error::{Error, Result};
use rivet_sdk::extension::{ConnectRequest, Connection, Credential, Credentials, Driver};
use rivet_sdk::model::{ConnectionProfile, Endpoint, ProviderRef, TlsSettings};
use rivet_sdk::secret::Secret;
use url::Url;

fn main() -> ExitCode {
    let dotenv = std::fs::read_to_string(".env").unwrap_or_default();
    let lookup = |key: &str| {
        std::env::var(key)
            .ok()
            .or_else(|| from_dotenv(&dotenv, key))
    };
    let address = match std::env::args().nth(1) {
        Some(address) if address.contains("://") => Some(address),
        Some(name) => lookup(&key_of(&name)),
        None => lookup(ADDRESS_KEY),
    };
    let Some(address) = address else {
        eprintln!(
            "usage: rivet [postgres://… | mysql://… | <name>]\n\
             \n\
             No argument uses {ADDRESS_KEY}; a <name> uses {ADDRESS_KEY}_<NAME>.\n\
             Both are read from the environment, then from ./.env \
             (docker/playground.sh writes one).\n\
             Names in ./.env: {}",
            names(&dotenv).join(", ")
        );
        return ExitCode::from(2);
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: cannot start the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut target = String::new();
    let connection = match parse(&address).and_then(|(request, driver)| {
        let endpoint = &request.profile.endpoint;
        target = format!(
            "{} {}:{}/{}",
            request.profile.engine.id,
            endpoint.host,
            endpoint
                .port
                .map_or("default".to_owned(), |port| port.to_string()),
            endpoint.database.as_deref().unwrap_or("")
        );
        runtime.block_on(driver.connect(request))
    }) {
        Ok(connection) => connection,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "connected to {target} (plaintext, no TLS). End a statement with `;`. \
         Ctrl-C cancels it. `\\q` quits."
    );
    repl(
        &runtime,
        connection.as_ref(),
        io::stdin().lock(),
        io::stdout().lock(),
    );
    ExitCode::SUCCESS
}

/// The variable that holds the default database address. A named
/// connection uses this name, `_` and the upper-case name.
// shortcut: named connections live in .env with their passwords; move them
// to the settings file with keychain:// passwords (ARCHITECTURE.md §6.2).
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

/// Reads statements from `input` and writes their results to `output`.
fn repl(
    runtime: &tokio::runtime::Runtime,
    connection: &dyn Connection,
    input: impl BufRead,
    mut output: impl Write,
) {
    let mut statement = String::new();
    let prompt = |output: &mut dyn Write, more: bool| {
        let _ = write!(output, "{}", if more { "...> " } else { "sql> " });
        let _ = output.flush();
    };
    prompt(&mut output, false);
    for line in input.lines() {
        let Ok(line) = line else { break };
        if statement.is_empty() && line.trim() == "\\q" {
            return;
        }
        statement.push_str(&line);
        statement.push('\n');
        if !line.trim_end().ends_with(';') {
            prompt(&mut output, !statement.trim().is_empty());
            if statement.trim().is_empty() {
                statement.clear();
            }
            continue;
        }
        let sql = std::mem::take(&mut statement);
        let text = runtime
            .block_on(async {
                let mut query = pin!(run(connection, sql.trim().trim_end_matches(';').to_owned()));
                tokio::select! {
                    result = &mut query => result,
                    _ = tokio::signal::ctrl_c() => {
                        // The query then ends with a `cancelled` error.
                        if let Err(error) = connection.cancel().await {
                            let _ = writeln!(output, "error: cancel failed: {error}");
                        }
                        query.await
                    }
                }
            })
            .unwrap_or_else(|error| format!("error: {error}\n"));
        let _ = output.write_all(text.as_bytes());
        prompt(&mut output, false);
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
