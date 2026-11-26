//! The statement loop: reads statements, checks them with the guard, runs
//! them and writes their results.

use std::future::poll_fn;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::pin::pin;

use futures_core::Stream;
use rivet_core::guard::{Decision, decide};
use rivet_core::settings::user_settings_path;
use rivet_sdk::error::{Error, Result};
use rivet_sdk::extension::Connection;
use rivet_sdk::model::ConnectionProfile;
use rustyline::error::ReadlineError;

use crate::output::{Format, render, rows, start};

/// What the loop works with.
pub struct Session<'a> {
    pub runtime: &'a tokio::runtime::Runtime,
    pub connection: &'a dyn Connection,
    /// Its `read_only` and `confirm_on_write` flags drive the guard.
    pub profile: &'a ConnectionProfile,
    pub format: Format,
}

/// Where the statements come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A person at a terminal: can confirm a write.
    Prompt,
    /// Piped input: goes on after an error.
    Pipe,
    /// A file (`-f`): stops at the first error and runs a last statement
    /// without `;`.
    Script,
}

/// One input of the loop.
pub enum Input {
    Line(String),
    /// Ctrl-C at the prompt: drop the statement typed so far.
    Clear,
    /// The input cannot be read.
    Failed,
    End,
}

const HELP: &str = "\
\\d            list the tables
\\d <table>    describe a table (<table> or <schema>.<table>)
\\?            this help
\\q            quit
A statement ends with `;` at the end of a line. Ctrl-C cancels it.
";

/// The lines of `input`, without a prompt.
pub fn lines(input: impl BufRead) -> impl FnMut(&str) -> Input {
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
pub fn prompt(session: &Session<'_>, output: &mut impl Write) -> bool {
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
        session,
        |prompt| match editor.readline(prompt) {
            Ok(line) => {
                // A y/N answer is not worth recalling.
                if !prompt.ends_with(CONFIRM_SUFFIX) {
                    let _ = editor.add_history_entry(line.as_str());
                }
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
        Mode::Prompt,
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
/// Returns `false` if a statement or the input failed.
pub fn repl(
    session: &Session<'_>,
    mut next: impl FnMut(&str) -> Input,
    output: &mut impl Write,
    mode: Mode,
) -> bool {
    // shortcut: a statement ends at a line that ends with `;`, so a `;` at a
    // line end inside a function body splits it; the driver splits scripts
    // later (decision 86.2).
    let mut statement = String::new();
    let mut ok = true;
    loop {
        let prompt = if statement.is_empty() {
            "sql> "
        } else {
            "...> "
        };
        let line = match next(prompt) {
            Input::Line(line) => line,
            Input::Clear => {
                statement.clear();
                continue;
            }
            Input::Failed => return false,
            Input::End => break,
        };
        let sql = if statement.is_empty() && line.trim_start().starts_with('\\') {
            match line.trim() {
                "\\q" => return ok,
                "\\?" => {
                    let _ = output.write_all(HELP.as_bytes());
                    continue;
                }
                command => meta(command),
            }
        } else {
            if statement.is_empty() && line.trim().is_empty() {
                continue;
            }
            statement.push_str(&line);
            statement.push('\n');
            if !line.trim_end().ends_with(';') {
                continue;
            }
            Ok(std::mem::take(&mut statement))
        };
        let done = match sql {
            Ok(sql) => guarded(session, &sql, mode, &mut next, output),
            Err(error) => {
                eprintln!("error: {error}");
                false
            }
        };
        if !done {
            ok = false;
            if mode == Mode::Script {
                return false;
            }
        }
    }
    if mode == Mode::Script && !statement.trim().is_empty() {
        ok &= guarded(session, &statement, mode, &mut next, output);
    }
    ok
}

/// The end of the confirmation prompt.
const CONFIRM_SUFFIX: &str = "[y/N] ";

/// Asks the guard of the profile, then runs `statement`. A write on a
/// `confirm_on_write` profile needs a "y" at the prompt; other modes cannot
/// confirm, so it fails there. Returns `false` if it was refused or failed.
fn guarded(
    session: &Session<'_>,
    statement: &str,
    mode: Mode,
    next: &mut impl FnMut(&str) -> Input,
    output: &mut impl Write,
) -> bool {
    let profile = session.profile;
    let check = |confirmed| {
        decide(
            profile.read_only,
            profile.confirm_on_write,
            statement,
            confirmed,
        )
    };
    let decision = match check(false) {
        Decision::NeedsConfirmation if mode == Mode::Prompt => {
            let place = profile.environment.as_deref().unwrap_or("this connection");
            match next(&format!(
                "This statement may write on {place}. Run it? {CONFIRM_SUFFIX}"
            )) {
                Input::Line(answer) if matches!(answer.trim(), "y" | "Y" | "yes") => check(true),
                _ => {
                    eprintln!("not run");
                    return true;
                }
            }
        }
        Decision::NeedsConfirmation => Decision::Deny(Error::policy(
            "the profile flag `confirm_on_write` is set and this input cannot confirm a write; \
             run it at the prompt",
        )),
        decision => decision,
    };
    match decision {
        Decision::Allow => execute(session, statement, output),
        Decision::Deny(error) => {
            eprintln!("error: {error}");
            false
        }
        Decision::NeedsConfirmation => {
            eprintln!("error: the statement was not confirmed");
            false
        }
    }
}

/// The schemas of the database itself, left out of `\d`.
const SYSTEM_SCHEMAS: &str =
    "('pg_catalog', 'information_schema', 'mysql', 'performance_schema', 'sys')";

/// The SQL of a `\d` command. Uses `information_schema`, which PostgreSQL
/// and MySQL both have.
fn meta(command: &str) -> Result<String> {
    let mut words = command.split_whitespace();
    match (words.next(), words.next(), words.next()) {
        (Some("\\d"), None, None) => Ok(format!(
            "select table_schema as table_schema, table_name as table_name, \
             table_type as table_type from information_schema.tables \
             where table_schema not in {SYSTEM_SCHEMAS} order by 1, 2"
        )),
        (Some("\\d"), Some(name), None) => {
            // Checked, so it can go into the SQL text: no parameter binding
            // yet (decision 86.1).
            let valid = |part: &str| {
                !part.is_empty()
                    && part
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
            };
            let (schema, table) = match name.split_once('.') {
                Some((schema, table)) => (Some(schema), table),
                None => (None, name),
            };
            if !valid(table) || !schema.is_none_or(valid) {
                return Err(Error::user(format!(
                    "`{name}` is not a table name: use letters, digits, `_` and `$`, \
                     and at most one `.`"
                )));
            }
            let schema = schema.map_or(String::new(), |schema| {
                format!(" and table_schema = '{schema}'")
            });
            Ok(format!(
                "select column_name as column_name, data_type as data_type, \
                 is_nullable as is_nullable, column_default as column_default \
                 from information_schema.columns \
                 where table_name = '{table}'{schema} and table_schema not in {SYSTEM_SCHEMAS} \
                 order by table_schema, ordinal_position"
            ))
        }
        _ => Err(Error::user(format!(
            "unknown command `{command}`; `\\?` lists the commands"
        ))),
    }
}

/// Runs one statement; Ctrl-C cancels it. Returns `false` if it failed.
fn execute(session: &Session<'_>, statement: &str, output: &mut impl Write) -> bool {
    let connection = session.connection;
    let statement = statement.trim().trim_end_matches(';').to_owned();
    let result = session.runtime.block_on(async {
        let mut query = pin!(run(connection, statement, session.format, &mut *output));
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
        Ok(()) => true,
        Err(error) => {
            eprintln!("error: {error}");
            false
        }
    }
}

/// Runs one statement and writes its result to `output`. CSV and JSON
/// are written batch by batch, so memory stays flat and output starts at
/// once. A failed write (for example a closed pipe) stops the statement.
async fn run(
    connection: &dyn Connection,
    statement: String,
    format: Format,
    output: &mut impl Write,
) -> Result<()> {
    let result = connection.execute(statement).await?;
    let header: Vec<String> = result
        .schema()
        .fields()
        .iter()
        .map(|field| field.name().clone())
        .collect();
    let mut result = pin!(result);
    let mut write = |text: String| {
        output
            .write_all(text.as_bytes())
            .and_then(|()| output.flush())
            .map_err(|error| Error::user(format!("cannot write the result: {error}")))
    };
    if format == Format::Table {
        // shortcut: the table holds the whole result to align its columns;
        // page it when large results at the prompt matter.
        let mut batches = Vec::new();
        while let Some(batch) = poll_fn(|cx| result.as_mut().poll_next(cx)).await {
            batches.push(batch?);
        }
        return write(render(format, &header, &batches));
    }
    write(start(format, &header))?;
    while let Some(batch) = poll_fn(|cx| result.as_mut().poll_next(cx)).await {
        write(rows(format, &header, &batch?))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_lists_and_describes_tables() {
        assert!(meta("\\d").unwrap().contains("information_schema.tables"));
        let describe = meta("\\d playground.orders").unwrap();
        assert!(describe.contains("table_name = 'orders' and table_schema = 'playground'"));
        assert!(
            meta("\\d orders")
                .unwrap()
                .contains("table_name = 'orders' and table_schema not in")
        );
    }

    #[test]
    fn meta_refuses_unsafe_names_and_unknown_commands() {
        for bad in ["\\d x'y", "\\d a.b.c", "\\d .x", "\\d a b", "\\x"] {
            assert!(meta(bad).is_err(), "{bad}");
        }
    }
}
