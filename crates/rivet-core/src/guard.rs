//! Statement guard: decides if a statement may run on a connection profile
//! (ARCHITECTURE.md §5.3, §5.6).
//!
//! - [`decide`] is one pure function. It does no I/O and needs no driver.
//! - The classifier sorts a statement into "read" or "write". It fails
//!   closed: anything it cannot prove to be a read is a write.
//!
//! # Limit
//!
//! This is a guard against mistakes. It is NOT a security boundary.
//! `SELECT f()` can write, and the scanner is not a SQL parser. The real
//! boundary is a read-only session in the database.
//!
//! # Shortcuts
//!
//! The scanner treats these as a write, also when the database would read
//! them as harmless: a `$` or `#` outside quotes, a `--` that is not
//! followed by white space, a `/*!` or `/*M!` comment, a backslash inside
//! a quote, and the word `ANALYZE` or `ANALYSE` anywhere in an `EXPLAIN`.
//! A false "write" only costs a confirmation or a refusal. A false "read"
//! would let a write pass.

use rivet_sdk::error::Error;

/// The result of [`decide`].
#[derive(Debug)]
pub enum Decision {
    /// The statement may run.
    Allow,
    /// The statement is a write on a `confirm_on_write` profile. The caller
    /// must ask the user, then call [`decide`] again with `confirmed = true`.
    NeedsConfirmation,
    /// The statement must not run. The error is a `policy` error. It names
    /// the profile flag and never contains the statement text.
    Deny(Error),
}

/// Decides if `statement` may run.
///
/// - `read_only` and a write: [`Decision::Deny`]. `confirmed` does not change this.
/// - `confirm_on_write` and a write: [`Decision::NeedsConfirmation`], or
///   [`Decision::Allow`] when `confirmed` is `true`.
/// - A read: [`Decision::Allow`].
pub fn decide(
    read_only: bool,
    confirm_on_write: bool,
    statement: &str,
    confirmed: bool,
) -> Decision {
    if is_read(statement) {
        Decision::Allow
    } else if read_only {
        Decision::Deny(Error::policy(
            "the profile flag `read_only` is set: write statements are not allowed",
        ))
    } else if confirm_on_write && !confirmed {
        Decision::NeedsConfirmation
    } else {
        Decision::Allow
    }
}

/// Statements that start with one of these words are reads.
const READ_WORDS: [&str; 6] = ["SELECT", "SHOW", "EXPLAIN", "DESCRIBE", "VALUES", "TABLE"];

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80
}

/// `true` only when the statement is provably one read statement.
fn is_read(sql: &str) -> bool {
    let b = sql.as_bytes();
    let mut i = 0;
    let mut first_word: Option<&str> = None;
    let mut ended = false; // a `;` was seen: only white space and comments may follow
    while i < b.len() {
        match b[i] {
            c if c.is_ascii_whitespace() => i += 1,
            b'-' if b.get(i + 1) == Some(&b'-') => {
                if !b.get(i + 2).is_none_or(u8::is_ascii_whitespace) {
                    return false;
                }
                i = b[i..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .map_or(b.len(), |p| i + p);
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                if sql[i..].starts_with("/*!") || sql[i..].starts_with("/*M!") {
                    return false;
                }
                match sql[i + 2..].find("*/") {
                    Some(p) => i += p + 4,
                    None => return false, // unclosed comment
                }
            }
            _ if ended => return false,
            b'$' | b'#' => return false,
            b';' => {
                ended = true;
                i += 1;
            }
            q @ (b'\'' | b'"' | b'`') => {
                let Some(len) = b[i + 1..].iter().position(|&c| c == q || c == b'\\') else {
                    return false; // unclosed quote
                };
                if b[i + 1 + len] == b'\\' {
                    return false;
                }
                i += len + 2; // `''` closes and opens again: the same result
            }
            b'(' => i += 1,
            // Before the first word only `(` may stand.
            _ if first_word.is_none() && !b[i].is_ascii_alphabetic() => return false,
            c if is_word_byte(c) => {
                let end = i + b[i..].iter().take_while(|&&c| is_word_byte(c)).count();
                let word = &sql[i..end];
                match first_word {
                    None if READ_WORDS.iter().any(|r| word.eq_ignore_ascii_case(r)) => {
                        first_word = Some(word);
                    }
                    None => return false,
                    Some(first) => {
                        let explain = first.eq_ignore_ascii_case("EXPLAIN");
                        let analyze = word.eq_ignore_ascii_case("ANALYZE")
                            || word.eq_ignore_ascii_case("ANALYSE");
                        if word.eq_ignore_ascii_case("INTO") || (explain && analyze) {
                            return false;
                        }
                    }
                }
                i = end;
            }
            _ => i += 1, // other punctuation
        }
    }
    first_word.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_table() {
        // (statement, is a read)
        let cases: &[(&str, bool)] = &[
            // reads, also case and white space
            ("SELECT 1", true),
            ("select 1", true),
            ("  \n\tSeLeCt 1", true),
            ("SHOW TABLES", true),
            ("EXPLAIN SELECT 1", true),
            ("DESCRIBE users", true),
            ("VALUES (1)", true),
            ("TABLE users", true),
            // comments and leading `(`
            ("-- note\nSELECT 1", true),
            ("/* a */ SELECT 1", true),
            ("/* a */ -- b\n /* c */ select 1", true),
            ("(SELECT 1)", true),
            ("  ( (select 1) )", true),
            ("SELECT 1 -- trailing", true),
            // quoted text with `;`, `$`, `INTO`, `--`
            ("SELECT 'a;b'", true),
            ("SELECT 'it''s; fine'", true),
            ("SELECT \"a;b\"", true),
            ("SELECT `a;b`", true),
            ("SELECT 'INTO'", true),
            ("SELECT 'a -- b'", true),
            ("SELECT 'a $$ b'", true),
            // one trailing `;` is fine
            ("SELECT 1;", true),
            ("SELECT 1; -- done", true),
            ("SELECT 1; /* done */ \n", true),
            // writes
            ("INSERT INTO t VALUES (1)", false),
            ("update t set a = 1", false),
            ("DELETE FROM t", false),
            ("DROP TABLE t", false),
            ("CREATE TABLE t (a int)", false),
            ("TRUNCATE t", false),
            // WITH is a write, also a plain read
            ("WITH x AS (SELECT 1) SELECT * FROM x", false),
            ("WITH x AS (SELECT 1) DELETE FROM t", false),
            // EXPLAIN ANALYZE
            ("EXPLAIN ANALYZE DELETE FROM t", false),
            ("explain analyse select 1", false),
            ("EXPLAIN (ANALYZE) SELECT 1", false),
            ("EXPLAIN (FORMAT JSON, ANALYZE true) DELETE FROM t", false),
            // SELECT ... INTO
            ("SELECT * INTO t2 FROM t", false),
            ("select a into outfile 'x' from t", false),
            // fail closed: empty, unreadable, no keyword
            ("", false),
            ("   \n ", false),
            ("-- only a comment", false),
            ("/* only a comment */", false),
            (";", false),
            ("123", false),
            ("* FROM t", false),
            ("SELECTED 1", false),
            // fail closed: more than one statement
            ("SELECT 1; DELETE FROM t", false),
            ("SELECT 1; SELECT 2", false),
            ("SELECT 1;; ", false),
            ("SELECT 1; -- c\nDROP TABLE t", false),
            ("/* a */ SELECT 1; /* b */ DROP TABLE t", false),
            // fail closed: unclosed comment or quote
            ("SELECT 1 /* open", false),
            ("/* open SELECT 1", false),
            ("SELECT 'open", false),
            ("SELECT \"open", false),
            ("SELECT `open", false),
            ("SELECT 'a''", false),
            // fail closed: `$` outside quotes (dollar quoting)
            ("SELECT $$ ; DELETE FROM t ; $$", false),
            ("SELECT $a$ x $a$", false),
            ("SELECT $1", false),
            // fail closed: dialect comment forms
            ("SELECT 1 /*! ; DROP TABLE t */", false),
            ("SELECT 1 /*M! ; DROP TABLE t */", false),
            ("SELECT 1 --1; DROP TABLE t", false),
            ("SELECT 1 # '\n; DROP TABLE t; --'", false),
            // fail closed: backslash in a quote
            ("SELECT 'a\\'; DROP TABLE t; --'", false),
        ];
        for (sql, read) in cases {
            assert_eq!(is_read(sql), *read, "statement: {sql:?}");
        }
    }

    #[test]
    fn flag_matrix() {
        const READ: &str = "SELECT 1";
        const WRITE: &str = "DELETE FROM t";
        // (read_only, confirm_on_write, confirmed, statement, expected)
        let cases: &[(bool, bool, bool, &str, &str)] = &[
            (false, false, false, READ, "allow"),
            (false, false, false, WRITE, "allow"),
            (false, false, true, WRITE, "allow"),
            (false, true, false, READ, "allow"),
            (false, true, false, WRITE, "confirm"),
            (false, true, true, WRITE, "allow"),
            (true, false, false, READ, "allow"),
            (true, false, false, WRITE, "deny"),
            (true, false, true, WRITE, "deny"),
            (true, true, false, READ, "allow"),
            (true, true, false, WRITE, "deny"),
            (true, true, true, WRITE, "deny"), // read_only wins over confirmed
        ];
        for &(ro, cow, confirmed, sql, expected) in cases {
            let got = match decide(ro, cow, sql, confirmed) {
                Decision::Allow => "allow",
                Decision::NeedsConfirmation => "confirm",
                Decision::Deny(_) => "deny",
            };
            assert_eq!(
                got, expected,
                "read_only={ro} confirm_on_write={cow} confirmed={confirmed} {sql}"
            );
        }
    }

    #[test]
    fn deny_error_names_the_flag_and_not_the_statement() {
        let sql = "DELETE FROM secret_table WHERE token = 'hunter2'";
        let Decision::Deny(err) = decide(true, false, sql, false) else {
            panic!("expected Deny");
        };
        assert_eq!(err.category(), rivet_sdk::error::ErrorCategory::Policy);
        let text = format!("{err} {err:?}");
        assert!(text.contains("read_only"));
        for part in ["secret_table", "hunter2", "DELETE"] {
            assert!(!text.contains(part), "error leaks {part}");
        }
    }
}
