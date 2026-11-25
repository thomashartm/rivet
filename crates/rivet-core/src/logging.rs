//! Structured logging and tracing, with central redaction of secrets
//! (ARCHITECTURE.md §7.4).
//!
//! Code logs with the [`tracing`] macros. [`dispatch`] builds the subscriber
//! that formats the events and spans. Every formatted line goes through a
//! [`Redactor`] before it reaches the output, so a secret value that code
//! logs by mistake is replaced with [`REDACTED`].
//!
//! The redactor replaces text in the formatted line. It is the second line
//! of defence, not a proof: see the limits of [`Redactor`]. The first line
//! is the `Secret` type, which code cannot print by accident.

use rivet_sdk::error::{Error, Result};
use rivet_sdk::secret::Secret;
use std::borrow::Cow;
use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, PoisonError, RwLock};
use tracing::{Dispatch, Metadata};
use tracing_subscriber::fmt::MakeWriter;
use zeroize::{Zeroize, Zeroizing};

pub use tracing::Level;

/// The text that replaces a secret value in log output.
pub const REDACTED: &str = "[REDACTED]";

/// A secret value shorter than this number of bytes is not redacted.
///
/// A value such as `a` or `42` occurs in almost every log line. To replace it
/// would make the log unreadable, and the positions of the replacements would
/// disclose the value. A secret this short gives no protection in any case.
pub const MIN_REDACTED_LEN: usize = 4;

/// One secret value in all the forms it can have in a log line.
struct Registered {
    /// The value, then its escaped forms. See [`needles`].
    needles: Vec<Zeroizing<String>>,
    /// How many times the value was registered and not yet forgotten.
    count: usize,
}

/// Cuts `text` to a maximum of `max` bytes at a character boundary. Returns
/// the start of the text, and the mark `…` if the text was cut.
///
/// The start has `max` bytes at most. With the mark (3 bytes) the two parts
/// have `max + 3` bytes at most.
pub(crate) fn cut(text: &str, max: usize) -> (&str, &'static str) {
    let start = &text[..text.floor_char_boundary(max)];
    (start, if start.len() < text.len() { "…" } else { "" })
}

/// Returns text from outside for an error message: cut to `max` bytes
/// ([`cut`]), and with each control character escaped so that it cannot
/// start a line in a log.
///
/// The escape is after the cut, so the result can be longer than `max`
/// bytes. One byte becomes 6 bytes at most (`\u{1b}`), so the result has
/// `6 * max + 3` bytes at most.
pub(crate) fn shown(text: &str, max: usize) -> String {
    let (start, mark) = cut(text, max);
    format!("{}{mark}", start.escape_debug())
}

/// How many escapes on top of each other the redactor undoes: up to two by
/// the log path (a field logged with `?` in the JSON format), and two by the
/// application before it logs the text.
const ESCAPE_DEPTH: usize = 4;

/// The forms of `value` that a log line can contain: the value itself, then
/// each chain of up to [`ESCAPE_DEPTH`] escapes of it. An escape is the
/// `Debug` form (a field logged with `?`, a string field in the human
/// format), a JSON string (the JSON format, a JSON body) or the
/// [`sanitized`] form (a message in the human format).
///
/// A value in which no escape changes a character has one form only.
fn needles(value: &str) -> Vec<Zeroizing<String>> {
    let escapes: [fn(&str) -> Zeroizing<String>; 3] = [debug_escaped, json_escaped, sanitized];
    let mut needles = vec![Zeroizing::new(value.to_owned())];
    // The forms that the last round added. Only these get one more escape.
    let mut added = 0..1;
    for _ in 0..ESCAPE_DEPTH {
        let start = needles.len();
        for index in added {
            for escape in escapes {
                let form = escape(&needles[index]);
                if !needles.iter().any(|known| **known == *form) {
                    needles.push(form);
                }
            }
        }
        added = start..needles.len();
    }
    needles
}

/// Returns `value` as `Debug` writes it, without the quotes.
fn debug_escaped(value: &str) -> Zeroizing<String> {
    let quoted = Zeroizing::new(format!("{value:?}"));
    Zeroizing::new(quoted[1..quoted.len() - 1].to_owned())
}

/// Returns `value` as serde_json writes it in a string, without the quotes.
fn json_escaped(value: &str) -> Zeroizing<String> {
    // A string always serialises; the fallback keeps the function total.
    let quoted = Zeroizing::new(serde_json::to_string(value).unwrap_or_default());
    // Not `trim_matches`: it also removes the escaped quote of a value that
    // ends with `"`.
    let inner = quoted.get(1..quoted.len().saturating_sub(1)).unwrap_or("");
    Zeroizing::new(inner.to_owned())
}

/// Returns `value` as the human format writes it in a message and in an
/// error field. The format rewrites the control characters that a terminal
/// can interpret as text.
///
/// This is the rule of `EscapingWriter` in tracing-subscriber 0.3.23
/// (`src/fmt/format/escape.rs`). The rule is private there, so it is repeated
/// here. The test `a_secret_with_any_special_character_is_redacted_in_every_position`
/// fails if an update of tracing-subscriber changes the rule.
fn sanitized(value: &str) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(value.len()));
    for ch in value.chars() {
        match ch {
            '\x07' | '\x08' | '\x0c' | '\x1b' | '\x7f' => {
                text.push_str(&format!("\\x{:02x}", u32::from(ch)));
            }
            '\u{80}'..='\u{9f}' => text.push_str(&format!("\\u{{{:x}}}", u32::from(ch))),
            _ => text.push(ch),
        }
    }
    text
}

/// The set of live secret values that must not appear in log output.
///
/// A clone shares the same set. Give one clone to [`dispatch`] and one to the
/// secret store ([`SecretStore::with_redactor`](crate::secrets::SecretStore::with_redactor)).
///
/// # Lifetime of a registration
///
/// A value stays registered until [`forget`](Self::forget) is called for it,
/// or until the process ends. `Secret` has no hook that runs when it is
/// dropped, so the redactor cannot remove the value automatically.
///
/// Trade-off: the redactor keeps its own copy of the value in zeroizing
/// memory. If the owner drops the `Secret` and does not call `forget`, the
/// copy stays in memory for the life of the process. This is on purpose:
/// redaction (a MUST in §7.4) has priority over the early drop (a SHOULD in
/// §6.4), and a value that was copied by mistake can still reach a log after
/// the `Secret` is gone.
///
/// # Limits
///
/// - A value shorter than [`MIN_REDACTED_LEN`] bytes is not redacted.
/// - The redactor searches the formatted line for the value and for its
///   escaped forms. An escape is the `Debug` form of Rust, a JSON string as
///   serde_json writes it, or the form in which the human format writes
///   control characters (for example ESC as `\\x1b`). Up to four escapes on
///   top of each other are found. The log path adds up to two (a field
///   logged with `?` in the JSON format), so the application can add two:
///   for example a JSON body in a `Debug` text. Text that the application
///   escaped three or more times is not redacted.
/// - Cost: each form of each value is searched in each log line. A value
///   that no escape changes has 1 form. Measured: a value with one quote
///   has 5 forms; a value with a quote, a backslash and control characters
///   has 25 forms.
/// - It does not find other encodings of the value: Base64, URL encoding,
///   hex, a JSON encoder with other rules than serde_json (for example `\\/`
///   or `\\u001B`), or a part of the value.
/// - The redactor replaces text and does not know the log format. A value
///   that is equal to a part of the format damages the line: with the
///   values `true` and `1234`, the JSON text `"ok":true,"rows":12345`
///   becomes `"ok":[REDACTED],"rows":[REDACTED]5`, which is not JSON.
///   [`MIN_REDACTED_LEN`] does not prevent this.
/// - Redaction applies to log output only. Errors must not contain secrets
///   by construction (§5.6).
///
/// ```
/// use rivet_core::logging::Redactor;
/// use rivet_sdk::secret::Secret;
///
/// let redactor = Redactor::new();
/// let secret = Secret::from(String::from("hunter2-value"));
/// redactor.register(&secret);
/// assert_eq!(redactor.redact("login with hunter2-value"), "login with [REDACTED]");
/// redactor.forget(&secret);
/// assert_eq!(redactor.redact("hunter2-value"), "hunter2-value");
/// ```
#[derive(Clone, Default)]
pub struct Redactor {
    secrets: Arc<RwLock<Vec<Registered>>>,
}

impl Redactor {
    /// Creates a redactor with no registered values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers the value of `secret`. From now on [`redact`](Self::redact)
    /// replaces it.
    ///
    /// A value shorter than [`MIN_REDACTED_LEN`] bytes is ignored. A value
    /// that is registered twice must be forgotten twice.
    pub fn register(&self, secret: &Secret) {
        let value = secret.expose();
        if value.len() < MIN_REDACTED_LEN {
            return;
        }
        let mut secrets = self.secrets.write().unwrap_or_else(PoisonError::into_inner);
        match secrets.iter_mut().find(|known| *known.needles[0] == value) {
            Some(known) => known.count += 1,
            None => secrets.push(Registered {
                needles: needles(value),
                count: 1,
            }),
        }
    }

    /// Removes one registration of the value of `secret`. The copy of the
    /// value is set to zero when the last registration is removed.
    ///
    /// Does nothing if the value is not registered.
    pub fn forget(&self, secret: &Secret) {
        let value = secret.expose();
        let mut secrets = self.secrets.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(index) = secrets.iter().position(|known| *known.needles[0] == value) {
            secrets[index].count -= 1;
            if secrets[index].count == 0 {
                secrets.swap_remove(index);
            }
        }
    }

    /// Returns `text` with every occurrence of a registered value replaced
    /// by [`REDACTED`].
    pub fn redact<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let secrets = self.secrets.read().unwrap_or_else(PoisonError::into_inner);
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        for needle in secrets.iter().flat_map(|known| &known.needles) {
            let mut from = 0;
            while let Some(found) = text[from..].find(needle.as_str()) {
                let start = from + found;
                ranges.push((start, start + needle.len()));
                // Step one character only: a value can overlap itself.
                from = start + text[start..].chars().next().map_or(1, char::len_utf8);
            }
        }
        if ranges.is_empty() {
            return Cow::Borrowed(text);
        }
        // Ranges that overlap become one marker, so no part of a value stays.
        ranges.sort_unstable();
        let mut redacted = String::with_capacity(text.len());
        let mut done = 0;
        for (start, end) in ranges {
            if start >= done {
                redacted.push_str(&text[done..start]);
                redacted.push_str(REDACTED);
            }
            done = done.max(end);
        }
        redacted.push_str(&text[done..]);
        Cow::Owned(redacted)
    }
}

impl fmt::Debug for Redactor {
    /// Prints no values.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redactor").finish_non_exhaustive()
    }
}

/// Wraps a [`MakeWriter`] so that all output goes through a [`Redactor`].
struct RedactingMakeWriter<M> {
    inner: M,
    redactor: Redactor,
}

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for RedactingMakeWriter<M> {
    type Writer = RedactingWriter<'a, M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter::new(self.inner.make_writer(), &self.redactor)
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        RedactingWriter::new(self.inner.make_writer_for(meta), &self.redactor)
    }
}

/// The writer for one log event. It collects all writes and sends the
/// redacted text to `inner` on `flush` or on drop. A value that is split
/// over two `write` calls is therefore still found.
struct RedactingWriter<'a, W: Write> {
    inner: W,
    redactor: &'a Redactor,
    /// The text is not redacted yet, so it is set to zero after use.
    buffer: Zeroizing<Vec<u8>>,
}

impl<'a, W: Write> RedactingWriter<'a, W> {
    fn new(inner: W, redactor: &'a Redactor) -> Self {
        Self {
            inner,
            redactor,
            buffer: Zeroizing::default(),
        }
    }

    fn emit(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let result = {
            let text = String::from_utf8_lossy(&self.buffer);
            self.inner.write_all(self.redactor.redact(&text).as_bytes())
        };
        self.buffer.zeroize();
        result
    }
}

impl<W: Write> Write for RedactingWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit()?;
        self.inner.flush()
    }
}

impl<W: Write> Drop for RedactingWriter<'_, W> {
    fn drop(&mut self) {
        if let Err(error) = self.emit() {
            // Last resort. `eprintln!` would panic if stderr is closed.
            let _ = writeln!(io::stderr(), "cannot write a log event: {error}");
        }
    }
}

/// The output format of the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// One line of text per event, for a human reader.
    #[default]
    Human,
    /// One JSON object per line, for a machine.
    Json,
}

/// The configuration of the log output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogConfig {
    /// The least severe level that is written. For example, `Level::INFO`
    /// writes `ERROR`, `WARN` and `INFO`.
    pub level: Level,
    /// The output format.
    pub format: LogFormat,
}

impl Default for LogConfig {
    /// `INFO` and [`LogFormat::Human`].
    fn default() -> Self {
        Self {
            level: Level::INFO,
            format: LogFormat::default(),
        }
    }
}

/// Builds the log subscriber. It does not install it.
///
/// - Events below `config.level` are dropped.
/// - Each event is written as one line to `writer`, with the spans it is in.
/// - Each line goes through `redactor` first. This covers the message, all
///   fields and all span data, in both formats.
///
/// Use [`init`] to install the subscriber for the process. Use
/// [`tracing::dispatcher::with_default`] to use it for one scope, for example
/// in a test.
///
/// ```
/// use rivet_core::logging::{LogConfig, Redactor, dispatch};
///
/// let log = dispatch(&LogConfig::default(), std::io::sink, Redactor::new());
/// tracing::dispatcher::with_default(&log, || {
///     let _span = tracing::info_span!("connect", profile = "prod").entered();
///     tracing::info!(attempt = 1, "connecting");
/// });
/// ```
pub fn dispatch<W>(config: &LogConfig, writer: W, redactor: Redactor) -> Dispatch
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let builder = tracing_subscriber::fmt()
        .with_max_level(config.level)
        .with_ansi(false)
        .with_writer(RedactingMakeWriter {
            inner: writer,
            redactor,
        });
    match config.format {
        LogFormat::Human => Dispatch::new(builder.finish()),
        LogFormat::Json => Dispatch::new(builder.json().finish()),
    }
}

/// Installs the subscriber from [`dispatch`] for the whole process.
///
/// # Errors
///
/// Returns an `internal` error if a subscriber is already installed.
pub fn init<W>(config: &LogConfig, writer: W, redactor: Redactor) -> Result<()>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    tracing::dispatcher::set_global_default(dispatch(config, writer, redactor))
        .map_err(|error| Error::internal("logging is already initialised").with_source(error))
}

/// A log output that tests can read back.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);

#[cfg(test)]
impl Capture {
    /// Builds a subscriber that writes to this capture.
    pub(crate) fn dispatch(
        &self,
        level: Level,
        format: LogFormat,
        redactor: &Redactor,
    ) -> Dispatch {
        let capture = self.clone();
        dispatch(
            &LogConfig { level, format },
            move || capture.clone(),
            redactor.clone(),
        )
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

#[cfg(test)]
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Makes `log` the log subscriber of this thread.
///
/// It also keeps a second subscriber alive for the whole test process.
/// Reason: while only one subscriber exists, tracing-core 0.1 decides if
/// a log statement is on with the subscriber of the thread that reaches
/// the statement first, and keeps the answer for the process
/// (`Rebuilder::JustOne` in `callsite.rs`). A parallel test with no
/// subscriber then turns the statement off for the test that captures.
/// With two subscribers, each event asks the subscriber of its thread.
#[cfg(test)]
pub(crate) fn capture_logs(log: &tracing::Dispatch) -> tracing::dispatcher::DefaultGuard {
    static SECOND: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
    SECOND.get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::new()));
    tracing::dispatcher::set_default(log)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::{debug, error, info, info_span, warn};

    const FORMATS: [LogFormat; 2] = [LogFormat::Human, LogFormat::Json];

    fn secret(value: &str) -> Secret {
        Secret::from(value.to_owned())
    }

    fn redactor(values: &[&str]) -> Redactor {
        let redactor = Redactor::new();
        for value in values {
            redactor.register(&secret(value));
        }
        redactor
    }

    /// Runs `log` with a subscriber and returns what it wrote.
    fn captured(
        level: Level,
        format: LogFormat,
        redactor: &Redactor,
        log: impl FnOnce(),
    ) -> String {
        let capture = Capture::default();
        {
            let _guard = capture_logs(&capture.dispatch(level, format, redactor));
            log();
        }
        capture.text()
    }

    #[test]
    fn cut_and_shown_keep_whole_characters_and_mark_a_cut_text() {
        assert_eq!(cut("abc", 3), ("abc", ""));
        assert_eq!(cut("abcd", 3), ("abc", "…"));
        // `é` has 2 bytes: a cut in its middle moves to its start.
        assert_eq!(cut("aéb", 2), ("a", "…"));
        assert_eq!(cut("", 0), ("", ""));
        assert_eq!(shown("a\nb\u{1b}'\"", 64), "a\\nb\\u{1b}\\'\\\"");
        assert_eq!(shown("a\nbc", 2), "a\\n…");
    }

    #[test]
    fn shown_has_six_times_the_cut_plus_the_mark_at_most() {
        // The worst case: each byte is a character with a 6 byte escape.
        let worst = "\u{1b}".repeat(2000);
        let (start, mark) = cut(&worst, 1024);
        assert_eq!((start.len(), mark.len()), (1024, 3));
        assert_eq!(shown(&worst, 1024).len(), 6 * 1024 + 3);
        // No character has a longer escape for each of its bytes.
        for c in (0..=u32::from(char::MAX)).filter_map(char::from_u32) {
            let text = c.to_string();
            assert!(shown(&text, 4).len() <= 6 * text.len(), "{c:?}");
        }
    }

    #[test]
    fn redact_replaces_every_occurrence_of_every_secret() {
        let redactor = redactor(&["hunter2-value", "tok_123456"]);
        assert_eq!(
            redactor.redact("a hunter2-value b tok_123456 c hunter2-value"),
            "a [REDACTED] b [REDACTED] c [REDACTED]"
        );
        assert_eq!(redactor.redact("nothing here"), "nothing here");
    }

    #[test]
    fn redact_leaves_no_part_of_overlapping_secrets() {
        // One value contains the other; two values overlap; a value overlaps itself.
        let redactor = redactor(&["abcd", "abcdefgh", "ghijkl", "xyxy"]);
        assert_eq!(redactor.redact("<abcdefgh>"), "<[REDACTED]>");
        assert_eq!(redactor.redact("<abcdefghijkl>"), "<[REDACTED]>");
        assert_eq!(redactor.redact("<xyxyxy>"), "<[REDACTED]>");
        assert_eq!(redactor.redact("abcdabcd"), "[REDACTED][REDACTED]");
    }

    #[test]
    fn empty_and_short_secrets_are_not_redacted() {
        let redactor = redactor(&["", "a", "abc"]);
        assert_eq!(redactor.redact("a b abc"), "a b abc");
        assert_eq!(redactor.redact(""), "");
    }

    #[test]
    fn redact_handles_non_ascii_text() {
        let redactor = redactor(&["pässwörd"]);
        assert_eq!(redactor.redact("ä pässwörd ö"), "ä [REDACTED] ö");
    }

    #[test]
    fn forget_removes_one_registration() {
        let redactor = Redactor::new();
        let (first, second) = (secret("hunter2-value"), secret("hunter2-value"));
        redactor.register(&first);
        redactor.register(&second);
        redactor.forget(&first);
        assert_eq!(redactor.redact("hunter2-value"), "[REDACTED]");
        redactor.forget(&second);
        assert_eq!(redactor.redact("hunter2-value"), "hunter2-value");
        redactor.forget(&second);
    }

    #[test]
    fn redactor_debug_never_contains_a_value() {
        let rendered = format!("{:?}", redactor(&["hunter2-value"]));
        assert!(!rendered.contains("hunter2"), "leaked: {rendered}");
    }

    #[test]
    fn redactor_is_send_sync_static() {
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<Redactor>();
    }

    #[test]
    fn both_formats_write_events_with_fields() {
        let human = captured(Level::INFO, LogFormat::Human, &Redactor::new(), || {
            info!(rows = 3, "query done");
        });
        assert!(human.contains("INFO"), "{human}");
        assert!(human.contains("query done"), "{human}");
        assert!(human.contains("rows=3"), "{human}");

        let json = captured(Level::INFO, LogFormat::Json, &Redactor::new(), || {
            info!(rows = 3, "query done");
        });
        let event: serde_json::Value = serde_json::from_str(json.trim()).expect(&json);
        assert_eq!(event["level"], "INFO");
        assert_eq!(event["fields"]["message"], "query done");
        assert_eq!(event["fields"]["rows"], 3);
    }

    #[test]
    fn events_below_the_level_are_dropped() {
        for format in FORMATS {
            let output = captured(Level::WARN, format, &Redactor::new(), || {
                debug!("debug-event");
                info!("info-event");
                warn!("warn-event");
                error!("error-event");
            });
            assert!(!output.contains("debug-event"), "{output}");
            assert!(!output.contains("info-event"), "{output}");
            assert!(output.contains("warn-event"), "{output}");
            assert!(output.contains("error-event"), "{output}");
            assert_eq!(output.lines().count(), 2, "{output}");
        }
    }

    #[test]
    fn spans_appear_in_the_output() {
        let log = || {
            let _outer = info_span!("connect", profile = "prod").entered();
            let _inner = info_span!("handshake").entered();
            info!("hello");
        };
        let human = captured(Level::INFO, LogFormat::Human, &Redactor::new(), log);
        assert!(
            human.contains("connect{profile=\"prod\"}:handshake"),
            "{human}"
        );

        let json = captured(Level::INFO, LogFormat::Json, &Redactor::new(), log);
        let event: serde_json::Value = serde_json::from_str(json.trim()).expect(&json);
        assert_eq!(event["span"]["name"], "handshake");
        assert_eq!(event["spans"][0]["name"], "connect");
        assert_eq!(event["spans"][0]["profile"], "prod");
    }

    #[test]
    fn a_secret_is_redacted_in_message_field_and_span() {
        let value = "hunter2-value";
        let redactor = redactor(&[value]);
        for format in FORMATS {
            let output = captured(Level::INFO, format, &redactor, || {
                let _span = info_span!("connect", password = value).entered();
                info!("message with {value} and {value}");
                info!(display = %value, debug = ?value, plain = value, "fields");
            });
            assert!(!output.contains("hunter2"), "{format:?} leaked: {output}");
            assert!(output.contains(REDACTED), "{output}");
            assert_eq!(output.lines().count(), 2, "{output}");
        }
    }

    #[test]
    fn a_secret_with_quote_backslash_and_newline_is_redacted_in_its_escaped_forms() {
        let value = "Zq\"Xw\\Jk\nVv\u{1}é";
        let redactor = redactor(&[value]);
        for format in FORMATS {
            let output = captured(Level::INFO, format, &redactor, || {
                let _span = info_span!("connect", password = value, debug = ?value).entered();
                info!("message with {value} and {value:?}");
                info!(display = %value, debug = ?value, plain = value, "fields");
            });
            for part in ["Zq", "Xw", "Jk", "Vv"] {
                assert!(!output.contains(part), "{format:?} leaked {part}: {output}");
            }
        }
    }

    /// R-1: the human format rewrites some control characters in a message
    /// as text. This test does not know which ones: it tries each character
    /// of C0, DEL, C1 and Latin-1, and some others, so it also guards an
    /// update of tracing-subscriber that changes the rule.
    #[test]
    fn a_secret_with_any_special_character_is_redacted_in_every_position() {
        let chars = ('\0'..='\u{ff}').chain(['\u{2028}', '\u{202e}', '\u{feff}', '\u{fffd}']);
        for ch in chars {
            // The character alone, then mixed with a quote and a backslash.
            for value in [format!("Zq{ch}Xw{ch}Jk"), format!("Zq\"{ch}Xw\\{ch}Jk")] {
                let redactor = redactor(&[&value]);
                let failure = io::Error::other(value.clone());
                for format in FORMATS {
                    let output = captured(Level::INFO, format, &redactor, || {
                        let _span =
                            info_span!("connect", display = %value, debug = ?value).entered();
                        info!("connecting with {value}");
                        info!(display = %value, debug = ?value, plain = value, "fields");
                        info!(
                            error = &failure as &(dyn std::error::Error + 'static),
                            "failed"
                        );
                        // R-43: text that the application escaped one or two
                        // times before it logged it. No `?` here: it is one
                        // more escape, and the texts include that form.
                        for text in escaped_by_the_application(&value) {
                            let failure = io::Error::other(text.clone());
                            let _span = info_span!("send", display = %text, plain = text).entered();
                            info!("request {text}");
                            info!(display = %text, plain = text, "fields");
                            info!(
                                error = &failure as &(dyn std::error::Error + 'static),
                                "failed"
                            );
                        }
                    });
                    for part in ["Zq", "Xw", "Jk"] {
                        assert!(
                            !output.contains(part),
                            "{format:?} leaked {part} of a secret with {ch:?}: {output}"
                        );
                    }
                    assert!(output.contains(REDACTED), "{output}");
                }
            }
        }
    }

    /// Texts that contain `value` after one and after two escapes by the
    /// application: JSON text, `Debug` text, and each of the two escaped again
    /// in each of the two ways.
    fn escaped_by_the_application(value: &str) -> Vec<String> {
        let json = |text: &str| serde_json::json!({ "password": text }).to_string();
        let debug = |text: &str| format!("{text:?}");
        let once = [json(value), debug(value)];
        let twice = once.iter().flat_map(|text| [json(text), debug(text)]);
        twice.chain(once.clone()).collect()
    }

    /// R-43, R-67 (a): each escape alone, and four escapes on top of each
    /// other.
    #[test]
    fn json_form_of_a_secret_with_a_quote_at_the_end_is_complete() {
        let value = "ZqXwJk7\"";
        assert_eq!(*json_escaped(value), "ZqXwJk7\\\"");
        let json = serde_json::to_string(value).unwrap();
        assert_eq!(redactor(&[value]).redact(&json), format!("\"{REDACTED}\""));
    }

    #[test]
    fn redact_finds_each_escaped_form_and_a_chain_of_four() {
        // No escape leaves this value as it is.
        let value = "Zq\"Xw\u{1b}Jk";
        let redactor = redactor(&[value]);
        let chain = json_escaped(&debug_escaped(&debug_escaped(&json_escaped(value))));
        let forms = [
            debug_escaped(value),
            json_escaped(value),
            sanitized(value),
            chain,
        ];
        for form in forms {
            assert_ne!(*form, value);
            assert_eq!(redactor.redact(&format!("<{}>", *form)), "<[REDACTED]>");
        }
        // The limit: five escapes are not found.
        let four = json_escaped(&json_escaped(&json_escaped(&json_escaped(value))));
        assert!(redactor.redact(&json_escaped(&four)).contains("Zq"));
    }

    /// R-43: the reported cases.
    #[test]
    fn a_secret_in_a_json_body_is_redacted_in_message_and_debug_field() {
        for value in ["Zq\"XwJk", "Zq\u{1b}XwJk", "Zq\"Xw\u{7f}Jk"] {
            let redactor = redactor(&[value]);
            let body = serde_json::json!({ "password": value }).to_string();
            for format in FORMATS {
                let output = captured(Level::INFO, format, &redactor, || {
                    info!(body = ?body, "request");
                    info!("request {body}");
                });
                for part in ["Zq", "Xw", "Jk"] {
                    assert!(
                        !output.contains(part),
                        "{format:?} leaked {part} of {value:?}: {output}"
                    );
                }
                assert_eq!(output.matches(REDACTED).count(), 2, "{output}");
            }
        }
    }

    #[test]
    fn the_reported_secret_with_an_escape_sequence_is_redacted() {
        let value = "tok\u{1b}[31mHUNTER2zz";
        let redactor = redactor(&[value]);
        let output = captured(Level::INFO, LogFormat::Human, &redactor, || {
            info!("connecting with {value}");
        });
        assert!(!output.contains("HUNTER2"), "leaked: {output}");
    }

    #[test]
    fn several_secrets_in_one_line_are_all_redacted() {
        let redactor = redactor(&["hunter2-value", "tok_123456"]);
        for format in FORMATS {
            let output = captured(Level::INFO, format, &redactor, || {
                info!(token = "tok_123456", "login hunter2-value tok_123456");
            });
            assert!(!output.contains("hunter2"), "{output}");
            assert!(!output.contains("tok_"), "{output}");
        }
    }

    #[test]
    fn a_secret_split_over_two_writes_is_redacted() {
        let redactor = redactor(&["hunter2-value"]);
        let mut output = Vec::new();
        {
            let mut writer = RedactingWriter::new(&mut output, &redactor);
            writer.write_all(b"login hunt").unwrap();
            writer.write_all(b"er2-value done\n").unwrap();
        }
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "login [REDACTED] done\n"
        );
    }

    #[test]
    fn flush_writes_the_redacted_text_once() {
        let redactor = redactor(&["hunter2-value"]);
        let mut output = Vec::new();
        {
            let mut writer = RedactingWriter::new(&mut output, &redactor);
            writer.write_all(b"hunter2-value\n").unwrap();
            writer.flush().unwrap();
        }
        assert_eq!(String::from_utf8(output).unwrap(), "[REDACTED]\n");
    }
    /// R-67 (a): the reported case. A JSON body in a `Debug` text in an error
    /// that is logged with `?`.
    #[test]
    fn a_secret_in_a_json_body_in_an_error_text_logged_with_debug_is_redacted() {
        let value = "Zq\"XwJk";
        let redactor = redactor(&[value]);
        let body = serde_json::json!({ "password": value }).to_string();
        let failure = format!("bad response {body:?}");
        for format in FORMATS {
            let output = captured(Level::INFO, format, &redactor, || {
                error!(err = ?failure, "request failed");
            });
            for part in ["Zq", "Xw", "Jk"] {
                assert!(!output.contains(part), "{format:?} leaked {part}: {output}");
            }
        }
    }

    /// R-67 (c): the documented limit. A secret that is equal to a part of
    /// the JSON syntax or of a number breaks the JSON line.
    #[test]
    fn a_secret_that_is_json_syntax_makes_the_json_line_invalid() {
        let redactor = redactor(&["true", "1234"]);
        let output = captured(Level::INFO, LogFormat::Json, &redactor, || {
            info!(ok = true, rows = 12345, "done");
        });
        assert!(output.contains("\"ok\":[REDACTED]"), "{output}");
        assert!(output.contains("\"rows\":[REDACTED]5"), "{output}");
        assert!(serde_json::from_str::<serde_json::Value>(output.trim()).is_err());
    }
}
