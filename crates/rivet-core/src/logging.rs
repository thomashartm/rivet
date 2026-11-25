//! Structured logging and tracing, with central redaction of secrets
//! (ARCHITECTURE.md §7.4).
//!
//! Code logs with the [`tracing`] macros. [`dispatch`] builds the subscriber
//! that formats the events and spans. Every formatted line goes through a
//! [`Redactor`] before it reaches the output, so a secret value that code
//! logs by mistake is replaced with [`REDACTED`].

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

/// The forms of `value` that the two log formats can write:
/// the value itself, its `Debug` form (a field logged with `?`), and each of
/// the two as a JSON string (the JSON format).
fn needles(value: &str) -> Vec<Zeroizing<String>> {
    let quoted = Zeroizing::new(format!("{value:?}"));
    let debug = &quoted[1..quoted.len() - 1];
    let mut needles: Vec<Zeroizing<String>> = Vec::new();
    for form in [value, debug] {
        let mut forms = vec![Zeroizing::new(form.to_owned())];
        if let Ok(json) = serde_json::to_string(form).map(Zeroizing::new) {
            forms.push(Zeroizing::new(json[1..json.len() - 1].to_owned()));
        }
        for needle in forms {
            if !needles.iter().any(|known| **known == *needle) {
                needles.push(needle);
            }
        }
    }
    needles
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
/// - The redactor finds the value itself, its `Debug`-escaped form and the
///   JSON-escaped form of both. It does not find other encodings of the
///   value, for example Base64, URL encoding or a part of the value.
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

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::dispatcher::with_default;
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
        with_default(&capture.dispatch(level, format, redactor), log);
        capture.text()
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
}
