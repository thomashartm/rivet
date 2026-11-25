//! Package signatures and the trust store (ARCHITECTURE.md §4.8, §7,
//! ADR-0006).
//!
//! A package is a file with a detached [minisign] signature. This module
//! only verifies. It does not sign and it handles no secret key.
//!
//! # Rules
//!
//! - A built-in extension must verify with the project key. No other key is
//!   tried.
//! - A package of a publisher must verify with the pinned key of that
//!   publisher. No other key is tried.
//! - A publisher without a pinned key is refused. The caller shows the key to
//!   the user and calls [`TrustStore::pin`] after the user confirms it.
//!   Nothing in this module pins a key on its own.
//! - The trusted comment of the signature is verified together with the
//!   package.
//! - Legacy signatures (not prehashed, made with `minisign -l`) are refused.
//!
//! # The caller must do this
//!
//! - **Blocking I/O.** [`verify`], [`TrustStore::verify_package`],
//!   [`TrustStore::load`] and [`TrustStore::save`] read or write files and
//!   hash the whole package. From async code, call them in
//!   [`tokio::task::spawn_blocking`] or in a blocking job
//!   ([`JobScheduler::spawn_blocking`](crate::jobs::JobScheduler::spawn_blocking)),
//!   never directly on an async worker thread (§5.1).
//! - **Use the bytes that were verified.** Verification reads the file at the
//!   given path. If another process can replace that file, copy the package
//!   to a private location first, verify the copy and use only the copy.
//!
//! # Trust store file
//!
//! The file holds the pinned keys only. The project key ships with the
//! binary and is never read from a file.
//!
//! The file is `trust.toml` in the user configuration directory, beside the
//! user settings file ([`user_settings_path`](crate::settings::user_settings_path)).
//! The caller gives the path. It MUST NOT be a path in a workspace directory
//! or in a bundled directory.
//!
//! ```toml
//! schema_version = 1
//!
//! [publishers]
//! acme = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"
//! ```
//!
//! # Example
//!
//! ```no_run
//! use rivet_core::package::{Origin, PublicKey, TrustStore};
//! use std::path::Path;
//!
//! let project_key: PublicKey =
//!     "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3".parse()?;
//! let file = Path::new("trust.toml");
//! let mut store = TrustStore::load(project_key, file)?;
//!
//! if store.pinned("acme").is_none() {
//!     let key = PublicKey::load(Path::new("acme.pub"))?;
//!     // Show `key` to the user here. Continue only after the user confirms.
//!     store.pin("acme", key)?;
//!     store.save(file)?;
//! }
//! store.verify_package(
//!     Origin::Publisher("acme"),
//!     Path::new("acme.postgres-1.0.0.rivetpkg"),
//!     Path::new("acme.postgres-1.0.0.rivetpkg.minisig"),
//! )?;
//! # Ok::<(), rivet_sdk::error::Error>(())
//! ```
//!
//! [minisign]: https://jedisct1.github.io/minisign/

use crate::settings::SCHEMA_VERSION_KEY;
use rivet_sdk::error::{Error, ErrorCategory, Result};
use rivet_sdk::manifest::ExtensionId;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::str::FromStr;
use toml::{Table, Value};

/// The schema version of the trust store file.
pub const SCHEMA_VERSION: i64 = 1;

/// The key of the table of pinned keys in the trust store file.
const PUBLISHERS_KEY: &str = "publishers";

/// The largest key or signature file that is read. minisign permits a
/// trusted comment of 8192 bytes; a valid file is always smaller than this.
const TEXT_FILE_MAX_BYTES: u64 = 16 * 1024;

/// A minisign public key.
///
/// The text form is the base64 line of a `minisign.pub` file. `Display`
/// prints that line. Two keys are equal when they hold the same key bytes.
///
/// ```
/// use rivet_core::package::PublicKey;
///
/// let text = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
/// let key: PublicKey = text.parse()?;
/// assert_eq!(key.to_string(), text);
/// assert!("not a key".parse::<PublicKey>().is_err());
/// # Ok::<(), rivet_sdk::error::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct PublicKey {
    base64: String,
    key: minisign_verify::PublicKey,
}

impl PublicKey {
    /// Reads a public key from a `minisign.pub` file.
    ///
    /// This is blocking I/O.
    ///
    /// # Errors
    ///
    /// Returns a `user` error that names `path` if the file cannot be read or
    /// does not hold a minisign public key.
    pub fn load(path: &Path) -> Result<Self> {
        read_text_file(path, "public key")?
            .parse()
            .map_err(|error: Error| {
                Error::user(format!("{}: {}", path.display(), error.message())).with_source(error)
            })
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    /// Parses the base64 line of a key, or the two lines of a `minisign.pub`
    /// file (`untrusted comment: …` and the base64 line).
    ///
    /// The `user` error does not contain `text`.
    fn from_str(text: &str) -> Result<Self> {
        let invalid = || Error::user("not a valid minisign public key");
        let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
        let base64 = match (lines.next(), lines.next(), lines.next()) {
            (Some(key), None, _) => key,
            (Some(comment), Some(key), None) if comment.starts_with("untrusted comment:") => key,
            _ => return Err(invalid()),
        };
        let key = minisign_verify::PublicKey::from_base64(base64)
            .map_err(|error| invalid().with_source(error))?;
        Ok(Self {
            base64: base64.to_owned(),
            key,
        })
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.base64)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for PublicKey {}

/// Verifies the file `package` against the detached minisign signature file
/// `signature` and the public key `key`.
///
/// The package is read in pieces, so a large package does not need much
/// memory. This is blocking I/O: see the [module documentation](self).
///
/// # Errors
///
/// - `user`: a file cannot be read, or `signature` is not a minisign
///   signature, or it is a legacy signature. The message names the file.
/// - `policy`: the signature does not verify. The package, the signature or
///   the trusted comment was changed, or the signature was made with another
///   key. The message names both files.
pub fn verify(package: &Path, signature: &Path, key: &PublicKey) -> Result<()> {
    let text = read_text_file(signature, "signature")?;
    let parsed = minisign_verify::Signature::decode(&text).map_err(|error| {
        Error::user(format!(
            "{}: not a valid minisign signature",
            signature.display()
        ))
        .with_source(error)
    })?;
    let rejected = || {
        Error::policy(format!(
            "{}: the signature {} does not verify with the public key {key}",
            package.display(),
            signature.display()
        ))
    };

    let mut verifier = key.key.verify_stream(&parsed).map_err(|error| match error {
        minisign_verify::Error::UnsupportedLegacyMode => Error::user(format!(
            "{}: legacy minisign signatures are not accepted; sign the package again without `-l`",
            signature.display()
        )),
        // The key id in the signature is not the id of `key`.
        _ => rejected(),
    })?;

    let unreadable = |error| io_error(package, "cannot read the package file", error);
    let mut file = File::open(package).map_err(unreadable)?;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(len) => verifier.update(&buffer[..len]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(unreadable(error)),
        }
    }
    verifier.finalize().map_err(|_| rejected())
}

/// Who a package comes from. It selects the one key that can verify it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin<'a> {
    /// A built-in extension. Only the project key verifies it.
    BuiltIn,
    /// An extension of the named third-party publisher. Only the pinned key
    /// of this publisher verifies it.
    Publisher(&'a str),
}

/// The keys that the host trusts: the project key and one pinned key for
/// each publisher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustStore {
    project_key: PublicKey,
    pins: BTreeMap<String, PublicKey>,
}

impl TrustStore {
    /// Creates a trust store with the project key and no pinned keys.
    pub fn new(project_key: PublicKey) -> Self {
        Self {
            project_key,
            pins: BTreeMap::new(),
        }
    }

    /// Returns the project key. It verifies built-in extensions.
    pub fn project_key(&self) -> &PublicKey {
        &self.project_key
    }

    /// Returns the pinned key of `publisher`, or `None` if no key is pinned.
    pub fn pinned(&self, publisher: &str) -> Option<&PublicKey> {
        self.pins.get(publisher)
    }

    /// Pins `key` as the only key of `publisher`. It replaces an earlier pin.
    ///
    /// This call is the confirmation of the caller. Call it only after the
    /// user reviewed the key: on the first install of a publisher, and after
    /// a new review when the publisher changed its key. Call
    /// [`save`](Self::save) to keep the pin.
    ///
    /// # Errors
    ///
    /// Returns a `user` error if `publisher` is not a valid name. A publisher
    /// name follows the rules of an [`ExtensionId`].
    pub fn pin(&mut self, publisher: &str, key: PublicKey) -> Result<()> {
        // The manifest has no publisher field yet, so the name is a string
        // with the character rules of an extension id.
        publisher
            .parse::<ExtensionId>()
            .map_err(|error| Error::user(format!("invalid publisher name: {}", error.message())))?;
        self.pins.insert(publisher.to_owned(), key);
        Ok(())
    }

    /// Verifies `package` against the signature file `signature` with the one
    /// key that `origin` permits. See the [module documentation](self) for
    /// the rules. This is blocking I/O.
    ///
    /// A rejected package is logged as a warning.
    ///
    /// # Errors
    ///
    /// - `policy`: the publisher has no pinned key. Check
    ///   [`pinned`](Self::pinned) first; confirm and [`pin`](Self::pin) the
    ///   key, then call again.
    /// - `policy`: the signature does not verify with the permitted key. For
    ///   a publisher, the message says that a new review is needed.
    /// - `user`: see [`verify`].
    pub fn verify_package(
        &self,
        origin: Origin<'_>,
        package: &Path,
        signature: &Path,
    ) -> Result<()> {
        self.check(origin, package, signature)
            .inspect_err(|error| tracing::warn!(%error, "package signature rejected"))
    }

    fn check(&self, origin: Origin<'_>, package: &Path, signature: &Path) -> Result<()> {
        let (key, rejected) = match origin {
            Origin::BuiltIn => (
                &self.project_key,
                format!(
                    "{}: a built-in extension must be signed with the project key, \
                     and the signature does not verify with it",
                    package.display()
                ),
            ),
            Origin::Publisher(publisher) => {
                let key = self.pins.get(publisher).ok_or_else(|| {
                    Error::policy(format!(
                        "{}: publisher `{publisher}` has no pinned key; \
                         confirm the key of the publisher and pin it first",
                        package.display()
                    ))
                })?;
                (
                    key,
                    format!(
                        "{}: the signature does not verify with the pinned key of publisher \
                         `{publisher}`: the package was changed, or the publisher changed its \
                         key. A key change needs a new review before the new key is pinned",
                        package.display()
                    ),
                )
            }
        };
        verify(package, signature, key).map_err(|error| match error.category() {
            ErrorCategory::Policy => Error::policy(rejected).with_source(error),
            _ => error,
        })
    }

    /// Reads the pinned keys from the TOML file `path`. A file that does not
    /// exist gives a trust store without pinned keys.
    ///
    /// `project_key` is never read from the file: it ships with the binary.
    /// This is blocking I/O.
    ///
    /// # Errors
    ///
    /// Returns a `user` error that names `path` if the file cannot be read,
    /// is not valid TOML, has another [`SCHEMA_VERSION`], has an unknown key,
    /// or holds an invalid publisher name or public key.
    pub fn load(project_key: PublicKey, path: &Path) -> Result<Self> {
        let mut store = Self::new(project_key);
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(store),
            Err(error) => return Err(io_error(path, "cannot read the trust store file", error)),
        };
        let invalid = |reason: String| Error::user(format!("{}: {reason}", path.display()));

        let mut table: Table = text
            .parse()
            .map_err(|error: toml::de::Error| invalid(error.message().to_owned()))?;
        if table.remove(SCHEMA_VERSION_KEY) != Some(Value::Integer(SCHEMA_VERSION)) {
            return Err(invalid(format!(
                "key `{SCHEMA_VERSION_KEY}` must be {SCHEMA_VERSION}"
            )));
        }
        let publishers = match table.remove(PUBLISHERS_KEY) {
            None => Table::new(),
            Some(Value::Table(publishers)) => publishers,
            Some(_) => return Err(invalid(format!("key `{PUBLISHERS_KEY}` must be a table"))),
        };
        if let Some(key) = table.keys().next() {
            return Err(invalid(format!("unknown key `{key}`")));
        }
        for (publisher, value) in publishers {
            let key = value
                .as_str()
                .ok_or_else(|| Error::user("the value must be a public key string"))
                .and_then(str::parse)
                .map_err(|error| {
                    invalid(format!("publisher `{publisher}`: {}", error.message()))
                })?;
            store
                .pin(&publisher, key)
                .map_err(|error| invalid(error.message().to_owned()))?;
        }
        Ok(store)
    }

    /// Writes the pinned keys to the TOML file `path`. It creates the
    /// directory if needed.
    ///
    /// The write is atomic: the content goes to a temporary file in the same
    /// directory, and that file then replaces `path`. A failed write leaves
    /// the old file as it was. This is blocking I/O.
    ///
    /// # Errors
    ///
    /// Returns a `user` error that names `path` if the file cannot be
    /// written.
    pub fn save(&self, path: &Path) -> Result<()> {
        let publishers = self
            .pins
            .iter()
            .map(|(publisher, key)| (publisher.clone(), Value::String(key.to_string())))
            .collect();
        let mut table = Table::new();
        table.insert(
            SCHEMA_VERSION_KEY.to_owned(),
            Value::Integer(SCHEMA_VERSION),
        );
        table.insert(PUBLISHERS_KEY.to_owned(), Value::Table(publishers));
        let text = table.to_string();

        let write = || {
            let dir = match path.parent() {
                Some(dir) if !dir.as_os_str().is_empty() => dir,
                _ => Path::new("."),
            };
            std::fs::create_dir_all(dir)?;
            let mut file = tempfile::NamedTempFile::new_in(dir)?;
            file.write_all(text.as_bytes())?;
            file.as_file().sync_all()?;
            file.persist(path).map_err(|error| error.error)?;
            Ok(())
        };
        write().map_err(|error| io_error(path, "cannot write the trust store file", error))
    }
}

/// Reads a small text file: a key or a signature. `what` names the kind of
/// file in the error.
fn read_text_file(path: &Path, what: &str) -> Result<String> {
    let mut text = String::new();
    File::open(path)
        .and_then(|file| file.take(TEXT_FILE_MAX_BYTES + 1).read_to_string(&mut text))
        .map_err(|error| io_error(path, &format!("cannot read the {what} file"), error))?;
    if text.len() as u64 > TEXT_FILE_MAX_BYTES {
        return Err(Error::user(format!(
            "{}: too large for a minisign {what} file",
            path.display()
        )));
    }
    Ok(text)
}

/// A `user` error that names the file, as for a settings file.
fn io_error(path: &Path, problem: &str, error: io::Error) -> Error {
    Error::user(format!("{}: {problem}", path.display())).with_source(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    /// A TEST-ONLY key pair. It is made new in each test and never stored.
    struct TestKey {
        pair: minisign::KeyPair,
        public: PublicKey,
    }

    impl TestKey {
        fn new() -> Self {
            let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
            let public = pair.pk.to_base64().parse().unwrap();
            Self { pair, public }
        }

        /// The text of a prehashed signature of `data`, as `minisign -S`
        /// writes it.
        fn sign(&self, data: &[u8]) -> String {
            minisign::sign(
                Some(&self.pair.pk),
                &self.pair.sk,
                data,
                Some(TRUSTED_COMMENT),
                None,
            )
            .unwrap()
            .into_string()
        }
    }

    const PACKAGE: &[u8] = b"rivet test package\n";
    const TRUSTED_COMMENT: &str = "file:acme.postgres-1.0.0.rivetpkg";

    /// A directory with a package file and its signature file.
    struct Files {
        _dir: tempfile::TempDir,
        package: PathBuf,
        signature: PathBuf,
    }

    fn files(package: &[u8], signature: &str) -> Files {
        let dir = tempfile::tempdir().unwrap();
        let files = Files {
            package: dir.path().join("ext.rivetpkg"),
            signature: dir.path().join("ext.rivetpkg.minisig"),
            _dir: dir,
        };
        std::fs::write(&files.package, package).unwrap();
        std::fs::write(&files.signature, signature).unwrap();
        files
    }

    /// Asserts an error of `category` whose text contains every part.
    fn assert_error<T: fmt::Debug>(
        result: Result<T>,
        category: ErrorCategory,
        parts: &[&str],
    ) -> String {
        let error = result.expect_err("an error");
        assert_eq!(error.category(), category, "{error}");
        let text = error.to_string();
        for part in parts {
            assert!(text.contains(part), "`{part}` is missing in: {text}");
        }
        text
    }

    fn shown(path: &Path) -> String {
        path.display().to_string()
    }

    /// Replaces the character at `index` of line `line` with another base64
    /// character. The text stays valid base64 of the same length.
    fn change_line(signature: &str, line: usize, index: usize) -> String {
        let mut lines: Vec<String> = signature.lines().map(str::to_owned).collect();
        let old = lines[line].as_bytes()[index];
        let new = if old == b'A' { "B" } else { "A" };
        lines[line].replace_range(index..=index, new);
        lines.join("\n") + "\n"
    }

    // --- verify -----------------------------------------------------------

    #[test]
    fn valid_signature_verifies() {
        let key = TestKey::new();
        let f = files(PACKAGE, &key.sign(PACKAGE));
        verify(&f.package, &f.signature, &key.public).unwrap();
    }

    #[test]
    fn package_larger_than_the_read_buffer_verifies() {
        let key = TestKey::new();
        let package = vec![7_u8; 200_000];
        let f = files(&package, &key.sign(&package));
        verify(&f.package, &f.signature, &key.public).unwrap();

        let mut changed = package;
        *changed.last_mut().unwrap() = 8;
        std::fs::write(&f.package, changed).unwrap();
        assert_error(
            verify(&f.package, &f.signature, &key.public),
            ErrorCategory::Policy,
            &[],
        );
    }

    #[test]
    fn changed_package_byte_is_rejected() {
        let key = TestKey::new();
        let f = files(b"rivet test package\r", &key.sign(PACKAGE));
        assert_error(
            verify(&f.package, &f.signature, &key.public),
            ErrorCategory::Policy,
            &[&shown(&f.package), &shown(&f.signature), "does not verify"],
        );
    }

    #[test]
    fn changed_signature_is_rejected() {
        let key = TestKey::new();
        let signature = key.sign(PACKAGE);
        // Line 1 holds the signature of the package (after the key id);
        // line 3 holds the global signature.
        for (line, index) in [(1, 40), (3, 40)] {
            let f = files(PACKAGE, &change_line(&signature, line, index));
            assert_error(
                verify(&f.package, &f.signature, &key.public),
                ErrorCategory::Policy,
                &["does not verify"],
            );
        }
    }

    #[test]
    fn changed_trusted_comment_is_rejected() {
        let key = TestKey::new();
        let signature = key.sign(PACKAGE);
        assert!(signature.contains(TRUSTED_COMMENT), "{signature}");
        let changed = signature.replace(TRUSTED_COMMENT, "file:other-9.9.9.rivetpkg");
        let f = files(PACKAGE, &changed);
        assert_error(
            verify(&f.package, &f.signature, &key.public),
            ErrorCategory::Policy,
            &["does not verify"],
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let key = TestKey::new();
        let other = TestKey::new();
        let f = files(PACKAGE, &key.sign(PACKAGE));
        assert_error(
            verify(&f.package, &f.signature, &other.public),
            ErrorCategory::Policy,
            &[&shown(&f.package), "does not verify"],
        );
    }

    #[test]
    fn malformed_signature_is_a_user_error_that_names_the_file() {
        let key = TestKey::new();
        let valid = key.sign(PACKAGE);
        assert!(valid.contains("\nRU"), "{valid}");
        let two_lines: String = valid.lines().take(2).collect::<Vec<_>>().join("\n");
        let cases = [
            String::new(),
            "SECRET-LOOKING-CONTENT, not a signature\n".to_owned(),
            two_lines,
            valid.replace("trusted comment: ", "trusted: "),
            valid.replacen("\nRU", "\n!!", 1),
        ];
        for text in cases {
            let f = files(PACKAGE, &text);
            let message = assert_error(
                verify(&f.package, &f.signature, &key.public),
                ErrorCategory::User,
                &[&shown(&f.signature), "not a valid minisign signature"],
            );
            assert!(!message.contains("SECRET-LOOKING"), "leaked: {message}");
        }
    }

    #[test]
    fn legacy_signature_is_a_user_error() {
        let key = TestKey::new();
        // Base64 `RU…` starts the prehashed algorithm id `ED`; `RW…` starts
        // the legacy algorithm id `Ed`.
        let signature = key.sign(PACKAGE);
        let legacy = signature.replacen("\nRU", "\nRW", 1);
        assert_ne!(legacy, signature);
        let f = files(PACKAGE, &legacy);
        assert_error(
            verify(&f.package, &f.signature, &key.public),
            ErrorCategory::User,
            &[&shown(&f.signature), "legacy"],
        );
    }

    #[test]
    fn missing_or_oversized_files_are_user_errors_that_name_the_file() {
        let key = TestKey::new();
        let f = files(PACKAGE, &key.sign(PACKAGE));

        let absent = f.package.with_file_name("absent");
        assert_error(
            verify(&absent, &f.signature, &key.public),
            ErrorCategory::User,
            &[&shown(&absent), "package file"],
        );
        assert_error(
            verify(&f.package, &absent, &key.public),
            ErrorCategory::User,
            &[&shown(&absent), "signature file"],
        );

        std::fs::write(&f.signature, "x".repeat(20_000)).unwrap();
        assert_error(
            verify(&f.package, &f.signature, &key.public),
            ErrorCategory::User,
            &[&shown(&f.signature), "too large"],
        );
    }

    // --- PublicKey --------------------------------------------------------

    #[test]
    fn public_key_parses_both_text_forms_and_prints_the_base64_line() {
        let key = TestKey::new();
        let base64 = key.pair.pk.to_base64();
        let file_form = key.pair.pk.to_box().unwrap().into_string();
        assert!(file_form.starts_with("untrusted comment:"), "{file_form}");

        for text in [base64.clone(), format!("  {base64}\n"), file_form] {
            let parsed: PublicKey = text.parse().unwrap();
            assert_eq!(parsed, key.public);
            assert_eq!(parsed.to_string(), base64);
        }
        assert_ne!(TestKey::new().public, key.public);
    }

    #[test]
    fn malformed_key_is_a_user_error_without_the_text() {
        let base64 = TestKey::new().pair.pk.to_base64();
        assert!(base64.starts_with("RW"), "{base64}");
        let cases = [
            String::new(),
            "SECRET-LOOKING-CONTENT".to_owned(),
            base64[..base64.len() - 4].to_owned(),
            format!("{base64}AAAA"),
            // A wrong algorithm id.
            base64.replacen("RW", "AA", 1),
            format!("some other line\n{base64}\n"),
            format!("untrusted comment: a\n{base64}\n{base64}\n"),
        ];
        for text in cases {
            let message = assert_error(
                text.parse::<PublicKey>(),
                ErrorCategory::User,
                &["not a valid minisign public key"],
            );
            assert!(!message.contains("SECRET-LOOKING"), "leaked: {message}");
        }
    }

    #[test]
    fn public_key_file_is_loaded_and_a_bad_file_is_named() {
        let key = TestKey::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.pub");

        std::fs::write(&path, key.pair.pk.to_box().unwrap().into_string()).unwrap();
        assert_eq!(PublicKey::load(&path).unwrap(), key.public);

        std::fs::write(&path, "SECRET-LOOKING-CONTENT\n").unwrap();
        let message = assert_error(
            PublicKey::load(&path),
            ErrorCategory::User,
            &[&shown(&path), "not a valid minisign public key"],
        );
        assert!(!message.contains("SECRET-LOOKING"), "leaked: {message}");

        let absent = dir.path().join("absent.pub");
        assert_error(
            PublicKey::load(&absent),
            ErrorCategory::User,
            &[&shown(&absent), "public key file"],
        );
    }

    // --- TrustStore -------------------------------------------------------

    #[test]
    fn trust_store_holds_the_project_key_and_the_pinned_keys() {
        let project = TestKey::new();
        let acme = TestKey::new();
        let mut store = TrustStore::new(project.public.clone());
        assert_eq!(store.project_key(), &project.public);
        assert_eq!(store.pinned("acme"), None);

        store.pin("acme", acme.public.clone()).unwrap();
        assert_eq!(store.pinned("acme"), Some(&acme.public));
        assert_eq!(store.pinned("other"), None);
    }

    #[test]
    fn first_install_is_refused_until_the_caller_pins_the_key() {
        let acme = TestKey::new();
        let f = files(PACKAGE, &acme.sign(PACKAGE));
        let mut store = TrustStore::new(TestKey::new().public);

        // A valid signature does not pin the key.
        assert_error(
            store.verify_package(Origin::Publisher("acme"), &f.package, &f.signature),
            ErrorCategory::Policy,
            &["publisher `acme`", "no pinned key", &shown(&f.package)],
        );
        assert_eq!(store.pinned("acme"), None);

        // The explicit confirmation of the caller.
        store.pin("acme", acme.public.clone()).unwrap();
        store
            .verify_package(Origin::Publisher("acme"), &f.package, &f.signature)
            .unwrap();
    }

    #[test]
    fn package_signed_with_another_key_than_the_pinned_key_needs_a_new_review() {
        let acme = TestKey::new();
        let new_key = TestKey::new();
        let mut store = TrustStore::new(TestKey::new().public);
        store.pin("acme", acme.public.clone()).unwrap();

        let f = files(PACKAGE, &new_key.sign(PACKAGE));
        assert_error(
            store.verify_package(Origin::Publisher("acme"), &f.package, &f.signature),
            ErrorCategory::Policy,
            &["publisher `acme`", "new review", &shown(&f.package)],
        );
        // The rejected key was not pinned.
        assert_eq!(store.pinned("acme"), Some(&acme.public));

        // After the review, the caller pins the new key.
        store.pin("acme", new_key.public.clone()).unwrap();
        store
            .verify_package(Origin::Publisher("acme"), &f.package, &f.signature)
            .unwrap();
    }

    #[test]
    fn publisher_package_does_not_verify_with_the_project_key_or_another_pin() {
        let project = TestKey::new();
        let acme = TestKey::new();
        let other = TestKey::new();
        let mut store = TrustStore::new(project.public.clone());
        store.pin("acme", acme.public.clone()).unwrap();
        store.pin("other", other.public.clone()).unwrap();

        for signer in [&project, &other] {
            let f = files(PACKAGE, &signer.sign(PACKAGE));
            assert_error(
                store.verify_package(Origin::Publisher("acme"), &f.package, &f.signature),
                ErrorCategory::Policy,
                &["publisher `acme`", "new review"],
            );
        }
    }

    #[test]
    fn built_in_verifies_with_the_project_key_only() {
        let project = TestKey::new();
        let acme = TestKey::new();
        let mut store = TrustStore::new(project.public.clone());
        store.pin("acme", acme.public.clone()).unwrap();

        let f = files(PACKAGE, &project.sign(PACKAGE));
        store
            .verify_package(Origin::BuiltIn, &f.package, &f.signature)
            .unwrap();

        // A pinned publisher key does not make a package a built-in.
        let f = files(PACKAGE, &acme.sign(PACKAGE));
        store
            .verify_package(Origin::Publisher("acme"), &f.package, &f.signature)
            .unwrap();
        assert_error(
            store.verify_package(Origin::BuiltIn, &f.package, &f.signature),
            ErrorCategory::Policy,
            &["built-in", "project key", &shown(&f.package)],
        );
    }

    #[test]
    fn malformed_signature_stays_a_user_error_in_the_trust_store() {
        let acme = TestKey::new();
        let mut store = TrustStore::new(TestKey::new().public);
        store.pin("acme", acme.public.clone()).unwrap();
        let f = files(PACKAGE, "not a signature\n");
        assert_error(
            store.verify_package(Origin::Publisher("acme"), &f.package, &f.signature),
            ErrorCategory::User,
            &[&shown(&f.signature)],
        );
    }

    #[test]
    fn invalid_publisher_name_is_refused() {
        let key = TestKey::new().public;
        let mut store = TrustStore::new(key.clone());
        for name in ["", "Acme", "acme corp", "acme\n", "-acme", "a..b"] {
            assert_error(
                store.pin(name, key.clone()),
                ErrorCategory::User,
                &["invalid publisher name"],
            );
        }
        store.pin("acme-corp.eu", key).unwrap();
    }

    #[test]
    fn trust_store_round_trips_through_a_file() {
        let project = TestKey::new();
        let mut store = TrustStore::new(project.public.clone());
        store.pin("acme", TestKey::new().public).unwrap();
        store.pin("zeta.labs", TestKey::new().public).unwrap();

        let dir = tempfile::tempdir().unwrap();
        // The directory does not exist yet.
        let path = dir.path().join("rivet").join("trust.toml");
        store.save(&path).unwrap();
        assert_eq!(
            TrustStore::load(project.public.clone(), &path).unwrap(),
            store
        );

        // A second save replaces the file and leaves no temporary file.
        store.pin("acme", TestKey::new().public).unwrap();
        store.save(&path).unwrap();
        assert_eq!(TrustStore::load(project.public, &path).unwrap(), store);
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["trust.toml"]);
    }

    #[test]
    fn project_key_is_not_read_from_the_file() {
        let saved_with = TestKey::new().public;
        let loaded_with = TestKey::new().public;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        TrustStore::new(saved_with).save(&path).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("schema_version = 1"), "{text}");
        let store = TrustStore::load(loaded_with.clone(), &path).unwrap();
        assert_eq!(store.project_key(), &loaded_with);
    }

    #[test]
    fn missing_trust_store_file_gives_an_empty_store() {
        let key = TestKey::new().public;
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::load(key.clone(), &dir.path().join("absent.toml")).unwrap();
        assert_eq!(store, TrustStore::new(key));
    }

    #[test]
    fn invalid_trust_store_file_is_an_error_that_names_the_file() {
        let key = TestKey::new().public;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        let cases = [
            ("schema_version = 1\n[publishers\n", ""),
            ("", "`schema_version`"),
            ("schema_version = 2\n", "`schema_version`"),
            ("schema_version = \"1\"\n", "`schema_version`"),
            ("schema_version = 1\npublishers = 5\n", "`publishers`"),
            ("schema_version = 1\nproject_key = \"x\"\n", "`project_key`"),
            (
                "schema_version = 1\n[publishers]\nacme = \"SECRET-LOOKING\"\n",
                "publisher `acme`",
            ),
            (
                "schema_version = 1\n[publishers]\nacme = 5\n",
                "publisher `acme`",
            ),
            (
                &format!("schema_version = 1\n[publishers]\nAcme = \"{key}\"\n"),
                "invalid publisher name",
            ),
        ];
        for (text, part) in cases {
            std::fs::write(&path, text).unwrap();
            let message = assert_error(
                TrustStore::load(key.clone(), &path),
                ErrorCategory::User,
                &[&shown(&path), part],
            );
            assert!(!message.contains("SECRET-LOOKING"), "leaked: {message}");
        }

        // A directory cannot be read as a file.
        assert_error(
            TrustStore::load(key, dir.path()),
            ErrorCategory::User,
            &[&shown(dir.path())],
        );
    }

    #[test]
    fn save_to_a_path_that_cannot_be_written_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, "").unwrap();
        // The parent of the target is a file, not a directory.
        let path = blocker.join("trust.toml");
        assert_error(
            TrustStore::new(TestKey::new().public).save(&path),
            ErrorCategory::User,
            &[&shown(&path), "cannot write"],
        );
    }

    #[tokio::test]
    async fn verification_runs_on_the_blocking_pool() {
        let project = TestKey::new();
        let f = files(PACKAGE, &project.sign(PACKAGE));
        let store = Arc::new(TrustStore::new(project.public));

        let (package, signature) = (f.package.clone(), f.signature.clone());
        tokio::task::spawn_blocking(move || {
            store.verify_package(Origin::BuiltIn, &package, &signature)
        })
        .await
        .unwrap()
        .unwrap();
    }
}
