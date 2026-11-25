//! Package signatures and the trust store (ARCHITECTURE.md §4.8, §7,
//! ADR-0006).
//!
//! A package is a file with a detached [minisign] signature. This module
//! only verifies. It does not sign and it handles no secret key.
//!
//! # Rules
//!
//! - A built-in extension must verify with the project key. No other key is
//!   tried. The first segment of its id is `rivet`. This segment is reserved
//!   for the project: `rivet` is not a publisher and gets no pinned key
//!   (ADR-0019).
//! - A package of a publisher must verify with the pinned key of that
//!   publisher. No other key is tried.
//! - A publisher without a pinned key is refused. The caller shows the key to
//!   the user and calls [`TrustStore::pin`] after the user confirms it.
//!   Nothing in this module pins a key on its own.
//! - The trusted comment of the signature is verified together with the
//!   package. It binds the signature to one extension id and one version. The
//!   whole trusted comment must be exactly
//!   `rivet-package id=<extension id> version=<version>`, for example made
//!   with `minisign -S -t "rivet-package id=acme.postgres version=1.0.0"`.
//! - [`TrustStore::verify_package`] refuses a signature for another id or
//!   another version than the caller expects. For a publisher it also
//!   refuses an id whose first segment is not the publisher name (ADR-0019).
//! - [`TrustStore::pin`] never replaces another pinned key. A key change
//!   needs a new review and [`TrustStore::replace_pin_after_review`].
//! - Legacy signatures (not prehashed, made with `minisign -l`) are refused.
//! - A package, a signature, a key file and the trust store file must each
//!   be a regular file. A symbolic link, a FIFO and a directory are refused.
//!   A package of more than [`PACKAGE_MAX_BYTES`] is refused.
//! - A public key is identified by its 32 Ed25519 key bytes. The key id in
//!   its text is not protected by a signature and is not compared.
//!
//! # The caller must do this
//!
//! - **Blocking I/O.** [`verify`], [`TrustStore::verify_package`],
//!   [`TrustStore::load`] and [`TrustStore::save`] read or write files and
//!   hash the whole package. From async code, call them in
//!   [`tokio::task::spawn_blocking`] or in a blocking job
//!   ([`JobScheduler::spawn_blocking`](crate::jobs::JobScheduler::spawn_blocking)),
//!   never directly on an async worker thread (§5.1).
//! - **Use the bytes that were verified.** The caller MUST copy the package
//!   to a private location first (a directory of the user that others cannot
//!   write), verify the copy, and read the package only from the file handle
//!   that [`Verified::into_file`] gives. The caller MUST NOT open the path
//!   again: another file can be at that path after the verification.
//! - **Compare with the manifest.** Give the id and the version of the
//!   manifest to [`TrustStore::verify_package`]. After plain [`verify`],
//!   compare [`Verified::id`] and [`Verified::version`] with the manifest.
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
//! let verified = store.verify_package(
//!     Origin::Publisher("acme"),
//!     &"acme.postgres".parse()?,
//!     &"1.0.0".parse().expect("a version"),
//!     Path::new("acme.postgres-1.0.0.rivetpkg"),
//!     Path::new("acme.postgres-1.0.0.rivetpkg.minisig"),
//! )?;
//! // Read the package from this handle only.
//! let package = verified.into_file();
//! # drop(package);
//! # Ok::<(), rivet_sdk::error::Error>(())
//! ```
//!
//! [minisign]: https://jedisct1.github.io/minisign/

use crate::settings::SCHEMA_VERSION_KEY;
use rivet_sdk::error::{Error, ErrorCategory, Result};
use rivet_sdk::manifest::{ExtensionId, Version};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, Write};
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

/// The largest trust store file that is read. One pinned key needs about 80
/// bytes, so this is room for more than 10 000 publishers.
const TRUST_FILE_MAX_BYTES: u64 = 1024 * 1024;

/// The largest package file that is verified: 256 MiB. The value is not
/// measured. It leaves room for native libraries of several targets.
pub const PACKAGE_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// The first id segment that is reserved for the project (ADR-0019). An
/// extension with this segment is a built-in extension.
const PROJECT_PUBLISHER: &str = "rivet";

/// The algorithm id of a minisign public key. A signature has another id
/// (`ED` for a prehashed signature).
const KEY_ALGORITHM: [u8; 2] = *b"Ed";

/// A minisign public key.
///
/// The text form is the base64 line of a `minisign.pub` file. `Display`
/// prints that line.
///
/// Two keys are equal when they hold the same 32 Ed25519 key bytes. The key
/// id in the text is not compared: a signature does not protect it, so the
/// same key can be written with any key id.
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
    /// The Ed25519 key. `minisign_verify` does not expose it.
    key_bytes: [u8; 32],
}

impl PublicKey {
    /// Reads a public key from a `minisign.pub` file.
    ///
    /// This is blocking I/O.
    ///
    /// # Errors
    ///
    /// Returns a `user` error that names `path` if the file cannot be read,
    /// is a symbolic link or not a regular file, or does not hold a minisign
    /// public key.
    pub fn load(path: &Path) -> Result<Self> {
        read_text_file(path, "minisign public key", TEXT_FILE_MAX_BYTES)?
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
        // 2 bytes algorithm id, 8 bytes key id, 32 bytes key.
        let bytes = decode_key(base64).ok_or_else(invalid)?;
        let (algorithm, rest) = bytes.split_at(KEY_ALGORITHM.len());
        if algorithm != KEY_ALGORITHM {
            return Err(invalid());
        }
        let key_bytes = rest[8..].try_into().map_err(|_| invalid())?;
        Ok(Self {
            base64: base64.to_owned(),
            key,
            key_bytes,
        })
    }
}

/// Decodes the 42 bytes of a public key from its 56 base64 characters
/// (standard alphabet, no padding). Returns `None` for any other text. It
/// is used for the algorithm id and for key equality only: `minisign_verify`
/// verifies with its own decoding of the same text.
// shortcut: own decoder for this one fixed size, no base64 crate is in the
// dependency tree; use a crate when a second base64 use appears.
fn decode_key(base64: &str) -> Option<[u8; 42]> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bytes = [0_u8; 42];
    if base64.len() != bytes.len() / 3 * 4 {
        return None;
    }
    for (chars, out) in base64.as_bytes().chunks(4).zip(bytes.chunks_mut(3)) {
        let mut bits = 0_u32;
        for char in chars {
            let value = ALPHABET.iter().position(|other| other == char)?;
            bits = bits << 6 | u32::try_from(value).ok()?;
        }
        out.copy_from_slice(&bits.to_be_bytes()[1..]);
    }
    Some(bytes)
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.base64)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.key_bytes == other.key_bytes
    }
}

impl Eq for PublicKey {}

/// A package whose signature verified.
///
/// It holds the extension id and the version from the trusted comment of
/// the signature, and the open file whose bytes were verified.
///
/// Limit: a process that can write to the package file can change the bytes
/// behind the handle after the verification. Keep the package in a private
/// location: see the [module documentation](self).
#[derive(Debug)]
pub struct Verified {
    id: ExtensionId,
    version: Version,
    file: File,
}

impl Verified {
    /// Returns the extension id that the signature is for.
    pub fn id(&self) -> &ExtensionId {
        &self.id
    }

    /// Returns the version that the signature is for.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// Returns the file that was verified, open for reading at position 0.
    /// Read the package from this handle. Do not open the path again.
    pub fn into_file(self) -> File {
        self.file
    }
}

/// Verifies the file `package` against the detached minisign signature file
/// `signature` and the public key `key`.
///
/// The package is read in pieces, so a large package does not need much
/// memory. This is blocking I/O: see the [module documentation](self).
///
/// This function does not know which extension the caller expects. Compare
/// [`Verified::id`] and [`Verified::version`] with the manifest, or use
/// [`TrustStore::verify_package`].
///
/// # Errors
///
/// - `user`: a file cannot be read, is a symbolic link or is not a regular
///   file, or `package` is larger than [`PACKAGE_MAX_BYTES`], or `signature`
///   is not a minisign signature, or it is a legacy signature. The message
///   names the file.
/// - `policy`: the signature does not verify. The package, the signature or
///   the trusted comment was changed, or the signature was made with another
///   key. The message names both files.
/// - `policy`: the signature verifies, but its trusted comment is not
///   `rivet-package id=<extension id> version=<version>`.
pub fn verify(package: &Path, signature: &Path, key: &PublicKey) -> Result<Verified> {
    let (trusted_comment, file) = verify_signature(package, signature, key)?;
    bound_package(&trusted_comment, signature, file)
}

/// Verifies the signature. Returns the verified trusted comment and the
/// verified file at position 0.
fn verify_signature(package: &Path, signature: &Path, key: &PublicKey) -> Result<(String, File)> {
    let text = read_text_file(signature, "minisign signature", TEXT_FILE_MAX_BYTES)?;
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
    let mut file = open_regular(package, "package", PACKAGE_MAX_BYTES)?;
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(len) => {
                // The file can grow after the size check of the open.
                total += len as u64;
                if total > PACKAGE_MAX_BYTES {
                    return Err(too_large(package, "package", PACKAGE_MAX_BYTES));
                }
                verifier.update(&buffer[..len]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(unreadable(error)),
        }
    }
    verifier.finalize().map_err(|_| rejected())?;
    file.rewind().map_err(unreadable)?;
    Ok((parsed.trusted_comment().to_owned(), file))
}

/// Reads the extension id and the version from a verified trusted comment.
fn bound_package(trusted_comment: &str, signature: &Path, file: File) -> Result<Verified> {
    trusted_comment
        .strip_prefix("rivet-package id=")
        .and_then(|rest| rest.split_once(" version="))
        .and_then(|(id, version)| Some((id.parse().ok()?, version.parse().ok()?)))
        // Only the one canonical text is accepted.
        .filter(|(id, version)| trusted_comment == binding(id, version))
        .map(|(id, version)| Verified { id, version, file })
        .ok_or_else(|| {
            Error::policy(format!(
                "{}: the trusted comment of the signature must be \
                 `rivet-package id=<extension id> version=<version>`",
                signature.display()
            ))
        })
}

/// The trusted comment that binds a signature to `id` and `version`.
fn binding(id: &ExtensionId, version: &Version) -> String {
    format!("rivet-package id={id} version={version}")
}

/// Who a package comes from. It selects the one key that can verify it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin<'a> {
    /// A built-in extension. Only the project key verifies it. The first
    /// segment of its id is `rivet`.
    BuiltIn,
    /// An extension of the named third-party publisher. Only the pinned key
    /// of this publisher verifies it. The name `rivet` is refused.
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

    /// Pins `key` as the only key of `publisher`, on the first install of
    /// that publisher. It never replaces another pinned key. To pin the same
    /// key again is permitted and changes nothing.
    ///
    /// This call is the confirmation of the caller. Call it only after the
    /// user reviewed the key. Call [`save`](Self::save) to keep the pin.
    ///
    /// # Errors
    ///
    /// - `user`: `publisher` is not a valid name. A publisher name is one
    ///   segment of an [`ExtensionId`]: it has no `.`.
    /// - `policy`: another key is pinned for `publisher`. A key change needs
    ///   a new review and then
    ///   [`replace_pin_after_review`](Self::replace_pin_after_review).
    /// - `policy`: `key` is the project key. Only built-in extensions use it.
    /// - `policy`: `publisher` is `rivet`. This name is reserved for the
    ///   project.
    pub fn pin(&mut self, publisher: &str, key: PublicKey) -> Result<()> {
        self.check_pin(publisher, &key)?;
        match self.pins.get(publisher) {
            Some(pinned) if *pinned != key => {
                return Err(Error::policy(format!(
                    "publisher `{publisher}` has another pinned key. A key change needs a new \
                     review before the new key replaces the pin"
                )));
            }
            // The same key: the pin stays as it is, also its key id.
            Some(_) => {}
            None => {
                self.pins.insert(publisher.to_owned(), key);
            }
        }
        Ok(())
    }

    /// Replaces the pinned key of `publisher` with `key`.
    ///
    /// Call it only after the user reviewed the key change of the publisher
    /// and confirmed the new key. Call [`save`](Self::save) to keep the pin.
    ///
    /// # Errors
    ///
    /// - `user`: `publisher` is not a valid name.
    /// - `policy`: `publisher` has no pinned key. Use [`pin`](Self::pin) for
    ///   a first install.
    /// - `policy`: `key` is the project key, or `publisher` is `rivet`.
    pub fn replace_pin_after_review(&mut self, publisher: &str, key: PublicKey) -> Result<()> {
        self.check_pin(publisher, &key)?;
        match self.pins.get_mut(publisher) {
            Some(pinned) => *pinned = key,
            None => {
                return Err(Error::policy(format!(
                    "publisher `{publisher}` has no pinned key to replace"
                )));
            }
        }
        Ok(())
    }

    /// The checks that each new pin must pass.
    fn check_pin(&self, publisher: &str, key: &PublicKey) -> Result<()> {
        // The publisher is the first segment of an extension id (ADR-0019),
        // so the name has the character rules of one id segment.
        publisher
            .parse::<ExtensionId>()
            .map_err(|error| Error::user(format!("invalid publisher name: {}", error.message())))?;
        if publisher.contains('.') {
            return Err(Error::user(format!(
                "invalid publisher name `{publisher}`: a publisher name is one segment of an \
                 extension id, without `.`"
            )));
        }
        if publisher == PROJECT_PUBLISHER {
            return Err(reserved_publisher());
        }
        if *key == self.project_key {
            return Err(Error::policy(format!(
                "publisher `{publisher}`: the project key cannot be the key of a publisher"
            )));
        }
        Ok(())
    }

    /// Verifies `package` against the signature file `signature` with the one
    /// key that `origin` permits, and checks that the signature is for
    /// `expected_id` and `expected_version` (the id and the version of the
    /// manifest). See the [module documentation](self) for the rules. This is
    /// blocking I/O.
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
    /// - `policy`: the first segment of `expected_id` is not the publisher
    ///   name, or the publisher name is `rivet`.
    /// - `policy`: the origin is built-in and the first segment of
    ///   `expected_id` is not `rivet`.
    /// - `policy`: the signature is for another extension id or another
    ///   version, or its trusted comment has another format.
    /// - `user`: see [`verify`].
    pub fn verify_package(
        &self,
        origin: Origin<'_>,
        expected_id: &ExtensionId,
        expected_version: &Version,
        package: &Path,
        signature: &Path,
    ) -> Result<Verified> {
        self.check(origin, expected_id, expected_version, package, signature)
            .inspect_err(|error| tracing::warn!(%error, "package signature rejected"))
    }

    fn check(
        &self,
        origin: Origin<'_>,
        expected_id: &ExtensionId,
        expected_version: &Version,
        package: &Path,
        signature: &Path,
    ) -> Result<Verified> {
        let first_segment = expected_id.as_str().split('.').next();
        let (key, rejected) = match origin {
            Origin::BuiltIn => {
                if first_segment != Some(PROJECT_PUBLISHER) {
                    return Err(Error::policy(format!(
                        "{}: extension `{expected_id}` is not a built-in extension: the first \
                         segment of the id must be `{PROJECT_PUBLISHER}`",
                        package.display()
                    )));
                }
                (
                    &self.project_key,
                    format!(
                        "{}: a built-in extension must be signed with the project key, \
                         and the signature does not verify with it",
                        package.display()
                    ),
                )
            }
            Origin::Publisher(PROJECT_PUBLISHER) => return Err(reserved_publisher()),
            Origin::Publisher(publisher) => {
                if first_segment != Some(publisher) {
                    return Err(Error::policy(format!(
                        "{}: extension `{expected_id}` is not an extension of publisher \
                         `{publisher}`: the first segment of the id must be the publisher name",
                        package.display()
                    )));
                }
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
        let (trusted_comment, file) =
            verify_signature(package, signature, key).map_err(|error| match error.category() {
                ErrorCategory::Policy => Error::policy(rejected).with_source(error),
                _ => error,
            })?;
        let verified = bound_package(&trusted_comment, signature, file)?;
        if verified.id != *expected_id || verified.version != *expected_version {
            return Err(Error::policy(format!(
                "{}: the signature is for `{}`, not for `{}`",
                package.display(),
                binding(&verified.id, &verified.version),
                binding(expected_id, expected_version)
            )));
        }
        Ok(verified)
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
    /// is a symbolic link or not a regular file, is larger than 1 MiB, is
    /// not valid TOML, has another
    /// [`SCHEMA_VERSION`], has an unknown key, or holds an invalid publisher
    /// name or public key.
    pub fn load(project_key: PublicKey, path: &Path) -> Result<Self> {
        let mut store = Self::new(project_key);
        if matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == io::ErrorKind::NotFound)
        {
            return Ok(store);
        }
        let text = read_text_file(path, "trust store", TRUST_FILE_MAX_BYTES)?;
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
    /// the old file as it was. On Unix the file can be read and written by
    /// its owner only (mode 0600). This is blocking I/O.
    ///
    /// Two processes that load, change and save at the same time lose the
    /// pin of one of them. That publisher is then refused until it is pinned
    /// again.
    ///
    /// # Errors
    ///
    /// Returns a `user` error that names `path` if `path` is a symbolic link
    /// or the file cannot be written. A symbolic link is refused because the
    /// write would replace the link and leave its target unchanged.
    pub fn save(&self, path: &Path) -> Result<()> {
        // shortcut: no lock file, two concurrent writers lose one pin (fails
        // closed); add a lock when a second process can pin keys.
        if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_symlink()) {
            return Err(Error::user(format!(
                "{}: the trust store file must not be a symbolic link",
                path.display()
            )));
        }
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

/// A `policy` error for the publisher name that the project keeps.
fn reserved_publisher() -> Error {
    Error::policy(format!(
        "publisher `{PROJECT_PUBLISHER}`: the name is reserved for the project. Its extensions \
         are built-in and verify with the project key only"
    ))
}

/// Reads a text file of at most `max_bytes`: a key, a signature or the trust
/// store. `what` names the kind of file in the error.
fn read_text_file(path: &Path, what: &str, max_bytes: u64) -> Result<String> {
    let mut text = String::new();
    open_regular(path, what, max_bytes)?
        .take(max_bytes + 1)
        .read_to_string(&mut text)
        .map_err(|error| io_error(path, &format!("cannot read the {what} file"), error))?;
    // The file can grow after the size check of the open.
    if text.len() as u64 > max_bytes {
        return Err(too_large(path, what, max_bytes));
    }
    Ok(text)
}

/// Opens `path` for reading. Refuses a symbolic link, anything that is not
/// a regular file (a directory, a FIFO, a device) and a file of more than
/// `max_bytes`. `what` names the kind of file in the error.
fn open_regular(path: &Path, what: &str, max_bytes: u64) -> Result<File> {
    let unreadable = |error| io_error(path, &format!("cannot read the {what} file"), error);
    let check = |meta: Metadata| {
        let refused =
            |problem: &str| Error::user(format!("{}: the {what} file {problem}", path.display()));
        if meta.is_symlink() {
            Err(refused("must not be a symbolic link"))
        } else if !meta.is_file() {
            Err(refused("is not a regular file"))
        } else if meta.len() > max_bytes {
            Err(too_large(path, what, max_bytes))
        } else {
            Ok(())
        }
    };
    // Checked before the open, because the open follows a symbolic link and
    // blocks on a FIFO without a writer.
    check(std::fs::symlink_metadata(path).map_err(unreadable)?)?;
    // shortcut: another file can be put at `path` between the check and the
    // open (std has no portable O_NOFOLLOW or O_NONBLOCK). The open then
    // follows a link or blocks on a FIFO; the check of the handle still
    // refuses what is not a regular file. Only a process that can write to
    // the directory can do this; use the flags if that must be closed.
    let file = File::open(path).map_err(unreadable)?;
    check(file.metadata().map_err(unreadable)?)?;
    Ok(file)
}

/// A `user` error for a file that is larger than its limit.
fn too_large(path: &Path, what: &str, max_bytes: u64) -> Error {
    Error::user(format!(
        "{}: too large for a {what} file: the limit is {max_bytes} bytes",
        path.display()
    ))
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
            self.sign_with(data, TRUSTED_COMMENT)
        }

        fn sign_with(&self, data: &[u8], trusted_comment: &str) -> String {
            minisign::sign(
                Some(&self.pair.pk),
                &self.pair.sk,
                data,
                Some(trusted_comment),
                None,
            )
            .unwrap()
            .into_string()
        }
    }

    const PACKAGE: &[u8] = b"rivet test package\n";
    const TRUSTED_COMMENT: &str = "rivet-package id=acme.postgres version=1.0.0";

    fn id() -> ExtensionId {
        "acme.postgres".parse().unwrap()
    }

    fn version() -> Version {
        Version::new(1, 0, 0)
    }

    const BUILT_IN_COMMENT: &str = "rivet-package id=rivet.postgres version=1.0.0";

    fn built_in_id() -> ExtensionId {
        "rivet.postgres".parse().unwrap()
    }

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

    /// The same key bytes as `key` with another key id. A signature does not
    /// protect the key id. Base64 characters 3 to 12 hold key id bits only.
    fn other_key_id(key: &PublicKey) -> PublicKey {
        let text = change_line(&key.to_string(), 0, 5);
        assert_ne!(text.trim(), key.to_string());
        text.trim().parse().unwrap()
    }

    /// Makes a FIFO. To open it for reading blocks until a writer opens it.
    #[cfg(unix)]
    fn fifo(path: &Path) {
        let status = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success());
    }

    // --- verify -----------------------------------------------------------

    #[test]
    fn valid_signature_verifies() {
        let key = TestKey::new();
        let f = files(PACKAGE, &key.sign(PACKAGE));
        let verified = verify(&f.package, &f.signature, &key.public).unwrap();
        assert_eq!((verified.id(), verified.version()), (&id(), &version()));

        // The handle gives the verified bytes, also after the path changed.
        std::fs::remove_file(&f.package).unwrap();
        let mut bytes = Vec::new();
        verified.into_file().read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, PACKAGE);
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
            // R-29: the algorithm id `ED` is for a signature, not for a key.
            base64.replacen("RW", "RU", 1),
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
            store.verify_package(
                Origin::Publisher("acme"),
                &id(),
                &version(),
                &f.package,
                &f.signature,
            ),
            ErrorCategory::Policy,
            &["publisher `acme`", "no pinned key", &shown(&f.package)],
        );
        assert_eq!(store.pinned("acme"), None);

        // The explicit confirmation of the caller.
        store.pin("acme", acme.public.clone()).unwrap();
        store
            .verify_package(
                Origin::Publisher("acme"),
                &id(),
                &version(),
                &f.package,
                &f.signature,
            )
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
            store.verify_package(
                Origin::Publisher("acme"),
                &id(),
                &version(),
                &f.package,
                &f.signature,
            ),
            ErrorCategory::Policy,
            &["publisher `acme`", "new review", &shown(&f.package)],
        );
        // The rejected key was not pinned.
        assert_eq!(store.pinned("acme"), Some(&acme.public));

        // After the review, the caller replaces the pin with the new key.
        store
            .replace_pin_after_review("acme", new_key.public.clone())
            .unwrap();
        store
            .verify_package(
                Origin::Publisher("acme"),
                &id(),
                &version(),
                &f.package,
                &f.signature,
            )
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
                store.verify_package(
                    Origin::Publisher("acme"),
                    &id(),
                    &version(),
                    &f.package,
                    &f.signature,
                ),
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

        let f = files(PACKAGE, &project.sign_with(PACKAGE, BUILT_IN_COMMENT));
        let built_in = built_in_id();
        store
            .verify_package(
                Origin::BuiltIn,
                &built_in,
                &version(),
                &f.package,
                &f.signature,
            )
            .unwrap();

        // A pinned publisher key does not make a package a built-in.
        let f = files(PACKAGE, &acme.sign(PACKAGE));
        store
            .verify_package(
                Origin::Publisher("acme"),
                &id(),
                &version(),
                &f.package,
                &f.signature,
            )
            .unwrap();
        let f = files(PACKAGE, &acme.sign_with(PACKAGE, BUILT_IN_COMMENT));
        assert_error(
            store.verify_package(
                Origin::BuiltIn,
                &built_in,
                &version(),
                &f.package,
                &f.signature,
            ),
            ErrorCategory::Policy,
            &["built-in", "project key", &shown(&f.package)],
        );
    }

    #[test]
    fn first_id_segment_rivet_is_reserved_for_built_in_extensions() {
        // R-45, ADR-0019.
        let project = TestKey::new();
        let other = TestKey::new();
        let mut store = TrustStore::new(project.public.clone());
        let verify = |store: &TrustStore, origin, id: &str, signer: &TestKey| {
            let comment = format!("rivet-package id={id} version=1.0.0");
            let f = files(PACKAGE, &signer.sign_with(PACKAGE, &comment));
            store.verify_package(
                origin,
                &id.parse().unwrap(),
                &version(),
                &f.package,
                &f.signature,
            )
        };

        // Built-in: the first segment is exactly `rivet`.
        verify(&store, Origin::BuiltIn, "rivet.postgres", &project).unwrap();
        verify(&store, Origin::BuiltIn, "rivet", &project).unwrap();
        for id in ["acme.postgres", "rivetx.postgres", "rivet-tools.postgres"] {
            assert_error(
                verify(&store, Origin::BuiltIn, id, &project),
                ErrorCategory::Policy,
                &["built-in", "first segment", "`rivet`"],
            );
        }

        // No key can be pinned for `rivet`.
        assert_error(
            store.pin("rivet", other.public.clone()),
            ErrorCategory::Policy,
            &["publisher `rivet`", "reserved"],
        );
        assert_error(
            store.replace_pin_after_review("rivet", other.public.clone()),
            ErrorCategory::Policy,
            &["publisher `rivet`", "reserved"],
        );
        assert_eq!(store.pinned("rivet"), None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        let text = format!(
            "schema_version = 1\n[publishers]\nrivet = \"{}\"\n",
            other.public
        );
        std::fs::write(&path, text).unwrap();
        assert_error(
            TrustStore::load(project.public.clone(), &path),
            ErrorCategory::User,
            &[&shown(&path), "publisher `rivet`", "reserved"],
        );

        // `rivet` is not a third-party publisher, with or without a pin.
        for signer in [&project, &other] {
            assert_error(
                verify(&store, Origin::Publisher("rivet"), "rivet.postgres", signer),
                ErrorCategory::Policy,
                &["publisher `rivet`", "reserved"],
            );
        }

        // Only the exact name is reserved.
        store.pin("rivet-tools", other.public.clone()).unwrap();
        store.pin("rivetx", other.public.clone()).unwrap();
        verify(
            &store,
            Origin::Publisher("rivet-tools"),
            "rivet-tools.postgres",
            &other,
        )
        .unwrap();
    }

    #[test]
    fn malformed_signature_stays_a_user_error_in_the_trust_store() {
        let acme = TestKey::new();
        let mut store = TrustStore::new(TestKey::new().public);
        store.pin("acme", acme.public.clone()).unwrap();
        let f = files(PACKAGE, "not a signature\n");
        assert_error(
            store.verify_package(
                Origin::Publisher("acme"),
                &id(),
                &version(),
                &f.package,
                &f.signature,
            ),
            ErrorCategory::User,
            &[&shown(&f.signature)],
        );
    }

    #[test]
    fn invalid_publisher_name_is_refused() {
        let key = TestKey::new().public;
        let mut store = TrustStore::new(TestKey::new().public);
        // R-45: a publisher is one id segment, so a name with `.` can never
        // verify.
        for name in [
            "",
            "Acme",
            "acme corp",
            "acme\n",
            "-acme",
            "a..b",
            "acme-corp.eu",
        ] {
            assert_error(
                store.pin(name, key.clone()),
                ErrorCategory::User,
                &["invalid publisher name"],
            );
            assert_eq!(store.pinned(name), None);
        }
        store.pin("acme-corp", key.clone()).unwrap();
        assert_error(
            store.replace_pin_after_review("acme-corp.eu", key),
            ErrorCategory::User,
            &["invalid publisher name"],
        );
    }

    #[test]
    fn trust_store_round_trips_through_a_file() {
        let project = TestKey::new();
        let mut store = TrustStore::new(project.public.clone());
        store.pin("acme", TestKey::new().public).unwrap();
        store.pin("zeta-labs", TestKey::new().public).unwrap();

        let dir = tempfile::tempdir().unwrap();
        // The directory does not exist yet.
        let path = dir.path().join("rivet").join("trust.toml");
        store.save(&path).unwrap();
        assert_eq!(
            TrustStore::load(project.public.clone(), &path).unwrap(),
            store
        );

        // A second save replaces the file and leaves no temporary file.
        store
            .replace_pin_after_review("acme", TestKey::new().public)
            .unwrap();
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
                "`Acme`",
            ),
            // R-45: the entry is not skipped.
            (
                &format!("schema_version = 1\n[publishers]\n\"acme.eu\" = \"{key}\"\n"),
                "invalid publisher name `acme.eu`",
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

    // --- review findings R-29, R-31 ---------------------------------------

    #[test]
    fn pin_refuses_a_different_key_and_accepts_the_same_key_again() {
        let first = TestKey::new().public;
        let mut store = TrustStore::new(TestKey::new().public);
        store.pin("acme", first.clone()).unwrap();
        store.pin("acme", first.clone()).unwrap();
        // R-29: the same key bytes with another key id are the same key. The
        // pin stays as it was.
        store.pin("acme", other_key_id(&first)).unwrap();
        assert_eq!(store.pinned("acme").unwrap().to_string(), first.to_string());
        assert_error(
            store.pin("acme", TestKey::new().public),
            ErrorCategory::Policy,
            &["publisher `acme`", "new review"],
        );
        assert_eq!(store.pinned("acme"), Some(&first));

        // The explicit replacement after a new review.
        let second = TestKey::new().public;
        store
            .replace_pin_after_review("acme", second.clone())
            .unwrap();
        assert_eq!(store.pinned("acme"), Some(&second));
        assert_error(
            store.replace_pin_after_review("other", second),
            ErrorCategory::Policy,
            &["publisher `other`", "no pinned key"],
        );
        assert_error(
            store.replace_pin_after_review("acme", store.project_key().clone()),
            ErrorCategory::Policy,
            &["project key"],
        );
    }

    #[test]
    fn project_key_cannot_be_pinned_for_a_publisher() {
        let project = TestKey::new().public;
        let mut store = TrustStore::new(project.clone());
        assert_error(
            store.pin("acme", project.clone()),
            ErrorCategory::Policy,
            &["publisher `acme`", "project key"],
        );
        assert_eq!(store.pinned("acme"), None);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        let text = format!("schema_version = 1\n[publishers]\nacme = \"{project}\"\n");
        std::fs::write(&path, text).unwrap();
        assert_error(
            TrustStore::load(project.clone(), &path),
            ErrorCategory::User,
            &[&shown(&path), "publisher `acme`", "project key"],
        );

        // R-29: a signature does not protect the algorithm id and the key id
        // of a key. The project key with another key id is the project key.
        let variant = other_key_id(&project);
        assert_eq!(variant, project);
        assert_error(
            store.pin("acme", variant.clone()),
            ErrorCategory::Policy,
            &["publisher `acme`", "project key"],
        );
        store.pin("acme", TestKey::new().public).unwrap();
        assert_error(
            store.replace_pin_after_review("acme", variant),
            ErrorCategory::Policy,
            &["publisher `acme`", "project key"],
        );
        assert_ne!(store.pinned("acme"), Some(&project));

        // The project key with the other algorithm id (`ED`, base64 `RU`) is
        // not a key that this module verifies with.
        let text = project.to_string();
        assert!(text.starts_with("RW"), "{text}");
        assert_error(
            text.replacen("RW", "RU", 1).parse::<PublicKey>(),
            ErrorCategory::User,
            &["not a valid minisign public key"],
        );
    }

    #[test]
    fn load_refuses_the_project_key_in_another_form() {
        let project = TestKey::new().public;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        for (key, part) in [
            (other_key_id(&project).to_string(), "project key"),
            (
                project.to_string().replacen("RW", "RU", 1),
                "not a valid minisign public key",
            ),
        ] {
            let text = format!("schema_version = 1\n[publishers]\nacme = \"{key}\"\n");
            std::fs::write(&path, text).unwrap();
            assert_error(
                TrustStore::load(project.clone(), &path),
                ErrorCategory::User,
                &[&shown(&path), "publisher `acme`", part],
            );
        }
    }

    #[test]
    fn key_decoder_gives_the_key_bytes_and_accepts_one_text_form_only() {
        let key = TestKey::new();
        let base64 = key.pair.pk.to_base64();
        let bytes = decode_key(&base64).unwrap();
        assert_eq!(bytes.to_vec(), key.pair.pk.to_bytes());
        assert_eq!(key.public.key_bytes, bytes[10..]);

        // The decoder and `minisign-verify` accept the same key text.
        assert!(minisign_verify::PublicKey::from_base64(&base64).is_ok());
        assert!(decode_key(VECTOR_KEY).is_some());
        assert!(minisign_verify::PublicKey::from_base64(VECTOR_KEY).is_ok());

        // 56 characters of the standard alphabet, and nothing else.
        let rejected = [
            String::new(),
            base64[..52].to_owned(),
            base64[..55].to_owned(),
            format!("{base64}A"),
            format!("{base64}AAAA"),
            format!("{base64}="),
            format!("{}=", &base64[..55]),
            format!("{} ", &base64[..55]),
            format!("{} {}", &base64[..20], &base64[21..]),
            format!("{}\n{}", &base64[..20], &base64[21..]),
            // The URL alphabet.
            format!("{}-{}", &base64[..20], &base64[21..]),
            format!("{}_{}", &base64[..20], &base64[21..]),
            format!("{}é{}", &base64[..20], &base64[22..]),
        ];
        for text in rejected {
            assert_eq!(decode_key(&text), None, "{text:?}");
            assert_error(
                text.parse::<PublicKey>(),
                ErrorCategory::User,
                &["not a valid minisign public key"],
            );
        }
    }

    // --- review finding R-45 ----------------------------------------------

    #[cfg(unix)]
    #[test]
    fn file_that_is_not_a_regular_file_is_refused() {
        let key = TestKey::new();
        let f = files(PACKAGE, &key.sign(PACKAGE));
        let dir = f.package.parent().unwrap();
        let (pipe, link) = (dir.join("pipe"), dir.join("link"));
        fifo(&pipe);

        // A FIFO must not block the verification. The verification runs on
        // another thread, so a regression fails this test and does not hang.
        let verify_on_thread = |package: &Path, signature: &Path| {
            let (package, signature) = (package.to_owned(), signature.to_owned());
            let public = key.public.clone();
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || sender.send(verify(&package, &signature, &public)));
            receiver
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("the verification must not block on a FIFO")
        };
        assert_error(
            verify_on_thread(&pipe, &f.signature),
            ErrorCategory::User,
            &[&shown(&pipe), "package file", "not a regular file"],
        );
        assert_error(
            verify_on_thread(&f.package, &pipe),
            ErrorCategory::User,
            &[&shown(&pipe), "signature file", "not a regular file"],
        );
        assert_error(
            verify(dir, &f.signature, &key.public),
            ErrorCategory::User,
            &[&shown(dir), "package file", "not a regular file"],
        );

        // A symbolic link is not followed.
        std::os::unix::fs::symlink(&f.package, &link).unwrap();
        assert_error(
            verify(&link, &f.signature, &key.public),
            ErrorCategory::User,
            &[&shown(&link), "package file", "symbolic link"],
        );
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&f.signature, &link).unwrap();
        assert_error(
            verify(&f.package, &link, &key.public),
            ErrorCategory::User,
            &[&shown(&link), "signature file", "symbolic link"],
        );
        assert_error(
            PublicKey::load(&link),
            ErrorCategory::User,
            &[&shown(&link), "public key file", "symbolic link"],
        );
    }

    #[test]
    fn oversized_package_is_refused() {
        let key = TestKey::new();
        let f = files(PACKAGE, &key.sign(PACKAGE));
        // A sparse file: no data is written.
        let file = File::options().write(true).open(&f.package).unwrap();
        file.set_len(PACKAGE_MAX_BYTES + 1).unwrap();
        drop(file);
        assert_error(
            verify(&f.package, &f.signature, &key.public),
            ErrorCategory::User,
            &[
                &shown(&f.package),
                "too large",
                "package file",
                "268435456 bytes",
            ],
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_a_symbolic_link() {
        let key = TestKey::new().public;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere.toml");
        let path = dir.path().join("trust.toml");
        let mut store = TrustStore::new(key.clone());
        store.pin("acme", TestKey::new().public).unwrap();
        store.save(&target).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        assert_error(
            TrustStore::load(key.clone(), &path),
            ErrorCategory::User,
            &[&shown(&path), "trust store file", "symbolic link"],
        );
        // A link without a target is refused too. It is not a missing file.
        std::fs::remove_file(&target).unwrap();
        assert_error(
            TrustStore::load(key, &path),
            ErrorCategory::User,
            &[&shown(&path), "symbolic link"],
        );
    }

    #[test]
    fn key_with_the_same_key_id_and_other_key_bytes_is_rejected() {
        let key = TestKey::new();
        let base64 = key.pair.pk.to_base64();
        // The key is 2 bytes algorithm id, 8 bytes key id, 32 bytes key.
        // Base64 characters from index 14 hold key bytes only.
        let same_id: PublicKey = change_line(&base64, 0, 20).trim().parse().unwrap();
        assert_eq!(same_id.to_string()[..14], base64[..14]);
        assert_ne!(same_id, key.public);

        let f = files(PACKAGE, &key.sign(PACKAGE));
        assert_error(
            verify(&f.package, &f.signature, &same_id),
            ErrorCategory::Policy,
            &["does not verify"],
        );
    }

    // Fixed vectors of the reference minisign tool, copied from the tests
    // `verify_prehashed` and `verify` in `src/lib.rs` of the crate
    // `minisign-verify` 0.3.0. Both sign the 4 bytes `test`.
    const VECTOR_KEY: &str = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
    const VECTOR_PREHASHED: &str = "untrusted comment: signature from minisign secret key\n\
        RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/\
        z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\n\
        trusted comment: timestamp:1556193335\tfile:test\n\
        y/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==\n";
    const VECTOR_LEGACY: &str = "untrusted comment: signature from minisign secret key\n\
        RWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=\n\
        trusted comment: timestamp:1555779966\tfile:test\n\
        QtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA==\n";

    #[test]
    fn signature_with_a_trusted_comment_in_another_format_is_rejected() {
        // R-30: the vector has the trusted comment `timestamp:…\tfile:test`.
        let f = files(b"test", VECTOR_PREHASHED);
        assert_error(
            verify(&f.package, &f.signature, &VECTOR_KEY.parse().unwrap()),
            ErrorCategory::Policy,
            &[&shown(&f.signature), "trusted comment"],
        );
    }

    #[test]
    fn real_prehashed_signature_of_the_reference_tool_verifies() {
        let f = files(b"test", VECTOR_PREHASHED);
        let key = VECTOR_KEY.parse().unwrap();
        let (trusted_comment, _) = verify_signature(&f.package, &f.signature, &key).unwrap();
        assert_eq!(trusted_comment, "timestamp:1556193335\tfile:test");

        std::fs::write(&f.package, b"Test").unwrap();
        assert_error(
            verify_signature(&f.package, &f.signature, &key),
            ErrorCategory::Policy,
            &["does not verify"],
        );
    }

    #[test]
    fn trusted_comment_must_be_the_one_canonical_text() {
        let key = TestKey::new();
        for comment in [
            "",
            "file:acme.postgres-1.0.0.rivetpkg",
            "rivet-package id=acme.postgres",
            "rivet-package version=1.0.0 id=acme.postgres",
            "rivet-package id=acme.postgres  version=1.0.0",
            "rivet-package id=acme.postgres version=1.0.0 ",
            " rivet-package id=acme.postgres version=1.0.0",
            "rivet-package id=Acme version=1.0.0",
            "rivet-package id=acme.postgres version=1.0",
            "rivet-package id=acme.postgres version=1.0.0 version=2.0.0",
            "timestamp:1\trivet-package id=acme.postgres version=1.0.0",
        ] {
            let f = files(PACKAGE, &key.sign_with(PACKAGE, comment));
            assert_error(
                verify(&f.package, &f.signature, &key.public),
                ErrorCategory::Policy,
                &[&shown(&f.signature), "trusted comment"],
            );
        }
    }

    #[test]
    fn signature_for_another_id_or_version_is_rejected() {
        let acme = TestKey::new();
        let mut store = TrustStore::new(TestKey::new().public);
        store.pin("acme", acme.public.clone()).unwrap();
        // A pinned key of `other` does not make `acme.postgres` its extension.
        store.pin("other", acme.public.clone()).unwrap();
        let f = files(PACKAGE, &acme.sign(PACKAGE));
        let verify = |origin, id: &str, version: &str| {
            store.verify_package(
                origin,
                &id.parse().unwrap(),
                &version.parse().unwrap(),
                &f.package,
                &f.signature,
            )
        };

        let verified = verify(Origin::Publisher("acme"), "acme.postgres", "1.0.0").unwrap();
        assert_eq!((verified.id(), verified.version()), (&id(), &version()));

        // Rollback: the signature of 1.0.0 does not install as 2.0.0.
        assert_error(
            verify(Origin::Publisher("acme"), "acme.postgres", "2.0.0"),
            ErrorCategory::Policy,
            &["version=1.0.0", "version=2.0.0", &shown(&f.package)],
        );
        // Substitution: the signature does not install under another id.
        assert_error(
            verify(Origin::Publisher("acme"), "acme.mysql", "1.0.0"),
            ErrorCategory::Policy,
            &["id=acme.postgres", "id=acme.mysql"],
        );
        // The publisher is the first segment of the id (ADR-0019).
        assert_error(
            verify(Origin::Publisher("other"), "acme.postgres", "1.0.0"),
            ErrorCategory::Policy,
            &["publisher `other`", "first segment"],
        );
        assert_error(
            verify(Origin::Publisher("acme"), "acmex.postgres", "1.0.0"),
            ErrorCategory::Policy,
            &["first segment"],
        );
    }

    #[test]
    fn real_legacy_signature_of_the_reference_tool_is_a_user_error() {
        let f = files(b"test", VECTOR_LEGACY);
        assert_error(
            verify(&f.package, &f.signature, &VECTOR_KEY.parse().unwrap()),
            ErrorCategory::User,
            &[&shown(&f.signature), "legacy"],
        );
    }

    #[cfg(unix)]
    #[test]
    fn saved_trust_store_file_is_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        TrustStore::new(TestKey::new().public).save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn save_refuses_a_symbolic_link() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere.toml");
        let path = dir.path().join("trust.toml");
        std::fs::write(&target, "untouched").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        assert_error(
            TrustStore::new(TestKey::new().public).save(&path),
            ErrorCategory::User,
            &[&shown(&path), "symbolic link"],
        );
        assert!(std::fs::symlink_metadata(&path).unwrap().is_symlink());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
    }

    #[test]
    fn oversized_trust_store_file_is_refused() {
        let key = TestKey::new().public;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        let text = format!("schema_version = 1\n#{}\n", "x".repeat(1024 * 1024));
        std::fs::write(&path, text).unwrap();
        assert_error(
            TrustStore::load(key, &path),
            ErrorCategory::User,
            &[&shown(&path), "too large"],
        );
    }

    #[tokio::test]
    async fn verification_runs_on_the_blocking_pool() {
        let project = TestKey::new();
        let f = files(PACKAGE, &project.sign_with(PACKAGE, BUILT_IN_COMMENT));
        let store = Arc::new(TrustStore::new(project.public));

        let (package, signature) = (f.package.clone(), f.signature.clone());
        tokio::task::spawn_blocking(move || {
            let id = built_in_id();
            store.verify_package(Origin::BuiltIn, &id, &version(), &package, &signature)
        })
        .await
        .unwrap()
        .unwrap();
    }
}
