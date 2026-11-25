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
//!   On Unix, a trust store file that the group or other users can write is
//!   refused. Limits: the owner of the file and the mode of its directory
//!   are not checked, and Windows has no such check.
//!   A package of more than [`PACKAGE_MAX_BYTES`] is refused.
//! - A public key is identified by its 32 Ed25519 key bytes. The key id in
//!   its text is not protected by a signature and is not compared. But a
//!   signature verifies only with a key text that has the key id of the
//!   signature. An error names a key id that differs, and
//!   [`TrustStore::pin`] refuses the pinned key bytes with another key id.
//! - A public key that is a small-order point, or that is not in canonical
//!   form, is refused when it is parsed. This holds for the project key, a
//!   pinned key, a key file and each entry of the trust store file.
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
use rivet_sdk::error::{Error, Result};
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

/// A longer key of the trust store file is cut to this length in an error.
/// A valid publisher name is shorter.
const MAX_SHOWN_KEY_BYTES: usize = 128;

/// Returns a key of the trust store file for an error message: cut to
/// [`MAX_SHOWN_KEY_BYTES`], and with its control characters escaped. The
/// file can come from another program, so a key has no safe form.
fn shown_key(key: &str) -> String {
    crate::logging::shown(key, MAX_SHOWN_KEY_BYTES)
}

/// The largest trust store file that is read. One pinned key needs about 80
/// bytes, so this is room for more than 10 000 publishers.
const TRUST_FILE_MAX_BYTES: u64 = 1024 * 1024;

/// The largest package file that is verified: 256 MiB. The value is not
/// measured. It leaves room for native libraries of several targets.
pub const PACKAGE_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// The first id segment that is reserved for the project (ADR-0019). An
/// extension with this segment is a built-in extension.
pub(crate) const PROJECT_PUBLISHER: &str = "rivet";

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
/// same key can be written with any key id. Verification is stricter: a
/// signature verifies only with a key text that has its key id.
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
    /// A key that is a small-order point, or whose y coordinate is not in
    /// canonical form, is refused: a signature for it needs no secret key.
    /// Each way to get a [`PublicKey`] goes through this parse.
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
        if is_weak_key(&key_bytes) {
            return Err(Error::user(
                "the minisign public key is refused: it is a small-order point or it is not in \
                 canonical form, so a signature for it needs no secret key",
            ));
        }
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

/// The y coordinates of the 8 points of small order (order 1, 2, 4 or 8) of
/// the Ed25519 curve, little-endian, in canonical form: 0, 1, p - 1 and the
/// two y of the points of order 8, with p = 2^255 - 19.
///
/// Source: the list `blacklist` in `ge25519_has_small_order` of libsodium,
/// tag `1.0.18`, file
/// `src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c`. The list
/// has 7 entries there; tag `1.0.20` has a list of 7 entries too.
/// The entries of the list for y = p and y = p + 1 are not here:
/// [`is_weak_key`] refuses each y that is not below p.
const SMALL_ORDER_Y: [[u8; 32]; 5] = [
    [0; 32],
    {
        let mut y = [0; 32];
        y[0] = 1;
        y
    },
    {
        let mut y = [0xff; 32];
        y[0] = 0xec;
        y[31] = 0x7f;
        y
    },
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
];

/// Returns `true` for an Ed25519 public key that must not verify anything: a
/// point of small order, or a y coordinate that is not in canonical form
/// (y is not below p). For a point of small order, a signature that verifies
/// can be made without a secret key. `minisign_verify` refuses only some of
/// these keys.
///
/// The key is public data, so the comparison does not need constant time.
// shortcut: a fixed list and no curve arithmetic, so a point of mixed order
// (a valid key plus a small-order point) is not refused; it does not permit
// a forged signature. Use a curve crate if such keys must be refused.
fn is_weak_key(key: &[u8; 32]) -> bool {
    // The top bit is the sign of x. Each y is refused with both signs.
    let mut y = *key;
    y[31] &= 0x7f;
    // p = 2^255 - 19 is `ed ff … ff 7f`.
    let not_below_p = y[0] >= 0xed && y[1..31] == [0xff; 30] && y[31] == 0x7f;
    not_below_p || SMALL_ORDER_Y.contains(&y)
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
///   key. The message names both files. If the key id of the signature is
///   not the key id of `key`, the message says so.
/// - `policy`: the signature verifies, but its trusted comment is not
///   `rivet-package id=<extension id> version=<version>`.
pub fn verify(package: &Path, signature: &Path, key: &PublicKey) -> Result<Verified> {
    let (trusted_comment, file) = verify_signature(package, signature, key, |_, error| error)?;
    bound_package(&trusted_comment, signature, file)
}

/// Why a signature does not verify with a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rejection {
    /// The key id of the signature is not the key id of the key text. The
    /// library compares the key ids first and does not try the key bytes.
    KeyId,
    /// The key ids are equal and the signature does not verify.
    Signature,
}

/// Verifies the signature. Returns the verified trusted comment and the
/// verified file at position 0.
///
/// `rejected` makes the `policy` error of a signature that does not verify.
/// It gets the reason and the error that names the files and the key.
fn verify_signature(
    package: &Path,
    signature: &Path,
    key: &PublicKey,
    rejected: impl Fn(Rejection, Error) -> Error,
) -> Result<(String, File)> {
    let text = read_text_file(signature, "minisign signature", TEXT_FILE_MAX_BYTES)?;
    let parsed = minisign_verify::Signature::decode(&text).map_err(|error| {
        Error::user(format!(
            "{}: not a valid minisign signature",
            signature.display()
        ))
        .with_source(error)
    })?;
    let rejected = |rejection| {
        let reason = match rejection {
            Rejection::KeyId => ": the signature has another key id than this key text",
            Rejection::Signature => "",
        };
        let error = Error::policy(format!(
            "{}: the signature {} does not verify with the public key {key}{reason}",
            package.display(),
            signature.display()
        ));
        rejected(rejection, error)
    };

    let mut verifier = key.key.verify_stream(&parsed).map_err(|error| match error {
        minisign_verify::Error::UnsupportedLegacyMode => Error::user(format!(
            "{}: legacy minisign signatures are not accepted; sign the package again without `-l`",
            signature.display()
        )),
        // The only other error of `verify_stream`: the key id in the
        // signature is not the id of `key`.
        _ => rejected(Rejection::KeyId),
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
    verifier
        .finalize()
        .map_err(|_| rejected(Rejection::Signature))?;
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
    /// key text again is permitted and changes nothing.
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
    /// - `policy`: the pinned key has the key bytes of `key` and another key
    ///   id. A signature verifies with one of the two texts only, so the pin
    ///   is not kept without a message and it is not replaced.
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
            Some(pinned) if pinned.base64 != key.base64 => {
                return Err(Error::policy(format!(
                    "publisher `{publisher}` has a pinned key with the same key bytes and another \
                     key id. A signature verifies only with the key text that has its key id. \
                     Review which text is correct before the new text replaces the pin"
                )));
            }
            // The same text: the pin stays as it is.
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
    ///   a publisher, the message says that a new review is needed. If the
    ///   key id of the signature is not the key id of the permitted key
    ///   text, the message says so.
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
        // The messages for a signature that does not verify, and for a
        // signature with another key id than the key text.
        let (key, rejected, other_key_id) = match origin {
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
                    format!(
                        "{}: a built-in extension must be signed with the project key, \
                         and the signature has another key id than the project key",
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
                    format!(
                        "{}: the signature has another key id than the pinned key text of \
                         publisher `{publisher}`: the package was signed with another key, or \
                         the pinned text has a wrong key id. A key change needs a new review \
                         before the new key is pinned",
                        package.display()
                    ),
                )
            }
        };
        let (trusted_comment, file) =
            verify_signature(package, signature, key, |rejection, error| {
                Error::policy(match rejection {
                    Rejection::KeyId => &other_key_id,
                    Rejection::Signature => &rejected,
                })
                .with_source(error)
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
    /// is a symbolic link or not a regular file, is larger than 1 MiB, can
    /// be written by the group or by other users (Unix), is not valid TOML,
    /// has another
    /// [`SCHEMA_VERSION`], has an unknown key, or holds an invalid publisher
    /// name or public key.
    pub fn load(project_key: PublicKey, path: &Path) -> Result<Self> {
        let mut store = Self::new(project_key);
        if matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == io::ErrorKind::NotFound)
        {
            return Ok(store);
        }
        let what = "trust store";
        let file = open_regular(path, what, TRUST_FILE_MAX_BYTES)?;
        // Another user who can write the file can pin a key. `save` writes
        // the file with mode 0600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = file
                .metadata()
                .map_err(|error| io_error(path, "cannot read the trust store file", error))?
                .permissions()
                .mode()
                & 0o7777;
            if mode & 0o022 != 0 {
                return Err(Error::user(format!(
                    "{}: the trust store file can be written by the group or by other users \
                     (mode {mode:04o}); permit the write for the owner only (`chmod 600`)",
                    path.display()
                )));
            }
        }
        let text = read_text(file, path, what, TRUST_FILE_MAX_BYTES)?;
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
            return Err(invalid(format!("unknown key `{}`", shown_key(key))));
        }
        for (publisher, value) in publishers {
            let key = value
                .as_str()
                .ok_or_else(|| Error::user("the value must be a public key string"))
                .and_then(str::parse)
                .map_err(|error| {
                    invalid(format!(
                        "publisher `{}`: {}",
                        shown_key(&publisher),
                        error.message()
                    ))
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
    /// Returns a `user` error that names `path` if `path` is a symbolic
    /// link, or is there and is not a regular file (a FIFO, a directory), or
    /// the file cannot be written. A symbolic link is refused because the
    /// write would replace the link and leave its target unchanged.
    pub fn save(&self, path: &Path) -> Result<()> {
        // shortcut: no lock file, two concurrent writers lose one pin (fails
        // closed); add a lock when a second process can pin keys.
        if let Ok(meta) = std::fs::symlink_metadata(path)
            && !meta.is_file()
        {
            let problem = if meta.is_symlink() {
                "must not be a symbolic link"
            } else {
                "is not a regular file"
            };
            return Err(Error::user(format!(
                "{}: the trust store file {problem}",
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
pub(crate) fn read_text_file(path: &Path, what: &str, max_bytes: u64) -> Result<String> {
    read_text(open_regular(path, what, max_bytes)?, path, what, max_bytes)
}

/// Reads the text of the open file `file` of `path`, at most `max_bytes`.
fn read_text(file: File, path: &Path, what: &str, max_bytes: u64) -> Result<String> {
    let mut text = String::new();
    file.take(max_bytes + 1)
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
pub(crate) fn open_regular(path: &Path, what: &str, max_bytes: u64) -> Result<File> {
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
    use rivet_sdk::error::ErrorCategory;
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

        // R-95 (b): a key of the file is cut and its control characters are
        // escaped in the message.
        let long = "k".repeat(100_000);
        for text in [
            format!("schema_version = 1\n{long} = 1\n"),
            format!("schema_version = 1\n[publishers]\n{long} = 5\n"),
            String::from("schema_version = 1\n\"a\\nb\\u001b[2J\" = 1\n"),
            String::from("schema_version = 1\n[publishers]\n\"a\\nb\\u001b[2J\" = 5\n"),
        ] {
            std::fs::write(&path, text).unwrap();
            let message = assert_error(
                TrustStore::load(key.clone(), &path),
                ErrorCategory::User,
                &[&shown(&path)],
            );
            let limit = shown(&path).len() + MAX_SHOWN_KEY_BYTES + 200;
            assert!(message.len() <= limit, "{} bytes", message.len());
            assert!(!message.contains(['\n', '\u{1b}']), "{message:?}");
            let start = "k".repeat(MAX_SHOWN_KEY_BYTES);
            assert!(
                message.contains(&format!("`{start}…`")) || message.contains("`a\\nb\\u{1b}[2J`"),
                "{message:?}"
            );
        }

        // A directory cannot be read as a file.
        assert_error(
            TrustStore::load(key, dir.path()),
            ErrorCategory::User,
            &[&shown(dir.path())],
        );
    }

    /// R-95 (b): a key is cut at a character boundary. `é` has 2 bytes.
    #[test]
    fn key_with_a_multi_byte_character_at_the_cut_is_cut_before_it() {
        // `é` is in the bytes 127 and 128: the cut moves to its start.
        let start = "k".repeat(MAX_SHOWN_KEY_BYTES - 1);
        assert_eq!(shown_key(&format!("{start}éx")), format!("{start}…"));
        // `é` ends at the limit: it stays.
        let start = "k".repeat(MAX_SHOWN_KEY_BYTES - 2);
        assert_eq!(shown_key(&format!("{start}éx")), format!("{start}é…"));
        assert_eq!(shown_key(&format!("{start}é")), format!("{start}é"));

        // The whole message of a trust store file with such a key.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        let start = "k".repeat(MAX_SHOWN_KEY_BYTES - 1);
        std::fs::write(&path, format!("schema_version = 1\n\"{start}éx\" = 1\n")).unwrap();
        let error = TrustStore::load(TestKey::new().public, &path).unwrap_err();
        assert_eq!(
            error.message(),
            format!("{}: unknown key `{start}…`", shown(&path))
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
        // R-59: the same key bytes with another key id are refused. The pin
        // is not kept without a message and it is not replaced.
        assert_error(
            store.pin("acme", other_key_id(&first)),
            ErrorCategory::Policy,
            &["publisher `acme`", "another key id"],
        );
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
        let (trusted_comment, _) =
            verify_signature(&f.package, &f.signature, &key, |_, error| error).unwrap();
        assert_eq!(trusted_comment, "timestamp:1556193335\tfile:test");

        std::fs::write(&f.package, b"Test").unwrap();
        assert_error(
            verify_signature(&f.package, &f.signature, &key, |_, error| error),
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

    // --- review finding: weak signature keys --------------------------------

    /// The encodings that libsodium 1.0.18 `ge25519_has_small_order` refuses: its 7
    /// list entries, each without and with the sign bit of x. Each entry is
    /// (order of the point, hex of the 32 bytes).
    const WEAK_KEYS: [(u8, &str); 14] = [
        (
            4,
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            4,
            "0000000000000000000000000000000000000000000000000000000000000080",
        ),
        (
            1,
            "0100000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            1,
            "0100000000000000000000000000000000000000000000000000000000000080",
        ),
        (
            8,
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        ),
        (
            8,
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        ),
        (
            8,
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        ),
        (
            8,
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        ),
        (
            2,
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ),
        (
            2,
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        // y = p and y = p + 1: other encodings of y = 0 and y = 1.
        (
            4,
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ),
        (
            4,
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        (
            1,
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ),
        (
            1,
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
    ];

    fn unhex(hex: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Standard base64 with padding, as minisign writes it.
    fn base64(bytes: &[u8]) -> String {
        let mut text = String::new();
        for chunk in bytes.chunks(3) {
            let mut group = [0_u8; 3];
            group[..chunk.len()].copy_from_slice(chunk);
            let bits = u32::from_be_bytes([0, group[0], group[1], group[2]]);
            for index in 0..4 {
                let char = BASE64[(bits >> (18 - 6 * index) & 63) as usize];
                text.push(if index > chunk.len() {
                    '='
                } else {
                    char.into()
                });
            }
        }
        text
    }

    fn unbase64(text: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for chunk in text.trim_end_matches('=').as_bytes().chunks(4) {
            let bits = chunk.iter().fold(0_u32, |bits, char| {
                bits << 6 | BASE64.iter().position(|other| other == char).unwrap() as u32
            }) << (6 * (4 - chunk.len()));
            bytes.extend_from_slice(&bits.to_be_bytes()[1..chunk.len()]);
        }
        bytes
    }

    /// The text of a public key with the key id 0 and these key bytes.
    fn key_text(key_bytes: &[u8; 32]) -> String {
        base64(&[b"Ed".as_slice(), &[0; 8], key_bytes].concat())
    }

    /// Tries to FORGE a signature that `store` accepts for a package of
    /// publisher `acme`, WITHOUT a secret key: S is 0 and R is a small-order
    /// point. The verification is the only oracle. Returns the files of the
    /// forged package and its version.
    ///
    /// With S = 0 the verification computes `[h](-A)` and compares it with
    /// R. For a small-order key A this is one of 8 points, so one of the 8
    /// values of R fits with a probability of 1/order for each try.
    fn forge(store: &TrustStore) -> Option<(Files, Version)> {
        // The canonical encodings of the 8 small-order points.
        let points = WEAK_KEYS.map(|(_, hex)| unhex(hex));
        let points = points.iter().filter(|point| point[..31] != [0xff; 31][..]);
        for content in 0_u8..8 {
            for r1 in points.clone() {
                for patch in 0..8 {
                    for r2 in points.clone() {
                        let version = Version::new(1, 0, patch);
                        let signature = format!(
                            "untrusted comment: forged without a secret key\n{}\n\
                             trusted comment: {}\n{}\n",
                            base64(&[b"ED".as_slice(), &[0; 8], r1, &[0; 32]].concat()),
                            binding(&id(), &version),
                            base64(&[r2.as_slice(), &[0; 32]].concat()),
                        );
                        let f = files(&[content], &signature);
                        let origin = Origin::Publisher("acme");
                        if store
                            .verify_package(origin, &id(), &version, &f.package, &f.signature)
                            .is_ok()
                        {
                            return Some((f, version));
                        }
                    }
                }
            }
        }
        None
    }

    /// A key that did NOT pass the parse. Only this module can build it.
    fn unchecked_key(key_bytes: &[u8; 32]) -> PublicKey {
        let base64 = key_text(key_bytes);
        PublicKey {
            key: minisign_verify::PublicKey::from_base64(&base64).unwrap(),
            base64,
            key_bytes: *key_bytes,
        }
    }

    #[test]
    fn weak_key_is_refused_wherever_a_key_is_read() {
        let more = [
            // Other values of y that are not below p, up to the largest.
            (
                0,
                "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            ),
            (
                0,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            ),
            (
                0,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
        ];
        let dir = tempfile::tempdir().unwrap();
        let project = TestKey::new().public;
        for (order, hex) in WEAK_KEYS.into_iter().chain(more) {
            let bytes = unhex(hex);
            assert!(is_weak_key(&bytes), "order {order}: {hex}");
            let text = key_text(&bytes);
            assert_eq!(decode_key(&text).unwrap()[10..], bytes);

            let message = assert_error(
                text.parse::<PublicKey>(),
                ErrorCategory::User,
                &["minisign public key", "small-order"],
            );
            assert!(!message.contains(&text), "leaked: {message}");

            let key_file = dir.path().join("weak.pub");
            std::fs::write(&key_file, format!("untrusted comment: weak\n{text}\n")).unwrap();
            assert_error(
                PublicKey::load(&key_file),
                ErrorCategory::User,
                &[&shown(&key_file), "small-order"],
            );

            let trust_file = dir.path().join("trust.toml");
            let toml = format!("schema_version = 1\n[publishers]\nacme = \"{text}\"\n");
            std::fs::write(&trust_file, toml).unwrap();
            assert_error(
                TrustStore::load(project.clone(), &trust_file),
                ErrorCategory::User,
                &[&shown(&trust_file), "publisher `acme`", "small-order"],
            );
        }
        // R-58: the key text of the review, the point of order 2.
        assert_error(
            "RWRGT1JHRURJROz///////////////////////////////////////9/".parse::<PublicKey>(),
            ErrorCategory::User,
            &["small-order"],
        );
        // `pin`, `replace_pin_after_review` and the project key take a
        // `PublicKey`. Only the parse makes one, so a weak key cannot reach
        // them.

        // The limits of the check: y = 2 and y = p - 2 are not refused.
        for hex in [
            "0200000000000000000000000000000000000000000000000000000000000000",
            "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "edfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe7f",
        ] {
            assert!(!is_weak_key(&unhex(hex)), "{hex}");
        }
        assert!(!is_weak_key(&TestKey::new().public.key_bytes));
        assert!(!is_weak_key(
            &VECTOR_KEY.parse::<PublicKey>().unwrap().key_bytes
        ));
    }

    #[test]
    fn signature_is_forged_for_a_weak_key_that_skips_the_parse() {
        // This shows why the parse must refuse these keys: `minisign-verify`
        // 0.3.0 accepts them. One key of each order, and y = p + 1.
        for index in [1, 4, 8, 12] {
            let (order, hex) = WEAK_KEYS[index];
            let bytes = unhex(hex);
            let mut store = TrustStore::new(TestKey::new().public);
            store.pins.insert("acme".to_owned(), unchecked_key(&bytes));

            let (f, version) = forge(&store).unwrap_or_else(|| panic!("order {order}: {hex}"));
            let verified = store
                .verify_package(
                    Origin::Publisher("acme"),
                    &id(),
                    &version,
                    &f.package,
                    &f.signature,
                )
                .unwrap();
            assert_eq!((verified.id(), verified.version()), (&id(), &version));

            // The same key cannot be loaded, so the forged signature has no
            // key to verify with.
            let text = key_text(&bytes);
            assert_error(
                text.parse::<PublicKey>(),
                ErrorCategory::User,
                &["small-order"],
            );
            let mut store = TrustStore::new(TestKey::new().public);
            assert!(text.parse().and_then(|key| store.pin("acme", key)).is_err());
            assert_error(
                store.verify_package(
                    Origin::Publisher("acme"),
                    &id(),
                    &version,
                    &f.package,
                    &f.signature,
                ),
                ErrorCategory::Policy,
                &["no pinned key"],
            );
        }
    }

    /// The order of the base point, little-endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    #[test]
    fn signature_with_s_not_below_l_is_rejected() {
        let key = TestKey::new();
        let signature = key.sign(PACKAGE);
        let mut lines: Vec<String> = signature.lines().map(str::to_owned).collect();
        // S + L gives the same point `[S]B` as S. Only the global signature
        // is changed: it does not sign itself, so only the check of S can
        // refuse it.
        let mut global = unbase64(&lines[3]);
        let mut carry = 0_u16;
        for (byte, l) in global[32..].iter_mut().zip(L) {
            let sum = u16::from(*byte) + u16::from(l) + carry;
            *byte = sum.to_le_bytes()[0];
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        assert_eq!(base64(&unbase64(&lines[3])), lines[3]);
        lines[3] = base64(&global);

        let f = files(PACKAGE, &signature);
        verify(&f.package, &f.signature, &key.public).unwrap();
        let f = files(PACKAGE, &(lines.join("\n") + "\n"));
        assert_error(
            verify(&f.package, &f.signature, &key.public),
            ErrorCategory::Policy,
            &["does not verify"],
        );
    }

    // A signature of `PACKAGE` with `TRUSTED_COMMENT` whose two R are the
    // identity (a small-order point), for a key that is NOT weak: the base
    // point, which has the known secret scalar 1. Then S = h mod L, with
    // h = SHA-512(R, A, message). Made with Python (hashlib), not with a tool.
    const BASE_POINT_KEY: &str = "RWQAAAAAAAAAAFhmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm";
    const SMALL_ORDER_R: &str = "untrusted comment: R is the identity\n\
        RUQAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAg6MveDwgn98YqynDheqoaePx6vFcxTLLyY/xR3b/Xgs=\n\
        trusted comment: rivet-package id=acme.postgres version=1.0.0\n\
        AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApkzz2E6zJFjla9ltmePDlZIkVHZJnJtoCNH0HKbt9Ag==\n";

    #[test]
    fn small_order_r_of_the_key_owner_is_accepted() {
        // `minisign-verify` 0.3.0 does not refuse a small-order R. Only the
        // owner of the secret key can make such a signature (it needs
        // S = h * secret), so this is not a forged signature. libsodium
        // refuses it. This test records the behaviour.
        let key: PublicKey = BASE_POINT_KEY.parse().unwrap();
        let f = files(PACKAGE, SMALL_ORDER_R);
        let verified = verify(&f.package, &f.signature, &key).unwrap();
        assert_eq!((verified.id(), verified.version()), (&id(), &version()));
    }

    // --- review finding R-59 ----------------------------------------------

    #[test]
    fn pin_with_the_right_key_bytes_and_a_wrong_key_id_is_named() {
        let genuine = TestKey::new();
        let wrong_id = other_key_id(&genuine.public);
        let f = files(PACKAGE, &genuine.sign(PACKAGE));
        let mut store = TrustStore::new(TestKey::new().public);
        store.pin("acme", wrong_id.clone()).unwrap();
        let verify_acme = |store: &TrustStore| {
            let origin = Origin::Publisher("acme");
            store.verify_package(origin, &id(), &version(), &f.package, &f.signature)
        };

        // The genuine text is not accepted as "the same key" while the pin
        // keeps the wrong text.
        assert_error(
            store.pin("acme", genuine.public.clone()),
            ErrorCategory::Policy,
            &["publisher `acme`", "another key id"],
        );
        assert_eq!(
            store.pinned("acme").unwrap().to_string(),
            wrong_id.to_string()
        );
        // The error names the key id. It does not say only that the
        // publisher changed its key.
        let message = assert_error(
            verify_acme(&store),
            ErrorCategory::Policy,
            &["publisher `acme`", "another key id", "new review"],
        );
        assert!(!message.contains("changed its key"), "{message}");
        assert_error(
            verify(&f.package, &f.signature, &wrong_id),
            ErrorCategory::Policy,
            &["does not verify", "another key id"],
        );

        store
            .replace_pin_after_review("acme", genuine.public.clone())
            .unwrap();
        verify_acme(&store).unwrap();

        // The right key id and a changed package: the key id is not named.
        std::fs::write(&f.package, b"changed").unwrap();
        let message = assert_error(
            verify_acme(&store),
            ErrorCategory::Policy,
            &["publisher `acme`", "changed its key", "new review"],
        );
        assert!(!message.contains("key id"), "{message}");
        let message = assert_error(
            verify(&f.package, &f.signature, &genuine.public),
            ErrorCategory::Policy,
            &["does not verify"],
        );
        assert!(!message.contains("key id"), "{message}");

        // A built-in extension with a project key text of another key id.
        let project = TestKey::new();
        let f = files(PACKAGE, &project.sign_with(PACKAGE, BUILT_IN_COMMENT));
        let store = TrustStore::new(other_key_id(&project.public));
        assert_error(
            store.verify_package(
                Origin::BuiltIn,
                &built_in_id(),
                &version(),
                &f.package,
                &f.signature,
            ),
            ErrorCategory::Policy,
            &["project key", "another key id"],
        );
    }

    // --- review finding R-68 ----------------------------------------------

    #[cfg(unix)]
    #[test]
    fn save_refuses_what_is_not_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::new(TestKey::new().public);

        let pipe = dir.path().join("pipe.toml");
        fifo(&pipe);
        assert_error(
            store.save(&pipe),
            ErrorCategory::User,
            &[&shown(&pipe), "not a regular file"],
        );
        // The FIFO was not replaced.
        assert!(!std::fs::symlink_metadata(&pipe).unwrap().is_file());

        let directory = dir.path().join("directory.toml");
        std::fs::create_dir(&directory).unwrap();
        assert_error(
            store.save(&directory),
            ErrorCategory::User,
            &[&shown(&directory), "not a regular file"],
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_a_trust_store_that_other_users_can_write() {
        use std::os::unix::fs::PermissionsExt;
        let key = TestKey::new().public;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.toml");
        TrustStore::new(key.clone()).save(&path).unwrap();
        let set_mode = |mode| {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        };

        for (mode, shown_mode) in [(0o664, "0664"), (0o646, "0646"), (0o666, "0666")] {
            set_mode(mode);
            assert_error(
                TrustStore::load(key.clone(), &path),
                ErrorCategory::User,
                &[&shown(&path), "trust store file", shown_mode, "chmod 600"],
            );
        }
        for mode in [0o600, 0o644, 0o400] {
            set_mode(mode);
            TrustStore::load(key.clone(), &path).unwrap();
        }
    }

    #[test]
    fn file_of_exactly_the_size_limit_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eight");
        std::fs::write(&path, "12345678").unwrap();
        open_regular(&path, "package", 8).unwrap();
        assert_eq!(read_text_file(&path, "text", 8).unwrap(), "12345678");
        for result in [
            open_regular(&path, "package", 7).map(drop),
            read_text_file(&path, "package", 7).map(drop),
        ] {
            assert_error(
                result,
                ErrorCategory::User,
                &[&shown(&path), "too large", "7 bytes"],
            );
        }
    }

    // R-68: this test shows only that the call works from `spawn_blocking`.
    // It cannot show that a caller uses the blocking pool.
    #[tokio::test]
    async fn verification_works_from_spawn_blocking() {
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
