//! The package format, and install, update and rollback from a registry
//! directory (ARCHITECTURE.md §4.7, §4.8, §7.7, ADR-0019).
//!
//! # Package format
//!
//! A package is one file, `<id>-<version>.rivetpkg`. It is a tar archive
//! without compression. It holds exactly these three regular files:
//!
//! | Entry | Content | Limit |
//! | --- | --- | --- |
//! | `extension.toml` | The manifest ([`Manifest`]). Its `sdk` range is the SDK docs reference: the documentation is part of each SDK release. | 1 MiB |
//! | `extension.wasm` | The WASM component. | [`DEFAULT_COMPONENT_BYTES`]: the limit of the WASM runtime, so a package that installs can load |
//! | `LICENSE` | The licence text. | 1 MiB |
//!
//! The signature is not in the package. It is a separate minisign file,
//! `<id>-<version>.rivetpkg.minisig`, as [`crate::package`] describes.
//! A package with native libraries is not defined yet.
//!
//! Make a package with the exact entry names, for example
//! `tar --format=ustar -cf acme.postgres-1.0.0.rivetpkg extension.toml extension.wasm LICENSE`.
//!
//! # Hostile content
//!
//! Each of these gives a `policy` error and installs nothing:
//!
//! - An entry with another name. Thus a path with `..`, an absolute path, a
//!   path with a directory and `./extension.toml` are refused.
//! - An entry that is not a regular file: a symbolic link, a hard link, a
//!   directory, a device, a FIFO. A GNU long name entry and a PAX header
//!   entry are entries too: they are refused, not applied to the next entry.
//! - An entry above its size limit. The bytes are counted during the copy.
//! - A second entry with the same name. Thus a package has three entries at
//!   most.
//! - An archive without the end mark (two blocks of zeros) after the last
//!   entry. After the entries only zeros are permitted: the end mark and
//!   the padding of `tar` to a full record, thus less than 11264 bytes.
//! - A package without one of the three entries.
//! - A manifest whose id or version is not the id or version of the
//!   signature.
//!
//! The archive is never unpacked by the archive library. This module writes
//! each of the three files with a fixed name. The modes, owners and times of
//! the archive are ignored.
//!
//! # Directories
//!
//! ```text
//! <registry>/<id>/<version>/<id>-<version>.rivetpkg           read only
//! <registry>/<id>/<version>/<id>-<version>.rivetpkg.minisig
//!
//! <data>/extensions/<id>/                the active version (the host scans this)
//! <data>/store/<id>/<id>-<version>.rivetpkg          the verified package of the active
//! <data>/store/<id>/<id>-<version>.rivetpkg.minisig  version, of the previous version and
//!                                                    of a version whose review waits
//! <data>/store/<id>/previous             the version for a rollback
//! <data>/store/<id>/pending              the journal of a change that is not complete
//! <data>/store/<id>/review               the version whose review waits
//! <data>/store/<id>/.lock                the lock of the id; never renamed, never deleted
//! ```
//!
//! `<data>` MUST be a directory of the user that other users cannot write.
//! On Unix each operation refuses, with a `user` error, a `<data>`,
//! `<data>/store`, `<data>/store/<id>`, `<data>/extensions` or
//! `<data>/extensions/<id>` that the group or other users can write. The
//! installer creates each directory with mode 0700 and each file with mode
//! 0600, whatever the umask is, so a kept package is verified again in a
//! private directory. The owner of a directory and the mode of a file that
//! exists are not checked. On Unix a lock file with a second hard link is
//! refused too. Windows has none of these checks. A `<data>/store/<id>`
//! that is a symbolic link is refused on each platform.
//! `<data>/extensions` is the user discovery directory of the host
//! ([`Installer::extensions_dir`]). The host does not scan `<data>/store`.
//!
//! # Order of an install, an update and a rollback
//!
//! 1. Copy the package and the signature from the registry to a private
//!    staging directory in `<data>/store/<id>`. A rollback uses the package
//!    that the store kept.
//! 2. Verify the signature of the copy ([`TrustStore::verify_package`]).
//! 3. Read the package only from the file handle that the verification
//!    returns.
//! 4. Compare the id and the version of the manifest with the signature.
//! 5. Update and rollback: compare the capabilities with the active version
//!    ([`added_capabilities`]). If the new manifest adds a capability, write
//!    `review` and stop with [`Outcome::NeedsReview`]. The active version
//!    does not change.
//! 6. Make the staged directory the active directory.
//!
//! An error in step 1 to 5 changes nothing in `<data>/extensions`. Step 6
//! has a point of no return: see the next section.
//!
//! # Why a failed change leaves the old version usable
//!
//! Step 6 is two renames with a journal:
//!
//! 1. Write `pending` with the old and the new version.
//! 2. Rename the active directory to `<data>/store/<id>/<old version>`.
//! 3. Rename the staged directory to `<data>/extensions/<id>`.
//! 4. Write `previous`. Delete `pending`.
//!
//! Each rename changes one directory entry on one filesystem. The operating
//! system does this as one step: a reader sees the full old directory or the
//! full new directory, never a part. `pending` and `previous` are written to
//! a temporary file that then replaces the old file, so they are never
//! written in part.
//!
//! The two renames together are not one step. Between rename 2 and rename 3
//! the id has no active directory. A load in this window fails and the host
//! tries again (ADR-0021). If the process stops there, [`Installer::recover`]
//! puts the old version back. Each operation on an id runs the recovery
//! first. The recovery never completes a change: it goes back to the old
//! version. One exception: if rename 3 was done, the new version is complete
//! and stays, and the recovery only writes `previous`.
//!
//! Rename 3 is the point of no return. An error before it leaves the old
//! version active, and the operation returns the error. After it the new
//! version is active and the operation returns `Ok`. If step 4 then fails
//! (for example on a full disk), the operation writes a warning to the log
//! and `pending` stays. The next operation on the id or the next
//! [`Installer::recover`] does step 4 again. Step 4 also deletes the kept
//! packages of all versions but the active and the previous one.
//!
//! A `pending` that is not a journal of this module (a text that is not
//! valid, a file that cannot be read, a directory, a symbolic link, more
//! than 16 KiB) does not stop the recovery and does not lose the active
//! version. The same applies to a journal whose old version has no
//! directory. The recovery then reads the directories: an active directory
//! stays; if there is none, the one retired directory in the store goes
//! back. A symbolic link is never moved back. `pending` is then deleted, a
//! directory with its content. With two or more retired
//! directories the recovery changes nothing and returns an `internal` error.
//! `previous` is not written in this case.
//!
//! An active version whose manifest is missing, cannot be read or is invalid
//! cannot be updated or rolled back. [`Installer::install`] replaces it with a verified package and
//! deletes it. A stop between the two renames of this change leaves no
//! active version.
//!
//! The recovery of an id runs only when an operation names that id.
//! [`Installer::recover_all`] recovers each id; no start-up code calls it
//! yet.
//!
//! # One operation on an id at a time
//!
//! [`Installer::install`], [`Installer::update`], [`Installer::rollback`],
//! [`Installer::activate_after_review`] and [`Installer::recover`] hold an
//! exclusive lock on `<data>/store/<id>/.lock` from start to end. A second
//! operation on the same id, in another thread or in another process, does
//! not wait: it changes nothing and fails at once with a `retryable` error
//! (ADR-0023). Operations on different ids do not stop each other. Thus a
//! recovery never deletes the staging directory or the journal of an
//! operation that runs. The lock is released when the operation ends or the
//! process stops. The lock is advisory: a program that does not take it is
//! not stopped.
//!
//! # The caller must do this
//!
//! - **Blocking I/O.** Each method reads and writes files. From async code,
//!   call it in a blocking job (§5.1).
//! - **Review.** Call [`Installer::activate_after_review`] only after the
//!   user reviewed the added capabilities and
//!   [`Permissions::grant`](crate::permissions::Permissions::grant) stored
//!   the grant (to enforce in #51; no check exists). The installer only
//!   checks that a review waits for this version: the last operation on the
//!   id returned [`Outcome::NeedsReview`] for it. An install, update or
//!   rollback of the id whose package passes step 4 removes the record of
//!   an older review. An operation that fails before that leaves it.
//! - **First install.** [`Installer::install`] activates the package without
//!   a review. The extension has no access until the caller grants its
//!   capabilities: the permission service denies by default.
//! - **Pinned keys.** The trust store file is `trust.toml` in the user
//!   configuration directory ([`trust_store_path`]). The installer reads no
//!   other file, and no method takes another path. Thus a workspace
//!   directory or a bundled directory cannot give a trust store (ADR-0019).
//!
//! # Example
//!
//! ```no_run
//! use rivet_core::install::{Installer, Outcome};
//! use rivet_core::package::PublicKey;
//!
//! let project_key: PublicKey =
//!     "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3".parse()?;
//! let installer = Installer::new(project_key, "data".into(), "registry".into())?;
//! let id = "acme.postgres".parse()?;
//!
//! installer.install(&id, &"1.0.0".parse().expect("a version"))?;
//! let new = "1.1.0".parse().expect("a version");
//! if let Outcome::NeedsReview { added } = installer.update(&id, &new)? {
//!     // Show `added` to the user. Grant it. Then:
//!     # drop(added);
//!     installer.activate_after_review(&id, &new)?;
//! }
//! installer.rollback(&id)?;
//! # Ok::<(), rivet_sdk::error::Error>(())
//! ```

use crate::host::MANIFEST_FILE;
use crate::package::{
    Origin, PACKAGE_MAX_BYTES, PROJECT_PUBLISHER, PublicKey, TrustStore, open_regular,
};
use crate::permissions::added_capabilities;
use crate::settings::user_settings_path;
use rivet_sdk::error::{Error, Result};
use rivet_sdk::manifest::{Capabilities, ExtensionId, Manifest, Version};
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub use crate::wasm::COMPONENT_FILE;
use crate::wasm::DEFAULT_COMPONENT_BYTES;

/// The name of the licence text in a package.
pub const LICENCE_FILE: &str = "LICENSE";

/// The file name extension of a package.
pub const PACKAGE_EXTENSION: &str = "rivetpkg";

/// The maximum size of the manifest and of the licence text in a package.
pub const TEXT_ENTRY_MAX_BYTES: u64 = 1024 * 1024;

/// The only entries of a package, each with its size limit.
const ENTRIES: [(&str, u64); 3] = [
    (MANIFEST_FILE, TEXT_ENTRY_MAX_BYTES),
    (COMPONENT_FILE, DEFAULT_COMPONENT_BYTES as u64),
    (LICENCE_FILE, TEXT_ENTRY_MAX_BYTES),
];

/// More than a minisign signature needs. The verification has its own limit.
const SIGNATURE_MAX_BYTES: u64 = 16 * 1024;

/// The end mark of a tar archive: two blocks of zeros.
const END_MARK_BYTES: u64 = 2 * 512;

/// The record size of `tar`. It fills the last record with zeros.
const RECORD_BYTES: u64 = 20 * 512;

const PENDING_FILE: &str = "pending";
const PREVIOUS_FILE: &str = "previous";
const STAGING_PREFIX: &str = ".staging-";
/// The start of the name of a temporary file of [`write_atomic`].
const TEMP_PREFIX: &str = ".tmp";
const LOCK_FILE: &str = ".lock";
const REVIEW_FILE: &str = "review";

/// More than a journal needs: two versions.
const JOURNAL_MAX_BYTES: u64 = 16 * 1024;

/// The number of bytes of a refused entry name that an error shows.
const ENTRY_NAME_SHOWN_BYTES: usize = 64;

/// The result of an install, an update or a rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The version is the active version now.
    Activated,
    /// The manifest of the version adds the capabilities `added` to those
    /// of the active version. The active version did not change. The
    /// verified package is kept: after the review, call
    /// [`Installer::activate_after_review`].
    NeedsReview {
        /// The capabilities that the active version does not request.
        added: Capabilities,
    },
}

/// Returns the path of the trust store file: `rivet/trust.toml` in the user
/// configuration directory, beside the user settings file
/// ([`user_settings_path`]). Pin a key with [`TrustStore`] and save it here.
///
/// # Errors
///
/// Returns a `user` error if the user configuration directory is unknown.
pub fn trust_store_path() -> Result<PathBuf> {
    Ok(user_settings_path()?.with_file_name("trust.toml"))
}

/// Where the package of an operation comes from.
#[derive(Clone, Copy, PartialEq)]
enum Source {
    Registry,
    Store,
}

/// Installs extension packages from a registry directory. See the
/// [module documentation](self) for the format, the directories and the
/// rules.
#[derive(Debug)]
pub struct Installer {
    project_key: PublicKey,
    data: PathBuf,
    registry: PathBuf,
    /// Never from a caller: see [`trust_store_path`].
    trust_file: PathBuf,
}

impl Installer {
    /// Creates an installer. `project_key` is the key that ships with the
    /// binary. `data` is the private data directory of the user. `registry`
    /// is the registry directory. Nothing is read or written here.
    ///
    /// # Errors
    ///
    /// Returns a `user` error if the user configuration directory is
    /// unknown, so the trust store file has no path.
    pub fn new(project_key: PublicKey, data: PathBuf, registry: PathBuf) -> Result<Self> {
        Ok(Self {
            project_key,
            data,
            registry,
            trust_file: trust_store_path()?,
        })
    }

    /// Returns the directory of the active versions. Give it to the host as
    /// the user discovery directory.
    pub fn extensions_dir(&self) -> PathBuf {
        self.data.join("extensions")
    }

    /// Returns the manifest of the active version of `id`, or `None` if the
    /// extension is not installed.
    ///
    /// # Errors
    ///
    /// Returns a `user` error that names the file if the manifest of the
    /// active version is missing, cannot be read or is invalid.
    pub fn installed(&self, id: &ExtensionId) -> Result<Option<Manifest>> {
        let active = self.active(id);
        match fs::symlink_metadata(&active) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(&active, "cannot read the directory", error)),
        }
        // The way out of a broken active version: `install` replaces it.
        let path = active.join(MANIFEST_FILE);
        let broken = |problem: &str| {
            Error::user(format!(
                "{}: {problem}; install a version of `{id}` to replace it",
                path.display()
            ))
        };
        let text = fs::read_to_string(&path)
            .map_err(|error| broken("cannot read the manifest").with_source(error))?;
        Manifest::parse(&text)
            .map(Some)
            .map_err(|error| broken(error.message()))
    }

    /// Installs `version` of `id` from the registry and activates it. An
    /// active version whose manifest is missing, cannot be read or is
    /// invalid is replaced and deleted.
    ///
    /// # Errors
    ///
    /// - `user`: a directory of the installer can be written by the group
    ///   or by other users (Unix), or the extension is installed already
    ///   (use [`update`](Self::update)), or the package or the signature is not
    ///   in the registry or cannot be read, or the package is not a tar
    ///   archive, or its manifest is invalid.
    /// - `policy`: the signature does not verify, the publisher has no
    ///   pinned key, or the package breaks a rule of the
    ///   [package format](self#hostile-content).
    /// - `retryable`: another operation on `id` runs.
    ///
    /// Each error installs nothing.
    pub fn install(&self, id: &ExtensionId, version: &Version) -> Result<Outcome> {
        let _lock = self.lock(id)?;
        self.repair(id)?;
        // An active version without a manifest that can be read and is
        // valid is replaced: no other operation can leave that state.
        let broken = match self.installed(id) {
            Ok(None) => false,
            Ok(Some(installed)) => {
                return Err(Error::user(format!(
                    "extension `{id}` is installed in version {}; update it instead",
                    installed.version
                )));
            }
            Err(_) => true,
        };
        self.activate(id, version, Source::Registry, false, broken)
    }

    /// Updates `id` to the newer `version` from the registry.
    ///
    /// If the new manifest adds capabilities, the result is
    /// [`Outcome::NeedsReview`] and the active version does not change.
    ///
    /// # Errors
    ///
    /// - `user`: the extension is not installed, or `version` is not newer
    ///   than the active version. Build metadata does not make a version
    ///   newer: `1.0.0+b` is the same version as `1.0.0+a`.
    /// - See [`install`](Self::install).
    ///
    /// Each error before the second rename leaves the active version as it
    /// was. After the second rename
    /// ([the point of no return](self#why-a-failed-change-leaves-the-old-version-usable))
    /// no error is returned.
    pub fn update(&self, id: &ExtensionId, version: &Version) -> Result<Outcome> {
        let _lock = self.lock(id)?;
        self.repair(id)?;
        match self.installed(id)? {
            None => Err(Error::user(format!(
                "extension `{id}` is not installed; install it first"
            ))),
            Some(installed) if version.cmp_precedence(&installed.version).is_le() => {
                Err(Error::user(format!(
                    "extension `{id}`: version {version} is not newer than the installed version {}",
                    installed.version
                )))
            }
            Some(_) => self.activate(id, version, Source::Registry, true, false),
        }
    }

    /// Goes back to the version that was active before the last change of
    /// `id`. The kept package of that version is verified again.
    ///
    /// If the manifest of that version adds capabilities to those of the
    /// active version, the result is [`Outcome::NeedsReview`] and the active
    /// version does not change.
    ///
    /// # Errors
    ///
    /// - `user`: there is no previous version.
    /// - See [`install`](Self::install).
    ///
    /// Each error before the second rename leaves the active version as it
    /// was. After the second rename
    /// ([the point of no return](self#why-a-failed-change-leaves-the-old-version-usable))
    /// no error is returned.
    pub fn rollback(&self, id: &ExtensionId) -> Result<Outcome> {
        let _lock = self.lock(id)?;
        self.repair(id)?;
        let path = self.store(id).join(PREVIOUS_FILE);
        let none = || Error::user(format!("extension `{id}` has no previous version"));
        let previous = match fs::read_to_string(&path) {
            Ok(text) => text.trim().parse::<Version>().map_err(|_| none())?,
            Err(error) if error.kind() == ErrorKind::NotFound => return Err(none()),
            Err(error) => return Err(io_error(&path, "cannot read the file", error)),
        };
        self.activate(id, &previous, Source::Store, true, false)
    }

    /// Activates `version` of `id` from the package that the store kept,
    /// without a comparison of capabilities. The package is verified again.
    ///
    /// Call this only after [`Outcome::NeedsReview`], the review by the user
    /// and the new grant: see the [module documentation](self).
    ///
    /// # Errors
    ///
    /// - `policy`: no review waits for this version of `id`.
    /// - `user`: the store has no package of this version, or the version
    ///   is active already.
    /// - See [`install`](Self::install).
    pub fn activate_after_review(&self, id: &ExtensionId, version: &Version) -> Result<()> {
        let _lock = self.lock(id)?;
        self.repair(id)?;
        // A record that cannot be read or is for another version is no review.
        let record = fs::read_to_string(self.store(id).join(REVIEW_FILE)).unwrap_or_default();
        if record.trim().parse::<Version>().ok().as_ref() != Some(version) {
            return Err(Error::policy(format!(
                "extension `{id}`: no review waits for version {version}; update to it first"
            )));
        }
        self.activate(id, version, Source::Store, false, false)
            .map(|_| ())
    }

    /// Repairs `id` after a change that did not complete, for example after
    /// a crash. Each operation runs this first. A caller can run it at
    /// start-up. If no change is pending, it only removes a staging
    /// directory and the temporary files that a stopped process left. For an id without a store
    /// directory it does nothing and creates nothing.
    ///
    /// # Errors
    ///
    /// - `user`: a file cannot be read, moved or written, or a directory
    ///   of the installer can be written by the group or by other users
    ///   (Unix). The error names the file or the directory.
    /// - `internal`: the journal does not name the version that was
    ///   active, no version is active and the store has two or more
    ///   retired directories. Nothing changes.
    /// - `retryable`: another operation on `id` runs.
    pub fn recover(&self, id: &ExtensionId) -> Result<()> {
        // No store directory: no operation got to a change of this id.
        if !self.store(id).is_dir() {
            return Ok(());
        }
        let _lock = self.lock(id)?;
        self.repair(id)
    }

    /// Runs [`recover`](Self::recover) for each id that has a directory in
    /// the store. Call it at start-up, before the host scans
    /// [`extensions_dir`](Self::extensions_dir).
    ///
    /// # Errors
    ///
    /// An error of one id does not stop the recovery of the others. Each
    /// error is logged. The first error is returned.
    pub fn recover_all(&self) -> Result<()> {
        let store = self.data.join("store");
        let unreadable = |error| io_error(&store, "cannot read the directory", error);
        let entries = match fs::read_dir(&store) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(unreadable(error)),
        };
        let mut first = None;
        for entry in entries {
            let entry = entry.map_err(unreadable)?;
            // The installer makes one directory per id and nothing else.
            let Ok(id) = entry.file_name().to_string_lossy().parse::<ExtensionId>() else {
                continue;
            };
            if !entry.path().is_dir() {
                continue;
            }
            if let Err(error) = self.recover(&id) {
                tracing::warn!(extension = %id, %error, "the recovery did not complete");
                first.get_or_insert(error);
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// The recovery. The caller holds the lock of `id`.
    fn repair(&self, id: &ExtensionId) -> Result<()> {
        let store = self.store(id);
        // With the lock held, each staging directory is of an operation that
        // stopped, with or without a journal.
        if let Ok(entries) = fs::read_dir(&store) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                // Best effort: what stays is never read. Neither call
                // follows a symbolic link.
                if name.starts_with(STAGING_PREFIX) {
                    let _ = fs::remove_dir_all(entry.path());
                } else if name.starts_with(TEMP_PREFIX)
                    && entry.file_type().is_ok_and(|kind| kind.is_file())
                {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        let pending = store.join(PENDING_FILE);
        let journal_is_dir = match fs::symlink_metadata(&pending) {
            Ok(meta) => meta.is_dir(),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(io_error(&pending, "cannot read the journal", error)),
        };
        let journal = read_journal(&pending);
        if journal.is_some() {
            tracing::warn!(extension = %id, "an install did not complete; recovering");
        } else {
            tracing::warn!(extension = %id, journal = %pending.display(), "an install did not complete and the journal cannot be read or is invalid; recovering from the directories");
        }
        let active = self.active(id);
        if fs::symlink_metadata(&active).is_err() {
            // The old version of the journal, if it has a directory. If
            // not, the directories say which version was active: a retired
            // version has a directory in the store only while a change runs.
            let old = match &journal {
                Some((Some(old), _)) if is_real_dir(&store.join(old.to_string())) => {
                    Some(old.clone())
                }
                // A first install: no version was active, so none goes back
                // (a retired directory here is one that a clean-up left).
                Some((None, _)) => None,
                _ => sole_retired(&store, &pending)?,
            };
            if let Some(old) = old {
                fs::rename(store.join(old.to_string()), &active)
                    .map_err(|error| io_error(&active, "cannot put the old version back", error))?;
            }
        } else if let Some((old, new)) = &journal
            // An active version without a valid manifest is not the new version.
            && self
                .installed(id)
                .is_ok_and(|active| active.is_some_and(|manifest| manifest.version == *new))
        {
            // The second rename was done: the new version is complete.
            return self.finish(id, old.as_ref(), new);
        }
        if journal_is_dir {
            // Not a journal of this module. If it stays, each operation
            // on the id runs this recovery again and fails.
            return fs::remove_dir_all(&pending)
                .map_err(|error| io_error(&pending, "cannot remove the directory", error));
        }
        remove_file(&pending)
    }

    /// Steps 1 to 6 of the [module documentation](self). `review` is `true`
    /// when added capabilities stop the operation. `broken` is `true` when
    /// the active version has no valid manifest and the new version
    /// replaces it. The caller holds the lock of `id`.
    fn activate(
        &self,
        id: &ExtensionId,
        version: &Version,
        source: Source,
        review: bool,
        broken: bool,
    ) -> Result<Outcome> {
        let installed = if broken { None } else { self.installed(id)? };
        if installed.as_ref().map(|manifest| &manifest.version) == Some(version) {
            return Err(Error::user(format!(
                "extension `{id}`: version {version} is active already"
            )));
        }
        let store = self.store(id);
        let name = format!("{id}-{version}.{PACKAGE_EXTENSION}");
        let signature_name = format!("{name}.minisig");
        let (kept_package, kept_signature) = (store.join(&name), store.join(&signature_name));
        if source == Source::Store && !kept_package.is_file() {
            return Err(Error::user(format!(
                "extension `{id}`: the store has no package of version {version}"
            )));
        }

        create_private_dir(&store)?;
        // Deleted when it goes out of scope. On Unix only the owner can use it.
        let staging = tempfile::Builder::new()
            .prefix(STAGING_PREFIX)
            .tempdir_in(&store)
            .map_err(|error| io_error(&store, "cannot create a staging directory", error))?;
        let (package, signature) = match source {
            Source::Store => (kept_package.clone(), kept_signature.clone()),
            Source::Registry => {
                let from = self.registry.join(id.as_str()).join(version.to_string());
                let package = staging.path().join(&name);
                let signature = staging.path().join(&signature_name);
                copy_regular(&from.join(&name), &package, PACKAGE_MAX_BYTES)?;
                copy_regular(&from.join(&signature_name), &signature, SIGNATURE_MAX_BYTES)?;
                (package, signature)
            }
        };

        let trust = TrustStore::load(self.project_key.clone(), &self.trust_file)?;
        let origin = match id.as_str().split('.').next() {
            Some(PROJECT_PUBLISHER) | None => Origin::BuiltIn,
            Some(publisher) => Origin::Publisher(publisher),
        };
        let verified = trust.verify_package(origin, id, version, &package, &signature)?;
        let (verified_id, verified_version) = (verified.id().clone(), verified.version().clone());
        let content = staging.path().join("content");
        extract(verified.into_file(), &name, &content)?;

        let manifest_path = content.join(MANIFEST_FILE);
        let text = fs::read_to_string(&manifest_path)
            .map_err(|error| io_error(&manifest_path, "cannot read the manifest", error))?;
        let manifest = Manifest::parse(&text)
            .map_err(|error| Error::user(format!("{name}: {}", error.message())))?;
        if manifest.id != verified_id || manifest.version != verified_version {
            return Err(Error::policy(format!(
                "{name}: the manifest is for `{}` version {}, but the signature is for \
                 `{verified_id}` version {verified_version}",
                manifest.id, manifest.version
            )));
        }

        if source == Source::Registry || review {
            // A verified package of a new install, update or rollback: an
            // older review is void. A refused package leaves it.
            remove_file(&store.join(REVIEW_FILE))?;
        }
        if source == Source::Registry {
            for (from, to) in [(&package, &kept_package), (&signature, &kept_signature)] {
                fs::rename(from, to)
                    .map_err(|error| io_error(to, "cannot keep the verified package", error))?;
            }
        }
        if review && let Some(installed) = &installed {
            let added = added_capabilities(&installed.capabilities, &manifest.capabilities);
            if added != Capabilities::default() {
                write_atomic(&store.join(REVIEW_FILE), &version.to_string())?;
                tracing::info!(extension = %id, %version, "the version adds capabilities and needs a review");
                return Ok(Outcome::NeedsReview { added });
            }
        }

        let old = installed.map(|manifest| manifest.version);
        self.write_pending(id, old.as_ref(), version)?;
        // A broken version has no version name for the store. It goes to
        // the staging directory and is deleted with it.
        let discarded = staging.path().join("broken");
        let retired = if broken {
            fs::rename(self.active(id), &discarded)
                .map_err(|error| io_error(&discarded, "cannot move the broken version", error))
        } else {
            self.retire(id, old.as_ref())
        };
        let moved = retired.and_then(|()| self.promote(id, &content));
        if let Err(error) = moved {
            self.repair(id)?;
            return Err(error);
        }
        // The point of no return: the new version is active. The journal
        // stays if the clean-up fails, and the next recovery completes it.
        if let Err(error) = self.finish(id, old.as_ref(), version) {
            tracing::warn!(extension = %id, %version, %error, "the version is active, but the clean-up did not complete");
        }
        tracing::info!(extension = %id, %version, "extension version activated");
        Ok(Outcome::Activated)
    }

    /// Writes the journal of a change from `old` to `new`.
    fn write_pending(&self, id: &ExtensionId, old: Option<&Version>, new: &Version) -> Result<()> {
        let mut journal = toml::Table::new();
        if let Some(old) = old {
            journal.insert("old".to_owned(), old.to_string().into());
        }
        journal.insert("new".to_owned(), new.to_string().into());
        write_atomic(&self.store(id).join(PENDING_FILE), &journal.to_string())
    }

    /// The first rename: moves the active directory into the store.
    fn retire(&self, id: &ExtensionId, old: Option<&Version>) -> Result<()> {
        let Some(old) = old else { return Ok(()) };
        let retired = self.store(id).join(old.to_string());
        // A directory that an earlier change left. The rename needs a free name.
        if retired.is_dir() {
            fs::remove_dir_all(&retired)
                .map_err(|error| io_error(&retired, "cannot remove the directory", error))?;
        }
        fs::rename(self.active(id), &retired)
            .map_err(|error| io_error(&retired, "cannot move the active version", error))
    }

    /// The second rename: makes the staged directory the active directory.
    fn promote(&self, id: &ExtensionId, content: &Path) -> Result<()> {
        let active = self.active(id);
        create_private_dir(&self.extensions_dir())?;
        fs::rename(content, &active)
            .map_err(|error| io_error(&active, "cannot activate the new version", error))
    }

    /// Completes a change from `old` to `new` after the second rename.
    fn finish(&self, id: &ExtensionId, old: Option<&Version>, new: &Version) -> Result<()> {
        let store = self.store(id);
        // The review, if one waited, was for the version that is active now.
        remove_file(&store.join(REVIEW_FILE))?;
        match old {
            Some(old) => write_atomic(&store.join(PREVIOUS_FILE), &old.to_string())?,
            // A broken version was replaced: its `previous` is void.
            None => remove_file(&store.join(PREVIOUS_FILE))?,
        }
        remove_file(&store.join(PENDING_FILE))?;
        if let Some(old) = old {
            // Best effort: `retire` removes a directory that stays. A
            // rollback extracts the kept package and does not read it.
            let _ = fs::remove_dir_all(store.join(old.to_string()));
        }
        self.prune(id, old, new);
        Ok(())
    }

    /// Deletes each kept package and signature of `id` that is not for the
    /// active version `new` or the previous version `old`. No review waits
    /// when a change completes. Best effort: a file that stays is deleted
    /// after the next change.
    fn prune(&self, id: &ExtensionId, old: Option<&Version>, new: &Version) {
        let store = self.store(id);
        let suffix = format!(".{PACKAGE_EXTENSION}");
        let keep = [Some(new), old].map(|version| version.map(|v| format!("{id}-{v}{suffix}")));
        let entries = match fs::read_dir(&store) {
            Ok(entries) => entries,
            Err(error) => {
                tracing::warn!(extension = %id, store = %store.display(), %error, "cannot list the kept packages");
                return;
            }
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let package = name.strip_suffix(".minisig").unwrap_or(&name);
            if package.ends_with(&suffix)
                && !keep.iter().flatten().any(|kept| kept == package)
                && let Err(error) = fs::remove_file(entry.path())
            {
                tracing::warn!(extension = %id, file = %entry.path().display(), %error, "cannot delete an old kept package");
            }
        }
    }

    /// Takes the lock of `id`. Refuses first, with a `user` error, a
    /// directory of the installer that the group or other users can write
    /// (Unix): they could put another file in the place of a verified one.
    /// The rule and the category are those of the trust store file
    /// (ADR-0019, ADR-0023). The owner is not
    /// checked. There is no check on Windows.
    fn lock(&self, id: &ExtensionId) -> Result<IdLock> {
        let store = self.store(id);
        // A link could point out of `<data>` or to the store of another id.
        if fs::symlink_metadata(&store).is_ok_and(|meta| meta.is_symlink()) {
            return Err(Error::user(format!(
                "{}: the directory must not be a symbolic link; remove the link",
                store.display()
            )));
        }
        let dirs = [
            self.data.clone(),
            self.data.join("store"),
            store.clone(),
            self.extensions_dir(),
            self.active(id),
        ];
        #[cfg(unix)]
        for dir in &dirs {
            use std::os::unix::fs::PermissionsExt;
            let mode = match fs::metadata(dir) {
                Ok(meta) => meta.permissions().mode() & 0o7777,
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                Err(error) => return Err(io_error(dir, "cannot read the directory mode", error)),
            };
            if mode & 0o022 != 0 {
                return Err(Error::user(format!(
                    "{}: the directory can be written by the group or by other users \
                     (mode {mode:04o}); permit the write for the owner only (`chmod 700`)",
                    dir.display()
                )));
            }
        }
        #[cfg(not(unix))]
        let _ = dirs;
        lock(&store, id)
    }

    fn store(&self, id: &ExtensionId) -> PathBuf {
        self.data.join("store").join(id.as_str())
    }

    fn active(&self, id: &ExtensionId) -> PathBuf {
        self.extensions_dir().join(id.as_str())
    }
}

/// Writes the three files of the verified package `file` to the new
/// directory `content`. `name` names the package in an error.
fn extract(file: File, name: &str, content: &Path) -> Result<()> {
    let malformed = |error: io::Error| {
        Error::user(format!("{name}: the package is not a valid tar archive")).with_source(error)
    };
    let refused = |reason: String| Error::policy(format!("{name}: {reason}"));
    create_private_dir(content)?;

    let mut archive = tar::Archive::new(file);
    // The position after the last entry.
    let mut end = 0;
    // Raw: a long name entry or a PAX entry is an entry, with its own name.
    for entry in archive.entries().map_err(malformed)?.raw(true) {
        let mut entry = entry.map_err(malformed)?;
        end = entry.raw_file_position() + entry.size().next_multiple_of(512);
        let path = entry.path_bytes().into_owned();
        // The target name is the constant, never the text of the archive.
        let Some(&(entry_name, limit)) = ENTRIES
            .iter()
            .find(|(entry_name, _)| entry_name.as_bytes() == path)
        else {
            let (shown, cut) = match path.get(..ENTRY_NAME_SHOWN_BYTES) {
                Some(start) if start.len() < path.len() => (start, "..."),
                _ => (&path[..], ""),
            };
            return Err(refused(format!(
                "the entry `{}{cut}` is not permitted: a package holds only `{MANIFEST_FILE}`, \
                 `{COMPONENT_FILE}` and `{LICENCE_FILE}`",
                String::from_utf8_lossy(shown).escape_debug()
            )));
        };
        if entry.header().entry_type() != tar::EntryType::Regular {
            return Err(refused(format!(
                "the entry `{entry_name}` is not a regular file"
            )));
        }
        let too_large = || {
            refused(format!(
                "the entry `{entry_name}` is larger than {limit} bytes"
            ))
        };
        if entry.size() > limit {
            return Err(too_large());
        }
        let target = content.join(entry_name);
        let mut out = create_private_file(&target).map_err(|error| match error.kind() {
            ErrorKind::AlreadyExists => refused(format!(
                "the entry `{entry_name}` is in the package more than one time"
            )),
            _ => io_error(&target, "cannot write the file", error),
        })?;
        let written = io::copy(&mut (&mut entry).take(limit + 1), &mut out)
            .and_then(|written| out.sync_all().map(|()| written))
            .map_err(|error| io_error(&target, "cannot extract the entry", error))?;
        if written > limit {
            return Err(too_large());
        }
    }
    // The archive library stops at the first block of zeros and at the end
    // of the file. The end mark and the padding of `tar` must follow the
    // entries, and nothing else.
    let mut rest = archive.into_inner();
    let zeros = rest
        .metadata()
        .map_err(malformed)?
        .len()
        .saturating_sub(end);
    if zeros < END_MARK_BYTES {
        return Err(refused(
            "the package does not end with the end mark of a tar archive (two blocks of zeros)"
                .to_owned(),
        ));
    }
    if zeros >= END_MARK_BYTES + RECORD_BYTES {
        return Err(refused(format!(
            "the package has {zeros} bytes after the entries; the end mark and the padding \
             are less than {} bytes",
            END_MARK_BYTES + RECORD_BYTES
        )));
    }
    let mut tail = Vec::new();
    rest.seek(SeekFrom::Start(end))
        .and_then(|_| {
            rest.take(END_MARK_BYTES + RECORD_BYTES)
                .read_to_end(&mut tail)
        })
        .map_err(malformed)?;
    if (tail.len() as u64) < END_MARK_BYTES || tail.iter().any(|byte| *byte != 0) {
        return Err(refused(
            "the package has data after the end of the archive".to_owned(),
        ));
    }
    match ENTRIES
        .iter()
        .find(|(entry_name, _)| !content.join(entry_name).is_file())
    {
        Some((missing, _)) => Err(refused(format!("the entry `{missing}` is missing"))),
        None => Ok(()),
    }
}

/// The held lock of an id.
struct IdLock(File);

impl Drop for IdLock {
    fn drop(&mut self) {
        // To close the file is not sufficient. A child process that another
        // thread starts at this moment holds a copy of the file handle until
        // its `exec`, and the lock would stay for that time.
        let _ = self.0.unlock();
    }
}

/// Takes the exclusive lock of the id with the store directory `store`, or
/// returns a `retryable` error if another operation holds it. To drop the
/// result releases the lock.
///
/// Each call opens the file again: the lock belongs to the open file, so it
/// also stops a second thread of this process.
fn lock(store: &Path, id: &ExtensionId) -> Result<IdLock> {
    create_private_dir(store)?;
    let path = store.join(LOCK_FILE);
    // Does not follow a symbolic link and does not open a FIFO.
    match create_private_file(&path) {
        Err(error) if error.kind() != ErrorKind::AlreadyExists => {
            return Err(io_error(&path, "cannot create the lock file", error));
        }
        _ => {}
    }
    // A planted symbolic link could lock or create a file out of the store;
    // the open of a planted FIFO does not return. The content is never
    // read, so there is no size limit.
    let file = open_regular(&path, "lock", u64::MAX)?;
    // A second hard link could be the lock file of another id.
    #[cfg(unix)]
    {
        let links = file
            .metadata()
            .map(|meta| std::os::unix::fs::MetadataExt::nlink(&meta))
            .map_err(|error| io_error(&path, "cannot read the lock file", error))?;
        if links > 1 {
            return Err(Error::user(format!(
                "{}: the lock file has {links} hard links; remove the file and try again",
                path.display()
            )));
        }
    }
    match file.try_lock() {
        Ok(()) => Ok(IdLock(file)),
        Err(fs::TryLockError::WouldBlock) => Err(Error::retryable(format!(
            "extension `{id}`: another install operation on this extension runs; try again"
        ))),
        Err(fs::TryLockError::Error(error)) => Err(io_error(&path, "cannot lock the file", error)),
    }
}

/// Creates the directory `dir` and each parent that is missing. On Unix,
/// only the owner can use a directory that this creates (mode 0700).
fn create_private_dir(dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(dir)
        .map_err(|error| io_error(dir, "cannot create the directory", error))
}

/// Creates the new file `path` for writing. Fails if something has that
/// name; does not follow a symbolic link. On Unix, only the owner can read
/// and write the file (mode 0600), whatever the umask is.
fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = File::options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Reads the journal file `path`. Returns `None` for a file that cannot be
/// read: a symbolic link, a directory, more than [`JOURNAL_MAX_BYTES`], a
/// text that is not UTF-8 or that [`parse_journal`] refuses.
fn read_journal(path: &Path) -> Option<(Option<Version>, Version)> {
    let mut text = String::new();
    open_regular(path, "journal", JOURNAL_MAX_BYTES)
        .ok()?
        .take(JOURNAL_MAX_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    parse_journal(&text)
}

/// Returns `true` if `path` is a directory and not a symbolic link to one.
fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir())
}

/// Reads the journal text: the old version, if one was active, and the new
/// version. Returns `None` for a text that [`Installer::write_pending`]
/// does not write.
fn parse_journal(text: &str) -> Option<(Option<Version>, Version)> {
    let journal: toml::Table = text.parse().ok()?;
    let version = |key: &str| journal.get(key)?.as_str()?.parse::<Version>().ok();
    let old = if journal.contains_key("old") {
        Some(version("old")?)
    } else {
        None
    };
    Some((old, version("new")?))
}

/// Returns the version of the one retired directory in `store`, or `None`
/// if there is none. This is the answer of the directories when the journal
/// `journal` does not name a retired directory and the active directory is
/// missing. A symbolic link is not a retired directory.
///
/// Returns an `internal` error, and changes nothing, if there are two or
/// more: the directories do not say which version was active.
fn sole_retired(store: &Path, journal: &Path) -> Result<Option<Version>> {
    let unreadable = |error| io_error(store, "cannot read the directory", error);
    let mut retired = Vec::new();
    for entry in fs::read_dir(store).map_err(unreadable)? {
        let entry = entry.map_err(unreadable)?;
        if let Ok(version) = entry.file_name().to_string_lossy().parse::<Version>()
            && entry.file_type().is_ok_and(|kind| kind.is_dir())
        {
            retired.push(version);
        }
    }
    if retired.len() > 1 {
        return Err(Error::internal(format!(
            "{}: the journal does not name the version that was active and {} has {} \
             directories of retired versions; keep the directory of the version that was \
             active, remove the others and try again",
            journal.display(),
            store.display(),
            retired.len()
        )));
    }
    Ok(retired.pop())
}

/// Copies the regular file `from` to the new file `to`. Refuses a symbolic
/// link, anything that is not a regular file, and more than `max_bytes`.
fn copy_regular(from: &Path, to: &Path, max_bytes: u64) -> Result<()> {
    let source = open_regular(from, "registry", max_bytes)?;
    let mut target =
        create_private_file(to).map_err(|error| io_error(to, "cannot write the file", error))?;
    // A file that grows after the size check is cut. The signature of the
    // copy then does not verify.
    io::copy(&mut source.take(max_bytes), &mut target)
        .map_err(|error| io_error(from, "cannot read the registry file", error))?;
    Ok(())
}

/// Replaces `path` with a file that holds `text`. The text goes to a
/// temporary file in the same directory, and that file then replaces `path`.
/// On Unix `tempfile` creates the file with mode 0600.
// shortcut: the directory is not synced, so a power loss can undo the last
// rename; the journal then still describes a state that `recover` repairs
// (ADR-0023 accepts this).
fn write_atomic(path: &Path, text: &str) -> Result<()> {
    let write = || {
        let dir = path.parent().unwrap_or(Path::new("."));
        let mut file = tempfile::Builder::new()
            .prefix(TEMP_PREFIX)
            .tempfile_in(dir)?;
        file.write_all(text.as_bytes())?;
        file.as_file().sync_all()?;
        file.persist(path).map_err(|error| error.error)?;
        Ok(())
    };
    write().map_err(|error| io_error(path, "cannot write the file", error))
}

/// Removes a file. A file that does not exist is not an error.
fn remove_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != ErrorKind::NotFound => {
            Err(io_error(path, "cannot remove the file", error))
        }
        _ => Ok(()),
    }
}

/// A `user` error that names the file.
fn io_error(path: &Path, problem: &str, error: io::Error) -> Error {
    Error::user(format!("{}: {problem}", path.display())).with_source(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rivet_sdk::error::ErrorCategory;
    use tar::EntryType;

    const NETWORK: &str = "[[capabilities.network]]\nhost = \"db.example.com\"\nports = [5432]\n";

    fn id() -> ExtensionId {
        "acme.postgres".parse().unwrap()
    }

    fn v(text: &str) -> Version {
        text.parse().unwrap()
    }

    fn manifest(id: &str, version: &str, extra: &str) -> String {
        format!("id = \"{id}\"\nversion = \"{version}\"\nsdk = \">=0.1.0, <0.2.0\"\n{extra}")
    }

    /// A tar archive. The name is written as it is, so a hostile name is
    /// possible.
    fn archive(entries: &[(&str, EntryType, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, kind, data) in entries {
            let mut header = tar::Header::new_ustar();
            header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            header.set_entry_type(*kind);
            header.set_mode(0o777);
            if *kind == EntryType::Symlink {
                header.as_old_mut().linkname[..data.len()].copy_from_slice(data);
                header.set_size(0);
                header.set_cksum();
                builder.append(&header, &[][..]).unwrap();
            } else {
                header.set_size(data.len() as u64);
                header.set_cksum();
                builder.append(&header, *data).unwrap();
            }
        }
        builder.into_inner().unwrap()
    }

    /// A valid package with one more entry list in front of the licence.
    fn package_with(manifest: &str, more: &[(&str, EntryType, &[u8])]) -> Vec<u8> {
        let mut entries = vec![
            (MANIFEST_FILE, EntryType::Regular, manifest.as_bytes()),
            (COMPONENT_FILE, EntryType::Regular, &b"\0asm component"[..]),
        ];
        entries.extend_from_slice(more);
        archive(&entries)
    }

    fn package(version: &str, extra: &str) -> Vec<u8> {
        package_with(
            &manifest("acme.postgres", version, extra),
            &[(LICENCE_FILE, EntryType::Regular, b"MIT")],
        )
    }

    /// A data directory, a registry directory and a trust store that pins
    /// the TEST-ONLY key of the publisher `acme`.
    struct Fixture {
        dir: tempfile::TempDir,
        key: minisign::KeyPair,
        installer: Installer,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let key = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let project = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let project_key: PublicKey = project.pk.to_base64().parse().unwrap();
        let trust_file = dir.path().join("config/trust.toml");
        let mut trust = TrustStore::new(project_key.clone());
        trust
            .pin("acme", key.pk.to_base64().parse().unwrap())
            .unwrap();
        trust.save(&trust_file).unwrap();
        let installer = Installer {
            project_key,
            data: dir.path().join("data"),
            registry: dir.path().join("registry"),
            trust_file,
        };
        Fixture {
            dir,
            key,
            installer,
        }
    }

    impl Fixture {
        /// Puts `package` in the registry as `version`, signed for `version`.
        fn publish(&self, version: &str, package: &[u8]) {
            let dir = self.installer.registry.join("acme.postgres").join(version);
            fs::create_dir_all(&dir).unwrap();
            let name = format!("acme.postgres-{version}.rivetpkg");
            let comment = format!("rivet-package id=acme.postgres version={version}");
            let signature = minisign::sign(
                Some(&self.key.pk),
                &self.key.sk,
                package,
                Some(&comment),
                None,
            )
            .unwrap()
            .into_string();
            fs::write(dir.join(&name), package).unwrap();
            fs::write(dir.join(format!("{name}.minisig")), signature).unwrap();
        }

        fn install(&self, version: &str, package: &[u8]) -> Result<Outcome> {
            self.publish(version, package);
            self.installer.install(&id(), &v(version))
        }

        fn update(&self, version: &str, package: &[u8]) -> Result<Outcome> {
            self.publish(version, package);
            self.installer.update(&id(), &v(version))
        }

        fn active_version(&self) -> Option<String> {
            let manifest = self.installer.installed(&id()).unwrap()?;
            Some(manifest.version.to_string())
        }

        fn store(&self) -> PathBuf {
            self.installer.store(&id())
        }

        /// Asserts that nothing is installed and no package is kept.
        fn assert_nothing_installed(&self) {
            assert!(!self.installer.active(&id()).exists());
            let kept: Vec<_> = fs::read_dir(self.store())
                .map(|entries| entries.map(|entry| entry.unwrap().file_name()).collect())
                .unwrap_or_default();
            assert_eq!(kept, [LOCK_FILE]);
        }

        /// Installs 1.0.0, then stages 2.0.0 by hand for a crash test.
        /// Returns the staged directory.
        fn staged_update(&self) -> PathBuf {
            self.install("1.0.0", &package("1.0.0", "")).unwrap();
            let content = self.store().join(".staging-test").join("content");
            fs::create_dir_all(&content).unwrap();
            fs::write(
                content.join(MANIFEST_FILE),
                manifest("acme.postgres", "2.0.0", ""),
            )
            .unwrap();
            content
        }
    }

    /// Asserts an error of `category` whose text contains `part`.
    fn assert_error<T: std::fmt::Debug>(result: Result<T>, category: ErrorCategory, part: &str) {
        let error = result.expect_err("an error");
        assert_eq!(error.category(), category, "{error}");
        assert!(error.to_string().contains(part), "{error}");
    }

    // Criterion 1: the package format.

    #[test]
    fn a_package_holds_manifest_component_and_licence() {
        let f = fixture();
        assert_eq!(
            f.install("1.0.0", &package("1.0.0", "")).unwrap(),
            Outcome::Activated
        );

        let active = f.installer.extensions_dir().join("acme.postgres");
        let mut names: Vec<_> = fs::read_dir(&active)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["LICENSE", "extension.toml", "extension.wasm"]);
        assert_eq!(fs::read(active.join(LICENCE_FILE)).unwrap(), b"MIT");
        assert_eq!(
            fs::read(active.join(COMPONENT_FILE)).unwrap(),
            b"\0asm component"
        );
    }

    #[test]
    fn a_package_without_a_licence_is_refused() {
        let f = fixture();
        let package = package_with(&manifest("acme.postgres", "1.0.0", ""), &[]);
        assert_error(
            f.install("1.0.0", &package),
            ErrorCategory::Policy,
            "the entry `LICENSE` is missing",
        );
        f.assert_nothing_installed();
    }

    #[test]
    fn an_unknown_entry_is_refused() {
        let f = fixture();
        let package = package_with(
            &manifest("acme.postgres", "1.0.0", ""),
            &[
                (LICENCE_FILE, EntryType::Regular, b"MIT"),
                ("native/x86_64/lib.so", EntryType::Regular, b"x"),
            ],
        );
        assert_error(
            f.install("1.0.0", &package),
            ErrorCategory::Policy,
            "`native/x86_64/lib.so` is not permitted",
        );
        f.assert_nothing_installed();
    }

    // Criterion 2: install verifies first.

    #[test]
    fn install_keeps_the_verified_package_and_its_signature() {
        let f = fixture();
        let package = package("1.0.0", "");
        f.install("1.0.0", &package).unwrap();

        assert_eq!(f.active_version().as_deref(), Some("1.0.0"));
        let kept = f.store().join("acme.postgres-1.0.0.rivetpkg");
        assert_eq!(fs::read(&kept).unwrap(), package);
        assert!(kept.with_extension("rivetpkg.minisig").is_file());
        // No staging directory and no journal stay: only the lock file.
        assert!(!f.store().join(PENDING_FILE).exists());
        assert_eq!(fs::read_dir(f.store()).unwrap().count(), 3);
    }

    #[test]
    fn a_changed_package_installs_nothing() {
        let f = fixture();
        f.publish("1.0.0", &package("1.0.0", ""));
        let file = f
            .installer
            .registry
            .join("acme.postgres/1.0.0/acme.postgres-1.0.0.rivetpkg");
        fs::write(&file, package("1.0.0", NETWORK)).unwrap();

        assert_error(
            f.installer.install(&id(), &v("1.0.0")),
            ErrorCategory::Policy,
            "does not verify",
        );
        f.assert_nothing_installed();
    }

    #[test]
    fn a_manifest_for_another_version_or_id_installs_nothing() {
        let f = fixture();
        // The signature is for 1.0.0. The manifest in the package is not.
        assert_error(
            f.install("1.0.0", &package("1.0.1", "")),
            ErrorCategory::Policy,
            "the manifest is for `acme.postgres` version 1.0.1",
        );
        let other = package_with(
            &manifest("acme.mysql", "1.0.0", ""),
            &[(LICENCE_FILE, EntryType::Regular, b"MIT")],
        );
        assert_error(
            f.install("1.0.0", &other),
            ErrorCategory::Policy,
            "the manifest is for `acme.mysql`",
        );
        f.assert_nothing_installed();
    }

    #[test]
    fn a_package_that_is_not_in_the_registry_is_a_user_error() {
        let f = fixture();
        assert_error(
            f.installer.install(&id(), &v("1.0.0")),
            ErrorCategory::User,
            "cannot read the registry file",
        );
        f.assert_nothing_installed();
    }

    #[test]
    fn a_signed_file_that_is_not_an_archive_is_a_user_error() {
        let f = fixture();
        assert_error(
            f.install("1.0.0", &[b'x'; 2048]),
            ErrorCategory::User,
            "not a valid tar archive",
        );
        f.assert_nothing_installed();
    }

    #[test]
    fn an_invalid_manifest_is_a_user_error() {
        let f = fixture();
        let package = package_with("id = 1", &[(LICENCE_FILE, EntryType::Regular, b"MIT")]);
        assert_error(
            f.install("1.0.0", &package),
            ErrorCategory::User,
            "invalid extension manifest",
        );
        f.assert_nothing_installed();
    }

    // Criterion 3: update, rollback and failed changes.

    #[test]
    fn update_then_rollback_to_the_previous_version() {
        let f = fixture();
        f.install("1.0.0", &package("1.0.0", "")).unwrap();
        assert_eq!(
            f.update("1.1.0", &package("1.1.0", "")).unwrap(),
            Outcome::Activated
        );
        assert_eq!(f.active_version().as_deref(), Some("1.1.0"));

        assert_eq!(f.installer.rollback(&id()).unwrap(), Outcome::Activated);
        assert_eq!(f.active_version().as_deref(), Some("1.0.0"));
        // The active directory is complete after the rollback.
        assert!(f.installer.active(&id()).join(COMPONENT_FILE).is_file());
    }

    #[test]
    fn install_and_update_refuse_the_wrong_start_state() {
        let f = fixture();
        assert_error(
            f.update("1.0.0", &package("1.0.0", "")),
            ErrorCategory::User,
            "is not installed",
        );
        f.install("1.1.0", &package("1.1.0", "")).unwrap();
        assert_error(
            f.installer.install(&id(), &v("1.0.0")),
            ErrorCategory::User,
            "is installed in version 1.1.0",
        );
        assert_error(
            f.update("1.0.0", &package("1.0.0", "")),
            ErrorCategory::User,
            "is not newer",
        );
        assert_error(
            f.installer.rollback(&id()),
            ErrorCategory::User,
            "no previous version",
        );
        assert_eq!(f.active_version().as_deref(), Some("1.1.0"));
    }

    #[test]
    fn a_failed_update_keeps_the_installed_version() {
        let f = fixture();
        f.install("1.0.0", &package("1.0.0", "")).unwrap();
        // The manifest in the package is for another version.
        assert_error(
            f.update("2.0.0", &package("2.0.1", "")),
            ErrorCategory::Policy,
            "the manifest is for",
        );
        assert_eq!(f.active_version().as_deref(), Some("1.0.0"));
        assert!(f.installer.active(&id()).join(COMPONENT_FILE).is_file());
        assert!(!f.store().join("acme.postgres-2.0.0.rivetpkg").exists());
    }

    #[test]
    fn a_rollback_whose_kept_package_was_changed_keeps_the_active_version() {
        let f = fixture();
        f.install("1.0.0", &package("1.0.0", "")).unwrap();
        f.update("1.1.0", &package("1.1.0", "")).unwrap();
        fs::write(
            f.store().join("acme.postgres-1.0.0.rivetpkg"),
            package("1.0.0", NETWORK),
        )
        .unwrap();

        assert_error(
            f.installer.rollback(&id()),
            ErrorCategory::Policy,
            "does not verify",
        );
        assert_eq!(f.active_version().as_deref(), Some("1.1.0"));
    }

    #[test]
    fn a_crash_after_the_journal_keeps_the_old_version() {
        let f = fixture();
        let content = f.staged_update();
        f.installer
            .write_pending(&id(), Some(&v("1.0.0")), &v("2.0.0"))
            .unwrap();

        f.installer.recover(&id()).unwrap();
        assert_eq!(f.active_version().as_deref(), Some("1.0.0"));
        assert!(!f.store().join(PENDING_FILE).exists());
        assert!(!content.exists());
        assert!(!f.store().join(PREVIOUS_FILE).exists());
    }

    #[test]
    fn a_crash_after_the_first_rename_puts_the_old_version_back() {
        let f = fixture();
        f.staged_update();
        f.installer
            .write_pending(&id(), Some(&v("1.0.0")), &v("2.0.0"))
            .unwrap();
        f.installer.retire(&id(), Some(&v("1.0.0"))).unwrap();
        assert_eq!(f.active_version(), None);

        // The next operation recovers first. Here it fails after that.
        assert_error(
            f.installer.update(&id(), &v("2.0.0")),
            ErrorCategory::User,
            "cannot read the registry file",
        );
        assert_eq!(f.active_version().as_deref(), Some("1.0.0"));
        assert!(f.installer.active(&id()).join(COMPONENT_FILE).is_file());
        assert!(!f.store().join(PENDING_FILE).exists());
        assert!(!f.store().join("1.0.0").exists());
    }

    #[test]
    fn a_crash_after_the_second_rename_keeps_the_new_version_and_the_rollback() {
        let f = fixture();
        let content = f.staged_update();
        f.installer
            .write_pending(&id(), Some(&v("1.0.0")), &v("2.0.0"))
            .unwrap();
        f.installer.retire(&id(), Some(&v("1.0.0"))).unwrap();
        f.installer.promote(&id(), &content).unwrap();

        f.installer.recover(&id()).unwrap();
        assert_eq!(f.active_version().as_deref(), Some("2.0.0"));
        assert!(!f.store().join(PENDING_FILE).exists());
        assert!(!f.store().join("1.0.0").exists());
        assert_eq!(f.installer.rollback(&id()).unwrap(), Outcome::Activated);
        assert_eq!(f.active_version().as_deref(), Some("1.0.0"));
    }

    // R-70: the second rename is the point of no return.

    #[test]
    fn a_failed_clean_up_after_the_second_rename_is_not_an_error() {
        let f = fixture();
        f.install("1.0.0", &package("1.0.0", "")).unwrap();
        // `previous` cannot be written: a directory has its name.
        fs::create_dir(f.store().join(PREVIOUS_FILE)).unwrap();

        assert_eq!(
            f.update("1.1.0", &package("1.1.0", "")).unwrap(),
            Outcome::Activated
        );
        assert_eq!(f.active_version().as_deref(), Some("1.1.0"));
        assert!(f.store().join(PENDING_FILE).exists());

        // The next recovery completes the clean-up from the journal.
        fs::remove_dir(f.store().join(PREVIOUS_FILE)).unwrap();
        f.installer.recover(&id()).unwrap();
        assert!(!f.store().join(PENDING_FILE).exists());
        assert!(!f.store().join("1.0.0").exists());
        assert_eq!(f.active_version().as_deref(), Some("1.1.0"));
        assert_eq!(f.installer.rollback(&id()).unwrap(), Outcome::Activated);
        assert_eq!(f.active_version().as_deref(), Some("1.0.0"));
    }

    // R-69: the operations on one id run one after the other.

    #[test]
    fn concurrent_updates_of_one_id_keep_one_complete_active_version() {
        const THREADS: usize = 8;
        let versions: Vec<String> = (1..=THREADS).map(|minor| format!("1.{minor}.0")).collect();
        let (mut lost, mut incomplete, mut journal, mut staging, mut errors) = (0, 0, 0, 0, 0);
        for _round in 0..40 {
            let f = fixture();
            f.install("1.0.0", &package("1.0.0", "")).unwrap();
            for version in &versions {
                f.publish(version, &package(version, ""));
            }
            let start = std::sync::Barrier::new(THREADS);
            let results: Vec<Result<Outcome>> = std::thread::scope(|scope| {
                let threads: Vec<_> = versions
                    .iter()
                    .map(|version| {
                        let (start, installer) = (&start, &f.installer);
                        scope.spawn(move || {
                            start.wait();
                            installer.update(&id(), &v(version))
                        })
                    })
                    .collect();
                threads
                    .into_iter()
                    .map(|thread| thread.join().unwrap())
                    .collect()
            });

            // A thread that found the lock taken got a `retryable` error. A
            // thread that ran after a newer version got a `user` error.
            errors += usize::from(results.iter().any(|result| match result {
                Ok(outcome) => *outcome != Outcome::Activated,
                Err(error) => {
                    error.category() != ErrorCategory::Retryable
                        && !error.to_string().contains("is not newer")
                }
            }));
            let active = f.installer.active(&id());
            match f.installer.installed(&id()).ok().flatten() {
                Some(manifest) if versions.contains(&manifest.version.to_string()) => {
                    let complete = ENTRIES.iter().all(|(name, _)| active.join(name).is_file());
                    incomplete += usize::from(!complete);
                }
                _ => lost += 1,
            }
            journal += usize::from(f.store().join(PENDING_FILE).exists());
            staging += usize::from(fs::read_dir(f.store()).unwrap().any(|entry| {
                let name = entry.unwrap().file_name();
                name.to_string_lossy().starts_with(STAGING_PREFIX)
            }));
        }
        assert_eq!(
            (lost, incomplete, journal, staging, errors),
            (0, 0, 0, 0, 0),
            "rounds of 40 with (no active version, an incomplete active version, a journal \
             left, a staging directory left, an unexpected result)"
        );
    }

    #[test]
    fn the_lock_of_one_id_stops_a_second_operation_but_not_another_id() {
        let f = fixture();
        f.install("1.0.0", &package("1.0.0", "")).unwrap();
        f.publish("1.1.0", &package("1.1.0", ""));
        let held = lock(&f.store(), &id()).unwrap();

        // Each operation opens the lock file again and does not get the lock.
        let part = "another install operation";
        let (id, new) = (id(), v("1.1.0"));
        assert_error(
            f.installer.install(&id, &new),
            ErrorCategory::Retryable,
            part,
        );
        assert_error(
            f.installer.update(&id, &new),
            ErrorCategory::Retryable,
            part,
        );
        assert_error(f.installer.rollback(&id), ErrorCategory::Retryable, part);
        assert_error(f.installer.recover(&id), ErrorCategory::Retryable, part);
        assert_error(
            f.installer.activate_after_review(&id, &new),
            ErrorCategory::Retryable,
            part,
        );
        assert_eq!(f.active_version().as_deref(), Some("1.0.0"));
        // An operation on another id is not stopped.
        let other: ExtensionId = "acme.mysql".parse().unwrap();
        f.installer.recover(&other).unwrap();

        drop(held);
        assert_eq!(f.installer.update(&id, &new).unwrap(), Outcome::Activated);
    }

    /// Runs two times: the test, and a child process of the test that holds
    /// the lock of the store directory in `RIVET_TEST_LOCK_STORE`.
    #[test]
    fn the_lock_of_one_id_stops_a_second_process() {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        const STORE: &str = "RIVET_TEST_LOCK_STORE";
        const NAME: &str = "install::tests::the_lock_of_one_id_stops_a_second_process";

        if let Some(store) = std::env::var_os(STORE) {
            let _held = lock(Path::new(&store), &id()).unwrap();
            println!("locked");
            // Holds the lock until the parent closes the pipe.
            let _ = io::stdin().read(&mut [0]);
            return;
        }
        let f = fixture();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"])
            .env(STORE, f.store())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = io::BufReader::new(child.stdout.take().unwrap()).lines();
        assert!(lines.any(|line| line.unwrap().contains("locked")));

        let own = File::open(f.store().join(LOCK_FILE)).unwrap();
        assert!(matches!(own.try_lock(), Err(fs::TryLockError::WouldBlock)));
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        // The process stopped: the lock is free.
        own.try_lock().unwrap();
    }

    // Criterion 4: an update that adds capabilities.

    #[test]
    fn an_update_that_adds_capabilities_needs_a_review_and_is_not_activated() {
        let f = fixture();
        f.install("1.0.0", &package("1.0.0", "")).unwrap();

        let Outcome::NeedsReview { added } = f.update("1.1.0", &package("1.1.0", NETWORK)).unwrap()
        else {
            panic!("the update must need a review");
        };
        assert_eq!(added.network[0].host, "db.example.com");
        assert_eq!(f.active_version().as_deref(), Some("1.0.0"));

        f.installer
            .activate_after_review(&id(), &v("1.1.0"))
            .unwrap();
        assert_eq!(f.active_version().as_deref(), Some("1.1.0"));
    }

    #[test]
    fn a_rollback_that_adds_capabilities_needs_a_review() {
        let f = fixture();
        f.install("1.0.0", &package("1.0.0", NETWORK)).unwrap();
        // The update removes a capability: no review.
        assert_eq!(
            f.update("1.1.0", &package("1.1.0", "")).unwrap(),
            Outcome::Activated
        );

        assert!(matches!(
            f.installer.rollback(&id()).unwrap(),
            Outcome::NeedsReview { .. }
        ));
        assert_eq!(f.active_version().as_deref(), Some("1.1.0"));
    }

    #[test]
    fn activate_after_review_needs_a_kept_package() {
        let f = fixture();
        fs::create_dir_all(f.store()).unwrap();
        fs::write(f.store().join(REVIEW_FILE), "1.0.0").unwrap();
        assert_error(
            f.installer.activate_after_review(&id(), &v("1.0.0")),
            ErrorCategory::User,
            "the store has no package of version 1.0.0",
        );
    }

    // Criterion 5: hostile package content.

    fn assert_refused(entry: (&str, EntryType, &[u8]), part: &str) {
        let f = fixture();
        let hostile = package_with(
            &manifest("acme.postgres", "1.0.0", ""),
            &[(LICENCE_FILE, EntryType::Regular, b"MIT"), entry],
        );
        assert_error(f.install("1.0.0", &hostile), ErrorCategory::Policy, part);
        f.assert_nothing_installed();
        // Nothing was written out of the data directory.
        assert!(!f.dir.path().join("evil").exists());
        assert!(!f.installer.data.join("evil").exists());
    }

    #[test]
    fn an_entry_path_with_dot_dot_is_refused() {
        assert_refused(
            ("../../../evil", EntryType::Regular, b"x"),
            "`../../../evil` is not permitted",
        );
    }

    #[test]
    fn an_absolute_entry_path_is_refused() {
        assert_refused(
            ("/tmp/rivet-evil", EntryType::Regular, b"x"),
            "`/tmp/rivet-evil` is not permitted",
        );
    }

    #[test]
    fn a_symbolic_link_entry_is_refused() {
        let f = fixture();
        let hostile = package_with(
            &manifest("acme.postgres", "1.0.0", ""),
            &[(LICENCE_FILE, EntryType::Symlink, b"/etc/passwd")],
        );
        assert_error(
            f.install("1.0.0", &hostile),
            ErrorCategory::Policy,
            "the entry `LICENSE` is not a regular file",
        );
        f.assert_nothing_installed();
    }

    #[test]
    fn an_entry_above_the_size_limit_is_refused() {
        let f = fixture();
        let large = vec![b'x'; TEXT_ENTRY_MAX_BYTES as usize + 1];
        let hostile = package_with(
            &manifest("acme.postgres", "1.0.0", ""),
            &[(LICENCE_FILE, EntryType::Regular, &large)],
        );
        assert_error(
            f.install("1.0.0", &hostile),
            ErrorCategory::Policy,
            "the entry `LICENSE` is larger than 1048576 bytes",
        );
        f.assert_nothing_installed();
    }

    #[test]
    fn a_component_above_the_size_limit_is_refused() {
        let f = fixture();
        // Only the header: it declares the size, and no data follows.
        let mut header = tar::Header::new_ustar();
        header.as_old_mut().name[..COMPONENT_FILE.len()].copy_from_slice(COMPONENT_FILE.as_bytes());
        header.set_entry_type(EntryType::Regular);
        // The limit of the WASM runtime: a package that installs can load.
        let limit = DEFAULT_COMPONENT_BYTES as u64;
        header.set_size(limit + 1);
        header.set_cksum();
        assert_error(
            f.install("1.0.0", header.as_bytes()),
            ErrorCategory::Policy,
            &format!("the entry `extension.wasm` is larger than {limit} bytes"),
        );
        f.assert_nothing_installed();
    }

    #[test]
    fn a_fourth_entry_is_refused() {
        // The three names are used, so one more entry is a duplicate.
        assert_refused(
            (COMPONENT_FILE, EntryType::Regular, b"second"),
            "`extension.wasm` is in the package more than one time",
        );
    }

    // R-84: raw entries, the end of the archive, the entry name in an error.

    #[test]
    fn a_gnu_long_name_entry_is_refused() {
        let f = fixture();
        // The long name entry gives the next entry the name `extension.toml`.
        let hostile = archive(&[
            ("././@LongLink", EntryType::GNULongName, b"extension.toml\0"),
            (
                "../..",
                EntryType::Regular,
                manifest("acme.postgres", "1.0.0", "").as_bytes(),
            ),
            (COMPONENT_FILE, EntryType::Regular, b"\0asm component"),
            (LICENCE_FILE, EntryType::Regular, b"MIT"),
        ]);
        assert_error(
            f.install("1.0.0", &hostile),
            ErrorCategory::Policy,
            "`././@LongLink` is not permitted",
        );
        f.assert_nothing_installed();
    }

    #[test]
    fn an_entry_after_the_end_of_the_archive_is_refused() {
        let f = fixture();
        let mut hostile = package("1.0.0", "");
        hostile.extend(archive(&[("evil", EntryType::Regular, b"x")]));
        assert_error(
            f.install("1.0.0", &hostile),
            ErrorCategory::Policy,
            "data after the end of the archive",
        );
        f.assert_nothing_installed();
    }

    #[test]
    fn a_long_entry_name_is_cut_in_the_error() {
        let f = fixture();
        let name = "a".repeat(100);
        let hostile = package_with(
            &manifest("acme.postgres", "1.0.0", ""),
            &[(&name, EntryType::Regular, b"x")],
        );
        let error = f.install("1.0.0", &hostile).unwrap_err().to_string();
        let shown = "a".repeat(ENTRY_NAME_SHOWN_BYTES);
        assert!(
            error.contains(&format!("`{shown}...` is not permitted")),
            "{error}"
        );

        // A name of 1 MiB in a long name entry.
        let long = vec![b'a'; 1024 * 1024];
        let hostile = archive(&[
            ("././@LongLink", EntryType::GNULongName, &long),
            ("x", EntryType::Regular, b"x"),
        ]);
        let error = f.install("1.0.1", &hostile).unwrap_err().to_string();
        assert!(error.len() < 512, "{} bytes", error.len());
    }

    // R-84: a review that waits, and build metadata.

    #[test]
    fn activate_after_review_needs_a_review_that_waits_for_the_version() {
        let f = fixture();
        f.install("3.0.0", &package("3.0.0", "")).unwrap();
        // The update is refused, but the store has a signed package of 1.0.0.
        assert_error(
            f.update("1.0.0", &package("1.0.0", "")),
            ErrorCategory::User,
            "is not newer",
        );
        let from = f.installer.registry.join("acme.postgres/1.0.0");
        for name in [
            "acme.postgres-1.0.0.rivetpkg",
            "acme.postgres-1.0.0.rivetpkg.minisig",
        ] {
            fs::copy(from.join(name), f.store().join(name)).unwrap();
        }
        assert_error(
            f.installer.activate_after_review(&id(), &v("1.0.0")),
            ErrorCategory::Policy,
            "no review waits",
        );
        assert_eq!(f.active_version().as_deref(), Some("3.0.0"));

        // A review waits for 3.1.0 only, and a newer operation removes it.
        assert!(matches!(
            f.update("3.1.0", &package("3.1.0", NETWORK)).unwrap(),
            Outcome::NeedsReview { .. }
        ));
        assert_error(
            f.installer.activate_after_review(&id(), &v("1.0.0")),
            ErrorCategory::Policy,
            "no review waits",
        );
        assert_eq!(
            f.update("3.0.1", &package("3.0.1", "")).unwrap(),
            Outcome::Activated
        );
        assert_error(
            f.installer.activate_after_review(&id(), &v("3.1.0")),
            ErrorCategory::Policy,
            "no review waits",
        );
        assert_eq!(f.active_version().as_deref(), Some("3.0.1"));

        // The record is used one time.
        f.installer.update(&id(), &v("3.1.0")).unwrap();
        f.installer
            .activate_after_review(&id(), &v("3.1.0"))
            .unwrap();
        assert_eq!(f.active_version().as_deref(), Some("3.1.0"));
        assert!(!f.store().join(REVIEW_FILE).exists());
    }

    #[test]
    fn a_version_with_other_build_metadata_is_not_an_update() {
        let f = fixture();
        f.install("1.0.0+a", &package("1.0.0+a", "")).unwrap();
        assert_error(
            f.update("1.0.0+b", &package("1.0.0+b", "")),
            ErrorCategory::User,
            "is not newer",
        );
        assert_eq!(f.active_version().as_deref(), Some("1.0.0+a"));
    }

    // Criterion 6: the trust store file.

    #[test]
    fn the_trust_store_path_is_the_user_configuration_directory_only() {
        let key: PublicKey = minisign::KeyPair::generate_unencrypted_keypair()
            .unwrap()
            .pk
            .to_base64()
            .parse()
            .unwrap();
        let expected = user_settings_path()
            .map(|path| path.with_file_name("trust.toml"))
            .map_err(|error| error.to_string());
        let actual = Installer::new(key, "workspace/data".into(), "workspace/registry".into())
            .map(|installer| installer.trust_file)
            .map_err(|error| error.to_string());
        assert_eq!(actual, expected);
    }

    #[test]
    fn a_trust_store_in_a_workspace_or_bundled_directory_is_not_read() {
        let mut f = fixture();
        // The same valid trust store, in each directory that a workspace or
        // a bundle controls. The user configuration directory has none.
        let trust = fs::read(&f.installer.trust_file).unwrap();
        fs::remove_file(&f.installer.trust_file).unwrap();
        f.publish("1.0.0", &package("1.0.0", ""));
        for dir in [
            f.installer.registry.clone(),
            f.installer.registry.join("acme.postgres"),
            f.installer.registry.join("acme.postgres/1.0.0"),
            f.installer.data.clone(),
            f.installer.extensions_dir(),
            f.installer.store(&id()),
        ] {
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("trust.toml"), &trust).unwrap();
        }

        assert_error(
            f.installer.install(&id(), &v("1.0.0")),
            ErrorCategory::Policy,
            "publisher `acme` has no pinned key",
        );
        assert!(!f.installer.active(&id()).exists());

        // The same package installs with the file in the permitted place.
        // Only the user can write it, also with a wide umask (ADR-0019).
        f.installer.trust_file = f.dir.path().join("config/trust.toml");
        fs::write(&f.installer.trust_file, &trust).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&f.installer.trust_file, mode).unwrap();
        }
        assert_eq!(
            f.installer.install(&id(), &v("1.0.0")).unwrap(),
            Outcome::Activated
        );
    }

    // R-84 (f): the directories of the installer are private.

    #[cfg(unix)]
    fn set_mode(dir: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_that_other_users_can_write_is_refused() {
        let f = fixture();
        f.publish("1.0.0", &package("1.0.0", ""));
        f.publish("1.1.0", &package("1.1.0", ""));
        let data = f.installer.data.clone();
        fs::create_dir_all(&data).unwrap();
        set_mode(&data, 0o777);

        assert_error(
            f.installer.install(&id(), &v("1.0.0")),
            ErrorCategory::User,
            "(mode 0777)",
        );
        // Nothing was written to the directory.
        assert_eq!(fs::read_dir(&data).unwrap().count(), 0);

        set_mode(&data, 0o755);
        f.installer.install(&id(), &v("1.0.0")).unwrap();
        set_mode(&data, 0o777);
        assert_error(
            f.installer.recover(&id()),
            ErrorCategory::User,
            "(mode 0777)",
        );
        set_mode(&data, 0o755);
        f.installer.update(&id(), &v("1.1.0")).unwrap();
        // The kept package of a rollback is in a directory of the group.
        for dir in [
            f.store(),
            data.join("store"),
            f.installer.extensions_dir(),
            f.installer.active(&id()),
        ] {
            set_mode(&dir, 0o770);
            let error = f.installer.rollback(&id()).unwrap_err();
            assert_eq!(error.category(), ErrorCategory::User, "{error}");
            let part = format!("{}: the directory can be written", dir.display());
            assert!(error.to_string().contains(&part), "{error}");
            set_mode(&dir, 0o700);
        }
        assert_eq!(f.active_version().as_deref(), Some("1.1.0"));
        assert_eq!(f.installer.rollback(&id()).unwrap(), Outcome::Activated);
    }

    #[cfg(unix)]
    #[test]
    fn the_installer_creates_directories_for_the_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let f = fixture();
        f.install("1.0.0", &package("1.0.0", "")).unwrap();
        for dir in [
            f.installer.data.clone(),
            f.installer.data.join("store"),
            f.store(),
            f.installer.extensions_dir(),
            f.installer.active(&id()),
        ] {
            let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", dir.display());
        }
        // Each file is for the owner only, whatever the umask is: the
        // active files, the kept packages, `previous`, `review`, the
        // journal and the lock.
        f.update("1.1.0", &package("1.1.0", "")).unwrap();
        f.update("1.2.0", &package("1.2.0", NETWORK)).unwrap();
        f.installer
            .write_pending(&id(), Some(&v("1.1.0")), &v("1.2.0"))
            .unwrap();
        let mut files = 0;
        for dir in [f.installer.active(&id()), f.store()] {
            for entry in fs::read_dir(dir).unwrap() {
                let meta = entry.as_ref().unwrap().metadata().unwrap();
                let path = entry.unwrap().path();
                assert!(meta.is_file(), "{}", path.display());
                assert_eq!(
                    meta.permissions().mode() & 0o777,
                    0o600,
                    "{}",
                    path.display()
                );
                files += 1;
            }
        }
        // 3 active files, 3 packages with signatures, 4 other store files.
        assert_eq!(files, 13);
    }

    // R-84 (h): the journal, a broken active version, the kept packages.

    #[test]
    fn an_invalid_journal_does_not_lose_the_active_version() {
        let pending = |f: &Fixture| f.store().join(PENDING_FILE);
        for journal in ["not toml [", "new = 1", "old = \"x\"\nnew = \"2.0.0\""] {
            // A stop between the two renames: the one retired version goes back.
            let f = fixture();
            let content = f.staged_update();
            fs::write(pending(&f), journal).unwrap();
            f.installer.retire(&id(), Some(&v("1.0.0"))).unwrap();
            f.installer.recover(&id()).unwrap();
            assert_eq!(f.active_version().as_deref(), Some("1.0.0"), "{journal}");
            assert!(!pending(&f).exists());
            assert!(!f.store().join("1.0.0").exists());
            assert!(!content.exists());

            // A stop before the first rename: the active version stays.
            fs::write(pending(&f), journal).unwrap();
            f.installer.recover(&id()).unwrap();
            assert_eq!(f.active_version().as_deref(), Some("1.0.0"), "{journal}");
            assert!(!pending(&f).exists());
        }

        // Two retired versions: the recovery cannot know which was active.
        let f = fixture();
        f.staged_update();
        fs::write(pending(&f), "not toml [").unwrap();
        f.installer.retire(&id(), Some(&v("1.0.0"))).unwrap();
        fs::create_dir(f.store().join("0.9.0")).unwrap();
        let part = format!("{}: the journal does not name", pending(&f).display());
        assert_error(f.installer.recover(&id()), ErrorCategory::Internal, &part);
        assert!(pending(&f).exists());
        assert!(f.store().join("1.0.0").join(MANIFEST_FILE).is_file());
        // A person removes the wrong directory. The recovery then completes.
        fs::remove_dir(f.store().join("0.9.0")).unwrap();
        f.installer.recover(&id()).unwrap();
        assert_eq!(f.active_version().as_deref(), Some("1.0.0"));
    }

    // R-100: the lock file, an id without a store, staging directories.

    #[cfg(unix)]
    #[test]
    fn a_lock_file_that_is_not_a_regular_file_is_refused() {
        let f = std::sync::Arc::new(fixture());
        f.publish("1.0.0", &package("1.0.0", ""));
        fs::create_dir_all(f.store()).unwrap();
        let lock_file = f.store().join(LOCK_FILE);

        // A symbolic link to a file out of the data directory.
        let outside = f.dir.path().join("outside");
        std::os::unix::fs::symlink(&outside, &lock_file).unwrap();
        assert_error(
            f.installer.install(&id(), &v("1.0.0")),
            ErrorCategory::User,
            "the lock file must not be a symbolic link",
        );
        assert!(!outside.exists());
        fs::remove_file(&lock_file).unwrap();

        // A FIFO: the open of a FIFO without a reader does not return.
        let made = std::process::Command::new("mkfifo")
            .arg(&lock_file)
            .status()
            .unwrap();
        assert!(made.success());
        let (send, receive) = std::sync::mpsc::channel();
        let installer = std::sync::Arc::clone(&f);
        std::thread::spawn(move || {
            let _ = send.send(installer.installer.install(&id(), &v("1.0.0")));
        });
        let result = receive
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the install must return");
        assert_error(
            result,
            ErrorCategory::User,
            "the lock file is not a regular file",
        );
        assert_eq!(f.active_version(), None);

        fs::remove_file(&lock_file).unwrap();
        f.installer.install(&id(), &v("1.0.0")).unwrap();
    }

    #[test]
    fn recover_of_an_id_without_a_store_directory_creates_nothing() {
        let f = fixture();
        f.installer.recover(&id()).unwrap();
        assert!(!f.installer.data.exists());
    }

    #[test]
    fn the_staging_directory_of_a_stopped_process_is_removed_without_a_journal() {
        let f = fixture();
        let content = f.staged_update();
        assert!(!f.store().join(PENDING_FILE).exists());
        f.installer.recover(&id()).unwrap();
        assert!(!content.parent().unwrap().exists());
        assert_eq!(f.active_version().as_deref(), Some("1.0.0"));
    }

    /// A child process that starts while the lock is held has a copy of the
    /// file handle. The copy here stands for it.
    #[cfg(unix)]
    #[test]
    fn the_lock_is_released_while_a_copy_of_its_file_handle_is_open() {
        let f = fixture();
        let held = lock(&f.store(), &id()).unwrap();
        let _copy = held.0.try_clone().unwrap();
        drop(held);
        lock(&f.store(), &id()).unwrap();
    }

    // R-101: the review record, the end of the archive.

    #[test]
    fn a_failed_update_does_not_remove_the_review_that_waits() {
        let f = fixture();
        f.install("1.0.0", &package("1.0.0", "")).unwrap();
        assert!(matches!(
            f.update("1.1.0", &package("1.1.0", NETWORK)).unwrap(),
            Outcome::NeedsReview { .. }
        ));
        // The package of 1.2.0 is refused: its manifest is for 1.2.1.
        assert_error(
            f.update("1.2.0", &package("1.2.1", "")),
            ErrorCategory::Policy,
            "the manifest is for",
        );
        f.installer
            .activate_after_review(&id(), &v("1.1.0"))
            .unwrap();
        assert_eq!(f.active_version().as_deref(), Some("1.1.0"));
    }

    #[test]
    fn a_package_needs_the_end_mark_and_no_more_zeros_than_one_record() {
        let valid = package("1.0.0", "");
        let entries = valid.len() - END_MARK_BYTES as usize;
        let with_zeros = |zeros: usize| {
            let mut bytes = valid[..entries].to_vec();
            bytes.resize(entries + zeros, 0);
            bytes
        };
        for zeros in [0, 512, 1023] {
            let f = fixture();
            assert_error(
                f.install("1.0.0", &with_zeros(zeros)),
                ErrorCategory::Policy,
                "does not end with the end mark",
            );
            f.assert_nothing_installed();
        }
        let f = fixture();
        assert_error(
            f.install(
                "1.0.0",
                &with_zeros((END_MARK_BYTES + RECORD_BYTES) as usize),
            ),
            ErrorCategory::Policy,
            "bytes after the entries",
        );
        f.assert_nothing_installed();

        // The end mark, and the padding that `tar` writes to a full record.
        let padded = (entries + END_MARK_BYTES as usize).next_multiple_of(RECORD_BYTES as usize);
        for zeros in [END_MARK_BYTES as usize, padded - entries] {
            let f = fixture();
            assert_eq!(
                f.install("1.0.0", &with_zeros(zeros)).unwrap(),
                Outcome::Activated
            );
        }
    }

    #[test]
    fn recover_all_recovers_each_id_and_returns_the_first_error() {
        let f = fixture();
        // No store directory: nothing to do.
        f.installer.recover_all().unwrap();

        f.staged_update();
        f.installer
            .write_pending(&id(), Some(&v("1.0.0")), &v("2.0.0"))
            .unwrap();
        f.installer.retire(&id(), Some(&v("1.0.0"))).unwrap();
        // A second id whose recovery fails, and a name that is not an id.
        let other = f.installer.data.join("store/acme.mysql");
        fs::create_dir_all(other.join("1.0.0")).unwrap();
        fs::create_dir(other.join("2.0.0")).unwrap();
        fs::write(other.join(PENDING_FILE), "").unwrap();
        fs::write(f.installer.data.join("store/Not An Id"), "").unwrap();

        assert_error(
            f.installer.recover_all(),
            ErrorCategory::Internal,
            "2 directories of retired versions",
        );
        assert_eq!(f.active_version().as_deref(), Some("1.0.0"));
        assert!(!f.store().join(PENDING_FILE).exists());

        fs::remove_dir(other.join("2.0.0")).unwrap();
        f.installer.recover_all().unwrap();
    }

    #[test]
    fn install_replaces_an_active_version_with_an_invalid_manifest() {
        let f = fixture();
        f.install("1.0.0", &package("1.0.0", "")).unwrap();
        f.update("1.1.0", &package("1.1.0", "")).unwrap();
        f.publish("1.2.0", &package("1.2.0", NETWORK));
        let manifest = f.installer.active(&id()).join(MANIFEST_FILE);
        fs::write(&manifest, "id = 1").unwrap();
        // A journal is there too: the recovery must not stop on the manifest.
        f.installer
            .write_pending(&id(), Some(&v("1.1.0")), &v("1.2.0"))
            .unwrap();

        let part = format!("{}: invalid extension manifest", manifest.display());
        assert_error(f.installer.installed(&id()), ErrorCategory::User, &part);
        let way_out = "install a version of `acme.postgres` to replace it";
        assert_error(f.installer.rollback(&id()), ErrorCategory::User, way_out);
        assert_error(
            f.installer.update(&id(), &v("1.2.0")),
            ErrorCategory::User,
            way_out,
        );
        assert!(!f.store().join(PENDING_FILE).exists());

        assert_eq!(
            f.installer.install(&id(), &v("1.2.0")).unwrap(),
            Outcome::Activated
        );
        assert_eq!(f.active_version().as_deref(), Some("1.2.0"));
        assert!(f.installer.active(&id()).join(COMPONENT_FILE).is_file());
        // Only the lock file and the package and signature of 1.2.0 stay.
        assert_eq!(fs::read_dir(f.store()).unwrap().count(), 3);
        assert_error(
            f.installer.rollback(&id()),
            ErrorCategory::User,
            "no previous version",
        );
    }

    #[test]
    fn only_the_packages_of_the_active_and_the_previous_version_are_kept() {
        let f = fixture();
        let kept = |version: &str| {
            let package = f.store().join(format!("acme.postgres-{version}.rivetpkg"));
            let signature = package.with_extension("rivetpkg.minisig");
            assert_eq!(package.is_file(), signature.is_file(), "{version}");
            package.is_file()
        };
        f.install("1.0.0", &package("1.0.0", "")).unwrap();
        f.update("1.1.0", &package("1.1.0", "")).unwrap();
        f.update("1.2.0", &package("1.2.0", "")).unwrap();
        assert_eq!(
            [kept("1.0.0"), kept("1.1.0"), kept("1.2.0")],
            [false, true, true]
        );

        // A version whose review waits is kept until a change completes.
        assert!(matches!(
            f.update("1.3.0", &package("1.3.0", NETWORK)).unwrap(),
            Outcome::NeedsReview { .. }
        ));
        assert_eq!(
            [kept("1.1.0"), kept("1.2.0"), kept("1.3.0")],
            [true, true, true]
        );
        f.installer
            .activate_after_review(&id(), &v("1.3.0"))
            .unwrap();
        assert_eq!(
            [kept("1.1.0"), kept("1.2.0"), kept("1.3.0")],
            [false, true, true]
        );
        assert_eq!(f.installer.rollback(&id()).unwrap(), Outcome::Activated);
        assert_eq!(f.active_version().as_deref(), Some("1.2.0"));
        assert_eq!([kept("1.2.0"), kept("1.3.0")], [true, true]);
    }

    // R-108: a journal that cannot be read.

    /// A name and a function that makes the file at a path that shape.
    type Shape = (&'static str, fn(&Path));

    #[test]
    fn a_journal_that_cannot_be_read_does_not_lose_the_active_version() {
        let mut shapes: Vec<Shape> = vec![
            ("not UTF-8", |path| fs::write(path, [0xff, 0xfe]).unwrap()),
            ("a directory", |path| {
                fs::create_dir_all(path.join("inner")).unwrap();
            }),
        ];
        // The open of a FIFO without a writer does not return.
        #[cfg(unix)]
        shapes.push(("a FIFO", |path| {
            let made = std::process::Command::new("mkfifo").arg(path).status();
            assert!(made.unwrap().success());
        }));
        #[cfg(unix)]
        shapes.push(("mode 000", |path| {
            fs::write(path, "old = \"0.9.0\"\nnew = \"2.0.0\"").unwrap();
            set_mode(path, 0o000);
        }));
        #[cfg(unix)]
        shapes.push(("a symbolic link", |path| {
            let outside = path.parent().unwrap().join("../../../outside");
            fs::write(&outside, "new = \"2.0.0\"").unwrap();
            std::os::unix::fs::symlink(&outside, path).unwrap();
        }));
        for (shape, plant) in shapes {
            // A stop between the two renames: the one retired version goes back.
            let f = fixture();
            let content = f.staged_update();
            let pending = f.store().join(PENDING_FILE);
            plant(&pending);
            f.installer.retire(&id(), Some(&v("1.0.0"))).unwrap();
            f.installer.recover(&id()).unwrap();
            assert_eq!(f.active_version().as_deref(), Some("1.0.0"), "{shape}");
            assert!(fs::symlink_metadata(&pending).is_err(), "{shape}");
            assert!(!content.exists(), "{shape}");

            // A stop before the first rename: the active version stays.
            plant(&pending);
            f.update("1.1.0", &package("1.1.0", "")).unwrap();
            assert_eq!(f.active_version().as_deref(), Some("1.1.0"), "{shape}");
            assert!(fs::symlink_metadata(&pending).is_err(), "{shape}");
            // The target of a link is not deleted.
            assert_eq!(
                f.dir.path().join("outside").exists(),
                shape == "a symbolic link"
            );
        }
    }

    #[test]
    fn a_journal_above_the_size_limit_is_not_read() {
        let f = fixture();
        f.install("1.0.0", &package("1.0.0", "")).unwrap();
        // Without the limit this journal says: the change to 1.0.0 is done.
        let mut journal = "old = \"0.9.0\"\nnew = \"1.0.0\"\n#".to_owned();
        journal.push_str(&"#".repeat(JOURNAL_MAX_BYTES as usize));
        fs::write(f.store().join(PENDING_FILE), journal).unwrap();
        f.installer.recover(&id()).unwrap();
        assert!(!f.store().join(PENDING_FILE).exists());
        assert!(!f.store().join(PREVIOUS_FILE).exists());
        assert_eq!(f.active_version().as_deref(), Some("1.0.0"));
    }

    // R-109: an active manifest that is missing or cannot be read.

    #[test]
    fn install_replaces_an_active_version_whose_manifest_cannot_be_read() {
        let mut shapes: Vec<Shape> = vec![
            ("missing", |path| fs::remove_file(path).unwrap()),
            ("not UTF-8", |path| fs::write(path, [0xff, 0xfe]).unwrap()),
            ("a directory", |path| {
                fs::remove_file(path).unwrap();
                fs::create_dir(path).unwrap();
            }),
        ];
        #[cfg(unix)]
        shapes.push(("mode 000", |path| set_mode(path, 0o000)));
        for (shape, damage) in shapes {
            let f = fixture();
            f.install("1.0.0", &package("1.0.0", "")).unwrap();
            f.update("1.1.0", &package("1.1.0", "")).unwrap();
            f.publish("1.2.0", &package("1.2.0", NETWORK));
            damage(&f.installer.active(&id()).join(MANIFEST_FILE));

            let way_out = "install a version of `acme.postgres` to replace it";
            assert_error(f.installer.installed(&id()), ErrorCategory::User, way_out);
            assert_error(f.installer.rollback(&id()), ErrorCategory::User, way_out);
            assert_error(
                f.installer.update(&id(), &v("1.2.0")),
                ErrorCategory::User,
                way_out,
            );
            assert_eq!(
                f.installer.install(&id(), &v("1.2.0")).unwrap(),
                Outcome::Activated,
                "{shape}"
            );
            assert_eq!(f.active_version().as_deref(), Some("1.2.0"), "{shape}");
            // Only the lock file and the package and signature of 1.2.0 stay.
            assert_eq!(fs::read_dir(f.store()).unwrap().count(), 3, "{shape}");
        }
    }

    // R-110: symbolic links, the lock file, temporary files, a journal
    // that names no directory.

    #[cfg(unix)]
    #[test]
    fn a_store_directory_that_is_a_symbolic_link_is_refused() {
        use std::os::unix::fs::symlink;
        let f = fixture();
        f.publish("1.0.0", &package("1.0.0", ""));
        let outside = f.dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::create_dir_all(f.store().parent().unwrap()).unwrap();
        symlink(&outside, f.store()).unwrap();

        let part = format!("{}: the directory must not be", f.store().display());
        assert_error(
            f.installer.install(&id(), &v("1.0.0")),
            ErrorCategory::User,
            &part,
        );
        assert_error(f.installer.recover(&id()), ErrorCategory::User, &part);
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);

        fs::remove_file(f.store()).unwrap();
        f.installer.install(&id(), &v("1.0.0")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_recovery_does_not_move_or_follow_a_symbolic_link() {
        use std::os::unix::fs::symlink;
        let f = fixture();
        f.staged_update();
        // The active directory is moved out. A link has the name of the
        // retired version; another has the name of a staging directory.
        let outside = f.dir.path().join("outside");
        fs::rename(f.installer.active(&id()), &outside).unwrap();
        symlink(&outside, f.store().join("1.0.0")).unwrap();
        symlink(&outside, f.store().join(".staging-link")).unwrap();

        for journal in ["not toml [", "old = \"1.0.0\"\nnew = \"2.0.0\""] {
            fs::write(f.store().join(PENDING_FILE), journal).unwrap();
            f.installer.recover(&id()).unwrap();
            assert!(!f.installer.active(&id()).exists(), "{journal}");
            assert!(!f.store().join(PENDING_FILE).exists(), "{journal}");
            assert!(outside.join(MANIFEST_FILE).is_file(), "{journal}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_lock_file_with_a_second_hard_link_is_refused() {
        let f = fixture();
        f.publish("1.0.0", &package("1.0.0", ""));
        let other = f.installer.data.join("store/acme.mysql");
        drop(lock(&other, &"acme.mysql".parse().unwrap()).unwrap());
        fs::create_dir_all(f.store()).unwrap();
        fs::hard_link(other.join(LOCK_FILE), f.store().join(LOCK_FILE)).unwrap();

        assert_error(
            f.installer.install(&id(), &v("1.0.0")),
            ErrorCategory::User,
            "the lock file has 2 hard links",
        );
        assert_eq!(f.active_version(), None);
    }

    #[test]
    fn the_content_of_the_lock_file_is_ignored() {
        let f = fixture();
        fs::create_dir_all(f.store()).unwrap();
        fs::write(f.store().join(LOCK_FILE), "x").unwrap();
        f.install("1.0.0", &package("1.0.0", "")).unwrap();
        assert_eq!(fs::read(f.store().join(LOCK_FILE)).unwrap(), b"x");
    }

    #[test]
    fn the_temporary_files_of_a_stopped_process_are_removed() {
        let f = fixture();
        f.install("1.0.0", &package("1.0.0", "")).unwrap();
        let left = f.store().join(".tmpAbC123");
        fs::write(&left, "1.0.0").unwrap();
        // Not a regular file: it stays.
        let dir = f.store().join(".tmpdir");
        fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        let outside = {
            let outside = f.dir.path().join("outside");
            fs::write(&outside, "").unwrap();
            std::os::unix::fs::symlink(&outside, f.store().join(".tmplink")).unwrap();
            outside
        };

        f.installer.recover(&id()).unwrap();
        assert!(!left.exists());
        assert!(dir.is_dir());
        #[cfg(unix)]
        assert!(outside.is_file());
        assert_eq!(f.active_version().as_deref(), Some("1.0.0"));
    }

    #[test]
    fn a_journal_that_names_no_directory_puts_the_one_retired_version_back() {
        let pending = |f: &Fixture| f.store().join(PENDING_FILE);
        // The journal names an old version that has no directory: the one
        // retired version goes back. The journal of a first install names
        // no old version: nothing goes back.
        let journals = [
            ("old = \"0.8.0\"\nnew = \"2.0.0\"", Some("1.0.0")),
            ("new = \"2.0.0\"", None),
        ];
        for (journal, active) in journals {
            let f = fixture();
            f.staged_update();
            fs::write(pending(&f), journal).unwrap();
            f.installer.retire(&id(), Some(&v("1.0.0"))).unwrap();
            f.installer.recover(&id()).unwrap();
            assert_eq!(f.active_version().as_deref(), active, "{journal}");
            assert!(!pending(&f).exists());
        }

        // Two retired versions and none is the old version of the journal.
        let f = fixture();
        f.staged_update();
        fs::write(pending(&f), "old = \"0.8.0\"\nnew = \"2.0.0\"").unwrap();
        f.installer.retire(&id(), Some(&v("1.0.0"))).unwrap();
        fs::create_dir(f.store().join("0.9.0")).unwrap();
        assert_error(
            f.installer.recover(&id()),
            ErrorCategory::Internal,
            "2 directories of retired versions",
        );
        assert!(pending(&f).exists());
        // The old version of the journal has a directory: it goes back.
        fs::write(pending(&f), "old = \"1.0.0\"\nnew = \"2.0.0\"").unwrap();
        f.installer.recover(&id()).unwrap();
        assert_eq!(f.active_version().as_deref(), Some("1.0.0"));
    }
}
