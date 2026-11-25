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
//! | `extension.wasm` | The WASM component. | 128 MiB |
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
//!   directory, a device, a FIFO.
//! - An entry above its size limit. The bytes are counted during the copy.
//! - A second entry with the same name. Thus a package has three entries at
//!   most. The archive is read to its end.
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
//! <data>/store/<id>/<id>-<version>.rivetpkg          each verified package is kept
//! <data>/store/<id>/<id>-<version>.rivetpkg.minisig
//! <data>/store/<id>/previous             the version for a rollback
//! <data>/store/<id>/pending              the journal of a change that is not complete
//! ```
//!
//! `<data>` MUST be a directory of the user that other users cannot write.
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
//!    ([`added_capabilities`]). If the new manifest adds a capability, stop
//!    with [`Outcome::NeedsReview`]. The active version does not change.
//! 6. Make the staged directory the active directory.
//!
//! An error in step 1 to 5 changes nothing in `<data>/extensions`.
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
//! # The caller must do this
//!
//! - **Blocking I/O.** Each method reads and writes files. From async code,
//!   call it in a blocking job (§5.1).
//! - **Review.** Call [`Installer::activate_after_review`] only after the
//!   user reviewed the added capabilities and
//!   [`Permissions::grant`](crate::permissions::Permissions::grant) stored
//!   the grant (to enforce in #51; no check exists).
//! - **First install.** [`Installer::install`] activates the package without
//!   a review. The extension has no access until the caller grants its
//!   capabilities: the permission service denies by default.
//! - **One writer.** Two processes MUST NOT change the same id at the same
//!   time.
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
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

/// The name of the WASM component in a package.
// shortcut: a second constant for this name until pull request #130 merges;
// `wasm::COMPONENT_FILE` is then the single source, re-export it here.
pub const COMPONENT_FILE: &str = "extension.wasm";

/// The name of the licence text in a package.
pub const LICENCE_FILE: &str = "LICENSE";

/// The file name extension of a package.
pub const PACKAGE_EXTENSION: &str = "rivetpkg";

/// The maximum size of the WASM component in a package.
pub const COMPONENT_MAX_BYTES: u64 = 128 * 1024 * 1024;

/// The maximum size of the manifest and of the licence text in a package.
pub const TEXT_ENTRY_MAX_BYTES: u64 = 1024 * 1024;

/// The only entries of a package, each with its size limit.
const ENTRIES: [(&str, u64); 3] = [
    (MANIFEST_FILE, TEXT_ENTRY_MAX_BYTES),
    (COMPONENT_FILE, COMPONENT_MAX_BYTES),
    (LICENCE_FILE, TEXT_ENTRY_MAX_BYTES),
];

/// More than a minisign signature needs. The verification has its own limit.
const SIGNATURE_MAX_BYTES: u64 = 16 * 1024;

const PENDING_FILE: &str = "pending";
const PREVIOUS_FILE: &str = "previous";
const STAGING_PREFIX: &str = ".staging-";

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
    /// Returns a `user` error if the manifest of the active version cannot
    /// be read or is invalid.
    pub fn installed(&self, id: &ExtensionId) -> Result<Option<Manifest>> {
        let path = self.active(id).join(MANIFEST_FILE);
        match fs::read_to_string(&path) {
            Ok(text) => Manifest::parse(&text).map(Some),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io_error(&path, "cannot read the manifest", error)),
        }
    }

    /// Installs `version` of `id` from the registry and activates it.
    ///
    /// # Errors
    ///
    /// - `user`: the extension is installed already (use
    ///   [`update`](Self::update)), or the package or the signature is not
    ///   in the registry or cannot be read, or the package is not a tar
    ///   archive, or its manifest is invalid.
    /// - `policy`: the signature does not verify, the publisher has no
    ///   pinned key, or the package breaks a rule of the
    ///   [package format](self#hostile-content).
    ///
    /// Each error installs nothing.
    pub fn install(&self, id: &ExtensionId, version: &Version) -> Result<Outcome> {
        self.recover(id)?;
        if let Some(installed) = self.installed(id)? {
            return Err(Error::user(format!(
                "extension `{id}` is installed in version {}; update it instead",
                installed.version
            )));
        }
        self.activate(id, version, Source::Registry, false)
    }

    /// Updates `id` to the newer `version` from the registry.
    ///
    /// If the new manifest adds capabilities, the result is
    /// [`Outcome::NeedsReview`] and the active version does not change.
    ///
    /// # Errors
    ///
    /// - `user`: the extension is not installed, or `version` is not newer
    ///   than the active version.
    /// - See [`install`](Self::install). Each error leaves the active
    ///   version as it was.
    pub fn update(&self, id: &ExtensionId, version: &Version) -> Result<Outcome> {
        self.recover(id)?;
        match self.installed(id)? {
            None => Err(Error::user(format!(
                "extension `{id}` is not installed; install it first"
            ))),
            Some(installed) if *version <= installed.version => Err(Error::user(format!(
                "extension `{id}`: version {version} is not newer than the installed version {}",
                installed.version
            ))),
            Some(_) => self.activate(id, version, Source::Registry, true),
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
    /// - See [`install`](Self::install). Each error leaves the active
    ///   version as it was.
    pub fn rollback(&self, id: &ExtensionId) -> Result<Outcome> {
        self.recover(id)?;
        let path = self.store(id).join(PREVIOUS_FILE);
        let none = || Error::user(format!("extension `{id}` has no previous version"));
        let previous = match fs::read_to_string(&path) {
            Ok(text) => text.trim().parse::<Version>().map_err(|_| none())?,
            Err(error) if error.kind() == ErrorKind::NotFound => return Err(none()),
            Err(error) => return Err(io_error(&path, "cannot read the file", error)),
        };
        self.activate(id, &previous, Source::Store, true)
    }

    /// Activates `version` of `id` from the package that the store kept,
    /// without a comparison of capabilities. The package is verified again.
    ///
    /// Call this only after [`Outcome::NeedsReview`], the review by the user
    /// and the new grant: see the [module documentation](self).
    ///
    /// # Errors
    ///
    /// - `user`: the store has no package of this version, or the version
    ///   is active already.
    /// - See [`install`](Self::install).
    pub fn activate_after_review(&self, id: &ExtensionId, version: &Version) -> Result<()> {
        self.recover(id)?;
        self.activate(id, version, Source::Store, false).map(|_| ())
    }

    /// Repairs `id` after a change that did not complete, for example after
    /// a crash. Each operation runs this first. A caller can run it at
    /// start-up. It does nothing if no change is pending.
    ///
    /// # Errors
    ///
    /// Returns a `user` error that names the file if a file cannot be read,
    /// moved or written.
    pub fn recover(&self, id: &ExtensionId) -> Result<()> {
        let store = self.store(id);
        let pending = store.join(PENDING_FILE);
        let text = match fs::read_to_string(&pending) {
            Ok(text) => text,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(io_error(&pending, "cannot read the journal", error)),
        };
        let journal: toml::Table = text.parse().unwrap_or_default();
        let version = |key: &str| journal.get(key)?.as_str()?.parse::<Version>().ok();
        let (old, new) = (version("old"), version("new"));
        tracing::warn!(extension = %id, "an install did not complete; recovering");

        if let Ok(entries) = fs::read_dir(&store) {
            for entry in entries.flatten() {
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(STAGING_PREFIX)
                {
                    // Best effort: a staging directory that stays is never read.
                    let _ = fs::remove_dir_all(entry.path());
                }
            }
        }
        let active = self.active(id);
        if fs::symlink_metadata(&active).is_err() {
            if let Some(old) = &old {
                let retired = store.join(old.to_string());
                if retired.is_dir() {
                    fs::rename(&retired, &active).map_err(|error| {
                        io_error(&active, "cannot put the old version back", error)
                    })?;
                }
            }
        } else if new.is_some() && self.installed(id)?.map(|manifest| manifest.version) == new {
            // The second rename was done: the new version is complete.
            return self.finish(id, old.as_ref());
        }
        remove_file(&pending)
    }

    /// Steps 1 to 6 of the [module documentation](self). `review` is `true`
    /// when added capabilities stop the operation.
    fn activate(
        &self,
        id: &ExtensionId,
        version: &Version,
        source: Source,
        review: bool,
    ) -> Result<Outcome> {
        let installed = self.installed(id)?;
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

        fs::create_dir_all(&store)
            .map_err(|error| io_error(&store, "cannot create the directory", error))?;
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

        if source == Source::Registry {
            for (from, to) in [(&package, &kept_package), (&signature, &kept_signature)] {
                fs::rename(from, to)
                    .map_err(|error| io_error(to, "cannot keep the verified package", error))?;
            }
        }
        if review && let Some(installed) = &installed {
            let added = added_capabilities(&installed.capabilities, &manifest.capabilities);
            if added != Capabilities::default() {
                tracing::info!(extension = %id, %version, "the version adds capabilities and needs a review");
                return Ok(Outcome::NeedsReview { added });
            }
        }

        let old = installed.map(|manifest| manifest.version);
        self.write_pending(id, old.as_ref(), version)?;
        let moved = self
            .retire(id, old.as_ref())
            .and_then(|()| self.promote(id, &content));
        if let Err(error) = moved {
            self.recover(id)?;
            return Err(error);
        }
        self.finish(id, old.as_ref())?;
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
        fs::create_dir_all(self.extensions_dir())
            .and_then(|()| fs::rename(content, &active))
            .map_err(|error| io_error(&active, "cannot activate the new version", error))
    }

    /// Completes a change after the second rename.
    fn finish(&self, id: &ExtensionId, old: Option<&Version>) -> Result<()> {
        let store = self.store(id);
        if let Some(old) = old {
            write_atomic(&store.join(PREVIOUS_FILE), &old.to_string())?;
        }
        remove_file(&store.join(PENDING_FILE))?;
        if let Some(old) = old {
            // Best effort: `retire` removes a directory that stays. A
            // rollback extracts the kept package and does not read it.
            let _ = fs::remove_dir_all(store.join(old.to_string()));
        }
        Ok(())
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
    fs::create_dir(content)
        .map_err(|error| io_error(content, "cannot create the directory", error))?;

    let mut archive = tar::Archive::new(file);
    for entry in archive.entries().map_err(malformed)? {
        let mut entry = entry.map_err(malformed)?;
        let path = entry.path_bytes().into_owned();
        // The target name is the constant, never the text of the archive.
        let Some(&(entry_name, limit)) = ENTRIES
            .iter()
            .find(|(entry_name, _)| entry_name.as_bytes() == path)
        else {
            return Err(refused(format!(
                "the entry `{}` is not permitted: a package holds only `{MANIFEST_FILE}`, \
                 `{COMPONENT_FILE}` and `{LICENCE_FILE}`",
                String::from_utf8_lossy(&path).escape_debug()
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
        let mut out = File::create_new(&target).map_err(|error| match error.kind() {
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
    match ENTRIES
        .iter()
        .find(|(entry_name, _)| !content.join(entry_name).is_file())
    {
        Some((missing, _)) => Err(refused(format!("the entry `{missing}` is missing"))),
        None => Ok(()),
    }
}

/// Copies the regular file `from` to the new file `to`. Refuses a symbolic
/// link, anything that is not a regular file, and more than `max_bytes`.
fn copy_regular(from: &Path, to: &Path, max_bytes: u64) -> Result<()> {
    let source = open_regular(from, "registry", max_bytes)?;
    let mut target =
        File::create_new(to).map_err(|error| io_error(to, "cannot write the file", error))?;
    // A file that grows after the size check is cut. The signature of the
    // copy then does not verify.
    io::copy(&mut source.take(max_bytes), &mut target)
        .map_err(|error| io_error(from, "cannot read the registry file", error))?;
    Ok(())
}

/// Replaces `path` with a file that holds `text`. The text goes to a
/// temporary file in the same directory, and that file then replaces `path`.
// shortcut: the directory is not synced, so a power loss can undo the last
// rename; the journal then still describes a state that `recover` repairs.
fn write_atomic(path: &Path, text: &str) -> Result<()> {
    let write = || {
        let dir = path.parent().unwrap_or(Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(dir)?;
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
            assert!(kept.is_empty(), "{kept:?}");
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
        // No staging directory and no journal stay.
        assert!(!f.store().join(PENDING_FILE).exists());
        assert_eq!(fs::read_dir(f.store()).unwrap().count(), 2);
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
        header.set_size(COMPONENT_MAX_BYTES + 1);
        header.set_cksum();
        assert_error(
            f.install("1.0.0", header.as_bytes()),
            ErrorCategory::Policy,
            "the entry `extension.wasm` is larger than 134217728 bytes",
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
        f.installer.trust_file = f.dir.path().join("config/trust.toml");
        fs::write(&f.installer.trust_file, &trust).unwrap();
        assert_eq!(
            f.installer.install(&id(), &v("1.0.0")).unwrap(),
            Outcome::Activated
        );
    }
}
