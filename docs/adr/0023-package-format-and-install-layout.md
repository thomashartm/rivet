# ADR-0023: Package format and install layout

- Status: Proposed
- Date: 2026-11-25

## Context

ARCHITECTURE.md §4.8 lists what an extension package contains and requires versioned packages with rollback. It does not define the file format or the directories. ADR-0019 verifies one signed file. Part 2 of the registry ticket (#12) needs the format and the layout. The installer is on `main` since PR #134 (`crates/rivet-core/src/install.rs`). The behaviour below was not compared with that code line by line.

## Decision

Package file:

- A package is one file `<id>-<version>.rivetpkg` with a detached signature `<id>-<version>.rivetpkg.minisig`.
- The file is an uncompressed tar archive. It is read with the crate `tar` (default features off). Its licence was not checked for this ADR; the `cargo-deny` job in CI is the check.
- The archive has exactly three entries: `extension.toml`, `extension.wasm`, `LICENSE`. Each is a regular file. Every other entry name or entry type is refused.
- The "SDK docs reference" of §4.8 is the `sdk` version range in the manifest. The package has no separate file for it.
- Entries for native libraries are not defined. They come with the native runtime (#95).
- The installer writes each file itself. It ignores the modes, owners and times of the archive. It counts the bytes while it copies. The entry `extension.wasm` has at most the component size limit of the WASM runtime (ADR-0018; one constant, so a package that installs can load). On `main` since PR #153 (128 MiB before). The installer uses the default of the runtime; a runtime with a lower limit refuses such a package at load (ADR-0018). Also: the manifest and the licence have at most 1 MiB each.
- After extraction, the id and the version of the manifest must equal the id and the version in the signature.

Directories:

| Directory | Content |
| --- | --- |
| `<registry>/<id>/<version>/` | Package and signature. Read only. |
| `<data>/store/<id>/` | The verified package and signature of each version; staging directories; the retired version, only while a change runs. The host does not scan it. |
| `<data>/extensions/<id>/` | The active version, as a real directory. This is the user extension directory of §4.4. |

- A version is extracted to a staging directory and is renamed only when it is complete.
- To activate a version, the installer writes a journal file, moves the active directory to the store and moves the new directory in. A recovery step reads the journal file: if the second move is done, it completes the change; if not, it puts the old version back.
- A rollback does not reuse an extracted directory, because the signature does not cover it. It verifies the kept package again and extracts it again, with the same steps as an install.
- The installer copies the package to a private directory of the user, verifies the copy and extracts from the verified file handle (ADR-0019).
- The installer takes no trust store path. It uses `trust.toml` in the user configuration directory.
- An update or a rollback that adds capabilities is not activated. The installer returns what is added. A second call activates it after the review (ADR-0020).

## Consequences

- No decompression code and no decompression bomb. A package is larger than a compressed one.
- Two new crates: `tar` and `filetime`.
- The same code runs on Windows, macOS and Linux. No symbolic link is used.
- Between the two renames an extension id has no active directory. A load in that time fails and the host retries it (ADR-0021).
- Gap: the host does not verify a signature when it loads an extension. §7.7 and ADR-0006 require it ("on install and on load"). This ADR does not change that rule. The gap is tracked in ticket #138. The owner decides the design: check the extracted files against the kept signed package, or store digests at install. The store keeps the package and the signature for this.
- Limits of the first version (`install.rs`, on `main` since PR #134):
  - The caller gives `<data>`. No function for the platform data directory exists, and the installer does not check that `<data>` is outside a workspace. As merged, it also does not check that `<data>` is private. Decision (review finding R-84, on `main` since PR #167): on Unix the installer creates `<data>`, `store`, `store/<id>` and `extensions` with mode `0700`, and each operation is refused with a `user` error if the group or others can write one of them (same rule and same category as the trust store file, ADR-0019). The owner is not checked. There is no such check on Windows. The kept package is verified in place.
  - As merged with PR #134 there is no lock, and two operations on one id at the same time can lose the active version (review finding R-69). Decision for the fix (on `main` since PR #149): each operation on an id, the recovery step included, holds one exclusive lock file for this id for its whole time (`File::try_lock` of the standard library; it also works between processes). A second operation on the same id does not wait: it fails at once with a `retryable` error. The lock file is `<data>/store/<id>/.lock`; it is never deleted, and no step of a change renames or removes it. The operation releases the lock with an explicit unlock call when it ends: to close the file is not enough, because a child process that starts at that moment holds a copy of the handle for a short time, and the next operation then gets a false `retryable` error (measured by the fix agent: 5 of 40 test runs before, 0 of 40 after).
  - The lock file must be a regular file (review finding R-100, on `main` since PR #167). The installer refuses a symbolic link, a FIFO and each other shape before it opens the file, the way `open_regular` in `package.rs` does. Without this check a FIFO in that place stops an install without end, and a symbolic link makes the installer create a file outside `<data>`.
  - A review that waits is kept on disk (review finding R-84, on `main` since PR #153): when the installer returns that a review is needed, it writes the file `store/<id>/review`. As built, the file holds the version only; the id is the directory, and the added capabilities are not stored. The call that activates after the review works only for a record with the same version. Without such a record it is refused with a `policy` error. A new install, update or rollback from the registry deletes an older record. The record is a plain file, and a process of the same user can write it (review finding R-101). Such a process is outside the trust boundary: it can also change the engine and the grants. The record stops an error of the caller, not such a process. The package is verified again when it is activated, and the extension has no access until the user grants it.
  - Two versions that differ only in build metadata are the same version (semver precedence). Such a package is not an update. On `main` since PR #153.
  - Journal that cannot be read (review finding R-84, on `main` since PR #167, as the rules for a broken manifest, the kept packages and the recovery call below): recovery decides from the directories. If the active directory exists, it stays; staging directories and the journal are deleted. If it does not exist and exactly one retired version is in the store, that version is moved back. If nothing exists, the journal is deleted. If two or more retired versions exist, recovery returns an `internal` error and changes nothing. Each of these cases writes a `warn` event.
  - Active manifest that cannot be read (same finding): an install of a version from the registry replaces the broken directory. No review runs, because nothing can be compared; the grants of the user do not change, so the new version gets no access that was not granted. Update and rollback are refused with a `user` error that names this way out.
  - Kept packages: after a complete change the store keeps the package and the signature of the active version, of the version for a rollback and of a version whose review waits. The others are deleted.
  - The installer has a call that runs the recovery for each id. Nothing calls it at start-up yet; that call belongs to the wiring of the host and has no ticket.
  - After the second move the change is done (review finding R-70). If the clean-up after it fails, the failure is logged, the operation returns success, and the next recovery step completes the clean-up. Before the second move, each error leaves the old version active.
  - Files are synced; the parent directory is not synced after a move. A power loss can undo the last move. The recovery step repairs the states that the journal describes.
- The caller MUST activate a reviewed update only after the user review and the grant (to enforce in #51; no check exists).
