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
- The installer writes each file itself. It ignores the modes, owners and times of the archive. It counts the bytes while it copies. One entry has at most 128 MiB; the manifest and the licence have at most 1 MiB each.
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
- The host does not verify a signature when it loads an extension (§7.7 "on load"). The store keeps the package and the signature so that this can be added. No ticket has it yet.
- Limits of the first version (`install.rs`, on `main` since PR #134):
  - The caller gives `<data>`. The installer does not check that it is private or outside a workspace. No function for the platform data directory exists.
  - There is no lock. Two processes MUST NOT change the same extension id at the same time; nothing enforces this.
  - Files are synced; the parent directory is not synced after a move. A power loss can undo the last move. The recovery step repairs the states that the journal describes.
- The caller MUST activate a reviewed update only after the user review and the grant (to enforce in #51; no check exists).
