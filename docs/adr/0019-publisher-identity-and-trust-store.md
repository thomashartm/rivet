# ADR-0019: Publisher identity and trust store

- Status: Proposed
- Date: 2026-11-25

## Context

ADR-0006 pins publisher keys on first install. It does not say what identifies a publisher or where pinned keys are stored. The signature ticket (#12) needs both. Part 1 of #12 is on `main` (`crates/rivet-core/src/package.rs`). The rules for the caller are for part 2 of #12.

## Decision

- The publisher of an extension is the first segment of its extension id: `acme.postgres` has the publisher `acme`. An id with one segment is its own publisher. The manifest gets no free publisher field.
- The publisher of a bundled extension is the project. Its package is verified with the project key only. The first segment `rivet` is reserved for the project, in both directions: a built-in package is verified only if the first segment of its id is `rivet`, and a key cannot be pinned for the publisher `rivet`, and a publisher package with this segment is refused. The checks are in `package.rs` on `main` (read at commit cb047c8).
- Verification uses the `minisign-verify` crate. Legacy signatures (not prehashed) are refused, so a package is verified as a stream.
- Pinned keys are stored in `trust.toml` in the user configuration directory. The file has `schema_version` and a table `[publishers]` with one public key per publisher.
- The trust store MUST NOT be read from a workspace directory or a bundled directory The installer (`install.rs`, on `main` since PR #134) reads only `trust.toml` in the user configuration directory and takes no other path. `TrustStore::load` itself takes a path, so each other caller must obey this rule; nothing checks it there.
- The project key ships with the binary. It is never read from the trust store file.
- The trusted comment of a signature is exactly `rivet-package id=<extension id> version=<version>`. Verification fails if the comment has another form, or if the id or the version differs from the package that the caller expects. For a publisher package, the publisher must be the first segment of the id.
- Verification returns the open file that was verified. The caller reads the package from this handle and does not open the path again. The caller MUST verify a copy in a private location of the user The installer copies the package to a staging directory below its data directory and verifies the copy. It does not check that the data directory is private; that stays a rule for its caller (ADR-0023).
- The project key cannot be pinned as a publisher key. A pinned key is replaced only by a separate call that the caller makes after a new review.
- A package file larger than 256 MiB is not verified. The value is not measured.
- A trust store file with an invalid entry does not load. No entry is skipped.
- Failed verification, a key that differs from the pin, and a publisher without a pin give a `policy` error. Malformed or unreadable input gives a `user` error.

Weak keys (review fix, not on `main` on this date):

- A public key that is a point of small order, or that is not in the canonical encoding (y not less than p), is refused when it is parsed, with a `user` error. This applies to the project key, a pinned key, a key file and each entry of the trust store.
- Reason: with a key of small order, a signature that nobody signed can verify.
- A signature whose point R has a small order is accepted when the key is valid. Only the owner of the secret key can make it, so it is not a forgery. The project does not need one unique signature per package, so there is no check for it.
- The check is a fixed list of encodings in `package.rs`. No new crate. The list was not checked for this ADR; the tests of the fix must show that each listed encoding is refused and that the forged signature of the review finding does not verify.

Key id and file mode (review fixes R-59 and R-68b, not on `main` on this date):

- A signature whose key id differs from the key id of the key gives its own `policy` error. The text says that the package was signed with another key or that the pinned text has a wrong key id.
- A pin with the key bytes of the pinned key and another text is refused with a `policy` error. Nothing is kept or replaced without a message. The replace call after a review stays the way to change the text.
- On Unix, a trust store file that the group or others can write is not loaded (`user` error with the mode and the fix `chmod 600`). The engine itself writes the file with mode `0600`. A file made by hand with a umask of `002` is refused; this is intended. The owner and the mode of the parent directory are not checked. There is no such check on Windows.

## Consequences

- A package cannot name another publisher to replace that publisher's extension.
- A changed trust store file cannot replace the project key.
- Extension ids need a publisher prefix to share one key between extensions.
- A repository opened as a workspace cannot pin its own keys.
- A signature for one version cannot be used for another version or another extension id.
- A process of the same OS user can still change the verified file in place. The OS user is the trust boundary (§7.1). No hash crate is added for this.
