# ADR-0010: Architecture check with xtask

- Status: Accepted
- Date: 2026-11-25

## Context

ARCHITECTURE.md §3 requires that crate dependency rules are enforced by automated checks. General tools such as `cargo-deny` check licences and banned crates, but not layer rules between workspace crates.

## Decision

An `xtask check-arch` command reads `cargo metadata` and fails when a workspace crate depends on a crate that the table in ARCHITECTURE.md §3.2 does not allow. CI runs it on every pull request.

## Consequences

- The allowed-dependency table lives in one place inside the xtask and must match §3.2.
- No extra tool to install; the check is plain Rust in the workspace.
- New crate kinds need a table update in the same pull request.
