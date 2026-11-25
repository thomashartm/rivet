# ADR-0012: Project licence is not decided; dependencies stay permissive

- Status: Accepted
- Date: 2026-11-25

## Context

The repository started with an AGPL-3.0 `LICENSE` file and `license = "AGPL-3.0-only"` in Cargo. The maintainer has not decided the project licence. A copyleft dependency would remove options from that decision.

## Decision

- The project licence is not decided.
- Workspace crates have no Cargo `license` field and are `publish = false` (PR #110).
- The `LICENSE` file stays unchanged until the decision. It is not a statement of the final licence.
- Dependencies MUST have a permissive licence. The allow list is in `deny.toml`: MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib.
- Exception: `tiny-keccak` (CC0-1.0) is accepted.
- Each further exception needs the approval of the maintainer and an entry in `deny.toml`.

## Consequences

- Every licence choice stays possible, permissive or copyleft.
- A crate with a copyleft or unknown licence fails `cargo-deny` in CI.
- No crate can be published to crates.io before the licence is decided.
- The repository shows an AGPL text while the licence is open. The licence decision must replace or confirm the `LICENSE` file.
