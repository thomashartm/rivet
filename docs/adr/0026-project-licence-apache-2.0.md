# ADR-0026: Project licence is Apache-2.0

- Status: Accepted
- Date: 2026-11-26

## Context

ADR-0012 left the project licence open. The repository showed an AGPL-3.0 `LICENSE` file that was not a final statement. On 2026-11-26 the maintainer decided: "Change the license to Apache 2.0".

## Decision

- The project licence is Apache-2.0.
- `LICENSE` holds the unchanged Apache License 2.0 text from https://www.apache.org/licenses/LICENSE-2.0.txt.
- The workspace sets `license = "Apache-2.0"`. Every crate and `xtask` inherit it with `license.workspace = true`.
- The crates stay `publish = false`. Publishing to crates.io is a separate decision.
- Dependencies MUST still have a permissive licence from the allow list in `deny.toml`. The exceptions stay: `tiny-keccak` (CC0-1.0), `clipboard-win` and `error-code` (BSL-1.0).
- Each further exception needs the approval of the maintainer and an entry in `deny.toml`.

## Consequences

- Replaces ADR-0012.
- Users may use, change and ship rivet, also in closed products, if they keep the licence and notices.
- Apache-2.0 includes a patent grant from contributors.
- Copyleft dependencies stay out: they would force their terms on rivet.
- No `NOTICE` file exists. One is needed only when the project has notices to pass on.
