# ADR-0016: Dependency rule for `rivet-testkit`

- Status: Proposed
- Date: 2026-11-25

## Context

ARCHITECTURE.md §3.1 lists `rivet-testkit`, but the table in §3.2 had no row for it. `xtask check-arch` rejects a crate without a kind. The test harness (#13) needs the rule. The mock engine uses the real core services, so the testkit needs `rivet-core`.

## Decision

| # | Rule |
| --- | --- |
| 1 | `rivet-testkit` MAY depend on `rivet-sdk`, `rivet-engine-api` and `rivet-core`. It MUST NOT depend on another workspace crate. |
| 2 | A workspace crate MAY depend on `rivet-testkit` only as a dev-dependency. A normal dependency or a build dependency on it MUST NOT exist. |
| 3 | `rivet-sdk`, `rivet-engine-api` and `rivet-core` MUST NOT depend on `rivet-testkit` in any kind. |
| 4 | For every other pair of crates, §3.2 applies to normal, build and dev dependencies alike. Rule 2 is the only place where the dependency kind matters. |

## Consequences

- Test code never reaches a release binary through a normal dependency.
- Rule 3 prevents a dev-dependency cycle. With a cycle, the unit tests of `rivet-core` would see two copies of its types.
- An extension crate reaches `rivet-core` in its test build through the testkit. Its normal build still has only `rivet-sdk`.
- `xtask check-arch` must read the kind of each dependency edge.
