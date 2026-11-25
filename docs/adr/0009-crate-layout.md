# ADR-0009: Crate layout

- Status: Accepted
- Date: 2026-11-25

## Context

Dependency rules must be enforceable per crate. Contracts and implementations must be separate.

## Decision

The workspace uses the `rivet-*` crates listed in ARCHITECTURE.md §3.1: contract crates (`rivet-sdk`, `rivet-engine-api`, `rivet-ui-sdk`), `rivet-core`, one crate per extension (`rivet-ext-*`, `rivet-ui-ext-*`), interface binaries and `rivet-testkit`.

## Consequences

- The dependency table in §3.2 applies to these crates and is checked in CI.
- Extensions never depend on each other as crates.
