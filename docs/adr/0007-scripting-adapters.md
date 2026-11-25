# ADR-0007: Scripting: adapter framework, Rhai first

- Status: Accepted
- Date: 2026-11-25

## Context

The mission requires an embedded scripting language. Users will want different languages, so the engine must not depend on one.

## Decision

Scripting is an extension point (`script engine`). Each language is an adapter that runs scripts against the Engine API with the same permissions model as other extensions. Rhai is the first adapter.

## Consequences

- More languages can be added as extensions without core changes.
- Every adapter exposes the same Engine API surface; the SDK defines it once.
- Rhai is pure Rust and easy to sandbox.
