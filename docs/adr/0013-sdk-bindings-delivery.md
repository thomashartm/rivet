# ADR-0013: WIT and C ABI bindings are delivered with the runtimes

- Status: Accepted
- Date: 2026-11-25

## Context

ARCHITECTURE.md §4.1 says the SDK ships in two bindings: WIT interfaces and a C ABI header with a Rust wrapper. The contracts ticket (#6) delivered Rust traits only. A binding without a runtime that loads it cannot be tested.

## Decision

- The WIT interfaces and the C ABI header are not part of the contracts ticket (#6).
- WIT interfaces are delivered with the WASM runtime (#4). The C ABI header is delivered with the native runtime (#95).
- The WIT interface of an extension point (driver, tunnel, ...) is added with the first extension that uses that point. The interfaces are not written all at once.
- Until a binding exists, the Rust trait in `rivet-sdk` is the only definition of that contract.
- The SDK v1 freeze (#5) covers the bindings that exist at that time.

## Consequences

- Each binding is tested by a real extension when it is added.
- An extension point without a WIT interface cannot be implemented as a WASM component yet.
- The Rust trait and its bindings can differ. Each ticket that adds a binding must check it against the Rust trait.
