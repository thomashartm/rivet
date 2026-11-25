# ADR-0002: WASM runtime: Wasmtime

- Status: Accepted
- Date: 2026-11-25

## Context

WASM components are the default, sandboxed extension runtime. The runtime must support the component model, WIT interfaces, resource limits and interruption of long-running calls.

## Decision

Extensions run on Wasmtime using the component model. The supported WASI version is pinned in the SDK release and changes only with an SDK major version.

## Consequences

- Fuel or epoch interruption gives CPU limits per call.
- The SDK publishes WIT interfaces as the WASM contract.
- Wasmtime upgrades are tracked as `dependencies` work and tested against the extension test harness.
