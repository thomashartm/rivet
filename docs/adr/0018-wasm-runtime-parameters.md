# ADR-0018: WASM runtime parameters

- Status: Proposed
- Date: 2026-11-25

## Context

ADR-0002 chose Wasmtime and says that a WASI version is pinned. It names no version. ARCHITECTURE.md §4.3 allows fuel or epoch interruption and gives no memory rule. The WASM runtime ticket (#4) needs these values. They were asked by the implementing agent; the code is not merged on this date.

## Decision

| Topic | Decision |
| --- | --- |
| WASI | None for now. The host gives no `wasi:*` interface. A component that imports one does not load; the error names the import. |
| CPU limit | Fuel, set again before each call. Default 1 000 000 000 units per call, not measured. The value is a setting. |
| Memory limit | One budget per instance for linear memories and tables together. Default 64 MiB. Growth past the budget traps the instance. |
| WIT package | `rivet:extension`, in `crates/rivet-sdk/wit/`. World `extension` with `activate` and `deactivate`. Interfaces of extension points go into the same package (ADR-0013). |
| WIT version | Equal to the SDK crate version. A test checks it. |
| Errors in WIT | The WIT has an `error` record with the categories of §5.6. Lifecycle functions return it. The host keeps the category of the guest. Trap and limit violation give `internal`. Invalid component gives `user`. |
| Execution | Synchronous Wasmtime. Compile, instantiate and each call run on the blocking pool (§5.1). |

## Consequences

- No WASI: an extension gets no clock, random, file or network access without a grant (§7.3). A guest built with Rust std for a WASI target does not load.
- The first extension that needs WASI proposes the exact version. ADR-0002 is amended then.
- Fuel does not limit the time inside a blocking host import. Wall-clock timeouts come with #11.
- A memory limit violation puts the extension in `Failed` (§4.4) with a clear cause.
