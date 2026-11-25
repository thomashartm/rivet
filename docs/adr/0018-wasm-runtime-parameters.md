# ADR-0018: WASM runtime parameters

- Status: Proposed
- Date: 2026-11-25

## Context

ADR-0002 chose Wasmtime and says that a WASI version is pinned. It names no version. ARCHITECTURE.md §4.3 allows fuel or epoch interruption and gives no memory rule. The WASM runtime ticket (#4) needs these values. Part 1 of #4 is on `main` (`crates/rivet-core/src/wasm.rs`). The rows "Time limit", "Component size" and "Guest log output" are review fixes; they are on `main` (read in `wasm.rs` at commit aafd7b8).

## Decision

| Topic | Decision |
| --- | --- |
| WASI | None for now. The host gives no `wasi:*` interface. A component that imports one does not load; the error names the import. |
| CPU limit | Fuel, set again before each call. Default 1 000 000 000 units per call, not measured. The value is a setting. |
| Time limit | Epoch interruption, in addition to fuel. One ticker for the engine; each call has its own deadline. A call MUST NOT end before its limit: the number of ticks is rounded up. A call can run longer than the limit, by two ticks (200 ms) at most plus the delay of each tick; the reviewer measured about 10 % (3.0 s ended after 3.3 s). The ticker sleeps one tick length each time; it is not corrected for this delay, because a corrected ticker can end a call early. This limit is a backstop, not an exact timer. For a load the two limits do not start together (review finding R-102): the timer of the host starts before the compile step, the limit of the runtime starts when guest code starts, after the compile step. So after the host gave up a load, guest code can run for the full limit of the runtime plus the overshoot, counted from the end of the compile step. Decision: this stays; the module documentation of `wasm.rs` must say it (on `main` at commit 9b61096 it says that guest code stops within the overshoot, which is false for a load). (Rounding up: review fix R-62, on `main` since PR #144.) Default 30 s, the value of `extensions.call_timeout_ms` (ADR-0021). The host owns the setting and gives it to the runtime. Before PR #151 the value of the host was not given to the runtime (review finding R-80). Since PR #151 the limits of the runtime are built from the configuration of the host, so there is one value and one default; the wiring code MUST use the same configuration for both. |
| Component size | A component file larger than the limit does not load. Default 4 MiB since PR #151 (16 MiB before; review findings R-82 and R-83). The installer uses the same constant for the entry `extension.wasm` since PR #153 (ADR-0023). Reason: the compile step has no time limit and cannot be stopped; the reviewer measured 43 s for 16 MiB, above the call limit of 30 s. 4 MiB is an estimate from that number, not measured. No compile cache (it needs `unsafe`), no compile outside the lifecycle lock, no new crate for now. Limit of debug builds (review finding R-102, measured by the reviewer, not repeated for this record): a build with the `dev` profile compiles a component of 4 MiB in 35 to 64 s, more than the call limit of 30 s, so such a load fails. Limit of a lower value: `Limits::component_bytes` is a public field and `Limits::for_host` sets the default. The installer checks the default only; a runtime that is built with a lower value refuses at load, with a `user` error, a package that the installer accepted. No setting for the size exists. |
| Object counts | One instance of a component can have at most 64 core instances, 8 memories and 64 tables (review finding R-81, on `main` since PR #151 as three constants). The numbers are not measured. |
| Text from a guest | An error message of a guest gets a fixed prefix of the host that names the extension, in addition to the guest log rules. So the reason of a `Failed` state cannot imitate a message of the host (review finding R-83, on `main` since PR #151). |
| Source of a trap error | The engine is configured without the backtrace of Wasmtime. Then the source of a trap error holds only the cause that the host runtime made, and no text that the guest chose. Reason: with the backtrace, the source holds the function names of the name section of the component. Measured by a fix agent with a probe that is not committed (not repeated for this record): 10 138 bytes, a line break, an escape character and a registered secret that was not redacted. The message, the status reason and the host log did not hold it; a print of the source chain did. A test MUST prove for each kind of failure (trap, failed instantiation, broken rule of the component model) that the source holds no text of the guest; a kind that cannot be proven keeps no source. Consequence: the author of an extension gets no backtrace from the host. Not on `main` on this date. Also: the name of an import that the host does not give goes through the guest text rules before it is in an error message (same finding, not on `main` on this date). |
| Guest log output | Limited per call (64 KiB, 100 lines); the messages past the budget are dropped and counted. One message is cut to 8 KiB. A message that is not written because its level is off costs no budget (review fix R-60, on `main` since PR #144). One call of an import can pass 64 KiB of data at most; a log message above this size is not cut, it traps the instance. The guest text is logged as a separate field, so it cannot imitate a field of the host. |
| Memory limit | One budget per instance for linear memories and tables together. Default 64 MiB. Growth past the budget traps the instance. |
| WIT package | `rivet:extension`, in `crates/rivet-sdk/wit/`. World `extension` with `activate` and `deactivate`. Interfaces of extension points go into the same package (ADR-0013). |
| WIT version | Equal to the SDK crate version. A test checks it. |
| Errors in WIT | The WIT has an `error` record with the categories of §5.6. Lifecycle functions return it. The host keeps the category of the guest. Trap and limit violation give `internal`. Invalid component gives `user`. |
| Component file | The component of a package is the file `extension.wasm` in the package directory. The manifest has no field for it. (#4 part 2, on `main` since PR #130.) |
| Execution | Synchronous Wasmtime. Compile, instantiate and each call run on the blocking pool (§5.1). |

## Consequences

- No WASI: an extension gets no clock, random, file or network access without a grant (§7.3). A guest built with Rust std for a WASI target does not load.
- The first extension that needs WASI proposes the exact version. ADR-0002 is amended then.
- Fuel does not limit the time inside a blocking host import. The time limit ends a call when guest code runs again; a host import that blocks must have its own timeout.
- The compile time of a component is limited only through the size limit.
- A memory limit violation puts the extension in `Failed` (§4.4) with a clear cause.
