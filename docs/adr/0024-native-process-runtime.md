# ADR-0024: Native process runtime: protocol and supervision

- Status: Proposed
- Date: 2026-11-25

## Context

ADR-0003 says native plugins run in a separate extension host process. ARCHITECTURE.md §6.6 says control messages use a typed schema and bulk data uses Arrow IPC over a local socket. Neither fixes the process model, the message form or the limits. Part 1 of the native runtime ticket (#95) needs them. No code for it is on `main` on this date. None of the values below is measured.

## Decision

| Topic | Decision |
| --- | --- |
| Process model | One child process per native extension. The instance of the runtime contract owns its process. |
| Program | The code that builds the runtime gives the absolute path of the program to start and fixed leading arguments. One program serves all native extensions. The path never comes from a manifest, a package, a workspace setting or a search in `PATH`. A relative path is refused. |
| Start | The package directory is the last argument and the working directory of the child. |
| Control channel | The standard input and the standard output of the child. Bulk data does not use it; the local socket of §6.6 comes with the first native extension point. |
| Message form | One JSON object per line, UTF-8, with a `type` field. One call runs at a time and each request gets one answer, so a message has no request number. An error answer has a category and a message of the SDK error model (§5.6). An unknown category is a malformed message. |
| Messages | Engine to child: `hello` with `protocol`, `activate`, `deactivate`. Child to engine: `hello` with `protocol`, `ok`, `error` with `category` and `message`. The engine sends `hello` first and refuses a version that is not equal to its own (version 1). An answer while no call runs is a failure. |
| Limits | One message has at most 64 KiB. The handshake must complete in 5 s. On unload the child gets 2 s to exit after its input is closed; then it is killed. The values are defaults of a configuration struct that the constructor of the runtime takes. |
| Environment | The environment of the engine is removed. Only these variables are copied if they are set: `PATH`, `HOME`, `TMPDIR`, `LANG`, `LC_ALL`, `TZ`; on Windows also `SystemRoot`, `TEMP`, `TMP`. The list is fixed in code. |
| Error output | The standard error of the child goes to the engine log line by line at level `info`, as untrusted text with the rules of the WASM guest log (ADR-0018): own field, control characters replaced, redacted. The budget is 100 lines and 64 KiB; each call starts a new budget; lines past it are read, dropped and counted. |
| Failure | A child that exits, closes its output, or sends a malformed or too large message gives an `internal` error. Outside a call, the runtime reports it through a callback, which the wiring code connects to the crash report of the host (ADR-0021). The callback is not called after an orderly drop of the instance. |
| Cancelled call | If the caller drops a running call, the child is killed. |

## Consequences

- A crash of a native extension stops one process and one extension. Each native extension costs one process.
- No new crate and no `unsafe` for this part.
- A plugin that writes to its standard output breaks the control channel and is failed. The extension host program of part 3 must keep plugin output away from it.
- An extension cannot read the other variables of the engine environment. A credential source that needs it (for example the AWS default chain) cannot work yet. The first extension that needs it asks for a rule.
- The call timeout of the host (ADR-0021) also limits a native call, and it really stops the work, because the process is killed.
- The Windows allow list and the behaviour of pipes and process kill on Windows are not tested.
