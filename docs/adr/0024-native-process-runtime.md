# ADR-0024: Native process runtime: protocol and supervision

- Status: Proposed
- Date: 2026-11-25

## Context

ADR-0003 says native plugins run in a separate extension host process. ARCHITECTURE.md §6.6 says control messages use a typed schema and bulk data uses Arrow IPC over a local socket. Neither fixes the process model, the message form or the limits. Part 1 of the native runtime ticket (#95) needs them. No code for it is on `main` on this date. None of the values below is measured.

## Decision

| Topic | Decision |
| --- | --- |
| Process model | One child process per native extension. The instance of the runtime contract owns its process. |
| Program | The code that builds the runtime gives the absolute path of the program to start. The path never comes from a manifest, a package, a workspace setting or a search in `PATH`. A relative path is refused. |
| Start | The package directory is the argument and the working directory of the child. |
| Control channel | The standard input and the standard output of the child. Bulk data does not use it; the local socket of §6.6 comes with the first native extension point. |
| Message form | One JSON object per line, UTF-8. Each request has a number; the answer repeats it. An error answer has a category and a message of the SDK error model (§5.6). |
| Messages | Handshake with a protocol version (version 1), activate, deactivate, and the answer to each. |
| Limits | One message has at most 1 MiB. The handshake must complete in 5 s. On unload the child gets 2 s to exit after its input is closed; then it is killed. |
| Environment | The child starts with an empty environment. Allow list: nothing on Unix; `SystemRoot` on Windows. |
| Error output | The standard error of the child goes to the engine log as untrusted text, with the rules of the WASM guest log (ADR-0018). |
| Failure | A child that exits, closes its output, or sends a malformed or too large message gives an `internal` error. Outside a call, the runtime reports it through a callback, which the wiring code connects to the crash report of the host (ADR-0021). |
| Cancelled call | If the caller drops a running call, the child is killed. |

## Consequences

- A crash of a native extension stops one process and one extension. Each native extension costs one process.
- No new crate and no `unsafe` for this part.
- A plugin that writes to its standard output breaks the control channel and is failed. The extension host program of part 3 must keep plugin output away from it.
- An extension cannot read the environment of the engine. A credential source that needs it (for example the AWS default chain) cannot work yet. The first extension that needs it asks for a rule.
- The call timeout of the host (ADR-0021) also limits a native call, and it really stops the work, because the process is killed.
- The Windows allow list and the behaviour of pipes and process kill on Windows are not tested.
