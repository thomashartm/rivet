# ADR-0024: Native process runtime: protocol and supervision

- Status: Proposed
- Date: 2026-11-25

## Context

ADR-0003 says native plugins run in a separate extension host process. ARCHITECTURE.md §6.6 says control messages use a typed schema and bulk data uses Arrow IPC over a local socket. Neither fixes the process model, the message form or the limits. Part 1 of the native runtime ticket (#95) needs them. Part 1 is on `main` since PR #142 (`crates/rivet-core/src/native.rs`). Compared with that file at commit 12255a3: the environment list, the three limits (64 KiB, 5 s, 2 s), the refusal of a relative program path and the level `info` of the error output are equal to the table below. The other rows were not compared with the code. None of the values below is measured.

This ADR changes two accepted texts. They change only when the maintainer accepts this ADR; no "Amends" line is in them yet.

| Text | It says | This ADR says |
| --- | --- | --- |
| ADR-0003 | "a separate extension host process" (one) | One child process for each native extension. |
| ARCHITECTURE.md §6.6 | Control messages "in a typed schema" | JSON lines with a fixed set of messages. The types are Rust types in `native.rs`; no schema file exists. |

## Decision

| Topic | Decision |
| --- | --- |
| Process model | One child process per native extension. The instance of the runtime contract owns its process. |
| Program | The code that builds the runtime gives the absolute path of the program to start and fixed leading arguments. One program serves all native extensions. The path never comes from a manifest, a package, a workspace setting or a search in `PATH`. The constructor of the runtime refuses a relative path with a `user` error. |
| Start | The package directory is the last argument and the working directory of the child. |
| Control channel | The standard input and the standard output of the child. Bulk data does not use it; the local socket of §6.6 comes with the first native extension point. |
| Message form | One JSON object per line, UTF-8, with a `type` field. One call runs at a time and each request gets one answer, so a message has no request number. An error answer has a category and a message of the SDK error model (§5.6). An unknown category is a malformed message. |
| Messages | Engine to child: `hello` with `protocol`, `activate`, `deactivate`. Child to engine: `hello` with `protocol`, `ok`, `error` with `category` and `message`. The engine sends `hello` first and refuses a version that is not equal to its own (version 1). An answer while no call runs is a failure. |
| Limits | One message has at most 64 KiB. The handshake must complete in 5 s. On unload the child gets 2 s to exit after its input is closed; then it is killed. The values are defaults of a configuration struct that the constructor of the runtime takes. |
| Environment | The environment of the engine is removed. Only these variables are copied if they are set: `PATH`, `HOME`, `TMPDIR`, `LANG`, `LC_ALL`, `TZ`; on Windows also `SystemRoot`, `TEMP`, `TMP`. The list is fixed in code. |
| Error output | The standard error of the child goes to the engine log line by line at level `info`, as untrusted text with the rules of the WASM guest log (ADR-0018): own field, control characters replaced, redacted. The budget is 100 lines and 64 KiB for one request (`hello`, `activate`, `deactivate`); each request starts a new budget; the time until the next request uses the budget of the last request. Lines past the budget are read, dropped and counted; the count is written when the next budget starts and when the error output ends. |
| Failure | A child that exits, closes its output, or sends a malformed or too large message gives an `internal` error. Outside a call, the runtime reports it through a callback, which the wiring code connects to the crash report of the host (ADR-0021). The callback is not called after an orderly drop of the instance. |
| Cancelled call | If the caller drops a running call, the child is killed. When the runtime ends a child itself (dropped call, drop of the instance), it does not call the crash callback; the host already handles that case (ADR-0021). |

## Consequences

- A child lives as long as its instance. The host must drop the instance to end the process; see ADR-0021 for the shutdown.
- A native extension that is idle for a long time and writes to its error output gets no new budget until the next request. With only lifecycle requests this means: about 100 lines for the whole time in `Active`. The first native extension point brings more requests.
- Rules from the review of the first code (PR #142). On `main` since PR #161: one process at a time, report only after the handshake, the wait for the error output task. On `main` since PR #187: the failure time in the crash report (third argument of the callback and of `report_crash`; the runtime takes the time when it sees the end of the child):
  - A crash report must not hit a newer instance. The callback gives the time of the failure; the host ignores a report that is older than the load of the instance that it has now. Without this, a report that waits behind a reload restarts the new instance one time and counts for the restart limit.
  - One extension has one process at a time (review finding R-92). The drop of an instance does not wait, so the old process can live for the grace time. A load of the same extension waits until the old process of this extension has ended; the wait is bounded by two grace times. Without this, two processes run in one package directory, and the crash report rule above is not safe: a late failure of the old process would be newer than the new load.
  - The runtime reports a crash only for a child whose handshake was successful. A program that exits before the handshake gives the load error only.
  - To drop the instance also ends the task that reads the error output, also when another process still holds the pipe. After the child has ended, the runtime waits for this task for the grace time at most, so the last lines of a crash are not lost; then it stops the task and writes the count of dropped lines.
  - After the child exits during a call, the runtime waits for the grace time at most for an answer that is still in the pipe (review finding R-104, on `main` since PR #172; read in the module documentation of `native.rs`). Before, it read one time, and an answer was lost under load. Consequences: if another process holds the output of the child open, a failed call ends later by the grace time (2 s by default; 0 before), so the rule that such a process delays no call is not true for a failed call. An answer without a line end is refused: the message form is one JSON object per line. So a last line that the child wrote without a line end before its exit is an `internal` error; before PR #172 it was taken as the answer. Known limit: the runtime cannot see which process wrote a line. If a process that the child started holds the output open and writes a line inside the grace time, that line counts as the answer of the child. This is accepted: each process of a native extension is code of the same extension (review finding R-117). With a grace time of 0 an answer directly before an exit can be lost.
  - Known limit: a process that the child starts itself is not ended with the child. To end a process group needs a system call that the standard library and tokio do not give without `unsafe` or a new crate. It belongs to the OS sandbox work.
  - Proposed, waits for the owner (review finding R-87; nothing of this is built): the limit above is closed on Unix with the crate `rustix`.
    - The child starts in its own process group (`process_group(0)` of the tokio command; no crate is needed for this).
    - To end an extension, the runtime sends the kill signal to the group, not only to the child: `rustix::process::kill_process_group`, a safe function. The workspace rule `unsafe_code = "forbid"` stays for each crate of the workspace; the `unsafe` call is inside `rustix`.
    - The runtime sends the group signal before it reads the exit status of the child. After that read the number of the group can belong to other processes.
    - After a child that ended by itself (exit, crash), the runtime also ends the group, by the same rule.
    - `rustix` 1.1.6 is in `Cargo.lock` already (the WASM runtime uses it). The direct dependency needs the feature `process`. Expected: no new package in `Cargo.lock`; the diff of the lock file is the proof and was not made for this record.
    - Limits that stay: a process that leaves the group (it makes its own session or group) is not ended. This is not a sandbox. On Windows nothing changes: `rustix` has no process module there; the matching tool is a job object, which needs another crate. CI runs on Linux only on this date.
    - Candidates compared (registry data of this date; sources not read, except the three function signatures):

      | Candidate | Safe call for "kill the group" | Licence | New packages in `Cargo.lock` | Note |
      | --- | --- | --- | --- | --- |
      | `rustix` 1.1.6 | yes, `process::kill_process_group` | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT (in the allow list) | 0 expected | Same organisation as Wasmtime. No Windows. |
      | `nix` 0.32.0 | yes, `sys::signal::killpg` | MIT (in the allow list) | 2 expected (`nix`, `cfg_aliases`) | No Windows. |
      | `process-wrap` 11.0.0 | yes, it wraps the command | Apache-2.0 OR MIT | more: `nix`, and `windows` for job objects | Changes how the child is started; has job objects for Windows. |
      | `command-group` 5.0.1 | yes | Apache-2.0 OR MIT | more: `nix` 0.27, `winapi` | Older versions of its dependencies. |
      | `libc` | no, the call is `unsafe` | | 0 | Breaks `unsafe_code = "forbid"`. |
      | The program `kill` | no crate | | 0 | A second program in `PATH`; not proposed. |
- Limits of this part, not resolved here:
  - A native process has no memory limit and no CPU limit (§4.3 requires limits per extension). No ticket has it.
  - The process is not sandboxed by the OS. §4.7 then requires that the install review says "runs with full user privileges"; that text is for #51 and does not exist.
  - Nothing says yet which files of a native package the signature covers; the package format has no entry for native libraries (ADR-0023). A native extension MUST NOT ship before that is defined. No code enforces this rule (review finding R-113). On this date nothing can break it: no manifest field selects the native runtime, and the program of the child comes from the code that builds the runtime, not from a package. The rule becomes a check with part 2 of ticket #95 (runtime selection): a native package is refused until the signature rule exists.
  - The capability checks of ADR-0020 do not apply to a native process: it can open files and connections itself.
- A crash of a native extension stops one process and one extension. Each native extension costs one process.
- No new crate and no `unsafe` for this part.
- A plugin that writes to its standard output breaks the control channel and is failed. The extension host program of part 3 must keep plugin output away from it.
- An extension cannot read the other variables of the engine environment. A credential source that needs it (for example the AWS default chain) cannot work yet. The first extension that needs it asks for a rule.
- The call timeout of the host (ADR-0021) also limits a native call, and it really stops the work, because the process is killed.
- The Windows allow list and the behaviour of pipes and process kill on Windows are not tested.
