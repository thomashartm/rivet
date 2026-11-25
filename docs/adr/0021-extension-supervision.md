# ADR-0021: Extension supervision: restart, timeouts and job limit

- Status: Proposed
- Date: 2026-11-25

## Context

ARCHITECTURE.md §4.4 has the edges `Failed → Active: restart (with backoff)` and `Failed → Disabled: restart limit reached`. §4.3 requires limits per extension. §9 requires that a restart of a failed extension takes less than 1 s. The values and the behaviour of dependents are not defined. The fault isolation ticket (#11) needs them. Part 1 of #11 is on `main` (PR #121). The ten setting keys and their defaults below were compared with `HostConfig` in `host.rs` and `JobConfig` in `jobs.rs`: they are equal. The behaviour rules were not compared with the code line by line.

## Decision

Settings and defaults:

| Key | Default | Meaning |
| --- | --- | --- |
| `extensions.call_timeout_ms` | 30000 | Longest time of one call into an extension |
| `extensions.restart.backoff_initial_ms` | 100 | Delay before the first restart |
| `extensions.restart.backoff_factor` | 2 | Factor for each further delay |
| `extensions.restart.backoff_max_ms` | 1000 | Longest delay |
| `extensions.restart.limit` | 5 | Failed restarts in a row before `Disabled` |
| `extensions.restart.reset_after_ms` | 300000 | Time in `Active` after which the failure count is 0 |
| `jobs.max_per_extension` | 8 | Queued plus running jobs of one extension |
| `jobs.max_concurrent` | 4 | Jobs that run at the same time |
| `jobs.retain_finished` | 100 | Finished jobs that stay readable |
| `jobs.cancel_grace_ms` | 5000 | Time between a cancel request and the abort of an async job |

Behaviour:

- A runtime reports the crash of an active extension to the host. The extension code gets no handle for this.
- A call that exceeds the timeout gives an `internal` error and the state `Failed`. The host drops the instance.
- A job above the limit is refused with a `policy` error.
- When an extension fails, its active dependents are deactivated first. After a successful restart they are activated again. If the extension ends in `Disabled`, they stay `Inactive`.
- The automatic restart applies to a failed activation, a call timeout of load or activate, and a reported crash. A failure in a `deactivate` call starts no automatic restart: the extension stays `Failed` until a manual restart or disable, because the caller asked to stop it.
- A failed restart keeps the state `Failed`. It is no state change (see ADR-0017 b).
- The host publishes an event when it schedules a restart, with the attempt number, the delay and the reason.
- The `jobs.*` settings are owned by the job scheduler. The `extensions.*` settings are owned by the extension host.
- A cancel request of a running async job starts the grace period. After it the scheduler aborts the task and the job ends `Cancelled`.
- A job keeps its slot until its code has really stopped. A blocking job and an async job that never yields cannot be aborted; each keeps its slot.
- Unload, disable, a manual restart and shutdown cancel the pending restarts that they make useless.

## Consequences

- The §9 target "a restart of a failed extension takes < 1 s" is read as: for the first restart, the time from the failure to the state `Active` is below 1 s. That is the delay of 100 ms plus the restart call. Later attempts add their backoff delay on purpose; the target does not apply to them.
- With the defaults the delays are 100, 200, 400, 800 and 1000 ms. The time of the restart call is not measured yet, so the target is not proven.
- An earlier text of this ADR had `backoff_max_ms` = 60000. That value gave a fifth delay of 1600 ms and was never reached with 5 restarts.
- The defaults are not measured. They are settings and can change without a contract change.
- A timed-out call can still run on the blocking pool until it returns or its fuel is used (ADR-0018).
- `ExtensionHost::new` gets a configuration argument. Callers in other tickets must follow.
