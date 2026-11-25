# ADR-0021: Extension supervision: restart, timeouts and job limit

- Status: Proposed
- Date: 2026-11-25

## Context

ARCHITECTURE.md §4.4 has the edges `Failed → Active: restart (with backoff)` and `Failed → Disabled: restart limit reached`. §4.3 requires limits per extension. §9 requires that a restart of a failed extension takes less than 1 s. The values and the behaviour of dependents are not defined. The fault isolation ticket (#11) needs them. Part 1 of #11 is not merged on this date.

## Decision

Settings and defaults:

| Key | Default | Meaning |
| --- | --- | --- |
| `extensions.call_timeout_ms` | 30000 | Longest time of one call into an extension |
| `extensions.restart.backoff_initial_ms` | 100 | Delay before the first restart |
| `extensions.restart.backoff_factor` | 2 | Factor for each further delay |
| `extensions.restart.backoff_max_ms` | 60000 | Longest delay |
| `extensions.restart.limit` | 5 | Failed restarts in a row before `Disabled` |
| `extensions.restart.reset_after_ms` | 300000 | Time in `Active` after which the failure count is 0 |
| `jobs.max_per_extension` | 8 | Queued plus running jobs of one extension |

Behaviour:

- A runtime reports the crash of an active extension to the host. The extension code gets no handle for this.
- A call that exceeds the timeout gives an `internal` error and the state `Failed`. The host drops the instance.
- A job above the limit is refused with a `policy` error.
- When an extension fails, its active dependents are deactivated first. After a successful restart they are activated again. If the extension ends in `Disabled`, they stay `Inactive`.
- The automatic restart applies to a failed activation, a call timeout of load or activate, and a reported crash. A failure in a `deactivate` call starts no automatic restart: the extension stays `Failed` until a manual restart or disable, because the caller asked to stop it.
- A failed restart keeps the state `Failed`. It is no state change (see ADR-0017 b).
- The host publishes an event when it schedules a restart, with the attempt number, the delay and the reason.
- Unload, disable, a manual restart and shutdown cancel the pending restarts that they make useless.

## Consequences

- The first restart starts after 100 ms, so the §9 target of 1 s can be met. The target is not measured yet.
- The defaults are not measured. They are settings and can change without a contract change.
- A timed-out call can still run on the blocking pool until it returns or its fuel is used (ADR-0018).
- `ExtensionHost::new` gets a configuration argument. Callers in other tickets must follow.
