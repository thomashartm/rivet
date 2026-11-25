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
| `extensions.restart.limit` | 5 | Automatic restarts that are permitted. The failure after the last one gives `Disabled`. Each failure counts, also when the restart before it was successful. |
| `extensions.restart.reset_after_ms` | 300000 | Time in `Active` after which the failure count is 0. Nothing else sets it to 0. |
| `jobs.max_per_extension` | 8 | Queued plus running jobs of one extension |
| `jobs.max_concurrent` | 4 | Jobs that run at the same time |
| `jobs.retain_finished` | 100 | Finished jobs that stay readable |
| `jobs.cancel_grace_ms` | 5000 | Time between a cancel request and the abort of an async job |

Behaviour:

- A runtime reports the crash of an active extension to the host. The extension code gets no handle for this.
- A call that exceeds the timeout gives an `internal` error and the state `Failed`. The host drops the instance.
- A call that ends after the limit with an error keeps its own error; the host refuses only a success that comes late (review finding R-51, on `main` since PR #179; comment in `host.rs` at the function `joined`). Reason: the WASM runtime has the same limit and ends the call with its own error, which says more than the error of the host timer.
- Known limit of the host timer: the time limit of the host runs on the async runtime. If code of an extension blocks a worker thread, it can happen that no thread drives the timer; then the limit does not end the call until a worker runs again. Seen by the orchestrator in a host test with 2 workers, about 1 time in 40 runs under load (not repeated for this record). Rule: a runtime MUST NOT block a worker thread in a call. It runs code that can block on the blocking pool, or it has its own limit that does not need the async runtime (as the epoch limit of the WASM runtime, ADR-0018). No code checks this rule. The WASM runtime and the native runtime keep it on this date; a runtime that runs extension code in the process of the engine must prove it.
- A job above the limit is refused with a `policy` error.
- When an extension fails, its active dependents are deactivated first. After a successful restart they are activated again. If the extension ends in `Disabled`, they stay `Inactive`.
- The automatic restart applies to a failed activation, a call timeout of load or activate, and a reported crash. A failure in a `deactivate` call starts no automatic restart: the extension stays `Failed` until a manual restart or disable, because the caller asked to stop it.
- The limit counts failures, not failed restarts: an extension that starts and crashes again in less than the reset time is a crash loop, and it must end in `Disabled`. With the defaults, the sixth failure without 5 minutes in `Active` disables the extension (as built, `host.rs`).
- A failed restart keeps the state `Failed`. It is no state change (see ADR-0017 b).
- The host publishes an event when it schedules a restart, with the attempt number, the delay and the reason.
- The `jobs.*` settings are owned by the job scheduler. The `extensions.*` settings are owned by the extension host.
- A cancel request of a running async job starts the grace period. After it the scheduler aborts the task and the job ends `Cancelled`. If the job ends in the same poll as the grace period, the result of the job wins. This is exact only on a runtime with one thread. On a runtime with more threads the two events have no fixed order: a job whose code returns in the moment of the abort can be recorded as `Cancelled`, and its result is dropped. Measured by the reviewer for a job that ends at the grace time (not repeated for this record): 29 of 1000 on 2 worker threads, 18 of 1000 on 8. This limit is accepted: the user asked for the cancel, and only a job that ends at the end of its grace period is affected (review finding R-120). `jobs.cancel_grace_ms` must be from 1 to 60 000; 0 and a larger value are refused with a `user` error that names the key. Reason for the upper bound: the release of an extension and the shutdown wait for this time. The number 60 000 is not measured. The range is checked for the setting only. A scheduler that code builds from a configuration value (`JobScheduler::with_config`) is not checked, the same as the configuration of the host: a grace time of zero aborts at once, and a very long one makes a release wait. The code that builds the application is trusted for this (review finding R-79). (Review finding R-79, on `main` since PR #180.)
- A job keeps its slot until its code has really stopped. A blocking job and an async job that never yields cannot be aborted; each keeps its slot.
- When the host releases an extension, the service registry, the command bus, the event bus, the job scheduler and the secret store refuse this owner until the release has ended (review finding R-17a; on `main` since PR #179 for the registry, the two buses and the job scheduler, and since PR #182 for the secret store). Each component keeps its own mark and checks it under its own lock. A new subscription of this owner is closed at once. The secret store checks its mark under the lock of its backend map (stated by the fix agent; the lock was not checked for this record).
- Known limit, the owner is given by the caller: the service registry, the command bus, the event bus, the job scheduler and the secret store take the owner as an argument and do not prove it. A call without an owner is not released with an extension (for example a subscription to the event bus without owner stays after a deactivation), and a call can name the id of another extension (review findings R-74 and R-90). This is safe only because an extension never gets these services: no host import for them exists on this date. Rule for the code that will give them to an extension (host imports of the WASM runtime, the native protocol): it MUST set the owner to the id of the extension that calls, MUST NOT take the owner from the guest, and MUST NOT offer a call without owner.
- Limit: the host waits until each job has ended or was aborted after the grace period. Code that cannot be aborted can run on after the release and after a restart of the same extension, and it can register again under the same id. The next release removes it. The host does not keep the extension stopped for this.
- The shutdown of the host deactivates each active extension and then drops each instance, also the instance of an extension that was `Inactive` before. No code and no process of an extension stays after the shutdown (§5.2, §5.7). The entries and their states stay readable; the host activates nothing after a shutdown. (On `main` since PR #182; before, the shutdown kept the instances.)
- Crash report rules (review finding R-89 and ADR-0024). On `main` since PR #182: the three rules for an extension that is not `Active` and for an unknown id. NOT on `main` on this date: a crash report carries the time of the failure, and the host ignores a report that is older than the load of the instance that it has now. A report for an extension that is not `Active` but has an instance (for example `Inactive`) drops this instance: the state does not change, no failure is counted, nothing restarts, and the next activation loads a new instance. A report for an extension without an instance is ignored: the call returns success, nothing changes, and one `debug` log event is written. A report for an id that the host does not know is a `user` error. The failure time and the rule for an older report need a change of the call and of the callback of the native runtime; they are not in host slice 3 and have no ticket.
- Details of the failure time (ruled for host slice 4, not on `main` on this date). "The load of the instance" is the start of the load, not its end: a failure of the new instance in the time of its own load must not be lost. The clock is the monotonic clock of the standard library, not the clock of the async runtime; a paused test clock does not change it. A report that is ignored returns success and writes one `debug` event. Rule for each runtime: it MUST NOT report a crash of an instance that the host dropped. Reason: the load of a native extension waits for the old process inside the load (ADR-0024), so a report about the old process could have a time after the start of the new load. The native runtime keeps the rule: it reports nothing after it ended the child itself.
- Unload, disable, a manual restart and shutdown cancel the pending restarts that they make useless.

## Consequences

- The §9 target "a restart of a failed extension takes < 1 s" is read as: for the first restart, the time from the failure to the state `Active` is below 1 s. That is the delay of 100 ms plus the restart call. Later attempts add their backoff delay on purpose; the target does not apply to them.
- With the defaults the delays are 100, 200, 400, 800 and 1000 ms. The time of the restart call is not measured yet, so the target is not proven.
- An earlier text of this ADR had `backoff_max_ms` = 60000. That value gave a fifth delay of 1600 ms and was never reached with 5 restarts.
- The defaults are not measured. They are settings and can change without a contract change.
- A timed-out call can still run on the blocking pool until it returns or its fuel is used (ADR-0018).
- `ExtensionHost::new` gets a configuration argument. Callers in other tickets must follow.
