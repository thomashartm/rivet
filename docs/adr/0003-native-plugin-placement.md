# ADR-0003: Native plugins run out-of-process by default

- Status: Accepted
- Date: 2026-11-25

## Context

Native plugins (C ABI) are used for drivers and performance-critical code. A crash or memory corruption inside the engine process cannot be contained, but the mission requires that a crashing extension is contained and restartable.

## Decision

Native plugins MUST run in a separate extension host process by default. A signed first-party extension MAY run in-process only when a benchmark shows the out-of-process cost is unacceptable; that exception needs its own ADR.

## Consequences

- Data crosses the process boundary as Arrow IPC over a local socket.
- The engine supervises and restarts the extension host process.
- Out-of-process placement adds latency per call; streaming in batches keeps the cost small.
