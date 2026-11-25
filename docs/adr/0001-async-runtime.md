# ADR-0001: Async runtime: Tokio

- Status: Accepted
- Date: 2026-11-25

## Context

The engine needs one async runtime for drivers, tunnels, pools, jobs and the control API. Most Rust database, AWS SDK, GCP and gRPC libraries are built on Tokio.

## Decision

The engine uses a single multi-threaded Tokio runtime. Blocking work runs on Tokio's blocking pool. Extensions do not create their own runtimes.

## Consequences

- Direct reuse of the AWS SDK, tonic (gRPC) and async database libraries.
- Native plugins in the out-of-process host also use Tokio.
- Switching runtime later would be a breaking change for native extensions.
