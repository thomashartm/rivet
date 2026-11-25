# ADR-0004: Control API: gRPC with Arrow Flight

- Status: Accepted
- Date: 2026-11-25

## Context

The mission allows local gRPC or JSON-RPC. The control API must manage tunnels, run queries and jobs, and stream large result sets.

## Decision

The control API uses gRPC. Query results stream over Arrow Flight. The API is versioned by gRPC package (`rivet.control.v1`). Transport is a Unix socket or loopback with token auth.

## Consequences

- Typed contracts generated from protobuf for every client language.
- Results stream in Arrow format without conversion.
- Ad-hoc scripting with plain HTTP tools is harder than with JSON-RPC; client libraries cover this.
