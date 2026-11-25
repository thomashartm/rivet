# ADR-0015: Integration tests use local database containers

- Status: Accepted
- Date: 2026-11-25

## Context

ARCHITECTURE.md §9 requires integration tests against real PostgreSQL and MySQL containers. The way to start them was not fixed.

## Decision

Integration tests run against local PostgreSQL and MySQL containers. A Docker Compose file in the repository starts them. `rivet-testkit` gives the fixtures (#13).

## Consequences

- Developers and CI use the same container definitions.
- No cloud account is needed for integration tests.
- Tests that need containers need Docker. They run only when asked for, so `cargo test` passes without Docker (#13).
- Cloud-specific paths (IAM, SSM, IAP) are not covered by these containers.
