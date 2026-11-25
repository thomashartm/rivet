# ADR-0005: Local persistence: SQLite

- Status: Accepted
- Date: 2026-11-25

## Context

Query history, the metadata cache and the audit logs need durable local storage. The product is local first and must not need a server.

## Decision

Local persistent state uses SQLite, one database file per owner component. The audit log is append-only.

## Consequences

- No external service; one file per store.
- Each owner manages its own schema migrations.
- Settings and profiles stay in TOML files, not in SQLite, so they remain diffable.
