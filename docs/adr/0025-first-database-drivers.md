# ADR-0025: First database drivers

- Status: Proposed
- Date: 2026-11-25

## Context

Ticket #15 asks for PostgreSQL and MySQL drivers as extensions "with native async wire-protocol implementations". The maintainer started Epic 2 on this date and asked for small steps.

Facts on `main` on this date:

- The driver contract exists in `rivet-sdk` (`extension.rs`): `Driver` (dialect, connect), `Connection` (execute, cancel), `ConnectRequest` with an optional transport stream.
- `rivet-sdk` depends on `arrow-array` and `arrow-schema`.
- The native runtime cannot load a driver yet (#95 parts 2 to 4 wait for decisions of the maintainer).

## Decision

All rows are proposals of the architect. The rows marked "question" wait for the maintainer; work starts with the default.

| Topic | Decision |
| --- | --- |
| Contract | The existing contract is used. It changes only where a driver cannot be written without the change. |
| Crates | `rivet-ext-postgres` and `rivet-ext-mysql`. Each depends on `rivet-sdk`, and on `rivet-testkit` as a dev-dependency only (§3.2, ADR-0016). No edge to or from `rivet-core`. |
| Arrow | A driver crate MAY depend on `arrow-array` and `arrow-schema`, in the version of `rivet-sdk`. No other Arrow crate. |
| Conformance suite | It is in `rivet-testkit` and takes a `&dyn Driver`, because the testkit MUST NOT depend on an extension crate. Each driver crate runs it in its own tests. |
| Wire protocol (question) | Default: the crates `tokio-postgres` and `mysql_async` behind the contract. Reading of the architect: "native async" means a pure Rust async implementation, not own protocol code. |
| New dependencies (question) | Default: permitted for the two driver crates only, default features off, TLS features off (TLS features on since #222: rustls with the `ring` provider). Licences and the number of packages are not checked on this date. |
| First type mapping (question) | Default: boolean, signed and unsigned integers, floats, text and binary are typed, except MySQL `boolean` (`tinyint(1)`), which is `Int8` (`UInt8` if unsigned) with source type `tinyint(1)`, because it can hold values such as 2 or -1. Each other type is its text form in a `Utf8` column, with the type name of the database in the field metadata. |
| Transport | If the request has a transport stream, the driver uses it and opens no socket. A driver that cannot do this refuses the request. It never connects directly in silence. |
| TLS | Until #19 a profile that asks for TLS was refused. Since #222 (2026-11-26, #19 slice 1): TLS with rustls, the certificate and the host name are verified, trust is the system store or only `tls.ca_certificate`, the PostgreSQL cancel request uses TLS too, a server without TLS is refused, a client certificate is refused with `user` (not supported yet). No plain text in silence. |

## Consequences

- A driver is tested as a Rust value in its own crate. That it loads as an extension is not proven by #15.
- If `mysql_async` cannot run over a given stream (not checked), MySQL through a tunnel needs own protocol code or another crate later. The contract hides this choice.
- A typed mapping of numbers with decimals, dates, times, UUID and JSON is later work. A client sees these values as text until then.
- Not in #15: packaging and load through the native runtime (#95), TLS (#19), pooling (#21), IAM (#16, #17), introspection (#23), statement parameters, more than one statement in one call.
