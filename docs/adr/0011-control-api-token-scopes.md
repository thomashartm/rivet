# ADR-0011: Control API token scopes

- Status: Accepted
- Date: 2026-11-25

## Context

The control API lets local tools manage tunnels, run queries and jobs. A single all-powerful token gives every script full access, including writes to production databases.

## Decision

Every control API token MUST carry one or more scopes:

| Scope | Allows |
| --- | --- |
| `read-only` | Read profiles, metadata, job status; run statements only on read-only transactions |
| `run-queries` | Run statements and jobs, subject to profile guards |
| `manage-tunnels` | Open and close tunnels and auth proxy endpoints |

The engine checks scopes on every call. Profile guards (read-only profiles, confirm-on-write) still apply on top of scopes.

## Consequences

- Tokens can be given to CI jobs or tools with least privilege.
- New API methods must declare the scope they need.
