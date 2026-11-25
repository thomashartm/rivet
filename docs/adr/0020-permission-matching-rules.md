# ADR-0020: Permission matching rules

- Status: Proposed
- Date: 2026-11-25

## Context

ARCHITECTURE.md §4.7 lists the capabilities and their scopes. It does not say how a request is compared with a grant. The permissions ticket (#7) needs the rules. Part 1 of #7 is not merged on this date.

## Decision

| Capability | Rule |
| --- | --- |
| `network` | The host must equal a granted host (ASCII case ignored) and the port must be in its list. No wildcard, no subdomain, no name resolution. Two IP addresses are compared as addresses. |
| `filesystem` | A scope is an absolute path or starts with `~`. The scope and the requested path are resolved (symbolic links, `..`) before the comparison. Write access needs a read-write scope. |
| `secrets` | A namespace is the first `/` segments of the path of a secret URI. Exact and case-sensitive. It applies to every secret backend scheme. An entry that contains `://` grants nothing; this form is reserved for a later rule per scheme. |
| Update review | A new manifest is compared with the current grant. If it asks for something the grant does not cover by exact text, the grant is removed until a new review. |
| Secret backends | An extension registers a backend with itself as owner. The first registration of a scheme stays; a second one fails with a `policy` error. The built-in keychain backend has no owner and cannot be removed. |

## Consequences

- Every rule denies in case of doubt.
- A grant for a secret namespace gives access to that namespace in each backend. The install review MUST say this.
- A user who granted only a part of a request gets a new review on each update.
- A granted host name does not grant its addresses. The caller MUST connect to the host that was checked.
