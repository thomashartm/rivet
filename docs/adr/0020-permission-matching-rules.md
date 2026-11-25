# ADR-0020: Permission matching rules

- Status: Proposed
- Date: 2026-11-25

## Context

ARCHITECTURE.md §4.7 lists the capabilities and their scopes. It does not say how a request is compared with a grant. The permissions ticket (#7) needs the rules. Part 1 of #7 is on `main` (`crates/rivet-core/src/permissions.rs`). The rows "Secret backends" and "Secret namespace and scheme" and part 2 of the `filesystem` row are not implemented.

## Decision

| Capability | Rule |
| --- | --- |
| `network` | The host must equal a granted host (ASCII case ignored) and the port must be in its list. No wildcard, no subdomain, no name resolution. Two IP addresses are compared as addresses. |
| `filesystem` | A scope is an absolute path or starts with `~`. The scope and the requested path are resolved (symbolic links, `..`) before the comparison. Write access needs a read-write scope. Part 2 of #7: the service opens the file itself, below a directory handle of the scope root, and returns the open handle. It returns no path that a caller opens again. |
| `secrets` | A namespace is the first `/` segments of the path of a secret URI. Exact and case-sensitive. It applies to every secret backend scheme. An entry that contains `://` grants nothing; this form is reserved for a later rule per scheme. |
| Update review | The service stores the capabilities that the installed manifest requested. A new manifest is compared with that request. A network entry is compared with the rule of the `network` row (ASCII case ignored, IP addresses as addresses), so another spelling of the same host is not an addition. A filesystem path and a secret namespace are compared by exact text. If it adds nothing, the grant of the user is kept, also a partial grant, and is cut to what the new manifest still requests. If it adds something, the grant is removed until a new review. |
| Secret backends | An extension registers a backend with itself as owner. It may register a scheme only if its manifest declares the scheme and the user granted it in the install review. The scheme `keychain` is reserved for the core on every platform. The schemes `aws-sm` and `gcp-sm` are reserved for built-in extensions when the signature check can prove the origin (#12). A second registration of a scheme fails with a `policy` error. Not implemented, no code: the manifest declaration and the reserved scheme `keychain` are for #7 part 2 and wait for the decision of the maintainer on the manifest format; the reserved schemes `aws-sm` and `gcp-sm` are for #12 part 2. |
| Secret service | Each extension gets its own secret service. It checks the namespace first and asks the backend only after that. An extension can read through a backend that another extension registered. The service cannot remove a value from the log redaction; only the host can. (#7 part 2, not on `main` on this date.) |
| Secret namespace and scheme | Open, for the maintainer: bind each namespace to one scheme with a manifest table (`scheme`, `namespace`). Until then a namespace applies to every scheme. |

## Consequences

- Every rule denies in case of doubt.
- A grant for a secret namespace gives access to that namespace in each backend. The install review MUST say this (to enforce in #51; no check exists).
- An update that adds no capability needs no new review (§4.7), also after a partial grant.
- The manifest needs a place to declare secret schemes. This is a manifest format change.
- A swap of a parent directory for a symbolic link after the check cannot redirect an open, when part 2 is done. The crate for directory handles (candidate: `cap-std`) is not chosen; its licence and size are not checked.
- A secret value that an extension already holds stays usable after a revoke. Only the next request is denied. To stop the use, the host must deactivate the extension.
- A granted host name does not grant its addresses. The caller MUST connect to the host that was checked (to enforce in the network host import, #7 part 2; no check exists).
