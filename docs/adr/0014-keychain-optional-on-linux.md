# ADR-0014: The OS keychain backend is optional on Linux

- Status: Accepted
- Date: 2026-11-25

## Context

The secret store has one built-in backend, the OS keychain (`keychain://`). On Linux the keychain library adds about 130 crates (number given by the maintainer, not measured again for this ADR). On macOS and Windows it uses system libraries.

## Decision

- On macOS and Windows the keychain backend is always built in.
- On Linux the keychain backend is behind a cargo feature of `rivet-core`.
- A Linux build without the feature registers no backend for `keychain`. `keychain://` URIs still parse. Resolving one fails with a clear error that names the missing backend.

## Consequences

- A Linux build for servers and containers can leave the keychain out and use cloud secret managers.
- §6.4 still holds: without a keychain backend, credentials come only from another registered secret backend.
- Open: the feature name and whether it is on by default. The ticket that implements it decides both and records them here.
- Not implemented on 2026-11-25: `rivet-core` depends on `keyring` on every platform.
