# ADR-0006: Extension signing: minisign

- Status: Accepted
- Date: 2026-11-25

## Context

Extensions must be signed and verified on install and on load. The product is local first and must not depend on an online service for verification.

## Decision

Packages are signed with minisign. Built-in extensions are signed with the project key, which ships with the binary. Third-party publisher keys are pinned on first install; a key change requires a new review. Unsigned extensions load only in an explicit developer mode.

## Consequences

- Verification works offline.
- No transparency log; key compromise is handled by key rotation and registry revocation.
- Publishers must manage their own minisign keys.
