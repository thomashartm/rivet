# ADR-0008: Manifest name and secret URI scheme

- Status: Accepted
- Date: 2026-11-25

## Context

Extensions need a fixed manifest file name. Configuration as code must reference secrets without containing them.

## Decision

The manifest file is `extension.toml`. Secrets are referenced by URI: `keychain://…` (OS keychain), `aws-sm://…` (AWS Secrets Manager), `gcp-sm://…` (GCP Secret Manager). New schemes are added by credential source extensions.

Grammar of a secret URI (as built, PR #108):

- Form: `<scheme>://<path>`.
- Scheme: one lowercase letter, then lowercase letters, digits, `+`, `-` or `.`. Uppercase is not accepted, so a scheme has one spelling.
- Path: not empty.
- Any well-formed scheme parses. The three schemes above are the built-in names; they are not a closed list.
- A scheme without a registered backend fails when the secret is resolved, not when the URI is parsed.

## Consequences

- Profiles and policies stay free of secrets and can be committed.
- The secret service resolves URIs at connection time only.
- A wrong scheme name in a profile is found only at connection time.
