# ADR-0008: Manifest name and secret URI scheme

- Status: Accepted
- Date: 2026-11-25

## Context

Extensions need a fixed manifest file name. Configuration as code must reference secrets without containing them.

## Decision

The manifest file is `extension.toml`. Secrets are referenced by URI: `keychain://…` (OS keychain), `aws-sm://…` (AWS Secrets Manager), `gcp-sm://…` (GCP Secret Manager). New schemes are added by credential source extensions.

## Consequences

- Profiles and policies stay free of secrets and can be committed.
- The secret service resolves URIs at connection time only.
