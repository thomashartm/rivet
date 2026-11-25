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

Names and hosts in a manifest (Proposed, not decided by the owner; review finding R-55b):

| Field | Rule | Reason |
| --- | --- | --- |
| Extension id, contribution id, activation `command`, activation `type` | Segments separated by `.`; a segment has lowercase ASCII letters, digits and `-`. No `_`, no uppercase. `pg_vacuum` is refused; `pg-vacuum` and `pg.vacuum` are valid. | The author chooses the name, so one spelling costs nothing. To permit more characters later is a compatible change; to forbid them later is not. |
| Network `host`: character `_` | Permitted in a label, at each position. `db_1.example.com` is valid. | The user cannot rename a real host, and such names exist (for example container service names). |
| Network `host`: `.` at the end | Refused. `db.example.com.` is not valid; the message says to remove the `.`. | The permission check compares text (ADR-0020). Two spellings of one host would make a grant that does not match. |

- The command bus does not check the name of a command. A command with a name that the manifest rule refuses can be registered, but it cannot be an activation event.

## Consequences

- Profiles and policies stay free of secrets and can be committed.
- The secret service resolves URIs at connection time only.
- A wrong scheme name in a profile is found only at connection time.
