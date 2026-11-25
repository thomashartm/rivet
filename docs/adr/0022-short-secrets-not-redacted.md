# ADR-0022: Secrets shorter than 4 bytes are not redacted in logs

- Status: Proposed
- Date: 2026-11-25

## Context

ARCHITECTURE.md §7.4 says secrets MUST be redacted in logs, traces, errors and crash reports. The logging layer replaces each known secret value in the output text. As built, it ignores values shorter than 4 bytes (`MIN_REDACTED_LEN` in `crates/rivet-core/src/logging.rs`). To replace a value of 1 to 3 bytes would damage most log lines, and the places of the replacements would show the value.

## Decision

- The exception stays: a secret value shorter than 4 bytes is not redacted by text replacement.
- The secret store does not refuse short secrets. Development and test databases use them.
- When the secret store resolves a value shorter than 4 bytes, it writes one `warn` log event with the secret URI and without the value.
- Text replacement is the second line of defence. The first line stays a MUST: a secret value is carried only in the `Secret` type, which has no `Display` and no `Serialize`, so code cannot write it to a log by accident.
- §7.4 gets the words "of 4 bytes or more" when the maintainer accepts this ADR.

## Consequences

- A secret of 1 to 3 bytes can appear in a log if code exposes it on purpose and logs it.
- The user sees a warning for each such secret.
- The alternative, to refuse short secrets, was not chosen: a user cannot change the password rules of each database they must connect to.
