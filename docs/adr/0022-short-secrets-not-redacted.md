# ADR-0022: Secrets shorter than 4 bytes are not redacted in logs

- Status: Accepted (maintainer, 2026-11-25). The points that the text marks as open or as a proposal stay open.
- Date: 2026-11-25

## Context

ARCHITECTURE.md §7.4 says secrets MUST be redacted in logs, traces, errors and crash reports. The logging layer replaces each known secret value in the output text. As built, it ignores values shorter than 4 bytes (`MIN_REDACTED_LEN` in `crates/rivet-core/src/logging.rs`). To replace a value of 1 to 3 bytes would damage most log lines, and the places of the replacements would show the value.

## Decision

- The exception stays: a secret value shorter than 4 bytes is not redacted by text replacement.
- The secret store does not refuse short secrets. Development and test databases use them.
- When the secret store resolves a value shorter than 4 bytes, it writes one `warn` log event with the secret URI and without the value. Implemented since PR #170 (`secrets.rs`, in the read path of the store; the event has the URI and the reader, never the value). The event is written at each such read, not one time per secret.
- Text replacement is the second line of defence. The first line stays a MUST: a secret value is carried only in the `Secret` type, which has no `Display` and no `Serialize`, so code cannot write it to a log by accident.
- §7.4 has the words "of 4 bytes or more" since the maintainer accepted this ADR (2026-11-25). A short secret gives the warning only; it is not refused (decided by the maintainer on 2026-11-25; review finding R-3).

## Consequences

- Text replacement also has a second limit: it finds a secret value as plain text and in the escaped forms of Rust `Debug`, JSON and the human log format, up to four layers (review fix R-67a, on `main` since PR #146). The log path uses up to two of them (a value logged with `?` in the Json format), so two layers are left for an escape that the application made itself. Measured by the fix agent: four layers give at most 25 forms per secret, three give 17. It does not find other encodings, for example Base64 or URL encoding. (Review fix R-43, on `main`: read in `logging.rs` at commit aafd7b8.)
- A secret of 1 to 3 bytes can appear in a log if code exposes it on purpose and logs it.
- The user sees a warning for each read of such a secret.
- The alternative, to refuse short secrets, was not chosen: a user cannot change the password rules of each database they must connect to.
