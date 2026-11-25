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
- Path: not empty and not only white space (`path.trim().is_empty()` in `secret.rs` is refused).
- Keychain on Windows only: a `.` in the service part of a `keychain` URI is refused with a `user` error that says why. A `.` in the account part is permitted. Reason: the Windows store names an entry `<account>.<service>`, so `keychain://b.c/a` and `keychain://c/a.b` would name one entry, and a grant for one namespace would read a secret of another. macOS and Linux do not change. (Review finding R-78; on `main` since PR #185. The entry name rule was read by the fix agent in the sources of the keyring crates, not checked for this record. CI does not run on Windows.)
- Any well-formed scheme parses. The three schemes above are the built-in names; they are not a closed list.
- A scheme without a registered backend fails when the secret is resolved, not when the URI is parsed.

Names and hosts in a manifest (Proposed, not decided by the owner; review finding R-55b):

| Field | Rule | Reason |
| --- | --- | --- |
| Extension id, contribution id, activation `command`, activation `type` | Segments separated by `.`; a segment has lowercase ASCII letters, digits and `-`. No `_`, no uppercase. `pg_vacuum` is refused; `pg-vacuum` and `pg.vacuum` are valid. | The author chooses the name, so one spelling costs nothing. To permit more characters later is a compatible change; to forbid them later is not. |
| Network `host`: character `_` | Permitted in a label, at each position. `db_1.example.com` is valid. | The user cannot rename a real host, and such names exist (for example container service names). |
| Network `host`: `.` at the end | Refused. `db.example.com.` is not valid; the message says to remove the `.`. | The permission check compares text (ADR-0020). Two spellings of one host would make a grant that does not match. |

- Each of the lists `contributes`, `activation`, `capabilities.network`, `capabilities.filesystem` and `capabilities.secrets` has at most 256 entries (one constant). `ports` and `dependencies` have no limit of their own: a port list has no duplicates, and the package limits the manifest to 1 MiB (ADR-0023). (Review finding R-54.)
- A filesystem scope path has one spelling (review finding R-55c). Refused: an empty component (`/a//b`, `//host/share`; the start `\\` of a UNC path stays permitted), a `.` component, a separator at the end except for a root (`/`, `C:\`, `C:/`; write `~`, not `~/`), each control character, and the same path two times, also with different access (read-write includes read).
- The command bus does not check the name of a command. A command with a name that the manifest rule refuses can be registered, but it cannot be an activation event.

Secret check of settings files (Proposed, not decided by the owner; review findings R-44, R-64, R-65; `settings.rs`; on `main` since PR #146, except where a line says otherwise):

- The check is a guard against common mistakes. It is not a proof. The check reads the name of a key. It does not read inside a value. Inputs that it accepts, found in the close-out audit of ticket #9 (not tested for this record): a secret in a string of the form `NAME=value` (`env = "PGPASSWORD=..."`), in text that holds JSON, and in a list of arguments (`args = ["--password", "..."]`). So the criterion "no secret value is accepted in settings" of ticket #9 is not met as written.
- An error of a settings file names the file and the key. A syntax error of TOML is the exception: it names the file and the line, and a fixed text. Reason: no key is known at a syntax error, and the text of the parser can repeat a part of the file, which can be a secret value (review finding R-63).
- A key path is "about a secret" if the secret segment, or a key below it, comes with a word of one fixed list: `max`, `min`, `ttl`, `length`, `len`, `limit`, `count`, `size`, `timeout`, `retries`, `per`, `file`, `path`, `encryption`. Examples: `max_tokens`, `token_ttl`, `db_password_file`.
- Position of the word (review finding R-93, on `main` since PR #158): the last word of the key name is in the list (`token_ttl`, `password_file`); or the first word is `max` or `min` (`max_tokens`); or the word `per` is at any position (`tokens_per_page`). No other position counts: `file_password = "hunter2"` is refused.
- A table key with a list word below a secret key (`[credentials] retries`, `[tokens.limit] burst`): numbers and booleans below it are accepted; a string below it must be a secret URI. So `[credentials] file = "/etc/creds"` is refused; write `credentials_file`.
- Under a secret key that is not "about a secret": a string must be a secret URI; a number and a date are refused; a boolean is accepted.
- Under a key "about a secret": each value type is accepted. The checks of the text (URL with a password, parameter with a secret name) still apply.
- A parameter name in a text follows the same list: `password_encryption=...` is accepted.
- A parameter with a secret name is accepted if its whole value is a placeholder of the form `${...}`, `{...}` or `%s`.
- A built-in secret URI gets no text check only if it has one `://`, no whitespace and no `;`.
- Known limits: `pin` is not a secret name (it is a common word for user interface settings); `user:password@host` without `://` is not found; `password_file = "hunter2"` and `keychain://x?password=hunter2` are accepted.

## Consequences

- Profiles and policies stay free of secrets and can be committed.
- The secret service resolves URIs at connection time only.
- A wrong scheme name in a profile is found only at connection time.
