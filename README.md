<p align="center">
  <img src="docs/assets/rivet-logo.jpg" alt="rivet logo: a smiling database with a rivet head and a keyhole" width="300">
</p>

# Rivet

Rivet is a headless-first database client for PostgreSQL and MySQL, written in Rust. The goal is to run queries and stream results from the command line, with an optional desktop client that uses the same engine.

The design calls for native IAM authentication on AWS and Google Cloud. Database drivers, authentication providers, and UI features all use the same public extension API available to third-party developers.

[Project mission](MISSION.md) · [Architecture](ARCHITECTURE.md)

## How to build

**You need**

| Tool | For |
|---|---|
| Rust (rustup) | Building. The toolchain version comes from `rust-toolchain.toml`. |
| `make` | The short commands below |
| Docker with Docker Compose | The test databases |
| `openssl` | Random passwords for the test databases |

**Steps**

1. Open a terminal in the repository root.
2. Run `make build`.
3. The program is `target/release/rivet`.
4. Optional: run `make install`. This puts `rivet` into `~/.cargo/bin`.

**All make commands**

| Command | What it does |
|---|---|
| `make help` | Lists the commands |
| `make build` | Builds `target/release/rivet` |
| `make install` | Installs `rivet` into `~/.cargo/bin` |
| `make playground` | Starts the test databases and writes `.env` |
| `make run` | Builds if needed, then opens the PostgreSQL test database |
| `make run-mysql` | Builds if needed, then opens the MySQL test database |
| `make stop` | Stops the test databases. The data stays. |
| `make reset` | Stops the test databases. Deletes their data and `.env`. |
| `make check` | Runs all checks: format, lint, tests, architecture, licences |

## How to run

Run every command from the repository root: rivet reads `./.env` there.

**First run with the test databases**

1. Run `make playground`.
   - PostgreSQL starts on 127.0.0.1:55432.
   - MySQL starts on 127.0.0.1:53306.
   - Both get the sample tables `customers`, `products`, `orders`, `order_items`.
   - Both use TLS with a throwaway certificate for `localhost`. `.env` trusts only its CA, `docker/test-certs/ca.pem`.
2. Run `make run`. The PostgreSQL prompt `sql>` opens. The connect line ends with `(TLS)`.
3. Type `select * from customers;` and press Enter.
4. Type `\q` to quit.
5. Run `make run-mysql` for MySQL.
6. Run `make stop` when you are done.

**Which database opens**

| Command | Opens |
|---|---|
| `rivet` | `RIVET_DATABASE_URL` |
| `rivet <name>` | The saved connection `<name>`, else `RIVET_DATABASE_URL_<NAME>` |
| `rivet postgres://user:password@host:port/db` | That address. `mysql://…` works too. |

**Commands at the `sql>` prompt**

| Command | What it does |
|---|---|
| `\l` | Lists the databases on the server |
| `\c <database>` | Connects to `<database>` on the same server. User, password, TLS and flags stay the same. If it fails, the old connection stays. |
| `\d` | Lists the tables |
| `\d <table>` | Shows the columns of a table |
| `\?` | Shows this list |
| `\q` | Quits |

**TLS**

| Address ends with | Connection |
|---|---|
| nothing | TLS. The server certificate and the host name are checked against the system trust store. |
| `?tls_ca=/path/ca.pem` | TLS. Only the CA in that file is trusted. |
| `?tls=off` | Plain text. The connect line says `plaintext, no TLS`. Use it only for a local server. |
| `?tls_cert=/path/client.pem&tls_key=keychain://rivet/<name>-key` | TLS with a client certificate: the PEM file and its PEM key from the secret URI. It replaces the password. The connect line says `TLS, client certificate`. |

- Any other parameter in the address is refused.
- A server without TLS is refused unless the address has `?tls=off`.

**At the prompt**

| Input | Action |
|---|---|
| A statement that ends with `;` | Runs it. A statement can span lines. |
| `\d` | Lists the tables |
| `\d <table>` or `\d <schema>.<table>` | Describes a table |
| `\?` | Lists the commands |
| `\q` or Ctrl-D | Quits |
| Ctrl-C while a statement runs | Cancels the statement |
| Ctrl-C while typing | Clears the line |
| Arrow up / down | Recalls earlier statements |

**Files, pipes and output formats**

| Task | Command |
|---|---|
| Run a SQL file | `rivet pg -f script.sql` |
| Pipe statements in | `echo 'select 1;' \| rivet pg` |
| CSV output | `rivet pg -f report.sql --format csv > report.csv` |
| JSON output (one object per row) | `rivet pg -f report.sql --format json` |

- A file stops at the first error, with exit code 1.
- A pipe goes on after an error and ends with exit code 1.
- CSV and JSON stream. Memory stays flat. `| head` stops the query.
- The table format holds the whole result in memory.
- After `insert`, `update`, `delete`, `merge`, `replace` or `with`: `(n rows changed)`. After another statement without result rows, for example `create table`: `ok`. CSV and JSON print this line to stderr.

## Credential management

Two places hold credentials.

| Place | Password stored in | Use for |
|---|---|---|
| `.env` in the repository root | The file, as plain text | The local test databases only |
| The settings file plus the keychain | The OS keychain | Real databases |

### `.env`

- `make playground` writes it, with random passwords.
- Git ignores it. Never commit it.
- One line per connection: `RIVET_DATABASE_URL_<NAME>=postgres://user:password@host:port/db`.
- Open it with `rivet <name>`. Upper or lower case both work.
- Variables in the shell environment win over `.env`.

### Settings file plus keychain

The settings file:

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/rivet/settings.toml` |
| Linux | `~/.config/rivet/settings.toml` |

**Save a connection**

1. Run `rivet save prod postgres://app@db.example.com:5432/app --env prod --read-only`. Leave the password out of the address.
2. rivet checks the address and the flags. A bad one stops here, before the password prompt.
3. Type the password. It is hidden.
4. rivet connects once to check the password.
5. rivet stores the password in the keychain as `keychain://rivet/prod`.
6. rivet adds the connection to the settings file.
7. Run `rivet prod`.

Flags (after `save`, in any order, each once):

| Flag | Written to the settings file | Effect |
|---|---|---|
| `--read-only` | `read_only = true` | Refuses statements that write |
| `--confirm-on-write` | `confirm_on_write = true` | Asks y/N before a statement that writes. A file or a pipe cannot answer, so it is refused there. |
| `--env <label>` | `environment = "<label>"` | A label. Shown when you connect and in the confirmation question. |

TLS options stay in the address: `?tls=off`, `?tls_ca=<path>`.

- A wrong password stores nothing.
- A name that already exists is refused.
- A name has letters, digits, `-` and `_` only.

**The saved result**

```toml
schema_version = 1

[connections.prod]
url = "postgres://app@db.example.com:5432/app"   # a password here is refused
password = "keychain://rivet/prod"
environment = "prod"
read_only = true
```

You can also edit these lines by hand.

**Known limit**

- A client certificate and a password together are refused (#19).
- `rivet save` cannot save a connection with a client certificate yet: write its `[connections.<name>]` table by hand, with `tls_cert` and `tls_key` in `url` and no `password`.

## Licence

[Apache License 2.0](LICENSE).
