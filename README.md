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
2. Run `make run`. The PostgreSQL prompt `sql>` opens.
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

1. Run `rivet save prod postgres://app@db.example.com:5432/app`. Leave the password out of the address.
2. Type the password. It is hidden.
3. rivet connects once to check the password.
4. rivet stores the password in the keychain as `keychain://rivet/prod`.
5. rivet adds the connection to the settings file.
6. Run `rivet prod`.

- A wrong password stores nothing.
- A name that already exists is refused.
- A name has letters, digits, `-` and `_` only.

**Add safety flags (by hand, in the settings file)**

```toml
schema_version = 1

[connections.prod]
url = "postgres://app@db.example.com:5432/app"   # a password here is refused
password = "keychain://rivet/prod"
environment = "prod"
read_only = true
```

| Flag | Effect |
|---|---|
| `environment = "prod"` | A label. Shown when you connect and in the confirmation question. |
| `read_only = true` | Refuses statements that write |
| `confirm_on_write = true` | Asks y/N before a statement that writes. A file or a pipe cannot answer, so it is refused there. |

**Known limit**

- No TLS yet: connections are plain text (#19).
