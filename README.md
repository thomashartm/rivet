# Rivet

Rivet is a headless-first database client for PostgreSQL and MySQL, written in Rust. The goal is to run queries and stream results from the command line, with an optional desktop client that uses the same engine.

The design calls for native IAM authentication on AWS and Google Cloud. Database drivers, authentication providers, and UI features all use the same public extension API available to third-party developers.

[Project mission](MISSION.md) · [Architecture](ARCHITECTURE.md)

## Quick start

```sh
docker/playground.sh          # starts PostgreSQL (127.0.0.1:55432) and MySQL (127.0.0.1:53306), writes .env
cargo run -p rivet-cli        # default connection: the PostgreSQL playground
cargo run -p rivet-cli -- mysql
sql> select * from customers;
```

- `.env` is generated and never committed. It holds random passwords and the connections.
- A named connection is a line `RIVET_DATABASE_URL_<NAME>=postgres://…` or `mysql://…` in `.env` (or the environment); `rivet <name>` opens it. `rivet` alone opens `RIVET_DATABASE_URL`.
- Any other database: `cargo run -p rivet-cli -- postgres://user:password@host:port/database`.
- Run a file: `cargo run -p rivet-cli -- pg -f script.sql`. It stops at the first error with exit code 1.
- Ctrl-C cancels the running statement; at the prompt it clears the line. Arrow keys recall the history. `\q` or Ctrl-D quits.
- `\d` lists the tables, `\d <table>` describes one, `\?` lists the commands.
- `--format csv` or `--format json` (one object per row) for scripts: `rivet pg -f report.sql --format csv > report.csv`. These stream: memory stays flat, and `| head` stops the query.

### Saved connections with a keychain password

The user settings file (macOS: `~/Library/Application Support/rivet/settings.toml`, Linux: `~/.config/rivet/settings.toml`):

```toml
schema_version = 1

[connections.prod]
url = "postgres://app@db.example.com:5432/app"   # no password here; it is refused
password = "keychain://rivet/prod"
environment = "prod"       # a label, shown when you connect
read_only = true           # refuse writes
# confirm_on_write = true  # ask y/N before a write; refused in a file or a pipe
```

Fastest way: `rivet save prod postgres://app@db.example.com:5432/app`. It asks for the password (hidden), checks that the connection works, stores the password in the keychain and adds the table above. Then: `rivet prod`. The flags (`read_only`, …) you add by hand. A name is looked up in the settings file first, then in `.env`.
- Stop: `docker compose --env-file .env -f docker/compose.playground.yml down`. Add `-v` to delete the data, then delete `.env`.
- Plaintext only for now: the drivers have no TLS yet (#19).
