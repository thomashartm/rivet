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
- Ctrl-C cancels the running statement. `\q` or Ctrl-D quits.
- Stop: `docker compose --env-file .env -f docker/compose.playground.yml down`. Add `-v` to delete the data, then delete `.env`.
- Plaintext only for now: the drivers have no TLS yet (#19).
