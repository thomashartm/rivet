# Rivet

Rivet is a headless-first database client for PostgreSQL and MySQL, written in Rust. The goal is to run queries and stream results from the command line, with an optional desktop client that uses the same engine.

The design calls for native IAM authentication on AWS and Google Cloud. Database drivers, authentication providers, and UI features all use the same public extension API available to third-party developers.

[Project mission](MISSION.md) · [Architecture](ARCHITECTURE.md)

## Quick start

```sh
docker/playground.sh          # starts PostgreSQL on 127.0.0.1:55432, writes .env on the first run
cargo run -p rivet-cli        # reads RIVET_DATABASE_URL from .env
sql> select * from customers;
```

- `.env` is generated and never committed. It holds a random password.
- Any other database: `cargo run -p rivet-cli -- postgres://user:password@host:port/database`.
- Stop: `docker compose --env-file .env -f docker/compose.playground.yml down`. Add `-v` to delete the data, then delete `.env`.
- Plaintext only for now: the PostgreSQL driver has no TLS yet (#19).
