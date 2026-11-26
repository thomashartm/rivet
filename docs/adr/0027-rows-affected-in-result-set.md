# ADR-0027: Changed-row count in `ResultSet`

- Status: Proposed
- Date: 2026-11-26

## Context

Ticket #229 (part of #87): after `insert`, `update` or `delete` the CLI prints `(0 rows)`. The user cannot see if the statement changed anything. The maintainer approved the design of the ticket on 2026-11-26 and asked for this ADR before the code.

Facts on `main` on this date:

| Place | Fact |
| --- | --- |
| `rivet-sdk`, `model.rs`, `ResultSet` | Three private fields (`schema`, `columns`, `batches`). Only `ResultSet::new` makes one. No count of changed rows. |
| `rivet-ext-postgres`, `PostgresConnection::execute` | Prepares the statement (this gives the columns and refuses a second statement), then runs it with `simple_query_raw`. It returns the `ResultSet` before the statement ends. `Batches::poll_next` ignores each message that is not a row, also the count. |
| `rivet-ext-postgres`, cancel | `Connection::cancel` sends the cancel request through `Canceller::send`; it does not take the `busy` lock. A dropped `Batches` calls `Running::stop`, which sends the cancel request in the background. |
| `rivet-ext-mysql`, `MysqlConnection::execute` | `query_iter` returns after the first answer of the server. For a statement with no result set this is the OK packet: the statement has ended. The early return "No result set" drops the count. `busy` is `true` while `query_iter` runs, so `cancel` (`KILL QUERY`) works then. |
| `rivet-core`, `execute.rs`, `stream_rows` | Makes a new `ResultSet` from the schema and the columns of the driver result. Other data is lost. |
| `rivet-cli`, `output.rs`, `Table::finish` | Prints `(N rows)`, where N is the number of rows read. |
| `tokio-postgres` 0.7.18, `simple_query.rs`, `SimpleQueryStream::poll_next` | Gives `SimpleQueryMessage::CommandComplete(u64)`. The number comes from `query.rs`, `extract_row_affected`: the last word of the command tag, or 0 if that word is not a number. An empty statement also gives `CommandComplete(0)`. The tag itself is not given. |
| `mysql_async` 0.37.1, `conn/mod.rs`, `Conn::affected_rows` | The affected rows of the last OK packet (`QueryResult::affected_rows` in `queryable/query_result/mod.rs` calls it). `Opts::client_found_rows` (`opts/mod.rs`) is off by default: then an `update` counts only rows whose values change, not the rows it finds. |
| WIT, native protocol | No result set crosses these borders yet. `wit/extension.wit` has only lifecycle and logging; the protocol of ADR-0024 has only `hello`, `activate`, `deactivate`. |

## Decision

All rows are proposals of the architect. The rows marked "question" wait for the maintainer; work starts with the default.

| Topic | Decision |
| --- | --- |
| SDK API | `ResultSet::with_rows_affected(self, rows: u64) -> Self` and `ResultSet::rows_affected(&self) -> Option<u64>`. A new private field `rows_affected: Option<u64>`; `ResultSet::new` sets `None`. `Debug` shows the field. |
| Semver | Additive (ARCHITECTURE.md §4.1, §10): the fields are private, `new` keeps its signature, no trait changes. Not a breaking change. |
| Meaning | `Some(n)`: the statement has no result columns and ended; `n` is the number the engine reports for it. `None`: the statement returns rows (also with `RETURNING`, also a row result with zero columns such as PostgreSQL `select;`), or the driver has no count. A client MUST NOT read `None` as 0. |
| DDL and other statements without a count (question) | Default: report what the engine reports. Both engines report 0 (PostgreSQL: `extract_row_affected` gives 0 for a tag such as `CREATE TABLE`; MySQL: the OK packet of DDL has 0 affected rows). So DDL gives `Some(0)` on both. A driver cannot give `None` for DDL: `tokio-postgres` does not pass the command tag, and MySQL sends no tag. Engine-specific results that follow from this rule: PostgreSQL `create table ... as select` reports the rows it wrote (tag `SELECT n`); MySQL `create table ... select` too. |
| MySQL `update` count (question) | Default: the driver turns on `client_found_rows`. Then an `update` counts the rows it finds, as PostgreSQL does, and one rule holds for both engines. Without it, an `update` that writes the same values reports 0 on MySQL and N on PostgreSQL. Side effect: `ROW_COUNT()` in the session and `insert ... on duplicate key update` follow the found-rows rule of MySQL. |
| PostgreSQL driver | If the prepared statement has no columns, `execute` reads the stream to its end before it returns. It keeps the number of `CommandComplete`. If a `RowDescription` comes (a row result with zero columns), `rows_affected` stays `None` and the result gives the same zero-column batches as today. Else it returns an empty result with `with_rows_affected(n)`. An error of the statement is the error of `execute`. A statement with columns is unchanged. |
| PostgreSQL cancel | The wait MUST stay cancellable. `Connection::cancel` already works during the wait, because it does not take `busy`. The read MUST go through `Batches` (or another value that holds `Running`), so that a dropped `execute` future sends the cancel request as a dropped result does today. `busy` is held until the stream has ended. A cancelled wait gives the `cancelled` error (SQLSTATE 57014). |
| MySQL driver | In the "No result set" path, read `affected_rows` of the query result before it is dropped, and return the empty result with `with_rows_affected(n)`. Cancel does not change. A statement with a result set is unchanged. More than one statement in one call stays refused (decision 83). |
| Core | `stream_rows` in `execute.rs` carries `rows_affected` of the driver result into the result that it makes. |
| CLI table output | If `rows_affected` is `Some(n)`: `(n rows changed)` in place of `(0 rows)`. If `None`: `(N rows)` as today. |
| CLI CSV and JSON output | Maintainer decision: the line `(n rows changed)` goes to stderr. stdout stays as today. |
| Conformance | New case in `rivet_testkit::conformance`, run by `run_all`: on one connection, make a temporary table, insert 2 rows, `update` both to new values → `Some(2)`; a `select` → `None`. If the `client_found_rows` row is accepted, an `update` that writes the same values also gives `Some(2)`. The SQL of each engine is in `Sql`. |
| PostgreSQL cancel test | A driver test: a long statement without result columns (for example `do $$ begin perform pg_sleep(30); end $$`) is cancelled with `Connection::cancel` and gives `cancelled`; the connection runs the next statement. |
| WIT and C ABI | Not changed now. When a result set crosses the WIT border or the native protocol (ADR-0013, ADR-0024), the count MUST be part of it, with the same meaning (`option<u64>` in WIT). |

## Consequences

- A user sees the count after a write. CSV and JSON stdout stays only data, so scripts do not change.
- A write with no result columns on PostgreSQL now returns from `execute` only after it ends. A client that shows "running" while it waits for `execute` sees no change: today the empty stream also ends only at the end of the statement.
- DDL prints `(0 rows changed)`. The CLI cannot tell DDL from a write that changed no rows.
- With `client_found_rows`, the MySQL count means "rows found", not "rows with new values". The CLI text says "changed"; for an `update` that writes the same values this is not exact on either engine.
- Each new driver must fill the count; the conformance case checks it.
- Not in scope: a count for `... RETURNING` (the rows are shown), the statement verb in the message (`UPDATE 2`; MySQL does not send it), parameter binding (decision 86.1).

## Status

Proposed. The maintainer approves this ADR before the code of #229 starts.
