//! The conformance suite for [`Driver`] implementations (ARCHITECTURE.md
//! §4.2, §5.5, §5.6).
//!
//! Each case takes the driver as `&dyn Driver`, a [`DatabaseFixture`] and the
//! [`Sql`] of the database. It returns `Ok(())`, or an `internal` error whose
//! message starts with ``conformance `<case>`:``. [`run_all`] runs every case.
//!
//! A driver test for a database in a container:
//!
//! ```no_run
//! # async fn test(driver: &dyn rivet_sdk::extension::Driver) -> rivet_sdk::error::Result<()> {
//! use rivet_testkit::{conformance, database};
//!
//! if !database::containers_enabled() {
//!     return Ok(());
//! }
//! let fixture = database::postgres();
//! fixture.ensure_reachable().await?;
//! conformance::run_all(driver, &fixture, &conformance::Sql::postgres()).await
//! # }
//! ```
//!
//! | Case | Checks |
//! | --- | --- |
//! | [`connects`] | A connection with the right credentials runs a statement. |
//! | [`rejects_wrong_password`] | A wrong password gives `auth`. No secret in the error. |
//! | [`maps_types`] | The first type mapping, with NULL. |
//! | [`returns_empty_result`] | No rows: the schema is there, the stream is empty. |
//! | [`reads_slowly`] | A result that never ends is read slowly, then dropped: the statement stops and the connection runs the next statement. |
//! | [`cancels`] | `cancel` of a running statement gives `cancelled`; the connection works again. |
//! | [`survives_sql_error`] | A wrong statement gives `user`; the connection works again. |
//! | [`reports_dialect`] | `dialect()` has the expected name and identifier quote. |
//!
//! The suite cannot measure the memory of a driver. A driver that reads
//! ahead without limit does not stop the endless statement of
//! [`reads_slowly`] in time, and that case fails.

use std::fmt::Display;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use arrow_array::{
    Array, ArrayRef, BinaryArray, BooleanArray, Float32Array, Float64Array, Int16Array, Int32Array,
    Int64Array, RecordBatch, StringArray, UInt32Array, UInt64Array,
};
use futures_core::Stream;
use rivet_sdk::error::{Error, ErrorCategory, Result};
use rivet_sdk::extension::{ConnectRequest, Connection, Credential, Credentials, Dialect, Driver};
use rivet_sdk::model::ResultSet;
use rivet_sdk::secret::Secret;

use crate::database::DatabaseFixture;

/// The time limit of each step. A driver that is slower fails the case.
const STEP: Duration = Duration::from_secs(30);
/// The wait before `cancel`, so that the statement is running.
const RUNNING: Duration = Duration::from_millis(300);
/// The pause between two batches in [`reads_slowly`].
const SLOW_READ: Duration = Duration::from_millis(100);
/// The number of batches that [`reads_slowly`] reads.
const SLOW_BATCHES: usize = 3;
/// A password that is not the password of any test database.
const WRONG_PASSWORD: &str = "wrong-password-for-the-conformance-suite";

/// The SQL that the suite sends. It differs for each database.
///
/// [`Sql::postgres`] and [`Sql::mysql`] give the values for the two
/// databases of `docker/compose.test.yml`.
#[derive(Debug)]
pub struct Sql {
    /// The dialect that `Driver::dialect` must report. The suite compares
    /// the name and the identifier quote.
    pub dialect: Dialect,
    /// A statement that gives one row with one column.
    pub ping: String,
    /// Statements that make the data of `type_query`. They run on the same
    /// connection before it. The data is in temporary tables.
    pub type_setup: Vec<String>,
    /// A statement that gives the columns of `type_columns`, in this order,
    /// and the rows of their `expected` arrays, in this order.
    pub type_query: String,
    /// What `type_query` must give for each column.
    pub type_columns: Vec<TypeColumn>,
    /// A statement that gives no rows and at least one column.
    pub empty: String,
    /// A statement that gives rows without end, at least two batches.
    pub endless: String,
    /// A statement that runs for 30 seconds or more and fails when it is
    /// cancelled.
    pub slow: String,
    /// A statement that the database refuses because of its text.
    pub syntax_error: String,
}

/// One column that `Sql::type_query` gives.
#[derive(Debug)]
pub struct TypeColumn {
    /// The name of the column.
    pub name: String,
    /// The values, with NULL: the Arrow type of the array is the type that
    /// the driver must give.
    pub expected: ArrayRef,
    /// A text that the source type of the column contains, ignoring case.
    /// `None`: not checked.
    pub source_type: Option<String>,
}

fn column(name: &str, expected: impl Array + 'static, source_type: Option<&str>) -> TypeColumn {
    TypeColumn {
        name: name.to_owned(),
        expected: Arc::new(expected),
        source_type: source_type.map(str::to_owned),
    }
}

/// The columns that both databases have. Row 1 has a value, row 2 has NULL.
fn common_columns() -> Vec<TypeColumn> {
    vec![
        column("b", BooleanArray::from(vec![Some(true), None]), None),
        column("i16", Int16Array::from(vec![Some(7), None]), None),
        column("i32", Int32Array::from(vec![Some(70_000), None]), None),
        column("i64", Int64Array::from(vec![Some(i64::MAX), None]), None),
    ]
}

fn text_columns() -> Vec<TypeColumn> {
    vec![
        column("t", StringArray::from(vec![Some("héllo"), None]), None),
        column(
            "bin",
            BinaryArray::from_opt_vec(vec![Some(&[1, 2]), None]),
            None,
        ),
    ]
}

fn float_columns() -> Vec<TypeColumn> {
    vec![
        column("f32", Float32Array::from(vec![Some(1.5), None]), None),
        column("f64", Float64Array::from(vec![Some(2.25), None]), None),
    ]
}

impl Sql {
    /// The SQL for the PostgreSQL container.
    pub fn postgres() -> Self {
        let mut type_columns = common_columns();
        type_columns.extend(float_columns());
        type_columns.extend(text_columns());
        type_columns.push(column(
            "other",
            StringArray::from(vec![Some("12.50"), None]),
            Some("numeric"),
        ));
        Self {
            dialect: Dialect::new("postgresql", '"'),
            ping: "select 1".to_owned(),
            type_setup: vec![
                "create temporary table conformance_types (id integer primary key, \
                 b boolean, i16 smallint, i32 integer, i64 bigint, f32 real, \
                 f64 double precision, t text, bin bytea, other numeric(5,2))"
                    .to_owned(),
                "insert into conformance_types values \
                 (1, true, 7, 70000, 9223372036854775807, 1.5, 2.25, 'héllo', \
                 decode('0102', 'hex'), 12.50), \
                 (2, null, null, null, null, null, null, null, null, null)"
                    .to_owned(),
            ],
            type_query: "select b, i16, i32, i64, f32, f64, t, bin, other \
                         from conformance_types order by id"
                .to_owned(),
            type_columns,
            empty: "select 1 where false".to_owned(),
            endless: "select g from generate_series(1::bigint, 1000000000000::bigint) g".to_owned(),
            slow: "select pg_sleep(30)".to_owned(),
            syntax_error: "this is not sql".to_owned(),
        }
    }

    /// The SQL for the MySQL container.
    pub fn mysql() -> Self {
        let mut type_columns = common_columns();
        type_columns.push(column(
            "u32",
            UInt32Array::from(vec![Some(u32::MAX), None]),
            None,
        ));
        type_columns.push(column(
            "u64",
            UInt64Array::from(vec![Some(u64::MAX), None]),
            None,
        ));
        type_columns.extend(float_columns());
        type_columns.extend(text_columns());
        type_columns.push(column(
            "other",
            StringArray::from(vec![Some("12.50"), None]),
            Some("decimal"),
        ));
        // 1000^4 rows: more than a test can read. Not a system view: the
        // plan of three `information_schema` views takes 10 s or more.
        // `NO_BNL`: a nested loop gives the first row at once; a hash join
        // first builds 1000^3 rows.
        let numbers = "with recursive t(n) as \
                       (select 1 union all select n + 1 from t where n < 1000)";
        let rows = "from t a, t b, t c, t d";
        Self {
            dialect: Dialect::new("mysql", '`'),
            ping: "select 1".to_owned(),
            type_setup: vec![
                "create temporary table conformance_types (id int primary key, \
                 b boolean, i16 smallint, i32 int, i64 bigint, u32 int unsigned, \
                 u64 bigint unsigned, f32 float, f64 double, t varchar(20), \
                 bin varbinary(16), other decimal(5,2))"
                    .to_owned(),
                "insert into conformance_types values \
                 (1, true, 7, 70000, 9223372036854775807, 4294967295, \
                 18446744073709551615, 1.5, 2.25, 'héllo', x'0102', 12.50), \
                 (2, null, null, null, null, null, null, null, null, null, null, null)"
                    .to_owned(),
            ],
            type_query: "select b, i16, i32, i64, u32, u64, f32, f64, t, bin, other \
                         from conformance_types order by id"
                .to_owned(),
            type_columns,
            empty: "select 1 from dual where false".to_owned(),
            endless: format!("{numbers} select /*+ NO_BNL() */ a.n {rows}"),
            // KILL QUERY stops it with an error. `sleep()` would return 1.
            slow: format!("{numbers} select /*+ NO_BNL() */ count(*) {rows}"),
            syntax_error: "this is not sql".to_owned(),
        }
    }
}

/// Runs every case, in the order of the table of this module. Stops at the
/// first failure.
///
/// # Errors
///
/// The error of the first case that fails.
pub async fn run_all(driver: &dyn Driver, fixture: &DatabaseFixture, sql: &Sql) -> Result<()> {
    reports_dialect(driver, sql)?;
    connects(driver, fixture, sql).await?;
    rejects_wrong_password(driver, fixture).await?;
    maps_types(driver, fixture, sql).await?;
    returns_empty_result(driver, fixture, sql).await?;
    reads_slowly(driver, fixture, sql).await?;
    cancels(driver, fixture, sql).await?;
    survives_sql_error(driver, fixture, sql).await
}

fn fail(case: &str, message: impl Display) -> Error {
    Error::internal(format!("conformance `{case}`: {message}"))
}

/// A failure that has an error of the driver as its cause.
fn failed(case: &str, step: &str, error: Error) -> Error {
    fail(case, format!("{step} failed: {error}")).with_source(error)
}

/// Waits for `future`, at most [`STEP`].
async fn within<T>(case: &str, step: &str, future: impl Future<Output = T>) -> Result<T> {
    let limit = format!("{step} took more than {STEP:?}");
    tokio::time::timeout(STEP, future)
        .await
        .map_err(|elapsed| fail(case, limit).with_source(elapsed))
}

fn request(fixture: &DatabaseFixture, password: &str) -> ConnectRequest {
    let credential = Credential::Password(Secret::from(password.to_owned()));
    let credentials = Credentials::new(credential).with_user(fixture.user.clone());
    ConnectRequest::new(fixture.profile.clone(), credentials)
}

async fn open(
    case: &str,
    driver: &dyn Driver,
    fixture: &DatabaseFixture,
) -> Result<Arc<dyn Connection>> {
    let request = request(fixture, fixture.password.expose());
    let connection = within(case, "connect", driver.connect(request)).await?;
    connection
        .map(Arc::from)
        .map_err(|error| failed(case, "connect", error))
}

async fn next(result: &mut ResultSet) -> Option<Result<RecordBatch>> {
    poll_fn(|context| Pin::new(&mut *result).poll_next(context)).await
}

async fn run(case: &str, connection: &dyn Connection, statement: &str) -> Result<ResultSet> {
    let step = format!("`{statement}`");
    let result = within(case, &step, connection.execute(statement.to_owned())).await?;
    result.map_err(|error| failed(case, &step, error))
}

async fn read_all(case: &str, result: &mut ResultSet) -> Result<Vec<RecordBatch>> {
    let mut batches = Vec::new();
    while let Some(batch) = within(case, "read of a batch", next(result)).await? {
        batches.push(batch.map_err(|error| failed(case, "read of a batch", error))?);
    }
    Ok(batches)
}

fn rows(batches: &[RecordBatch]) -> usize {
    batches.iter().map(RecordBatch::num_rows).sum()
}

/// Runs the ping statement and checks that it gives one row.
async fn check_usable(case: &str, connection: &dyn Connection, sql: &Sql) -> Result<()> {
    let mut result = run(case, connection, &sql.ping).await?;
    let count = rows(&read_all(case, &mut result).await?);
    if count == 1 {
        Ok(())
    } else {
        Err(fail(
            case,
            format!(
                "the connection is not usable: `{}` gave {count} rows, not 1",
                sql.ping
            ),
        ))
    }
}

/// Fails if the text of the error, or of its sources, has a secret.
fn check_no_secret(case: &str, error: &Error, secrets: &[&str]) -> Result<()> {
    let text = format!("{error:?}");
    match secrets.iter().find(|secret| text.contains(**secret)) {
        Some(_) => Err(fail(case, "the error contains a secret")),
        None => Ok(()),
    }
}

/// `dialect()` has the name and the identifier quote of `sql.dialect`.
///
/// # Errors
///
/// An `internal` error that says what differs.
pub fn reports_dialect(driver: &dyn Driver, sql: &Sql) -> Result<()> {
    let (actual, expected) = (driver.dialect(), &sql.dialect);
    if actual.name != expected.name || actual.identifier_quote != expected.identifier_quote {
        return Err(fail(
            "reports_dialect",
            format!(
                "expected `{}` with quote `{}`, got `{}` with quote `{}`",
                expected.name, expected.identifier_quote, actual.name, actual.identifier_quote
            ),
        ));
    }
    Ok(())
}

/// A connection with the credentials of the fixture runs one statement. The
/// schema is known before the first batch.
///
/// # Errors
///
/// An `internal` error that says what failed.
pub async fn connects(driver: &dyn Driver, fixture: &DatabaseFixture, sql: &Sql) -> Result<()> {
    const CASE: &str = "connects";
    let connection = open(CASE, driver, fixture).await?;
    let mut result = run(CASE, &*connection, &sql.ping).await?;
    if result.schema().fields().len() != 1 || result.columns().len() != 1 {
        return Err(fail(
            CASE,
            "the schema of the ping statement has not 1 column",
        ));
    }
    let count = rows(&read_all(CASE, &mut result).await?);
    if count != 1 {
        return Err(fail(
            CASE,
            format!("the ping statement gave {count} rows, not 1"),
        ));
    }
    Ok(())
}

/// A wrong password gives an `auth` error. The text of the error contains
/// neither the wrong password nor the right one.
///
/// # Errors
///
/// An `internal` error that says what failed.
pub async fn rejects_wrong_password(driver: &dyn Driver, fixture: &DatabaseFixture) -> Result<()> {
    const CASE: &str = "rejects_wrong_password";
    let request = request(fixture, WRONG_PASSWORD);
    let outcome = within(CASE, "connect", driver.connect(request)).await?;
    let error = match outcome {
        Ok(_connection) => return Err(fail(CASE, "the driver accepted a wrong password")),
        Err(error) => error,
    };
    if error.category() != ErrorCategory::Auth {
        return Err(failed(
            CASE,
            "connect with a wrong password: expected `auth`",
            error,
        ));
    }
    check_no_secret(CASE, &error, &[WRONG_PASSWORD, fixture.password.expose()])
}

/// The first type mapping: each type of `sql.type_columns` has its Arrow type,
/// its values and NULL. The database type name is in the column metadata,
/// where `source_type` is set.
///
/// # Errors
///
/// An `internal` error that names the column and says what differs.
pub async fn maps_types(driver: &dyn Driver, fixture: &DatabaseFixture, sql: &Sql) -> Result<()> {
    const CASE: &str = "maps_types";
    let connection = open(CASE, driver, fixture).await?;
    for statement in &sql.type_setup {
        let mut result = run(CASE, &*connection, statement).await?;
        read_all(CASE, &mut result).await?;
    }
    let mut result = run(CASE, &*connection, &sql.type_query).await?;
    let expected_columns = &sql.type_columns;
    if result.schema().fields().len() != expected_columns.len() {
        let got = result.schema().fields().len();
        let want = expected_columns.len();
        return Err(fail(
            CASE,
            format!("the result has {got} columns, not {want}"),
        ));
    }
    for (index, expected) in expected_columns.iter().enumerate() {
        let field = result.schema().field(index);
        let (name, got) = (&expected.name, field.data_type());
        if field.name() != name || got != expected.expected.data_type() {
            let want = expected.expected.data_type();
            let found = field.name();
            return Err(fail(
                CASE,
                format!(
                    "column {index}: expected `{name}` of type {want}, got `{found}` of type {got}"
                ),
            ));
        }
        if let Some(text) = &expected.source_type {
            let source = &result.columns()[index].source_type;
            if !source.to_lowercase().contains(&text.to_lowercase()) {
                let message = format!("column `{name}`: source type `{source}` lacks `{text}`");
                return Err(fail(CASE, message));
            }
        }
    }
    let batches = read_all(CASE, &mut result).await?;
    let want = expected_columns
        .first()
        .map_or(0, |column| column.expected.len());
    if rows(&batches) != want {
        return Err(fail(
            CASE,
            format!("the result has {} rows, not {want}", rows(&batches)),
        ));
    }
    let mut offset = 0;
    for batch in &batches {
        for (index, expected) in expected_columns.iter().enumerate() {
            let expected_part = expected.expected.slice(offset, batch.num_rows());
            if batch.column(index).as_ref() != expected_part.as_ref() {
                let (got, name) = (batch.column(index), &expected.name);
                return Err(fail(
                    CASE,
                    format!("column `{name}`: expected {expected_part:?}, got {got:?}"),
                ));
            }
        }
        offset += batch.num_rows();
    }
    Ok(())
}

/// A statement with no rows still gives its schema, and a stream with no rows.
///
/// # Errors
///
/// An `internal` error that says what failed.
pub async fn returns_empty_result(
    driver: &dyn Driver,
    fixture: &DatabaseFixture,
    sql: &Sql,
) -> Result<()> {
    const CASE: &str = "returns_empty_result";
    let connection = open(CASE, driver, fixture).await?;
    let mut result = run(CASE, &*connection, &sql.empty).await?;
    if result.schema().fields().is_empty() {
        return Err(fail(CASE, "the schema has no column"));
    }
    let count = rows(&read_all(CASE, &mut result).await?);
    if count != 0 {
        return Err(fail(CASE, format!("the result has {count} rows, not 0")));
    }
    check_usable(CASE, &*connection, sql).await
}

/// A result without end is read slowly, a few batches, and then dropped.
/// The statement stops, and the same connection runs the next statement
/// within the time limit.
///
/// # Errors
///
/// An `internal` error that says what failed. A driver that reads ahead
/// without limit, or does not stop the statement on drop, fails here.
pub async fn reads_slowly(driver: &dyn Driver, fixture: &DatabaseFixture, sql: &Sql) -> Result<()> {
    const CASE: &str = "reads_slowly";
    let connection = open(CASE, driver, fixture).await?;
    let mut result = run(CASE, &*connection, &sql.endless).await?;
    for number in 1..=SLOW_BATCHES {
        tokio::time::sleep(SLOW_READ).await;
        let batch = within(CASE, "read of a batch", next(&mut result)).await?;
        match batch {
            Some(Ok(batch)) if batch.num_rows() > 0 => {}
            Some(Ok(_)) => return Err(fail(CASE, format!("batch {number} has no rows"))),
            Some(Err(error)) => return Err(failed(CASE, "read of a batch", error)),
            None => return Err(fail(CASE, "the endless result ended")),
        }
    }
    drop(result);
    check_usable(CASE, &*connection, sql).await
}

/// `cancel` of a running statement: the statement fails with `cancelled`,
/// and the connection runs the next statement. `cancel` on an idle
/// connection is not an error.
///
/// # Errors
///
/// An `internal` error that says what failed.
pub async fn cancels(driver: &dyn Driver, fixture: &DatabaseFixture, sql: &Sql) -> Result<()> {
    const CASE: &str = "cancels";
    let connection = open(CASE, driver, fixture).await?;
    within(CASE, "cancel of an idle connection", connection.cancel())
        .await?
        .map_err(|error| failed(CASE, "cancel of an idle connection", error))?;

    let running = Arc::clone(&connection);
    let statement = sql.slow.clone();
    let mut task = tokio::spawn(async move {
        let mut result = running.execute(statement).await?;
        while let Some(batch) = next(&mut result).await {
            batch?;
        }
        Ok::<(), Error>(())
    });
    tokio::time::sleep(RUNNING).await;
    within(CASE, "cancel", connection.cancel())
        .await?
        .map_err(|error| failed(CASE, "cancel", error))?;
    let finished = match tokio::time::timeout(STEP, &mut task).await {
        Ok(finished) => finished,
        Err(elapsed) => {
            task.abort();
            let message = format!("the statement still ran {STEP:?} after cancel");
            return Err(fail(CASE, message).with_source(elapsed));
        }
    };
    match finished.map_err(|error| fail(CASE, "the statement task failed").with_source(error))? {
        Ok(()) => return Err(fail(CASE, "the statement finished: it was not cancelled")),
        Err(error) if error.category() == ErrorCategory::Cancelled => {}
        Err(error) => {
            return Err(failed(
                CASE,
                "the cancelled statement: expected `cancelled`",
                error,
            ));
        }
    }
    check_usable(CASE, &*connection, sql).await
}

/// A statement that the database refuses gives a `user` error without a
/// secret, and the connection runs the next statement.
///
/// # Errors
///
/// An `internal` error that says what failed.
pub async fn survives_sql_error(
    driver: &dyn Driver,
    fixture: &DatabaseFixture,
    sql: &Sql,
) -> Result<()> {
    const CASE: &str = "survives_sql_error";
    let connection = open(CASE, driver, fixture).await?;
    let statement = sql.syntax_error.clone();
    let outcome = within(CASE, "execute", connection.execute(statement)).await?;
    let error = match outcome {
        Err(error) => error,
        Ok(mut result) => match next(&mut result).await {
            Some(Err(error)) => error,
            _ => return Err(fail(CASE, "the driver accepted a wrong statement")),
        },
    };
    if error.category() != ErrorCategory::User {
        return Err(failed(CASE, "a wrong statement: expected `user`", error));
    }
    check_no_secret(CASE, &error, &[fixture.password.expose()])?;
    check_usable(CASE, &*connection, sql).await
}
