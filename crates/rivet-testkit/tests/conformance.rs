//! The conformance suite against an in-memory driver. No container is
//! needed. The good fake must pass every case. Each broken fake has one flaw
//! and must fail the case that checks it, and only that case.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use arrow_array::{ArrayRef, Int64Array, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use futures_core::Stream;
use rivet_sdk::error::{Error, ErrorCategory, Result};
use rivet_sdk::extension::{BoxFuture, ConnectRequest, Connection, Credential, Dialect, Driver};
use rivet_sdk::model::{ColumnMetadata, ResultSet};
use rivet_testkit::conformance::{self, Sql};
use rivet_testkit::database::{self, DatabaseFixture};

/// What a broken fake does wrong. The default is no flaw.
#[derive(Clone, Copy, Default)]
struct Flaws {
    accept_any_password: bool,
    wrong_password_is_user_error: bool,
    leak_password: bool,
    wrong_type: bool,
    ignore_drop: bool,
    ignore_cancel: bool,
    sql_error_is_database_error: bool,
    wrong_quote: bool,
}

struct FakeDriver(Flaws);

struct FakeConnection {
    flaws: Flaws,
    columns: Vec<(String, ArrayRef)>,
    busy: Arc<AtomicBool>,
    slow_running: AtomicBool,
    cancel_requested: AtomicBool,
}

/// Frees the connection when the result set is dropped.
struct Guard {
    busy: Arc<AtomicBool>,
    ignore_drop: bool,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.ignore_drop {
            self.busy.store(false, Ordering::SeqCst);
        }
    }
}

/// Makes its batches only when they are read.
struct Batches {
    next: Box<dyn FnMut() -> Option<RecordBatch> + Send>,
    guard: Guard,
}

impl Stream for Batches {
    type Item = Result<RecordBatch>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let batch = (self.next)();
        if batch.is_none() {
            // A result that is read to its end frees the connection.
            self.guard.busy.store(false, Ordering::SeqCst);
        }
        Poll::Ready(batch.map(Ok))
    }
}

fn fake_sql() -> Sql {
    Sql {
        dialect: Dialect::new("fake", '"'),
        ping: "ping".to_owned(),
        type_setup: vec!["setup".to_owned()],
        type_query: "types".to_owned(),
        empty: "empty".to_owned(),
        endless: "endless".to_owned(),
        slow: "slow".to_owned(),
        syntax_error: "garbage".to_owned(),
        ..Sql::postgres()
    }
}

fn fixture() -> DatabaseFixture {
    database::postgres()
}

fn ints(schema: &SchemaRef, values: Vec<i64>) -> RecordBatch {
    let column: ArrayRef = Arc::new(Int64Array::from(values));
    RecordBatch::try_new(schema.clone(), vec![column]).unwrap()
}

impl Driver for FakeDriver {
    fn dialect(&self) -> Dialect {
        Dialect::new("fake", if self.0.wrong_quote { '\'' } else { '"' })
    }

    fn connect(&self, request: ConnectRequest) -> BoxFuture<'_, Result<Box<dyn Connection>>> {
        Box::pin(async move {
            let Credential::Password(password) = &request.credentials.credential else {
                return Err(Error::internal("the fake takes a password"));
            };
            let right = password.expose() == database::TEST_ONLY_PASSWORD;
            if !right && !self.0.accept_any_password {
                let message = if self.0.leak_password {
                    format!("login refused for password {}", password.expose())
                } else {
                    "login refused".to_owned()
                };
                return Err(if self.0.wrong_password_is_user_error {
                    Error::user(message)
                } else {
                    Error::auth(message)
                });
            }
            let mut columns: Vec<(String, ArrayRef)> = Sql::postgres()
                .type_columns
                .into_iter()
                .map(|column| (column.name, column.expected))
                .collect();
            if self.0.wrong_type {
                columns[1].1 = Arc::new(Int64Array::from(vec![Some(7), None]));
            }
            Ok(Box::new(FakeConnection {
                flaws: self.0,
                columns,
                busy: Arc::default(),
                slow_running: AtomicBool::new(false),
                cancel_requested: AtomicBool::new(false),
            }) as Box<dyn Connection>)
        })
    }
}

impl FakeConnection {
    fn result(
        &self,
        schema: SchemaRef,
        columns: Vec<ColumnMetadata>,
        next: impl FnMut() -> Option<RecordBatch> + Send + 'static,
    ) -> Result<ResultSet> {
        let guard = Guard {
            busy: self.busy.clone(),
            ignore_drop: self.flaws.ignore_drop,
        };
        let batches = Batches {
            next: Box::new(next),
            guard,
        };
        ResultSet::new(schema, columns, Box::pin(batches))
    }

    fn one_column(&self) -> (SchemaRef, Vec<ColumnMetadata>) {
        let schema = Arc::new(Schema::new(vec![Field::new("n", DataType::Int64, true)]));
        (schema, vec![ColumnMetadata::new("bigint", true)])
    }

    fn types(&self) -> Result<ResultSet> {
        let fields: Vec<Field> = self
            .columns
            .iter()
            .map(|(name, array)| Field::new(name, array.data_type().clone(), true))
            .collect();
        let schema = Arc::new(Schema::new(fields));
        let metadata = self
            .columns
            .iter()
            .map(|(name, _)| {
                ColumnMetadata::new(if name == "other" { "numeric(5,2)" } else { "t" }, true)
            })
            .collect();
        let arrays = self
            .columns
            .iter()
            .map(|(_, array)| array.clone())
            .collect();
        let mut batch = Some(RecordBatch::try_new(schema.clone(), arrays).unwrap());
        self.result(schema, metadata, move || batch.take())
    }

    async fn slow(&self) -> Result<ResultSet> {
        self.slow_running.store(true, Ordering::SeqCst);
        for _ in 0..200 {
            if self.cancel_requested.swap(false, Ordering::SeqCst) {
                self.slow_running.store(false, Ordering::SeqCst);
                self.busy.store(false, Ordering::SeqCst);
                return Err(Error::cancelled("the statement was cancelled"));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.slow_running.store(false, Ordering::SeqCst);
        let (schema, columns) = self.one_column();
        self.result(schema, columns, || None)
    }
}

impl Connection for FakeConnection {
    fn execute(&self, statement: String) -> BoxFuture<'_, Result<ResultSet>> {
        Box::pin(async move {
            let known = ["ping", "setup", "types", "empty", "endless", "slow"];
            if !known.contains(&statement.as_str()) {
                let message = format!(
                    "syntax error in `{statement}` with password {}",
                    database::TEST_ONLY_PASSWORD
                );
                let message = if self.flaws.leak_password {
                    message
                } else {
                    "syntax error".to_owned()
                };
                return Err(if self.flaws.sql_error_is_database_error {
                    Error::database(message)
                } else {
                    Error::user(message)
                });
            }
            if self.busy.swap(true, Ordering::SeqCst) {
                return Err(Error::database("the connection runs a statement"));
            }
            let (schema, columns) = self.one_column();
            match statement.as_str() {
                "types" => self.types(),
                "slow" => self.slow().await,
                "endless" => {
                    let batch_schema = schema.clone();
                    let mut start = 0;
                    self.result(schema, columns, move || {
                        let batch = ints(&batch_schema, (start..start + 1000).collect());
                        start += 1000;
                        Some(batch)
                    })
                }
                "ping" => {
                    let mut batch = Some(ints(&schema, vec![1]));
                    self.result(schema, columns, move || batch.take())
                }
                _ => self.result(schema, columns, || None),
            }
        })
    }

    fn cancel(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            if !self.flaws.ignore_cancel && self.slow_running.load(Ordering::SeqCst) {
                self.cancel_requested.store(true, Ordering::SeqCst);
            }
            Ok(())
        })
    }
}

#[tokio::test]
async fn good_fake_passes_every_case() {
    let driver = FakeDriver(Flaws::default());
    let result = conformance::run_all(&driver, &fixture(), &fake_sql()).await;
    result.unwrap();
}

/// Runs `run_all` on a fake with one flaw and returns the error.
async fn failure(flaws: Flaws) -> Error {
    let driver = FakeDriver(flaws);
    let outcome = conformance::run_all(&driver, &fixture(), &fake_sql()).await;
    outcome.expect_err("the suite must fail for a broken driver")
}

fn assert_fails_case(error: &Error, case: &str) {
    let expected = format!("conformance `{case}`:");
    assert_eq!(error.category(), ErrorCategory::Internal);
    assert!(error.message().starts_with(&expected), "{error}");
}

#[tokio::test]
async fn accepting_a_wrong_password_fails() {
    let flaws = Flaws {
        accept_any_password: true,
        ..Flaws::default()
    };
    assert_fails_case(&failure(flaws).await, "rejects_wrong_password");
}

#[tokio::test]
async fn wrong_category_for_a_wrong_password_fails() {
    let flaws = Flaws {
        wrong_password_is_user_error: true,
        ..Flaws::default()
    };
    assert_fails_case(&failure(flaws).await, "rejects_wrong_password");
}

#[tokio::test]
async fn a_password_in_an_error_fails() {
    let flaws = Flaws {
        leak_password: true,
        ..Flaws::default()
    };
    assert_fails_case(&failure(flaws).await, "rejects_wrong_password");
}

#[tokio::test]
async fn a_wrong_arrow_type_fails() {
    let flaws = Flaws {
        wrong_type: true,
        ..Flaws::default()
    };
    assert_fails_case(&failure(flaws).await, "maps_types");
}

#[tokio::test]
async fn a_result_set_that_keeps_the_connection_after_drop_fails() {
    let flaws = Flaws {
        ignore_drop: true,
        ..Flaws::default()
    };
    assert_fails_case(&failure(flaws).await, "reads_slowly");
}

#[tokio::test]
async fn a_cancel_that_does_nothing_fails() {
    let flaws = Flaws {
        ignore_cancel: true,
        ..Flaws::default()
    };
    assert_fails_case(&failure(flaws).await, "cancels");
}

#[tokio::test]
async fn wrong_category_for_a_sql_error_fails() {
    let flaws = Flaws {
        sql_error_is_database_error: true,
        ..Flaws::default()
    };
    assert_fails_case(&failure(flaws).await, "survives_sql_error");
}

#[tokio::test]
async fn a_wrong_identifier_quote_fails() {
    let flaws = Flaws {
        wrong_quote: true,
        ..Flaws::default()
    };
    assert_fails_case(&failure(flaws).await, "reports_dialect");
}
