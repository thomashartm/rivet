//! Tests of `rivet_core::execute` against an in-memory connection. No
//! container is needed. The tests use the paused Tokio clock: a sleep
//! returns when every task waits, so no test depends on real time.

use std::future::poll_fn;
use std::io::Write;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use arrow_array::{Array, Int64Array, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use futures_core::Stream;
use rivet_core::Owner;
use rivet_core::execute::{Guarded, RESULT_BUFFER, execute, execute_guarded};
use rivet_core::jobs::{JobScheduler, JobState};
use rivet_core::logging::{LogConfig, Redactor, dispatch};
use rivet_sdk::error::{Error, ErrorCategory, Result};
use rivet_sdk::extension::{BoxFuture, Connection};
use rivet_sdk::model::{ColumnMetadata, ConnectionProfile, Endpoint, ProviderRef, ResultSet};

/// The statement of every test. A test checks that it is in no log event.
const STATEMENT: &str = "select secret_column from secret_table";

/// What the fake connection does.
#[derive(Clone, Copy)]
enum Plan {
    /// Returns this many batches, then ends.
    Batches(i64),
    /// Returns batches until the result set is dropped.
    Endless,
    /// Returns two batches, then a `database` error.
    FailAfterTwo,
    /// `execute` fails with a `user` error.
    Refuse,
    /// Returns no batches and this count of changed rows.
    Changed(u64),
}

/// What the fake connection saw. The test reads it.
#[derive(Default)]
struct Seen {
    /// `true` after `Connection::execute` was called.
    executed: AtomicBool,
    /// How often `Connection::execute` was called.
    executions: AtomicUsize,
    /// How many batches the driver made.
    produced: AtomicUsize,
    /// `true` after the driver result set was dropped.
    dropped: AtomicBool,
    /// `true` after `cancel` was called while the result set was alive.
    cancelled_while_running: AtomicBool,
}

struct FakeConnection {
    plan: Plan,
    seen: Arc<Seen>,
}

/// The batches of the fake. Each batch has one row: its number.
struct FakeBatches {
    plan: Plan,
    seen: Arc<Seen>,
    schema: SchemaRef,
}

impl Drop for FakeBatches {
    fn drop(&mut self) {
        self.seen.dropped.store(true, Ordering::SeqCst);
    }
}

impl Stream for FakeBatches {
    type Item = Result<RecordBatch>;

    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let number = self.seen.produced.load(Ordering::SeqCst) as i64;
        let next = match self.plan {
            Plan::Batches(total) if number >= total => return Poll::Ready(None),
            Plan::Changed(_) => return Poll::Ready(None),
            Plan::FailAfterTwo if number >= 2 => {
                let message = format!("bad row in `{STATEMENT}`");
                return Poll::Ready(Some(Err(Error::database(message))));
            }
            _ => number,
        };
        self.seen.produced.fetch_add(1, Ordering::SeqCst);
        let column = Arc::new(Int64Array::from(vec![next]));
        Poll::Ready(Some(Ok(RecordBatch::try_new(
            self.schema.clone(),
            vec![column],
        )
        .unwrap())))
    }
}

impl Connection for FakeConnection {
    fn execute(&self, statement: String) -> BoxFuture<'_, Result<ResultSet>> {
        self.seen.executed.store(true, Ordering::SeqCst);
        self.seen.executions.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if let Plan::Refuse = self.plan {
                return Err(Error::user(format!("syntax error in `{statement}`")));
            }
            let schema = Arc::new(Schema::new(vec![Field::new("n", DataType::Int64, false)]));
            let batches = FakeBatches {
                plan: self.plan,
                seen: self.seen.clone(),
                schema: schema.clone(),
            };
            let columns = vec![ColumnMetadata::new("bigint", false)];
            let result = ResultSet::new(schema, columns, Box::pin(batches))?;
            Ok(match self.plan {
                Plan::Changed(rows) => result.with_rows_affected(rows),
                _ => result,
            })
        })
    }

    fn cancel(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let running = !self.seen.dropped.load(Ordering::SeqCst);
            self.seen
                .cancelled_while_running
                .store(running, Ordering::SeqCst);
            Ok(())
        })
    }
}

fn owner() -> Owner {
    "acme.test".parse().unwrap()
}

fn connection(plan: Plan) -> (Box<dyn Connection>, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let connection = FakeConnection {
        plan,
        seen: seen.clone(),
    };
    (Box::new(connection), seen)
}

/// Returns when every task waits. The clock is paused, so this takes no
/// real time.
async fn idle() {
    tokio::time::sleep(Duration::from_secs(1)).await;
}

async fn next(result: &mut ResultSet) -> Option<Result<RecordBatch>> {
    poll_fn(|cx| Pin::new(&mut *result).poll_next(cx)).await
}

fn number(batch: &RecordBatch) -> i64 {
    let column = batch.column(0).as_any().downcast_ref::<Int64Array>();
    column.unwrap().value(0)
}

#[tokio::test(start_paused = true)]
async fn a_slow_reader_slows_the_driver() {
    const TOTAL: i64 = 50;
    let scheduler = JobScheduler::new(NonZeroUsize::MIN, 100);
    let (connection, seen) = connection(Plan::Batches(TOTAL));
    let (job, result, _) = execute(&scheduler, owner(), connection, STATEMENT.to_owned()).unwrap();

    let mut result = result.await.unwrap();
    assert_eq!(result.schema().field(0).name(), "n");
    assert_eq!(result.rows_affected(), None);
    for read in 0..TOTAL {
        idle().await;
        // The buffer is full and the job holds one more batch.
        let ahead = (read + RESULT_BUFFER as i64 + 1).min(TOTAL);
        assert_eq!(seen.produced.load(Ordering::SeqCst) as i64, ahead);
        let batch = next(&mut result).await.unwrap().unwrap();
        assert_eq!(number(&batch), read);
    }
    assert!(next(&mut result).await.is_none());
    assert!(next(&mut result).await.is_none());

    job.join().await.unwrap();
    assert_eq!(scheduler.jobs()[0].state, JobState::Succeeded);
}

#[tokio::test(start_paused = true)]
async fn the_count_of_changed_rows_reaches_the_result() {
    let scheduler = JobScheduler::new(NonZeroUsize::MIN, 100);
    let (connection, _) = connection(Plan::Changed(2));
    let (job, result, _) = execute(&scheduler, owner(), connection, STATEMENT.to_owned()).unwrap();
    let mut result = result.await.unwrap();
    assert_eq!(result.rows_affected(), Some(2));
    assert!(next(&mut result).await.is_none());
    job.join().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn cancel_calls_the_driver_and_ends_the_result() {
    let scheduler = JobScheduler::new(NonZeroUsize::MIN, 100);
    let (connection, seen) = connection(Plan::Endless);
    let (job, result, _) = execute(&scheduler, owner(), connection, STATEMENT.to_owned()).unwrap();
    let mut result = result.await.unwrap();
    next(&mut result).await.unwrap().unwrap();
    idle().await;

    job.cancel();
    let watch = job.watch();
    let error = job.join().await.unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Cancelled);
    assert_eq!(watch.borrow().state, JobState::Cancelled);
    assert!(seen.cancelled_while_running.load(Ordering::SeqCst));
    assert!(seen.dropped.load(Ordering::SeqCst));

    // The batches in the buffer arrive, then the `cancelled` error.
    let error = loop {
        match next(&mut result).await.unwrap() {
            Ok(_) => continue,
            Err(error) => break error,
        }
    };
    assert_eq!(error.category(), ErrorCategory::Cancelled);
    assert!(next(&mut result).await.is_none());
}

#[tokio::test(start_paused = true)]
async fn to_drop_the_result_stops_the_statement() {
    let scheduler = JobScheduler::new(NonZeroUsize::MIN, 100);
    let (connection, seen) = connection(Plan::Endless);
    let (job, result, _) = execute(&scheduler, owner(), connection, STATEMENT.to_owned()).unwrap();
    let mut result = result.await.unwrap();
    next(&mut result).await.unwrap().unwrap();
    idle().await;
    assert!(!seen.dropped.load(Ordering::SeqCst));

    drop(result);
    let watch = job.watch();
    let error = job.join().await.unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Cancelled);
    assert_eq!(watch.borrow().state, JobState::Cancelled);
    assert!(seen.dropped.load(Ordering::SeqCst));
    assert!(!seen.cancelled_while_running.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn a_driver_error_keeps_its_category_and_message() {
    let scheduler = JobScheduler::new(NonZeroUsize::MIN, 100);
    let (connection, _) = connection(Plan::FailAfterTwo);
    let (job, result, _) = execute(&scheduler, owner(), connection, STATEMENT.to_owned()).unwrap();
    let mut result = result.await.unwrap();
    assert_eq!(number(&next(&mut result).await.unwrap().unwrap()), 0);
    assert_eq!(number(&next(&mut result).await.unwrap().unwrap()), 1);
    let error = next(&mut result).await.unwrap().unwrap_err();
    let message = format!("bad row in `{STATEMENT}`");
    assert_eq!(error.category(), ErrorCategory::Database);
    assert_eq!(error.message(), message);
    assert!(next(&mut result).await.is_none());

    let watch = job.watch();
    let error = job.join().await.unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Database);
    assert_eq!(error.message(), message);
    assert_eq!(watch.borrow().state, JobState::Failed);
}

#[tokio::test(start_paused = true)]
async fn a_refused_statement_keeps_its_category_and_message() {
    let scheduler = JobScheduler::new(NonZeroUsize::MIN, 100);
    let (connection, _) = connection(Plan::Refuse);
    let (job, result, _) = execute(&scheduler, owner(), connection, STATEMENT.to_owned()).unwrap();
    let message = format!("syntax error in `{STATEMENT}`");
    let error = result.await.unwrap_err();
    assert_eq!(error.category(), ErrorCategory::User);
    assert_eq!(error.message(), message);

    let watch = job.watch();
    let error = job.join().await.unwrap_err();
    assert_eq!(error.category(), ErrorCategory::User);
    assert_eq!(error.message(), message);
    assert_eq!(watch.borrow().state, JobState::Failed);
}

/// A log output that the test reads.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Makes a capture the log subscriber of this thread, at level `TRACE`.
///
/// It also keeps a second subscriber alive for the whole test process, as
/// `rivet_core::logging::capture_logs` does: with one subscriber only,
/// tracing-core caches the interest of a log statement for the process, and
/// a parallel test with no subscriber could turn it off.
fn capture_log() -> (Capture, tracing::dispatcher::DefaultGuard) {
    static SECOND: OnceLock<tracing::Dispatch> = OnceLock::new();
    SECOND.get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::new()));
    let capture = Capture::default();
    let writer = {
        let capture = capture.clone();
        move || capture.clone()
    };
    let config = LogConfig {
        level: tracing::Level::TRACE,
        ..LogConfig::default()
    };
    let log = dispatch(&config, writer, Redactor::new());
    (capture, tracing::dispatcher::set_default(&log))
}

// The jobs run on this thread (current-thread runtime), so the capture of
// this thread sees their log events.
#[tokio::test(start_paused = true)]
async fn no_log_event_contains_the_statement() {
    let (capture, _guard) = capture_log();
    let scheduler = JobScheduler::new(NonZeroUsize::MIN, 100);
    for plan in [
        Plan::Batches(3),
        Plan::FailAfterTwo,
        Plan::Refuse,
        Plan::Endless,
    ] {
        let (connection, _) = connection(plan);
        let (job, result, _) =
            execute(&scheduler, owner(), connection, STATEMENT.to_owned()).unwrap();
        if let Ok(mut result) = result.await {
            next(&mut result).await.unwrap().unwrap();
            if let Plan::Endless = plan {
                job.cancel();
            }
            while let Some(Ok(_)) = next(&mut result).await {}
        }
        let _ = job.join().await;
    }

    let text = capture.text();
    assert_eq!(text.matches("statement started").count(), 4, "{text}");
    assert_eq!(text.matches("statement ended").count(), 4, "{text}");
    assert!(text.contains("job=4"), "{text}");
    assert!(!text.contains("secret_column"), "{text}");
    assert!(!text.contains("secret_table"), "{text}");
}

impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// A write that names secret data. A test checks that it is in no error
/// and no log event of the guard path.
const WRITE: &str = "delete from secret_table where token = 'hunter2'";

fn profile(read_only: bool, confirm_on_write: bool) -> ConnectionProfile {
    ConnectionProfile::new(
        ProviderRef::new("fake"),
        Endpoint::new("localhost"),
        ProviderRef::new("none"),
    )
    .with_read_only(read_only)
    .with_confirm_on_write(confirm_on_write)
}

#[tokio::test(start_paused = true)]
async fn the_guard_denies_a_write_on_a_read_only_profile() {
    let (capture, _guard) = capture_log();
    let scheduler = JobScheduler::new(NonZeroUsize::MIN, 100);
    let (connection, seen) = connection(Plan::Batches(1));
    let profile = profile(true, false);
    // `confirmed` does not change a deny.
    let Ok(Guarded::Denied { error, connection }) = execute_guarded(
        &scheduler,
        owner(),
        &profile,
        connection,
        WRITE.to_owned(),
        true,
    ) else {
        panic!("expected a deny");
    };
    assert_eq!(error.category(), ErrorCategory::Policy);
    assert!(!seen.executed.load(Ordering::SeqCst));
    assert!(scheduler.jobs().is_empty());
    // The connection comes back and runs the next statement (decision on #27).
    let (job, result, _) = execute(&scheduler, owner(), connection, "select 1".to_owned()).unwrap();
    drop(result.await.unwrap());
    job.join().await.unwrap();
    assert!(seen.executed.load(Ordering::SeqCst));

    let text = format!("{error} {error:?} {}", capture.text());
    for part in ["secret_table", "hunter2", "delete"] {
        assert!(!text.contains(part), "leaks {part}: {text}");
    }
}

#[tokio::test(start_paused = true)]
async fn the_guard_asks_to_confirm_a_write_then_runs_it() {
    let (capture, _guard) = capture_log();
    let scheduler = JobScheduler::new(NonZeroUsize::MIN, 100);
    let (connection, seen) = connection(Plan::Batches(1));
    let profile = profile(false, true);
    let guarded = execute_guarded(
        &scheduler,
        owner(),
        &profile,
        connection,
        WRITE.to_owned(),
        false,
    );
    let Ok(Guarded::NeedsConfirmation {
        connection,
        statement,
    }) = guarded
    else {
        panic!("expected NeedsConfirmation");
    };
    assert!(!seen.executed.load(Ordering::SeqCst));
    assert!(scheduler.jobs().is_empty());
    assert!(!capture.text().contains("secret_table"));

    let guarded = execute_guarded(&scheduler, owner(), &profile, connection, statement, true);
    let Ok(Guarded::Started(job, result, _)) = guarded else {
        panic!("expected Started");
    };
    let mut result = result.await.unwrap();
    assert_eq!(number(&next(&mut result).await.unwrap().unwrap()), 0);
    assert!(next(&mut result).await.is_none());
    job.join().await.unwrap();
    assert!(seen.executed.load(Ordering::SeqCst));
    assert_eq!(scheduler.jobs()[0].state, JobState::Succeeded);
}

#[tokio::test(start_paused = true)]
async fn the_guard_allows_a_read_and_the_job_runs_as_before() {
    let scheduler = JobScheduler::new(NonZeroUsize::MIN, 100);
    let (connection, seen) = connection(Plan::Endless);
    // A read passes both flags without a confirmation.
    let profile = profile(true, true);
    let guarded = execute_guarded(
        &scheduler,
        owner(),
        &profile,
        connection,
        STATEMENT.to_owned(),
        false,
    );
    let Ok(Guarded::Started(job, result, _)) = guarded else {
        panic!("expected Started");
    };
    let mut result = result.await.unwrap();
    next(&mut result).await.unwrap().unwrap();
    idle().await;
    // Bounded: the buffer is full and the job holds one more batch.
    assert_eq!(seen.produced.load(Ordering::SeqCst), RESULT_BUFFER + 2);

    job.cancel();
    let error = job.join().await.unwrap_err();
    assert_eq!(error.category(), ErrorCategory::Cancelled);
    assert!(seen.cancelled_while_running.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn the_job_hands_the_connection_back_for_a_second_statement() {
    let scheduler = JobScheduler::new(NonZeroUsize::MIN, 100);
    let (connection, seen) = connection(Plan::Batches(1));
    let (job, result, back) =
        execute(&scheduler, owner(), connection, STATEMENT.to_owned()).unwrap();
    let mut result = result.await.unwrap();
    assert_eq!(number(&next(&mut result).await.unwrap().unwrap()), 0);
    assert!(next(&mut result).await.is_none());
    job.join().await.unwrap();

    let connection = back.await.expect("the connection comes back");
    let (job, result, back) =
        execute(&scheduler, owner(), connection, STATEMENT.to_owned()).unwrap();
    // The fake made its one batch in the first statement.
    assert!(next(&mut result.await.unwrap()).await.is_none());
    job.join().await.unwrap();
    assert_eq!(seen.executions.load(Ordering::SeqCst), 2);
    assert!(back.await.is_some());
    assert!(
        scheduler
            .jobs()
            .iter()
            .all(|job| job.state == JobState::Succeeded)
    );
}

#[tokio::test(start_paused = true)]
async fn the_connection_comes_back_after_an_error_and_a_cancel() {
    let scheduler = JobScheduler::new(NonZeroUsize::MIN, 100);
    for plan in [Plan::Refuse, Plan::FailAfterTwo, Plan::Endless] {
        let (connection, _) = connection(plan);
        let (job, result, back) =
            execute(&scheduler, owner(), connection, STATEMENT.to_owned()).unwrap();
        if let Ok(mut result) = result.await {
            next(&mut result).await.unwrap().unwrap();
            if let Plan::Endless = plan {
                job.cancel();
            }
            while let Some(Ok(_)) = next(&mut result).await {}
        }
        assert!(job.join().await.is_err());
        assert!(back.await.is_some());
    }
}

#[tokio::test(start_paused = true)]
async fn a_job_cancelled_in_the_queue_drops_the_connection() {
    let scheduler = JobScheduler::new(NonZeroUsize::MIN, 100);
    let (running, _) = connection(Plan::Endless);
    let (first, _result, _) = execute(&scheduler, owner(), running, STATEMENT.to_owned()).unwrap();
    let (queued, seen) = connection(Plan::Batches(1));
    let (job, _result, back) = execute(&scheduler, owner(), queued, STATEMENT.to_owned()).unwrap();
    idle().await;
    job.cancel();
    assert!(back.await.is_none());
    assert!(!seen.executed.load(Ordering::SeqCst));
    first.cancel();
}
