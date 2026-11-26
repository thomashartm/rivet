//! Runs one statement as a job (ARCHITECTURE.md §5.3, §5.4, §5.5, §5.6).
//!
//! - [`execute_guarded`] calls the statement guard ([`guard::decide`]) with
//!   the profile flags `read_only` and `confirm_on_write` before the
//!   statement reaches the driver. Only an allowed statement starts a job.
//! - [`execute`] starts a job of the [`JobScheduler`] that runs one
//!   statement on one [`Connection`].
//! - The caller gets the job handle and a future of the result. The future
//!   is ready when the schema is known. The result then streams its record
//!   batches.
//! - The driver is read only as fast as the caller reads: the job holds at
//!   most [`RESULT_BUFFER`] batches that the caller has not read (§5.5).
//! - To cancel the job calls [`Connection::cancel`]. The job ends
//!   `Cancelled`, and the result ends with a `cancelled` error (§5.4).
//! - To drop the result (or its future) before its end stops the statement
//!   and ends the job `Cancelled`.
//! - A driver error keeps its category and message. The result ends with
//!   it, and the job ends `Failed` (or `Cancelled` for the category
//!   `cancelled`).
//! - The job hands the connection back when it ends (see [`HandBack`]), so
//!   one connection serves many statements: a transaction or a `SET` stays.
//! - The log events of this module contain the job id and an error
//!   category only, never the statement text: it can contain personal data.
//!   The guard path writes no log event, and its errors do not contain the
//!   statement text.
//!
//! [`execute`] runs without the guard. A caller that runs a statement of a
//! user uses [`execute_guarded`].

use std::future::poll_fn;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use arrow_array::RecordBatch;
use futures_core::Stream;
use rivet_sdk::error::{Error, Result};
use rivet_sdk::extension::{BoxFuture, Connection};
use rivet_sdk::model::{ConnectionProfile, ResultSet};
use tokio::sync::{mpsc, oneshot};

use crate::Owner;
use crate::guard::{self, Decision};
use crate::jobs::{JobContext, JobHandle, JobScheduler};

/// The most record batches that the job reads from the driver before the
/// caller reads them. A slow caller slows the driver read.
pub const RESULT_BUFFER: usize = 4;

/// The kind of the job in [`JobScheduler::jobs`].
pub const JOB_KIND: &str = "execute";

/// The connection that the job of [`execute`] hands back when it ends.
///
/// The future is ready when the work of the job ends, thus after the caller
/// has read the result to its end or dropped it, or after a cancel. The job
/// state can turn final a moment later. Its value:
///
/// | How the job ended | Value | State of the connection |
/// | --- | --- | --- |
/// | The statement succeeded | `Some` | As the statement left it: an open transaction, `SET` and `search_path` stay |
/// | The driver failed, the job was cancelled, or the caller dropped the result | `Some` | As the driver left it after the error or the cancel: no statement runs. An open transaction can be aborted by the database (PostgreSQL then needs `ROLLBACK`) |
/// | The job never started (cancelled while queued), was aborted after [`JobConfig::cancel_grace`](crate::jobs::JobConfig::cancel_grace), or panicked | `None` | Dropped, thus closed |
pub type HandBack = BoxFuture<'static, Option<Box<dyn Connection>>>;

/// The result of [`execute_guarded`].
pub enum Guarded {
    /// The guard allowed the statement. The values are the values of
    /// [`execute`].
    Started(
        JobHandle<()>,
        BoxFuture<'static, Result<ResultSet>>,
        HandBack,
    ),
    /// The statement is a write on a `confirm_on_write` profile. The driver
    /// was not called and no job was started. The caller asks the user, then
    /// calls [`execute_guarded`] again with these values and
    /// `confirmed = true`.
    NeedsConfirmation {
        /// The connection that the caller gave.
        connection: Box<dyn Connection>,
        /// The statement that the caller gave.
        statement: String,
    },
    /// The guard refused the statement. The driver was not called and no
    /// job was started; the connection is handed back unchanged (decision
    /// on #27).
    Denied {
        /// The `policy` error of the guard.
        error: Error,
        /// The connection that the caller gave.
        connection: Box<dyn Connection>,
    },
}

/// Calls the guard with the flags of `profile`, then runs `statement` as
/// [`execute`] does if the guard allows it.
///
/// `confirmed` is `true` when the user confirmed a write (see
/// [`Guarded::NeedsConfirmation`]).
///
/// # Errors
///
/// The errors of [`execute`]. A refusal of the guard is not an error but
/// [`Guarded::Denied`], which hands `connection` back.
pub fn execute_guarded(
    scheduler: &JobScheduler,
    owner: Owner,
    profile: &ConnectionProfile,
    connection: Box<dyn Connection>,
    statement: String,
    confirmed: bool,
) -> Result<Guarded> {
    let decision = guard::decide(
        profile.read_only,
        profile.confirm_on_write,
        &statement,
        confirmed,
    );
    match decision {
        Decision::Allow => {
            let (job, result, connection) = execute(scheduler, owner, connection, statement)?;
            Ok(Guarded::Started(job, result, connection))
        }
        Decision::NeedsConfirmation => Ok(Guarded::NeedsConfirmation {
            connection,
            statement,
        }),
        Decision::Deny(error) => Ok(Guarded::Denied { error, connection }),
    }
}

/// Starts a job that runs `statement` on `connection`. It does not call the
/// guard; see [`execute_guarded`].
///
/// Returns the job handle, a future of the result and the [`HandBack`] of
/// `connection`. The result future is ready when the schema is known; the
/// [`ResultSet`] then streams the batches. The job owns `connection` while
/// it runs and hands it back when it ends.
///
/// The future fails, or the result ends with an error, in these cases:
///
/// | Case | Error |
/// | --- | --- |
/// | The driver fails | The error of the driver |
/// | The job is cancelled or aborted, also before it starts | `cancelled` |
///
/// # Errors
///
/// The errors of [`JobScheduler::spawn`], for example a `policy` error if
/// `owner` has too many jobs.
pub fn execute(
    scheduler: &JobScheduler,
    owner: Owner,
    connection: Box<dyn Connection>,
    statement: String,
) -> Result<(
    JobHandle<()>,
    BoxFuture<'static, Result<ResultSet>>,
    HandBack,
)> {
    let (ready, result) = oneshot::channel();
    let (back, handed_back) = oneshot::channel();
    let job = scheduler.spawn(owner, JOB_KIND, move |ctx| {
        run(ctx, connection, statement, ready, back)
    })?;
    let result = Box::pin(async move {
        // No value means that the job ended before the schema was known.
        result.await.unwrap_or_else(|_| Err(stopped()))
    });
    // No value means that the job dropped the connection (see `HandBack`).
    let handed_back = Box::pin(async move { handed_back.await.ok() });
    Ok((job, result, handed_back))
}

/// The body of the job.
async fn run(
    ctx: JobContext,
    connection: Box<dyn Connection>,
    statement: String,
    ready: oneshot::Sender<Result<ResultSet>>,
    back: oneshot::Sender<Box<dyn Connection>>,
) -> Result<()> {
    let job = ctx.id();
    tracing::info!(%job, "statement started");
    let mut work = Box::pin(stream_rows(&*connection, statement, ready));
    let outcome = tokio::select! {
        outcome = &mut work => outcome,
        () = ctx.cancelled() => {
            // Cancel while the statement still runs, so that the database
            // stops it (§5.4).
            if let Err(error) = connection.cancel().await {
                let category = error.category();
                tracing::warn!(%job, ?category, "the driver could not cancel the statement");
            }
            Err(Error::cancelled("the statement was cancelled"))
        }
    };
    // Drops the driver result set: this stops the statement. The caller's
    // result then ends with a `cancelled` error.
    drop(work);
    // No receiver means that the caller does not want it: it is dropped.
    let _ = back.send(connection);
    match &outcome {
        Ok(()) => tracing::info!(%job, "statement ended"),
        Err(error) => {
            let category = error.category();
            tracing::info!(%job, ?category, "statement ended with an error");
        }
    }
    outcome
}

/// Runs the statement and sends its result to the caller.
async fn stream_rows(
    connection: &dyn Connection,
    statement: String,
    ready: oneshot::Sender<Result<ResultSet>>,
) -> Result<()> {
    let mut rows = match connection.execute(statement).await {
        Ok(rows) => rows,
        Err(error) => {
            let copy = same(&error);
            let _ = ready.send(Err(error));
            return Err(copy);
        }
    };
    let (sender, receiver) = mpsc::channel(RESULT_BUFFER);
    let (end, end_receiver) = oneshot::channel();
    let batches = Batches {
        receiver,
        end: Some(end_receiver),
    };
    let result = ResultSet::new(
        rows.schema().clone(),
        rows.columns().to_vec(),
        Box::pin(batches),
    );
    let failed = result.as_ref().err().map(same);
    if ready.send(result).is_err() {
        return Err(dropped());
    }
    if let Some(error) = failed {
        return Err(error);
    }
    loop {
        let next = tokio::select! {
            next = poll_fn(|cx| Pin::new(&mut rows).poll_next(cx)) => next,
            () = sender.closed() => return Err(dropped()),
        };
        match next {
            Some(Ok(batch)) => {
                if sender.send(batch).await.is_err() {
                    return Err(dropped());
                }
            }
            Some(Err(error)) => {
                let copy = same(&error);
                let _ = end.send(Err(error));
                return Err(copy);
            }
            None => {
                let _ = end.send(Ok(()));
                return Ok(());
            }
        }
    }
}

/// The batches that the caller reads. They end with the end marker of the
/// job; no marker means that the job stopped.
struct Batches {
    receiver: mpsc::Receiver<RecordBatch>,
    /// `None` after the stream ended.
    end: Option<oneshot::Receiver<Result<()>>>,
}

impl Stream for Batches {
    type Item = Result<RecordBatch>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        let Some(end) = this.end.as_mut() else {
            return Poll::Ready(None);
        };
        // `None` means that the job dropped its sender: it has ended, and it
        // sent the end marker before, if it had one.
        if let Some(batch) = ready!(this.receiver.poll_recv(cx)) {
            return Poll::Ready(Some(Ok(batch)));
        }
        let end = ready!(Pin::new(end).poll(cx));
        self.end = None;
        Poll::Ready(match end {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(Err(error)),
            Err(_) => Some(Err(stopped())),
        })
    }
}

/// A copy of `error` with the same category and message. The SDK error is
/// not `Clone`; the source chain stays with the caller's copy.
fn same(error: &Error) -> Error {
    Error::new(error.category(), error.message())
}

/// The caller dropped the result before its end.
fn dropped() -> Error {
    Error::cancelled("the caller dropped the result before its end")
}

/// The job ended before the end of the result.
fn stopped() -> Error {
    Error::cancelled("the statement stopped before the end of its result")
}
