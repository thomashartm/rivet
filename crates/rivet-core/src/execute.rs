//! Runs one statement as a job (ARCHITECTURE.md §5.4, §5.5, §5.6).
//!
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
//! - The log events of this module contain the job id and an error
//!   category only, never the statement text: it can contain personal data.
//!
//! Slice 1 of ticket #27 has no guard. Slice 2 calls the guard of ticket #20
//! before the statement reaches the driver.

use std::future::poll_fn;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use arrow_array::RecordBatch;
use futures_core::Stream;
use rivet_sdk::error::{Error, Result};
use rivet_sdk::extension::{BoxFuture, Connection};
use rivet_sdk::model::ResultSet;
use tokio::sync::{mpsc, oneshot};

use crate::Owner;
use crate::jobs::{JobContext, JobHandle, JobScheduler};

/// The most record batches that the job reads from the driver before the
/// caller reads them. A slow caller slows the driver read.
pub const RESULT_BUFFER: usize = 4;

/// The kind of the job in [`JobScheduler::jobs`].
pub const JOB_KIND: &str = "execute";

/// Starts a job that runs `statement` on `connection`.
///
/// Returns the job handle and a future of the result. The future is ready
/// when the schema is known; the [`ResultSet`] then streams the batches.
/// The job owns `connection` and drops it when it ends.
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
) -> Result<(JobHandle<()>, BoxFuture<'static, Result<ResultSet>>)> {
    let (ready, result) = oneshot::channel();
    let job = scheduler.spawn(owner, JOB_KIND, move |ctx| {
        run(ctx, connection, statement, ready)
    })?;
    let result = Box::pin(async move {
        // No value means that the job ended before the schema was known.
        result.await.unwrap_or_else(|_| Err(stopped()))
    });
    Ok((job, result))
}

/// The body of the job.
async fn run(
    ctx: JobContext,
    connection: Box<dyn Connection>,
    statement: String,
    ready: oneshot::Sender<Result<ResultSet>>,
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
