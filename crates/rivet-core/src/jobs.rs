//! Job scheduler: long-running work with progress, cancellation and a result
//! (ARCHITECTURE.md §5.1, §5.2, §5.4, §6.1).
//!
//! - A job has an id, a kind, an owner, a state, a progress, a cancellation
//!   token and a result.
//! - At most `max_concurrent` jobs run at the same time. The other jobs wait
//!   in the state [`JobState::Queued`].
//! - One extension can have at most `max_per_extension` queued and running
//!   jobs (§4.3). A job above the limit is refused.
//! - The limits are settings with defaults: see [`JobConfig`].
//! - Cancellation is cooperative: the job must watch its
//!   [`CancellationToken`] and return. A job that has not returned when
//!   [`JobConfig::cancel_grace`] is over is aborted and ends in the state
//!   [`JobState::Cancelled`] (§5.2).
//! - The abort stops async work at its next `.await`. It cannot stop
//!   blocking work, or async work that never reaches an `.await`. Such a
//!   job is `Cancelled` also, but it keeps its slot of `max_concurrent`
//!   and its place in `max_per_extension` until its code returns: the
//!   limits count real work. If the code never returns, the slot is taken
//!   until the process ends.
//! - Job state lives in memory only (§6.2).
//!
//! ```
//! // The job model is in `rivet_sdk::job`. This module re-exports it.
//! use rivet_core::jobs::{JobScheduler, JobState, Progress};
//! use std::num::NonZeroUsize;
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> rivet_sdk::error::Result<()> {
//! let scheduler = JobScheduler::new(NonZeroUsize::MIN, 100);
//! let job = scheduler.spawn("acme.export".parse()?, "export", |ctx| async move {
//!     for row in 1..=3 {
//!         if ctx.is_cancelled() {
//!             return Err(rivet_sdk::error::Error::cancelled("export stopped"));
//!         }
//!         ctx.report(Progress::new(row, Some(3)));
//!     }
//!     Ok("3 rows")
//! })?;
//!
//! let (watch, job_id) = (job.watch(), job.id());
//! assert_eq!(job.join().await?, "3 rows");
//! assert_eq!(watch.borrow().state, JobState::Succeeded);
//! assert_eq!(watch.borrow().progress.completed, 3);
//! let same_type: rivet_sdk::job::JobId = job_id;
//! assert_eq!(scheduler.jobs()[0].id, same_type);
//! # Ok(())
//! # }
//! ```

use crate::Owner;
use crate::registry::ClosedOwners;
use crate::settings::Settings;
use rivet_sdk::error::{Error, ErrorCategory, Result};
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::{Semaphore, oneshot, watch};
use tokio::task::JoinHandle;

// The job model is plain data in the SDK, so that an extension can use it
// (§3.2). This re-export keeps the paths `rivet_core::jobs::JobId`, etc.
pub use rivet_sdk::job::{JobId, JobSnapshot, JobState, JobStatus, Progress};

/// Tells a job that it must stop. Clones share the same state.
///
/// This is a few lines on `tokio::sync::watch`, which the scheduler already
/// uses, so the public API does not depend on the version of `tokio-util`.
#[derive(Debug, Clone)]
pub struct CancellationToken(watch::Receiver<bool>);

impl CancellationToken {
    /// Returns `true` after a cancel request.
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }

    /// Completes when a cancel request arrives. Completes immediately if it
    /// arrived earlier.
    pub async fn cancelled(&self) {
        let mut requests = self.0.clone();
        if requests.wait_for(|cancelled| *cancelled).await.is_err() {
            // The job is gone, so a cancel request cannot arrive any more.
            std::future::pending::<()>().await;
        }
    }
}

/// What a running job receives: its cancellation token and its progress
/// reporter. Clones belong to the same job.
#[derive(Debug, Clone)]
pub struct JobContext {
    id: JobId,
    token: CancellationToken,
    status: watch::Sender<JobStatus>,
}

impl JobContext {
    /// Returns the id of this job.
    pub fn id(&self) -> JobId {
        self.id
    }

    /// Returns the cancellation token of this job.
    pub fn cancellation(&self) -> &CancellationToken {
        &self.token
    }

    /// Returns `true` after a cancel request. Blocking jobs poll this.
    pub fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Completes when a cancel request arrives.
    pub async fn cancelled(&self) {
        self.token.cancelled().await;
    }

    /// Replaces the progress of this job. Observers see the new value at
    /// once. A report after the job finished is ignored.
    pub fn report(&self, progress: Progress) {
        self.status.send_if_modified(|status| {
            let running = status.state == JobState::Running;
            if running {
                status.progress = progress;
            }
            running
        });
    }
}

/// The handle to one job. Dropping the handle does not cancel the job.
#[derive(Debug)]
pub struct JobHandle<T> {
    id: JobId,
    cancel: watch::Sender<bool>,
    status: watch::Receiver<JobStatus>,
    result: oneshot::Receiver<Result<T>>,
}

impl<T> JobHandle<T> {
    /// Returns the id of the job.
    pub fn id(&self) -> JobId {
        self.id
    }

    /// Returns the current state and progress.
    pub fn status(&self) -> JobStatus {
        self.status.borrow().clone()
    }

    /// Returns a receiver that sees every change of state and progress
    /// while the job runs. A slow observer sees the newest value only.
    pub fn watch(&self) -> watch::Receiver<JobStatus> {
        self.status.clone()
    }

    /// Asks the job to stop. A queued job never starts. A running job must
    /// cooperate (see [`CancellationToken`]); a job that does not is
    /// aborted after [`JobConfig::cancel_grace`]. No effect on a finished
    /// job.
    pub fn cancel(&self) {
        self.cancel.send_replace(true);
    }

    /// Waits for the job and returns its result.
    ///
    /// # Errors
    ///
    /// - The error that the job returned, if it ended `Failed`.
    /// - An `internal` error if the job panicked.
    /// - A `cancelled` error if the job ended `Cancelled`.
    pub async fn join(self) -> Result<T> {
        let id = self.id;
        self.result.await.unwrap_or_else(|_| {
            Err(Error::internal(format!(
                "job {id} ended without a result because the runtime shut down"
            )))
        })
    }
}

/// The limits of a [`JobScheduler`].
///
/// [`from_settings`](Self::from_settings) reads it from these settings.
///
/// | Setting | Default | Field |
/// | --- | --- | --- |
/// | `jobs.max_concurrent` | 4 | [`max_concurrent`](Self::max_concurrent) |
/// | `jobs.max_per_extension` | 8 | [`max_per_extension`](Self::max_per_extension) |
/// | `jobs.retain_finished` | 100 | [`retain_finished`](Self::retain_finished) |
/// | `jobs.cancel_grace_ms` | 5000 | [`cancel_grace`](Self::cancel_grace) |
///
/// `jobs.cancel_grace_ms` is from 1 to 60000.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobConfig {
    /// How many jobs run at the same time.
    pub max_concurrent: NonZeroUsize,
    /// How many queued and running jobs one extension can have at the same
    /// time. `None` means no limit per extension.
    pub max_per_extension: Option<NonZeroUsize>,
    /// How many finished jobs [`JobScheduler::jobs`] still lists. Older
    /// finished jobs are forgotten.
    pub retain_finished: usize,
    /// How long a running job has to stop after a cancel request. Then the
    /// scheduler aborts it. The setting is in milliseconds.
    pub cancel_grace: Duration,
}

/// The longest grace period that the settings accept: a release of an
/// extension waits this long for a job that ignores the cancel request.
const MAX_CANCEL_GRACE_MS: u64 = 60_000;

impl Default for JobConfig {
    fn default() -> Self {
        Self {
            max_concurrent: NonZeroUsize::MIN.saturating_add(3),
            max_per_extension: NonZeroUsize::new(8),
            retain_finished: 100,
            cancel_grace: Duration::from_secs(5),
        }
    }
}

impl JobConfig {
    /// Reads the limits from `settings`. A key that no layer sets has its
    /// default (see the table in [`JobConfig`]).
    ///
    /// # Errors
    ///
    /// Returns a `user` error if a value has the wrong type, if
    /// `jobs.max_concurrent`, `jobs.max_per_extension` or
    /// `jobs.cancel_grace_ms` is `0`, or if `jobs.cancel_grace_ms` is more
    /// than 60000 (one minute).
    pub fn from_settings(settings: &Settings) -> Result<Self> {
        let default = Self::default();
        let invalid = |problem: String| Error::user(format!("invalid settings: {problem}"));
        // Read as a plain integer, so that the error for `0` names the key.
        let not_zero = |key: &str| -> Result<Option<NonZeroUsize>> {
            let value = settings.get::<usize>(key)?.map(NonZeroUsize::new);
            match value {
                Some(None) => Err(invalid(format!("`{key}` must not be 0"))),
                Some(value) => Ok(value),
                None => Ok(None),
            }
        };
        let max_concurrent = not_zero("jobs.max_concurrent")?;
        let max_per_extension = not_zero("jobs.max_per_extension")?;
        let retain_finished = settings.get("jobs.retain_finished")?;
        let cancel_grace = settings.get::<u64>("jobs.cancel_grace_ms")?;
        match cancel_grace {
            Some(0) => return Err(invalid("`jobs.cancel_grace_ms` must not be 0".into())),
            Some(millis) if millis > MAX_CANCEL_GRACE_MS => {
                return Err(invalid(format!(
                    "`jobs.cancel_grace_ms` must not be more than {MAX_CANCEL_GRACE_MS}"
                )));
            }
            _ => {}
        }
        Ok(Self {
            max_concurrent: max_concurrent.unwrap_or(default.max_concurrent),
            max_per_extension: max_per_extension.or(default.max_per_extension),
            retain_finished: retain_finished.unwrap_or(default.retain_finished),
            cancel_grace: cancel_grace.map_or(default.cancel_grace, Duration::from_millis),
        })
    }
}

/// Runs jobs with a limit on how many run at the same time.
///
/// Clones share the same jobs. All methods take `&self` and are safe for
/// concurrent use.
///
/// The Tokio runtime must have its timer: the abort of a job after
/// [`JobConfig::cancel_grace`] uses it.
#[derive(Debug, Clone)]
pub struct JobScheduler {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    slots: Arc<Semaphore>,
    max_per_extension: Option<NonZeroUsize>,
    retain_finished: usize,
    cancel_grace: Duration,
    next_id: AtomicU64,
    jobs: Mutex<Jobs>,
    /// The owners that the host stops: they cannot start a job.
    closed: ClosedOwners,
}

#[derive(Debug, Default)]
struct Jobs {
    /// Queued and running jobs.
    active: BTreeMap<JobId, Active>,
    /// The newest finished jobs, oldest first.
    finished: VecDeque<JobSnapshot>,
    /// The aborted jobs whose code has not stopped yet. They count for the
    /// limit per extension.
    stopping: BTreeMap<JobId, Owner>,
}

#[derive(Debug)]
struct Active {
    kind: String,
    owner: Owner,
    cancel: watch::Sender<bool>,
    status: watch::Receiver<JobStatus>,
}

impl JobScheduler {
    /// Creates a scheduler with the two given limits and the defaults of
    /// [`JobConfig`] for the other limits.
    ///
    /// - `max_concurrent`: how many jobs run at the same time.
    /// - `retain_finished`: how many finished jobs [`jobs`](Self::jobs)
    ///   still lists. Older finished jobs are forgotten.
    ///
    /// The limit per extension is thus the default: one owner can have at
    /// most 8 queued and running jobs. Use [`with_config`](Self::with_config)
    /// for another limit or for no limit.
    pub fn new(max_concurrent: NonZeroUsize, retain_finished: usize) -> Self {
        Self::with_config(JobConfig {
            max_concurrent,
            retain_finished,
            ..JobConfig::default()
        })
    }

    /// Creates a scheduler with the limits of `config`, for example from
    /// [`JobConfig::from_settings`].
    /// The values are used as given and are not checked; only
    /// [`JobConfig::from_settings`] checks the ranges (ADR-0021).
    pub fn with_config(config: JobConfig) -> Self {
        let slots = config.max_concurrent.get().min(Semaphore::MAX_PERMITS);
        Self {
            inner: Arc::new(Inner {
                slots: Arc::new(Semaphore::new(slots)),
                max_per_extension: config.max_per_extension,
                retain_finished: config.retain_finished,
                cancel_grace: config.cancel_grace,
                next_id: AtomicU64::new(1),
                jobs: Mutex::default(),
                closed: ClosedOwners::default(),
            }),
        }
    }

    /// Starts an async job. The job is `Queued` until a slot is free.
    ///
    /// `work` receives the [`JobContext`]. It runs on the async worker
    /// threads, so it MUST NOT block; use
    /// [`spawn_blocking`](Self::spawn_blocking) for blocking work.
    ///
    /// The scheduler does not prove `owner`: the caller (the binding layer)
    /// MUST give the id of the extension that starts the job, or the limit
    /// per extension has no effect.
    ///
    /// The final state follows from what `work` does:
    ///
    /// | `work` | State |
    /// | --- | --- |
    /// | returns `Ok` | `Succeeded` |
    /// | returns `Err` after a cancel request, or an `Err` of the category `cancelled` | `Cancelled` |
    /// | does not return in [`JobConfig::cancel_grace`] after a cancel request (it is aborted) | `Cancelled` |
    /// | returns another `Err`, or panics | `Failed` |
    ///
    /// The abort stops `work` at its next `.await`. See the
    /// [module documentation](self) for work that never reaches one.
    ///
    /// # Errors
    ///
    /// - An `internal` error if the caller is not in a Tokio runtime.
    /// - A `policy` error if `owner` has as many queued and running jobs as
    ///   [`JobConfig::max_per_extension`] permits.
    /// - A `policy` error while the host stops the extension `owner`.
    pub fn spawn<T, F, Fut>(
        &self,
        owner: Owner,
        kind: impl Into<String>,
        work: F,
    ) -> Result<JobHandle<T>>
    where
        T: Send + 'static,
        F: FnOnce(JobContext) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        // `work` is called inside the task, so a panic in it is contained.
        self.start(owner, kind.into(), |ctx| {
            tokio::spawn(async move { work(ctx).await })
        })
    }

    /// Starts a job that blocks its thread, for example compression or
    /// CPU-heavy parsing. It runs on the blocking pool of the runtime, not
    /// on an async worker thread (§5.1).
    ///
    /// The job counts against `max_concurrent`. States and errors are the
    /// same as for [`spawn`](Self::spawn), with one difference: the abort
    /// cannot stop blocking work. A blocking job that ignores a cancel
    /// request ends `Cancelled` after [`JobConfig::cancel_grace`], but it
    /// keeps its slot until `work` returns. To cooperate with a cancel
    /// request, `work` polls [`JobContext::is_cancelled`].
    ///
    /// # Errors
    ///
    /// The same errors as [`spawn`](Self::spawn).
    pub fn spawn_blocking<T, F>(
        &self,
        owner: Owner,
        kind: impl Into<String>,
        work: F,
    ) -> Result<JobHandle<T>>
    where
        T: Send + 'static,
        F: FnOnce(JobContext) -> Result<T> + Send + 'static,
    {
        self.start(owner, kind.into(), |ctx| {
            tokio::task::spawn_blocking(move || work(ctx))
        })
    }

    /// Refuses each new job of `owner` until
    /// [`open_owner`](Self::open_owner). The host calls it before
    /// [`stop_owner`](Self::stop_owner), so that a job cannot answer the
    /// cancel request with a new job.
    pub(crate) fn close_owner(&self, owner: &Owner) {
        self.inner.closed.close(owner);
    }

    /// Accepts the jobs of `owner` again.
    pub(crate) fn open_owner(&self, owner: &Owner) {
        self.inner.closed.open(owner);
    }

    /// Asks every queued or running job of `owner` to stop. Returns how
    /// many jobs received the request. A job that does not stop is aborted
    /// after [`JobConfig::cancel_grace`].
    pub fn cancel_owner(&self, owner: &Owner) -> usize {
        self.request_stop(owner).len()
    }

    /// Asks every queued or running job of `owner` to stop, and waits until
    /// each of them has ended (§5.2). Returns how many jobs these were.
    ///
    /// The wait is not longer than [`JobConfig::cancel_grace`]: then the
    /// scheduler aborts the jobs that still run.
    pub async fn stop_owner(&self, owner: &Owner) -> usize {
        let jobs = self.request_stop(owner);
        let count = jobs.len();
        for mut status in jobs {
            // An error means that the job is gone, thus it has ended.
            let _ = status.wait_for(|status| status.state.is_finished()).await;
        }
        count
    }

    /// Returns how many aborted jobs of `owner` have code that has not
    /// stopped. Such a job is `Cancelled`, but it keeps its slot.
    pub(crate) fn aborted_running(&self, owner: &Owner) -> usize {
        let jobs = self.inner.lock();
        jobs.stopping.values().filter(|of| *of == owner).count()
    }

    /// Sends a cancel request to every queued or running job of `owner`.
    fn request_stop(&self, owner: &Owner) -> Vec<watch::Receiver<JobStatus>> {
        let jobs = self.inner.lock();
        let of_owner = jobs.active.values().filter(|job| &job.owner == owner);
        of_owner
            .map(|job| {
                job.cancel.send_replace(true);
                job.status.clone()
            })
            .collect()
    }

    /// Returns a copy of all known jobs: the queued and running jobs in the
    /// order of their ids, then the retained finished jobs, oldest first.
    pub fn jobs(&self) -> Vec<JobSnapshot> {
        let jobs = self.inner.lock();
        let active = jobs.active.iter().map(|(id, job)| {
            let status = job.status.borrow();
            JobSnapshot::new(
                *id,
                job.kind.clone(),
                job.owner.clone(),
                status.state,
                status.progress.clone(),
            )
        });
        active.chain(jobs.finished.iter().cloned()).collect()
    }

    /// Registers a job and starts its supervisor task. `launch` starts the
    /// work as a task of its own, so a panic reaches the supervisor as an
    /// error of the `JoinHandle`.
    fn start<T, L>(&self, owner: Owner, kind: String, launch: L) -> Result<JobHandle<T>>
    where
        T: Send + 'static,
        L: FnOnce(JobContext) -> JoinHandle<Result<T>> + Send + 'static,
    {
        let runtime = Handle::try_current().map_err(|error| {
            Error::internal("a job can start only inside the Tokio runtime").with_source(error)
        })?;
        let id = JobId::new(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        let (cancel, cancel_requests) = watch::channel(false);
        let (status, status_watch) =
            watch::channel(JobStatus::new(JobState::Queued, Progress::default()));
        let (result_sender, result) = oneshot::channel();
        {
            // One lock for the count and the insert: two spawns at the same
            // time cannot both take the last place.
            let mut jobs = self.inner.lock();
            self.inner.closed.check(&owner)?;
            if let Some(limit) = self.inner.max_per_extension {
                let active = jobs.active.values().filter(|job| job.owner == owner);
                let stopping = jobs
                    .stopping
                    .iter()
                    .filter(|(id, of)| **of == owner && !jobs.active.contains_key(id));
                if active.count() + stopping.count() >= limit.get() {
                    return Err(Error::policy(format!(
                        "extension `{owner}` cannot start the job `{kind}`: it has {limit} \
                         queued or running jobs, which is the limit per extension"
                    )));
                }
            }
            let job = Active {
                kind,
                owner,
                cancel: cancel.clone(),
                status: status_watch.clone(),
            };
            jobs.active.insert(id, job);
        }

        let ctx = JobContext {
            id,
            token: CancellationToken(cancel_requests),
            status,
        };
        let inner = self.inner.clone();
        runtime.spawn(async move {
            let status = ctx.status.clone();
            let outcome = inner.run(ctx, launch).await;
            let state = match &outcome {
                Ok(_) => JobState::Succeeded,
                Err(error) if error.category() == ErrorCategory::Cancelled => JobState::Cancelled,
                Err(_) => JobState::Failed,
            };
            // The list and the status are final before `join` returns.
            inner.finish(id, state, &status, outcome.as_ref().err());
            status.send_modify(|status| status.state = state);
            // The send fails if the handle was dropped: nobody waits.
            let _ = result_sender.send(outcome);
        });
        Ok(JobHandle {
            id,
            cancel,
            status: status_watch,
            result,
        })
    }
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, Jobs> {
        self.jobs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits for a slot, runs the work and returns its result. An error
    /// has the category `cancelled` if and only if the job is `Cancelled`.
    async fn run<T, L>(self: &Arc<Self>, ctx: JobContext, launch: L) -> Result<T>
    where
        T: Send + 'static,
        L: FnOnce(JobContext) -> JoinHandle<Result<T>>,
    {
        let (id, token, status) = (ctx.id, ctx.token.clone(), ctx.status.clone());
        let slot = tokio::select! {
            biased;
            () = token.cancelled() => None,
            slot = self.slots.clone().acquire_owned() => slot.ok(),
        };
        // The semaphore is never closed: no slot means cancelled in the queue.
        let Some(slot) = slot else {
            return Err(Error::cancelled(format!(
                "job {id} was cancelled before it started"
            )));
        };
        status.send_modify(|status| status.state = JobState::Running);
        let mut work = launch(ctx);
        let grace = self.cancel_grace;
        let overdue = async {
            token.cancelled().await;
            tokio::time::sleep(grace).await;
            // Work that ends at the same moment as the grace period gets
            // its turn before the abort. On a runtime with more than one
            // thread this does not fix the order: there the result is what
            // happened first.
            tokio::task::yield_now().await;
        };
        let joined = tokio::select! {
            // A job that has finished keeps its result, also if the grace
            // period ends in the same poll.
            biased;
            joined = &mut work => joined,
            () = overdue => {
                work.abort();
                let owner = {
                    let mut jobs = self.lock();
                    let owner = jobs.active.get(&id).map(|job| job.owner.clone());
                    jobs.stopping.extend(owner.clone().map(|owner| (id, owner)));
                    owner
                };
                // The job ends now, but it keeps its slot until its code has
                // stopped: the limits count real work.
                let inner = Arc::clone(self);
                tokio::spawn(async move {
                    if tokio::time::timeout(grace, &mut work).await.is_err() {
                        let owner = owner.as_ref().map(ToString::to_string);
                        tracing::warn!(owner, job = %id, "an aborted job still runs and keeps its slot");
                        let _ = work.await;
                    }
                    inner.lock().stopping.remove(&id);
                    drop(slot);
                });
                return Err(Error::cancelled(format!(
                    "job {id} did not stop in {grace:?} after the cancel request and was aborted"
                )));
            }
        };
        match joined {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error))
                if token.is_cancelled() && error.category() != ErrorCategory::Cancelled =>
            {
                let message = format!("job {id} was cancelled: {}", error.message());
                Err(Error::cancelled(message).with_source(error))
            }
            Ok(Err(error)) => Err(error),
            Err(error) => {
                let what = if error.is_panic() {
                    "panicked"
                } else {
                    "was aborted by the runtime"
                };
                Err(Error::internal(format!("job {id} {what}")).with_source(error))
            }
        }
    }

    /// Moves the job from the active jobs to the retained finished jobs.
    fn finish(
        &self,
        id: JobId,
        state: JobState,
        status: &watch::Sender<JobStatus>,
        error: Option<&Error>,
    ) {
        let mut jobs = self.lock();
        let Some(job) = jobs.active.remove(&id) else {
            return;
        };
        let progress = status.borrow().progress.clone();
        let mut snapshot = JobSnapshot::new(id, job.kind, job.owner, state, progress);
        snapshot.error = error.map(ToString::to_string);
        jobs.finished.push_back(snapshot);
        while jobs.finished.len() > self.retain_finished {
            jobs.finished.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use tokio::sync::mpsc;

    fn owner(text: &str) -> Owner {
        text.parse().expect("valid extension id")
    }

    fn scheduler(max_concurrent: usize) -> JobScheduler {
        JobScheduler::new(NonZeroUsize::new(max_concurrent).expect("not zero"), 100)
    }

    /// A gate that holds jobs until the test opens it.
    fn gate() -> Arc<Semaphore> {
        Arc::new(Semaphore::new(0))
    }

    async fn pass(gate: &Semaphore) {
        drop(gate.acquire().await.expect("the gate is not closed"));
    }

    async fn wait_for<T>(handle: &JobHandle<T>, state: JobState) {
        let mut watch = handle.watch();
        watch
            .wait_for(|status| status.state == state)
            .await
            .expect("the job is known");
    }

    fn snapshot(scheduler: &JobScheduler, id: JobId) -> JobSnapshot {
        scheduler
            .jobs()
            .into_iter()
            .find(|job| job.id == id)
            .expect("the job is listed")
    }

    /// Opens the gate one time when it is dropped.
    struct DropPermit(Arc<Semaphore>);

    impl Drop for DropPermit {
        fn drop(&mut self) {
            self.0.add_permits(1);
        }
    }

    /// A job that waits for a cancel request and then stops.
    async fn until_cancelled(ctx: JobContext) -> Result<()> {
        ctx.cancelled().await;
        Err(Error::cancelled("stopped on request"))
    }

    #[tokio::test]
    async fn job_has_id_kind_owner_state_progress_and_result() {
        let scheduler = scheduler(2);
        let first = scheduler
            .spawn(owner("ext.a"), "query", |_| async { Ok(41 + 1) })
            .unwrap();
        let second = scheduler
            .spawn(owner("ext.b"), "export", |_| async { Ok("done") })
            .unwrap();
        assert_ne!(first.id(), second.id());

        let id = first.id();
        assert_eq!(first.join().await.unwrap(), 42);
        assert_eq!(second.join().await.unwrap(), "done");

        let job = snapshot(&scheduler, id);
        assert_eq!(job.kind, "query");
        assert_eq!(job.owner, owner("ext.a"));
        assert_eq!(job.state, JobState::Succeeded);
        assert_eq!(job.progress, Progress::default());
        assert_eq!(job.error, None);
    }

    #[tokio::test]
    async fn job_context_carries_the_job_id_and_the_token() {
        let scheduler = scheduler(1);
        let handle = scheduler
            .spawn(owner("ext.a"), "query", |ctx| async move {
                Ok((ctx.id(), ctx.cancellation().is_cancelled()))
            })
            .unwrap();
        let id = handle.id();
        assert_eq!(handle.join().await.unwrap(), (id, false));
    }

    #[tokio::test]
    async fn progress_is_observed_while_the_job_runs() {
        let scheduler = scheduler(1);
        let gate = gate();
        let job_gate = gate.clone();
        let handle = scheduler
            .spawn(owner("ext.a"), "export", |ctx| async move {
                ctx.report(Progress::new(3, Some(10)).with_message("rows"));
                pass(&job_gate).await;
                ctx.report(Progress::new(10, Some(10)));
                Ok(())
            })
            .unwrap();
        assert_eq!(handle.status().progress, Progress::default());

        let mut watch = handle.watch();
        let seen = watch
            .wait_for(|status| status.progress.completed == 3)
            .await
            .unwrap()
            .clone();
        assert_eq!(seen.state, JobState::Running);
        assert_eq!(seen.progress.total, Some(10));
        assert_eq!(seen.progress.message.as_deref(), Some("rows"));
        // The scheduler-level list shows the same progress.
        let listed = snapshot(&scheduler, handle.id());
        assert_eq!(listed.state, JobState::Running);
        assert_eq!(listed.progress.completed, 3);

        gate.add_permits(1);
        let id = handle.id();
        handle.join().await.unwrap();
        assert_eq!(watch.borrow().state, JobState::Succeeded);
        assert_eq!(snapshot(&scheduler, id).progress.completed, 10);
    }

    #[tokio::test]
    async fn report_after_the_job_finished_is_ignored() {
        let scheduler = scheduler(1);
        let handle = scheduler
            .spawn(owner("ext.a"), "export", |ctx| async move { Ok(ctx) })
            .unwrap();
        let watch = handle.watch();
        let leaked = handle.join().await.unwrap();
        leaked.report(Progress::new(9, None));
        assert_eq!(watch.borrow().state, JobState::Succeeded);
        assert_eq!(watch.borrow().progress, Progress::default());
    }

    #[tokio::test]
    async fn cancel_stops_a_running_job_and_the_state_is_cancelled() {
        let scheduler = scheduler(1);
        let handle = scheduler
            .spawn(owner("ext.a"), "query", until_cancelled)
            .unwrap();
        wait_for(&handle, JobState::Running).await;

        handle.cancel();
        let (id, watch) = (handle.id(), handle.watch());
        let error = handle.join().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Cancelled);
        assert_eq!(watch.borrow().state, JobState::Cancelled);
        let job = snapshot(&scheduler, id);
        assert_eq!(job.state, JobState::Cancelled);
        assert!(job.error.is_some());
    }

    #[tokio::test]
    async fn job_that_fails_because_of_a_cancel_request_is_cancelled() {
        // The job reports the cancel as another category, like a driver
        // that returns a database error for a killed query.
        let scheduler = scheduler(1);
        let handle = scheduler
            .spawn(owner("ext.a"), "query", |ctx| async move {
                ctx.cancelled().await;
                Err::<(), _>(Error::database("query was killed"))
            })
            .unwrap();
        wait_for(&handle, JobState::Running).await;
        handle.cancel();
        let watch = handle.watch();
        let error = handle.join().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Cancelled);
        assert_eq!(watch.borrow().state, JobState::Cancelled);
    }

    #[tokio::test]
    async fn cancel_of_a_queued_job_ends_cancelled_and_the_job_never_runs() {
        let scheduler = scheduler(1);
        let gate = gate();
        let job_gate = gate.clone();
        let first = scheduler
            .spawn(owner("ext.a"), "query", |_| async move {
                pass(&job_gate).await;
                Ok(1)
            })
            .unwrap();
        wait_for(&first, JobState::Running).await;

        let ran = Arc::new(AtomicBool::new(false));
        let job_ran = ran.clone();
        let second = scheduler
            .spawn(owner("ext.a"), "query", |_| async move {
                job_ran.store(true, Ordering::SeqCst);
                Ok(2)
            })
            .unwrap();
        assert_eq!(second.status().state, JobState::Queued);
        assert_eq!(snapshot(&scheduler, second.id()).state, JobState::Queued);

        second.cancel();
        let (id, watch) = (second.id(), second.watch());
        let error = second.join().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Cancelled);
        assert_eq!(watch.borrow().state, JobState::Cancelled);
        assert_eq!(snapshot(&scheduler, id).state, JobState::Cancelled);

        // The slot was never taken from the first job, which still succeeds.
        gate.add_permits(1);
        assert_eq!(first.join().await.unwrap(), 1);
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn job_that_returns_an_error_is_failed() {
        let scheduler = scheduler(1);
        let handle = scheduler
            .spawn(owner("ext.a"), "query", |_| async {
                Err::<(), _>(Error::database("relation does not exist"))
            })
            .unwrap();
        let (id, watch) = (handle.id(), handle.watch());
        let error = handle.join().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Database);
        assert_eq!(error.message(), "relation does not exist");
        assert_eq!(watch.borrow().state, JobState::Failed);
        let job = snapshot(&scheduler, id);
        assert_eq!(job.state, JobState::Failed);
        assert_eq!(
            job.error.as_deref(),
            Some("database: relation does not exist")
        );
    }

    #[tokio::test]
    async fn panicking_job_is_failed_and_the_scheduler_keeps_working() {
        // One slot: the next job can run only if the panic freed the slot.
        let scheduler = scheduler(1);
        let panicking = scheduler
            .spawn(owner("ext.a"), "query", |_| async {
                if true {
                    panic!("test panic in an async job");
                }
                Ok(())
            })
            .unwrap();
        let watch = panicking.watch();
        let error = panicking.join().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert_eq!(watch.borrow().state, JobState::Failed);

        let blocking = scheduler
            .spawn_blocking(owner("ext.a"), "export", |_| -> Result<()> {
                panic!("test panic in a blocking job")
            })
            .unwrap();
        let watch = blocking.watch();
        let error = blocking.join().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert_eq!(watch.borrow().state, JobState::Failed);

        let next = scheduler
            .spawn(owner("ext.a"), "query", |_| async { Ok("still works") })
            .unwrap();
        assert_eq!(next.join().await.unwrap(), "still works");
    }

    #[tokio::test]
    async fn cancel_owner_cancels_all_jobs_of_that_owner_only() {
        // One slot: `a_running` runs, `a_queued` and `b_queued` wait.
        let scheduler = scheduler(1);
        let a_running = scheduler
            .spawn(owner("ext.a"), "query", until_cancelled)
            .unwrap();
        wait_for(&a_running, JobState::Running).await;
        let a_queued = scheduler
            .spawn(owner("ext.a"), "export", until_cancelled)
            .unwrap();
        let b_queued = scheduler
            .spawn(owner("ext.b"), "query", |_| async { Ok("b") })
            .unwrap();

        assert_eq!(scheduler.cancel_owner(&owner("ext.a")), 2);

        for handle in [a_running, a_queued] {
            let watch = handle.watch();
            let error = handle.join().await.unwrap_err();
            assert_eq!(error.category(), ErrorCategory::Cancelled);
            assert_eq!(watch.borrow().state, JobState::Cancelled);
        }
        assert_eq!(b_queued.join().await.unwrap(), "b");
        // No job of the owner is left.
        assert_eq!(scheduler.cancel_owner(&owner("ext.a")), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn at_most_max_concurrent_jobs_run_at_the_same_time() {
        const LIMIT: usize = 2;
        const JOBS: usize = 6;
        let scheduler = scheduler(LIMIT);
        let gate = gate();
        let running = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        let (started, mut starts) = mpsc::unbounded_channel();

        let handles: Vec<_> = (0..JOBS)
            .map(|_| {
                let (gate, running, most, started) =
                    (gate.clone(), running.clone(), most.clone(), started.clone());
                scheduler
                    .spawn(owner("ext.a"), "query", |_| async move {
                        let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                        most.fetch_max(now, Ordering::SeqCst);
                        started.send(()).expect("the test listens");
                        pass(&gate).await;
                        running.fetch_sub(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .unwrap()
            })
            .collect();

        // All slots are taken; no further job can start before the gate opens.
        for _ in 0..LIMIT {
            starts.recv().await.expect("a job started");
        }
        let states = |state| {
            let jobs = scheduler.jobs();
            jobs.iter().filter(|job| job.state == state).count()
        };
        assert_eq!(states(JobState::Running), LIMIT);
        assert_eq!(states(JobState::Queued), JOBS - LIMIT);

        gate.add_permits(JOBS);
        for handle in handles {
            handle.join().await.unwrap();
        }
        assert_eq!(most.load(Ordering::SeqCst), LIMIT);
        assert_eq!(states(JobState::Succeeded), JOBS);
    }

    // The default test runtime has one worker thread: a job that blocked
    // this thread would stop the whole test.
    #[tokio::test]
    async fn blocking_job_runs_on_the_blocking_pool_and_does_not_stall_the_worker() {
        let scheduler = scheduler(2);
        let worker = std::thread::current().id();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let blocking = scheduler
            .spawn_blocking(owner("ext.a"), "compress", move |ctx| {
                ctx.report(Progress::new(1, Some(2)));
                released
                    .recv()
                    .map_err(|_| Error::internal("the test dropped the sender"))?;
                Ok(std::thread::current().id())
            })
            .unwrap();
        let mut watch = blocking.watch();
        watch
            .wait_for(|status| status.progress.completed == 1)
            .await
            .unwrap();

        // An async job runs to its end while the blocking job blocks.
        let quick = scheduler
            .spawn(owner("ext.a"), "query", |_| async { Ok(7) })
            .unwrap();
        assert_eq!(quick.join().await.unwrap(), 7);
        assert_eq!(blocking.status().state, JobState::Running);

        release.send(()).unwrap();
        assert_ne!(blocking.join().await.unwrap(), worker);
        assert_eq!(watch.borrow().state, JobState::Succeeded);
    }

    #[tokio::test]
    async fn blocking_job_cooperates_with_cancel() {
        let scheduler = scheduler(1);
        let handle = scheduler
            .spawn_blocking(owner("ext.a"), "compress", |ctx| {
                while !ctx.is_cancelled() {
                    std::thread::yield_now();
                }
                Err::<(), _>(Error::cancelled("compression stopped"))
            })
            .unwrap();
        wait_for(&handle, JobState::Running).await;
        handle.cancel();
        let watch = handle.watch();
        let error = handle.join().await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Cancelled);
        assert_eq!(watch.borrow().state, JobState::Cancelled);
    }

    #[tokio::test]
    async fn only_the_newest_finished_jobs_are_retained() {
        let scheduler = JobScheduler::new(NonZeroUsize::MIN, 2);
        let mut ids = Vec::new();
        for _ in 0..5 {
            let handle = scheduler
                .spawn(owner("ext.a"), "query", |_| async { Ok(()) })
                .unwrap();
            ids.push(handle.id());
            handle.join().await.unwrap();
        }
        let listed: Vec<JobId> = scheduler.jobs().iter().map(|job| job.id).collect();
        assert_eq!(listed, ids[3..]);
    }

    #[tokio::test]
    async fn retention_of_zero_lists_no_finished_job() {
        let scheduler = JobScheduler::new(NonZeroUsize::MIN, 0);
        let handle = scheduler
            .spawn(owner("ext.a"), "query", |_| async { Ok(()) })
            .unwrap();
        handle.join().await.unwrap();
        assert_eq!(scheduler.jobs(), Vec::new());
    }

    #[tokio::test]
    async fn dropped_handle_does_not_cancel_the_job() {
        let scheduler = scheduler(1);
        let (done, mut dones) = mpsc::unbounded_channel();
        drop(
            scheduler
                .spawn(owner("ext.a"), "query", |ctx| async move {
                    done.send(ctx.is_cancelled()).expect("the test listens");
                    Ok(())
                })
                .unwrap(),
        );
        assert_eq!(dones.recv().await, Some(false));
    }

    #[tokio::test]
    async fn job_above_the_limit_per_owner_is_refused_with_a_clear_error() {
        // The global limit is 1, so the second job of `ext.a` is queued.
        let scheduler = JobScheduler::with_config(JobConfig {
            max_concurrent: NonZeroUsize::MIN,
            max_per_extension: NonZeroUsize::new(2),
            ..JobConfig::default()
        });
        let running = scheduler
            .spawn(owner("ext.a"), "query", until_cancelled)
            .unwrap();
        wait_for(&running, JobState::Running).await;
        let queued = scheduler
            .spawn(owner("ext.a"), "export", until_cancelled)
            .unwrap();

        // Queued and running jobs count. Both ways to start a job refuse.
        let error = scheduler
            .spawn(owner("ext.a"), "diff", |_| async { Ok(()) })
            .unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Policy);
        assert!(error.message().contains("`ext.a`"), "{error}");
        assert!(error.message().contains("`diff`"), "{error}");
        assert!(error.message().contains("limit per extension"), "{error}");
        let error = scheduler
            .spawn_blocking(owner("ext.a"), "diff", |_| Ok(()))
            .unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Policy);
        // A refused job is not listed.
        assert_eq!(scheduler.jobs().len(), 2);

        // The limit is per owner, and the global limit still queues.
        let other = scheduler
            .spawn(owner("ext.b"), "query", |_| async { Ok("b") })
            .unwrap();
        assert_eq!(other.status().state, JobState::Queued);

        // A finished job frees its place.
        queued.cancel();
        queued.join().await.unwrap_err();
        let next = scheduler
            .spawn(owner("ext.a"), "export", |_| async { Ok("a") })
            .unwrap();
        running.cancel();
        running.join().await.unwrap_err();
        assert_eq!(other.join().await.unwrap(), "b");
        assert_eq!(next.join().await.unwrap(), "a");
    }

    #[tokio::test]
    async fn the_limits_come_from_the_settings_and_have_documented_defaults() {
        use crate::settings::Layer;
        let default = JobConfig::default();
        assert_eq!(default.max_concurrent.get(), 4);
        assert_eq!(default.max_per_extension, NonZeroUsize::new(8));
        assert_eq!(default.retain_finished, 100);
        assert_eq!(default.cancel_grace, Duration::from_secs(5));

        let read = |jobs: &str| {
            let mut settings = Settings::new();
            let text = format!("schema_version = 1\n[jobs]\n{jobs}");
            settings.set_layer(Layer::User, "test", &text).unwrap();
            JobConfig::from_settings(&settings)
        };
        assert_eq!(read("").unwrap(), default);
        for invalid in [
            "max_concurrent = 0\n",
            "max_per_extension = 0\n",
            "retain_finished = -1\n",
            "cancel_grace_ms = \"soon\"\n",
        ] {
            let error = read(invalid).expect_err(invalid);
            assert_eq!(error.category(), ErrorCategory::User, "{invalid}");
        }
        let config = read(
            "max_concurrent = 1\nmax_per_extension = 2\nretain_finished = 1\n\
             cancel_grace_ms = 250\n",
        )
        .unwrap();
        assert_eq!(config.max_concurrent, NonZeroUsize::MIN);
        assert_eq!(config.max_per_extension, NonZeroUsize::new(2));
        assert_eq!(config.retain_finished, 1);
        assert_eq!(config.cancel_grace, Duration::from_millis(250));

        // The settings limit the jobs of the scheduler.
        let scheduler = JobScheduler::with_config(config);
        let running = scheduler
            .spawn(owner("ext.a"), "query", until_cancelled)
            .unwrap();
        wait_for(&running, JobState::Running).await;
        let queued = scheduler
            .spawn(owner("ext.a"), "query", |_| async { Ok(()) })
            .unwrap();
        assert_eq!(queued.status().state, JobState::Queued);
        let refused = scheduler.spawn(owner("ext.a"), "query", |_| async { Ok(()) });
        assert_eq!(refused.unwrap_err().category(), ErrorCategory::Policy);
        running.cancel();
        running.join().await.unwrap_err();
        queued.join().await.unwrap();
        assert_eq!(scheduler.jobs().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn async_job_that_ignores_the_cancel_request_is_aborted_after_the_grace_period() {
        let grace = JobConfig::default().cancel_grace;
        let scheduler = scheduler(1);
        let dropped = gate();
        let job_dropped = dropped.clone();
        let stubborn = scheduler
            .spawn(owner("ext.a"), "query", |_| async move {
                // Tells the test when the work is dropped.
                let _guard = DropPermit(job_dropped);
                std::future::pending::<Result<()>>().await
            })
            .unwrap();
        wait_for(&stubborn, JobState::Running).await;
        let next = scheduler
            .spawn(owner("ext.b"), "query", |_| async { Ok("next") })
            .unwrap();
        let cooperative = scheduler
            .spawn(owner("ext.a"), "export", until_cancelled)
            .unwrap();
        let start = tokio::time::Instant::now();

        // The owner scope ends.
        assert_eq!(scheduler.cancel_owner(&owner("ext.a")), 2);

        // The queued job of the owner ends at once.
        let error = cooperative.join().await.unwrap_err();
        assert!(error.message().contains("before it started"), "{error}");
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert_eq!(stubborn.status().state, JobState::Running);
        assert_eq!(next.status().state, JobState::Queued);

        let (id, watch) = (stubborn.id(), stubborn.watch());
        let error = stubborn.join().await.unwrap_err();
        assert_eq!(start.elapsed(), grace);
        assert_eq!(error.category(), ErrorCategory::Cancelled);
        assert!(error.message().contains("was aborted"), "{error}");
        assert_eq!(watch.borrow().state, JobState::Cancelled);
        assert_eq!(snapshot(&scheduler, id).state, JobState::Cancelled);
        // The slot is free, and the work is gone.
        assert_eq!(next.join().await.unwrap(), "next");
        pass(&dropped).await;
    }

    #[tokio::test(start_paused = true)]
    async fn stop_owner_waits_until_the_jobs_of_the_owner_have_ended() {
        let grace = JobConfig::default().cancel_grace;
        let scheduler = scheduler(2);
        let cooperative = scheduler
            .spawn(owner("ext.a"), "query", until_cancelled)
            .unwrap();
        let stubborn = scheduler
            .spawn(owner("ext.a"), "export", |_| {
                std::future::pending::<Result<()>>()
            })
            .unwrap();
        let other = scheduler
            .spawn(owner("ext.b"), "query", until_cancelled)
            .unwrap();
        wait_for(&stubborn, JobState::Running).await;
        let start = tokio::time::Instant::now();

        assert_eq!(scheduler.stop_owner(&owner("ext.a")).await, 2);

        // The wait ends with the abort of the job that ignores the request.
        assert_eq!(start.elapsed(), grace);
        assert_eq!(cooperative.status().state, JobState::Cancelled);
        assert_eq!(stubborn.status().state, JobState::Cancelled);
        assert_eq!(other.status().state, JobState::Running);
        assert_eq!(scheduler.stop_owner(&owner("ext.a")).await, 0);
        assert_eq!(start.elapsed(), grace);
    }

    #[tokio::test]
    async fn job_cannot_start_a_job_of_its_owner_while_the_owner_is_closed() {
        let scheduler = scheduler(4);
        let again = scheduler.clone();
        // The parent answers the cancel request with a child job.
        let parent = scheduler
            .spawn(owner("ext.a"), "parent", |ctx| async move {
                ctx.cancelled().await;
                let child = again.spawn(owner("ext.a"), "child", until_cancelled);
                Err::<(), _>(child.map_or_else(|refused| refused, |_| Error::internal("started")))
            })
            .unwrap();
        wait_for(&parent, JobState::Running).await;

        scheduler.close_owner(&owner("ext.a"));
        assert_eq!(scheduler.stop_owner(&owner("ext.a")).await, 1);

        // The error of the parent is the refusal of the child.
        let refused = parent.join().await.unwrap_err();
        assert!(refused.message().contains("`ext.a` stops"), "{refused}");
        let left = |job: &JobSnapshot| !job.state.is_finished();
        assert_eq!(scheduler.jobs().into_iter().filter(left).count(), 0);
        // Only this owner is refused, and only until it is open again.
        let other = scheduler.spawn(owner("ext.b"), "query", |_| async { Ok(()) });
        other.unwrap().join().await.unwrap();
        scheduler.open_owner(&owner("ext.a"));
        let next = scheduler.spawn(owner("ext.a"), "query", |_| async { Ok(()) });
        next.unwrap().join().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn aborted_job_whose_code_still_runs_is_cancelled_but_keeps_its_slot() {
        let config = JobConfig {
            max_concurrent: NonZeroUsize::MIN,
            max_per_extension: NonZeroUsize::new(1),
            ..JobConfig::default()
        };
        let grace = config.cancel_grace;
        let scheduler = JobScheduler::with_config(config);
        // Blocking work cannot be aborted. It ignores the cancel request.
        let (release, released) = std::sync::mpsc::channel::<()>();
        let stubborn = scheduler
            .spawn_blocking(owner("ext.a"), "compress", move |ctx| {
                ctx.report(Progress::new(1, None));
                released.recv().ok();
                Ok(())
            })
            .unwrap();
        // The work has started: an abort cannot prevent it any more.
        let mut started = stubborn.watch();
        started
            .wait_for(|status| status.progress.completed == 1)
            .await
            .unwrap();
        let next = scheduler
            .spawn(owner("ext.b"), "query", |_| async { Ok("next") })
            .unwrap();

        stubborn.cancel();
        // The clock does not advance by itself while blocking work runs.
        while !stubborn.status().state.is_finished() {
            tokio::time::advance(grace).await;
        }
        let watch = stubborn.watch();
        let error = stubborn.join().await.unwrap_err();

        assert_eq!(error.category(), ErrorCategory::Cancelled);
        assert!(error.message().contains("was aborted"), "{error}");
        assert_eq!(watch.borrow().state, JobState::Cancelled);
        // The code still runs: the slot and the place of the owner are taken.
        assert_eq!(next.status().state, JobState::Queued);
        let refused = scheduler.spawn(owner("ext.a"), "query", |_| async { Ok(()) });
        assert_eq!(refused.unwrap_err().category(), ErrorCategory::Policy);

        // The code returns.
        release.send(()).unwrap();
        assert_eq!(next.join().await.unwrap(), "next");
        let again = scheduler.spawn(owner("ext.a"), "query", |_| async { Ok("again") });
        assert_eq!(again.unwrap().join().await.unwrap(), "again");
    }

    #[tokio::test(start_paused = true)]
    async fn job_that_ends_at_the_end_of_the_grace_period_keeps_its_result() {
        let grace = JobConfig::default().cancel_grace;
        let scheduler = scheduler(1);
        for round in 0..200 {
            // The work and the grace period end at the same moment.
            let handle = scheduler
                .spawn(owner("ext.a"), "query", move |ctx| async move {
                    ctx.cancelled().await;
                    tokio::time::sleep(grace).await;
                    Ok(round)
                })
                .unwrap();
            wait_for(&handle, JobState::Running).await;
            handle.cancel();

            let watch = handle.watch();
            assert_eq!(handle.join().await.unwrap(), round);
            assert_eq!(watch.borrow().state, JobState::Succeeded);
        }
    }

    #[test]
    fn zero_and_too_long_grace_in_the_settings_are_refused_with_the_key() {
        use crate::settings::Layer;
        let read = |jobs: &str| {
            let mut settings = Settings::new();
            let text = format!("schema_version = 1\n[jobs]\n{jobs}");
            settings.set_layer(Layer::User, "test", &text).unwrap();
            JobConfig::from_settings(&settings)
        };
        for (invalid, message) in [
            (
                "max_concurrent = 0",
                "invalid settings: `jobs.max_concurrent` must not be 0",
            ),
            (
                "max_per_extension = 0",
                "invalid settings: `jobs.max_per_extension` must not be 0",
            ),
            (
                "cancel_grace_ms = 0",
                "invalid settings: `jobs.cancel_grace_ms` must not be 0",
            ),
            (
                "cancel_grace_ms = 60001",
                "invalid settings: `jobs.cancel_grace_ms` must not be more than 60000",
            ),
        ] {
            let error = read(invalid).expect_err(invalid);
            assert_eq!(error.category(), ErrorCategory::User, "{invalid}");
            assert_eq!(error.message(), message);
        }
        let longest = read("cancel_grace_ms = 60000").unwrap();
        assert_eq!(longest.cancel_grace, Duration::from_secs(60));
    }

    #[test]
    fn spawn_outside_a_runtime_is_an_error_and_not_a_panic() {
        let scheduler = scheduler(1);
        let error = scheduler
            .spawn(owner("ext.a"), "query", |_| async { Ok(()) })
            .unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Internal);
        let error = scheduler
            .spawn_blocking(owner("ext.a"), "query", |_| Ok(()))
            .unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert_eq!(scheduler.jobs(), Vec::new());
    }

    #[test]
    fn job_state_knows_when_it_is_finished() {
        assert!(!JobState::Queued.is_finished());
        assert!(!JobState::Running.is_finished());
        assert!(JobState::Succeeded.is_finished());
        assert!(JobState::Failed.is_finished());
        assert!(JobState::Cancelled.is_finished());
    }
}
