//! The job model: the data that describes long-running work (§5.4, §6.1).
//!
//! These types are plain data. The scheduler that runs the jobs is in the
//! core. The core re-exports the types at `rivet_core::jobs`.
//!
//! ```
//! use rivet_sdk::job::{JobId, JobSnapshot, JobState, Progress};
//!
//! let progress = Progress::new(2, Some(3)).with_message("step 2");
//! let job = JobSnapshot::new(
//!     JobId::new(7),
//!     "export",
//!     "acme.export".parse()?,
//!     JobState::Running,
//!     progress,
//! );
//! assert_eq!(job.id.to_string(), "7");
//! assert_eq!(format!("{:?} {:?}", job.id, job.state), "JobId(7) Running");
//! assert!(!job.state.is_finished());
//! assert_eq!(job.error, None);
//! # Ok::<(), rivet_sdk::error::Error>(())
//! ```

use crate::manifest::ExtensionId;
use std::fmt;

/// The id of a job. It is unique in one scheduler.
///
/// An id is a name, not a permission: to hold one gives no right over the
/// job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobId(u64);

impl JobId {
    /// Creates an id from its number. The scheduler gives each job its id.
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the number of the id.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The state of a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum JobState {
    /// The job waits for a free slot.
    Queued,
    /// The job runs.
    Running,
    /// The job returned a value.
    Succeeded,
    /// The job returned an error or panicked.
    Failed,
    /// The job was cancelled before it started, or it stopped after a
    /// cancel request.
    Cancelled,
}

impl JobState {
    /// Returns `true` for `Succeeded`, `Failed` and `Cancelled`. A finished
    /// job does not change its state again.
    pub fn is_finished(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

/// How far a job is. The unit is chosen by the job, for example rows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Progress {
    /// The number of units that are done.
    pub completed: u64,
    /// The number of units in total, if the job knows it.
    pub total: Option<u64>,
    /// A short text for the user, for example the current step.
    pub message: Option<String>,
}

impl Progress {
    /// Creates a progress without a message.
    pub fn new(completed: u64, total: Option<u64>) -> Self {
        Self {
            completed,
            total,
            message: None,
        }
    }

    /// Sets the message.
    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }
}

/// The state and the progress of a job at one moment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct JobStatus {
    /// The state of the job.
    pub state: JobState,
    /// The last progress that the job reported.
    pub progress: Progress,
}

impl JobStatus {
    /// Creates a status.
    pub fn new(state: JobState, progress: Progress) -> Self {
        Self { state, progress }
    }
}

/// A copy of the data of one job, as the scheduler lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct JobSnapshot {
    /// The id of the job.
    pub id: JobId,
    /// What the job does, for example `query` or `export`.
    pub kind: String,
    /// The extension that started the job.
    pub owner: ExtensionId,
    /// The state of the job.
    pub state: JobState,
    /// The last progress that the job reported.
    pub progress: Progress,
    /// The error text of a `Failed` or `Cancelled` job. The value of a
    /// successful job goes only to the handle of the job.
    pub error: Option<String>,
}

impl JobSnapshot {
    /// Creates a snapshot with no error text.
    pub fn new(
        id: JobId,
        kind: impl Into<String>,
        owner: ExtensionId,
        state: JobState,
        progress: Progress,
    ) -> Self {
        Self {
            id,
            kind: kind.into(),
            owner,
            state,
            progress,
            error: None,
        }
    }

    /// Sets the error text.
    #[must_use]
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }
}
