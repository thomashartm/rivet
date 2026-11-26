//! Test support for rivet extensions (ARCHITECTURE.md §3.1): a mock engine
//! and database fixtures.
//!
//! | Part | Use |
//! | --- | --- |
//! | [`TestEngine`] | The real core services and the real extension host in a temporary directory. |
//! | [`Behaviour`], [`manifest`] | An extension written as Rust test code. |
//! | [`conformance`] | The conformance suite of the `Driver` contract. |
//! | [`database`] | PostgreSQL and MySQL containers: profile, test credentials, reachability check. |
//!
//! This crate is for tests only. Use it as a dev-dependency (ADR-0016). An
//! extension crate cannot depend on `rivet-core`, so this crate re-exports
//! the core types that a test names.
//!
//! # A complete test
//!
//! The test adds an extension, drives its lifecycle through the real host
//! and asserts the recorded calls and state changes.
//!
//! ```test_harness
#![doc = include_str!("../tests/example.rs")]
//! ```
#![warn(missing_docs)]

pub mod conformance;
pub mod database;
mod engine;

pub use engine::{Behaviour, TestEngine, manifest};
pub use rivet_core::bus::{Received, Subscription};
pub use rivet_core::host::{
    ActivationReport, ExtensionContext, ExtensionHost, ExtensionState, ExtensionStateChanged,
    ExtensionStatus, MANIFEST_FILE, Services,
};
pub use rivet_core::jobs::{JobContext, JobHandle, JobSnapshot, JobState, Progress};
pub use rivet_core::resolve::ActivationTrigger;
