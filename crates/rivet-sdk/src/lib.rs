//! Public extension contract for rivet (ARCHITECTURE.md §4.1).
//!
//! # Convention for data types
//!
//! A public data struct is `#[non_exhaustive]` with public fields, so it can
//! get a field without a breaking change. It has `Type::new(required fields)`
//! and one `#[must_use] with_<field>(self, ..) -> Self` method for each
//! optional field. A struct with only optional fields has `Default` also.
//! There are no builder types. A public enum that can grow is
//! `#[non_exhaustive]`. An enum that decides a permission stays exhaustive,
//! so that a new variant does not compile in the core until the core handles
//! it.

#![warn(missing_docs)]

pub mod error;
pub mod extension;
pub mod job;
pub mod manifest;
pub mod model;
pub mod secret;
