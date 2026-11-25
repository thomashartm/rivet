//! Rivet core: extension host, registry, buses and core services.
#![warn(missing_docs)]

pub mod bus;
pub mod registry;
pub mod resolve;

/// The extension that owns a registration.
pub type Owner = rivet_sdk::manifest::ExtensionId;
