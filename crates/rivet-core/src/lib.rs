//! Rivet core: extension host, registry, buses and core services.
#![warn(missing_docs)]

pub mod bus;
pub mod logging;
pub mod registry;
pub mod resolve;
pub mod secrets;

/// The extension that owns a registration.
pub type Owner = rivet_sdk::manifest::ExtensionId;
