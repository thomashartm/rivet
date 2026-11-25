//! Rivet core: extension host, registry, buses and core services.
#![warn(missing_docs)]

pub mod bus;
pub mod host;
pub mod jobs;
pub mod logging;
pub mod package;
pub mod permissions;
pub mod registry;
pub mod resolve;
pub mod secrets;
pub mod settings;
pub mod wasm;

/// The extension that owns a registration.
pub type Owner = rivet_sdk::manifest::ExtensionId;
