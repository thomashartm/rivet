//! Rivet core: extension host, registry, buses and core services.
#![warn(missing_docs)]

pub mod bus;
pub mod registry;

/// The extension that owns a registration.
// shortcut: plain string until rivet_sdk::manifest::ExtensionId lands (#2); swap the alias then
pub type Owner = String;
