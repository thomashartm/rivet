//! Rivet core: extension host, registry, buses and core services.

// Keeps the declared `rivet-sdk` dependency in use until core has real code; remove then.
use rivet_sdk as _;

pub mod bus;
pub mod registry;
