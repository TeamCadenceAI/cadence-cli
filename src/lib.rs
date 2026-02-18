//! Library entrypoint for cadence-cli.
//!
//! The primary interface is the `cadence` binary. This lib target exists to
//! expose internal modules to integration tests and future spec consumers.

pub mod config;
pub mod update;
