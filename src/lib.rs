//! Library entrypoint for cadence-cli.
//!
//! The primary interface is the `cadence` binary. This lib target exists to
//! expose internal modules to integration tests and future spec consumers.

pub mod config;
pub mod monitor;
pub mod publication;
pub mod publication_state;
pub mod state_files;
pub mod transport;
pub mod update;

#[cfg(test)]
pub(crate) mod test_support;
