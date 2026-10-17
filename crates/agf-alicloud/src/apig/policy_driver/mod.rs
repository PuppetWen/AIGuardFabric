//! Selected existing APIG ModelAPI policy updates with independently validated evidence.
//!
//! This driver does not implement provider CAS or prove data-plane application.
//! The owning workflow must claim a permanent UUID before calling `publish_once`.

mod client;
mod contract;
mod evidence;
mod json;
mod mock;
mod mock_bridge;
mod mock_entry;
mod mock_scope;
mod observe;
mod profile;
mod types;

pub use client::{CurrentGuard, observe_current, publish_once};
pub use evidence::restore_evidence;
pub use mock::MockState;
pub use mock_bridge::{MockBridge, MockCodec, MockSourceGuard};
pub use mock_scope::MockScope;
pub use observe::parse_current;
pub use profile::{current_limit, prepare_limit};
pub use types::{Binding, ManagedLimit, Observation, PreparedUpdate, ReadbackState, WriteOutcome};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_bridge;
#[cfg(test)]
mod tests_evidence;
#[cfg(test)]
mod tests_mock_entry;
