//! Bounded, read-only SchedulerX3 application and job observations.
//!
//! No job registration, HTTP carrier translation, callback or provider write is performed.
//! A resolved runtime client and current-authority guard remain the caller's responsibility.

mod client;
mod fields;
mod mock;
mod parse;
mod types;

pub use client::{CurrentGuard, observe_current};
pub use mock::MockState;
pub use parse::parse_current;
pub use types::{
    AppObservation, CarrierPresence, HttpConfiguration, JobObservation, Observation, PageEvidence, Pagination,
    Schedule, Scope,
};

pub(super) const PAGE_SIZE: u32 = 100;
pub(super) const MAX_PAGES: u32 = 20;
pub(super) const MAX_JOBS: u32 = 2_000;
pub(super) const MAX_RESPONSE_BYTES: usize = 2_097_152;
pub(super) const MAX_EVIDENCE_BYTES: usize = 4_194_304;
pub(super) const MAX_OBSERVATION_BYTES: usize = 2_097_152;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_boundaries;
