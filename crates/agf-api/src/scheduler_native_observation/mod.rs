//! Complete cloud observations and local associations are separate from callback execution authorization.
mod archive;
mod authority;
mod binding;
mod callback_execution;
mod claim;
mod eligibility;
mod input;
mod job_management;
mod observation;
mod proof;
mod provider;
mod records;
mod registry;
mod routes;
mod safe;
mod scope;
mod sql;
mod store;
mod util;
mod views;

pub use registry::Registry;
pub(crate) use routes::router;

pub(crate) fn source_fingerprint(value: &serde_json::Value) -> agf_core::error::DomainResult<String> {
    util::canonical_hash(value)
}
const NAME: &str = "alicloud-schedulerx3";
const MAX_RUNS: usize = 128;
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_STORED_BYTES: usize = 64 * 1024 * 1024;
const MAX_ARCHIVE: usize = 100;
const KINDS: [&str; 6] = ["asset-inventory", "log-pull", "redteam-cruise", "rule-hot-reload", "report", "archive"];

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_proof;
#[cfg(test)]
mod tests_proof_support;
