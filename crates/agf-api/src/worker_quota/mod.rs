//! Bind a real inventoried Worker to an enforced platform quota, then explicitly reconcile cloud limits.
mod alerts;
mod binding;
mod cloud;
mod context;
mod contract;
pub(crate) mod mock;
mod operations;
mod reconcile;
pub mod routes;
mod store;
pub(crate) mod write_guard;

use agf_core::error::DomainError;
pub(crate) const KIND: &str = "agentteams-worker-quota";
const RUNS: &str = "agentteams-worker-quota-run";

fn stale() -> DomainError {
    DomainError::Conflict("Worker、配额或云配置已改变，请刷新并重新观察云端限制".into())
}
