//! Explicit native Team changes with durable previews, receipts and conservative recovery.
mod cloud;
mod context;
mod contract;
mod input;
pub(crate) mod mock;
mod mock_actions;
mod mock_store;
mod observe;
mod operations;
mod preview;
mod projection;
pub(crate) mod publication;
mod routes;
mod store;
mod users;
mod validation;
mod write_guard;

pub(crate) use routes::router;
pub(crate) const KIND: &str = "agentteams-team-state";
pub(crate) const PREVIEWS: &str = "agentteams-team-preview";
pub(crate) const RUNS: &str = "agentteams-team-operation";
const DIRECTORIES: &str = "agentteams-user-directory";

fn stale() -> agf_core::error::DomainError {
    agf_core::error::DomainError::Conflict("团队、预览或云配置已改变；请重新读取并人工核对草稿".into())
}
