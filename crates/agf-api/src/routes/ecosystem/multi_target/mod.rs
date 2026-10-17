//! One fixed cross-target canary playbook. No arbitrary prompt, shell or replay.
mod authority;
mod execution;
mod history;
mod history_model;
mod managed;
mod managed_model;
mod mcp;
mod mcp_frames;
mod mcp_headers;
mod records;
mod routes;
mod source;
mod store;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_mcp;
mod transport;
mod types;
pub(super) fn router() -> axum::Router<crate::AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/redteam/multi-target/playbook", get(routes::playbook))
        .route("/redteam/multi-target/profiles/{kind}/{id}/transport", get(managed::get).put(managed::save))
        .route("/redteam/multi-target/preview", post(routes::preview))
        .route("/redteam/multi-target/runs", post(routes::execute).get(history::list))
        .route("/redteam/multi-target/runs/{id}", get(routes::get))
        .route("/redteam/multi-target/runs/{id}/archive", post(history::archive))
        .route("/redteam/multi-target/runs/{id}/cancel", post(routes::cancel))
        .route("/redteam/multi-target/runs/{id}/recover", post(routes::recover))
}
#[cfg(feature = "test-loopback-transport")]
pub(crate) use transport::TestCapability;

const KIND: &str = "redteam-multi-target-fact";
const CAPACITY_KIND: &str = "redteam-multi-target-capacity";
const VERSION: &str = "cross-service-readonly-v1";
const BUDGET: usize = 48 * 1024;
