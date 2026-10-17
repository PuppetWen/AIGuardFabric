//! Explicit isolated browser host lifecycle; never a browser, callback or cloud-execution acceptance result.
#![cfg(test)]
mod common;
#[allow(dead_code, reason = "Only the accepted signed provider is reused; its SQL assertion helpers are not invoked")]
#[path = "scheduler_native_observation_database_support/mod.rs"]
mod scheduler_native_observation_database_support;
mod scheduler_native_ui_host_support;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires exact owned UI PostgreSQL, marked candidate dist/data and bounded stdin-only random credentials"]
async fn owned_scheduler_native_101_jobs_browser_host() -> agf_core::error::DomainResult<()> {
    // Support maps every fallible boundary to a fixed stage; no raw error or credential escapes.
    scheduler_native_ui_host_support::run().await
}
