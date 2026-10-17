//! Explicitly run against one owned SQL database and existing local SDK runtimes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod zero_code_onboarding_database_support;

use agf_core::error::DomainResult;
use zero_code_onboarding_database_support::{mcp, startup};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL, AGF_ZERO_CODE_DATABASE_OWNER and SDK/runtime/task ENV"]
async fn python_startup_commits_real_task_call_sql_and_drains_lost_ack_without_business_retry() -> DomainResult<()> {
    Box::pin(startup::roundtrip(startup::Language::Python)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL, AGF_ZERO_CODE_DATABASE_OWNER and SDK/runtime/task ENV"]
async fn node_startup_commits_real_task_call_sql_and_drains_lost_ack_without_business_retry() -> DomainResult<()> {
    Box::pin(startup::roundtrip(startup::Language::Node)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires both existing Python/Node runtimes, owned SQL and exact project SDKROOT"]
async fn current_binding_disable_and_collector_key_revoke_do_not_replace_business_results() -> DomainResult<()> {
    Box::pin(startup::revocation()).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_ZERO_CODE task ownership"]
async fn http_mcp_empty_probe_proxy_signed_policy_and_key_revoke_survive_api_restart() -> DomainResult<()> {
    Box::pin(mcp::acceptance()).await
}
