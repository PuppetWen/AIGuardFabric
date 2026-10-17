//! Requires a fresh task-owned PostgreSQL database; provider traffic is synthetic literal-loopback only.
mod common;
mod scheduler_native_observation_database_support;
use agf_core::error::DomainResult;
use scheduler_native_observation_database_support::{authority, capacity, lifecycle, publication};

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_SCHEDULER_NATIVE_DATABASE_OWNER"]
async fn two_appstates_share_one_permanent_uuid_and_all_real_cloud_pages() -> DomainResult<()> {
    publication::durable_uuid().await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_SCHEDULER_NATIVE_DATABASE_OWNER"]
async fn rejected_claim_audit_rolls_back_before_any_provider_request() -> DomainResult<()> {
    publication::claim_rollback().await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_SCHEDULER_NATIVE_DATABASE_OWNER"]
async fn rejected_terminal_read_audit_preserves_latest_binding_and_body() -> DomainResult<()> {
    publication::terminal_rollback().await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_SCHEDULER_NATIVE_DATABASE_OWNER"]
async fn local_binding_and_archive_audit_rejections_preserve_every_record() -> DomainResult<()> {
    publication::association_and_archive_rollback().await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_SCHEDULER_NATIVE_DATABASE_OWNER"]
async fn current_key_revocation_during_claim_and_terminal_audit_wait_rolls_back() -> DomainResult<()> {
    authority::current_key(false).await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_SCHEDULER_NATIVE_DATABASE_OWNER"]
async fn removing_only_the_read_scope_during_audit_wait_rolls_back() -> DomainResult<()> {
    authority::current_key(true).await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_SCHEDULER_NATIVE_DATABASE_OWNER"]
async fn real_original_jwt_expiry_during_terminal_audit_wait_rolls_back() -> DomainResult<()> {
    authority::original_jwt().await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_SCHEDULER_NATIVE_DATABASE_OWNER; real 110-second budget"]
async fn the_original_110_second_budget_includes_sql_audit_wait() -> DomainResult<()> {
    authority::original_budget().await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_SCHEDULER_NATIVE_DATABASE_OWNER"]
async fn committed_source_changes_and_tenant_disable_stop_read_continuation() -> DomainResult<()> {
    authority::source_and_tenant().await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_SCHEDULER_NATIVE_DATABASE_OWNER"]
async fn publication_source_lock_precedes_audit_and_queued_save_does_not_deadlock() -> DomainResult<()> {
    lifecycle::source_lock_order().await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_SCHEDULER_NATIVE_DATABASE_OWNER"]
async fn cancelled_or_expired_read_is_local_only_and_late_completion_cannot_overwrite_archive() -> DomainResult<()> {
    lifecycle::cancelled_read().await?;
    lifecycle::expired_read_archive().await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_SCHEDULER_NATIVE_DATABASE_OWNER"]
async fn real_128_observation_capacity_and_100_body_archive_keep_every_permanent_fact() -> DomainResult<()> {
    capacity::bounded_archive().await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_SCHEDULER_NATIVE_DATABASE_OWNER"]
async fn real_2000_job_large_main_record_survives_restart_and_rejects_foreign_aad() -> DomainResult<()> {
    capacity::large_and_authenticated().await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_SCHEDULER_NATIVE_DATABASE_OWNER"]
async fn disabled_source_allows_local_disable_and_archive_but_never_foreign_tenant_receipts() -> DomainResult<()> {
    lifecycle::disabled_and_isolated().await
}
