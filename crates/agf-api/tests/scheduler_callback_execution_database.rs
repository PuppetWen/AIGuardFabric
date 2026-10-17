//! Owned SQL/API admission verification, never a claim that cloud consumers executed business handlers.
mod common;
mod scheduler_callback_execution_database_support;
// Reuse the accepted ownership/provider tree; its separate native test cases are not invoked here.
#[allow(dead_code)]
#[path = "scheduler_native_observation_database_support/mod.rs"]
mod scheduler_native_observation_database_support;

use agf_core::error::DomainResult;
use scheduler_callback_execution_database_support::{authority, crypto, identity, progress, publication};

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_SCHEDULER_NATIVE_DATABASE_OWNER"]
async fn twin_instances_admit_and_start_one_global_partition_once() -> DomainResult<()> {
    identity::concurrent().await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL database"]
async fn lost_admission_response_and_alias_uuid_lookup_are_pure_original_key_reads() -> DomainResult<()> {
    identity::lookup().await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL database"]
async fn permanent_uuid_and_global_identity_reject_body_kind_source_revision_and_total_changes() -> DomainResult<()> {
    identity::conflicts().await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL database"]
async fn callback_and_native_observe_binding_uuid_purposes_conflict_both_directions() -> DomainResult<()> {
    identity::purpose().await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL database"]
async fn distinct_partitions_do_not_reclaim_superseded_batches_or_replace_latest_progress() -> DomainResult<()> {
    progress::superseded().await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL database"]
async fn all_six_actual_task_dependencies_require_complete_latest_partition_success() -> DomainResult<()> {
    progress::dag().await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL database"]
async fn partial_skipped_and_failed_latest_batches_cannot_supply_dependencies() -> DomainResult<()> {
    progress::unqualified().await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL database"]
async fn previous_source_or_adoption_success_cannot_supply_current_dependencies() -> DomainResult<()> {
    progress::old_context().await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL database"]
async fn rejected_claim_and_start_audits_roll_back_all_records_and_start_permission() -> DomainResult<()> {
    publication::rollback().await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL database"]
async fn terminal_audit_failure_keeps_authenticated_known_outcome_for_same_body_local_recovery() -> DomainResult<()> {
    publication::recover().await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL database"]
async fn original_key_revocation_at_claim_start_and_terminal_audit_wait_cannot_publish() -> DomainResult<()> {
    authority::key_withdrawal(false).await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL database"]
async fn removing_only_actual_task_grant_at_audit_wait_cannot_publish() -> DomainResult<()> {
    authority::key_withdrawal(true).await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL database"]
async fn tenant_disabled_during_actual_tenant_guard_wait_cannot_admit_or_start() -> DomainResult<()> {
    authority::tenant_wait().await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL database"]
async fn source_change_and_authenticated_negative_qualification_stop_waiting_start() -> DomainResult<()> {
    authority::current_wait().await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL database"]
async fn archived_observation_body_does_not_destroy_authenticated_adoption_authority() -> DomainResult<()> {
    identity::archive().await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL database; actual 110-second immutable start lease"]
async fn expired_status_get_is_pure_and_does_not_renew_or_regrant_original_start() -> DomainResult<()> {
    publication::expired().await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL database"]
async fn fact_progress_and_pending_aead_or_foreign_aad_tampering_fail_closed_without_writes() -> DomainResult<()> {
    crypto::authenticated().await
}
