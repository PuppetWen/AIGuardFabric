//! Real router boundaries and an owned loopback provider; no external cloud is called.
mod common;
mod scheduler_generic_write_barrier_support;
// Reuse the accepted route fixture without importing another target's test cases.
#[path = "scheduler_managed_jobs_support/mod.rs"]
mod managed;

use agf_core::{error::DomainResult, ids::Id};
use common::*;
use scheduler_generic_write_barrier_support::*;

#[tokio::test]
async fn six_generic_writes_fail_before_provider_claim_journal_or_audit() -> DomainResult<()> {
    let provider = Provider::new().await?;
    for mocked in [false, true] {
        let h = configured(&provider, mocked).await?;
        let before = managed::digest(&h).await?;
        for action in ACTIONS {
            let request_id = Id::new();
            let response = h.post(OPERATIONS, request(action, request_id)).await;
            assert_eq!(response.status, StatusCode::PRECONDITION_FAILED, "blocked action {action}");
            assert!(response.text.contains("Scheduler"));
            assert_eq!(h.get(&format!("{OPERATIONS}/{request_id}")).await.status, StatusCode::NOT_FOUND);
            assert_eq!(managed::digest(&h).await?, before);
            assert_eq!(provider.count(), 0);
        }
        assert!(h.state.configurations.list::<Value>(h.tenant, "integration-operation").await?.is_empty());
        assert!(h.state.configurations.list::<Value>(h.tenant, "scheduler-native-fact").await?.is_empty());
        assert!(h.state.configurations.list::<Value>(h.tenant, "scheduler-managed-job-request").await?.is_empty());
        assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    }
    Ok(())
}

#[tokio::test]
async fn registered_scheduler_reads_remain_usable_with_safe_receipts() -> DomainResult<()> {
    let provider = Provider::new().await?;
    let h = configured(&provider, false).await?;
    for action in ["ListJobs", "ListJobExecutions", "GetJobExecution"] {
        let response = h.post(OPERATIONS, request(action, Id::new())).await;
        assert_eq!(response.status, StatusCode::OK);
        let value = response.json();
        assert_eq!(value["status"], "succeeded");
        assert_eq!(value["completion_state"], "complete");
        assert_eq!(value["receipt"]["response"]["Code"], 200);
        assert_eq!(value["receipt"]["response"]["RequestId"], "owned-generic-read");
        assert!(!response.text.contains("OWNED-BARRIER-SOURCE-SECRET"));
    }
    assert_eq!(provider.count(), 3);
    assert_eq!(h.state.configurations.list::<Value>(h.tenant, "integration-operation").await?.len(), 3);
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
async fn typed_entry_still_creates_all_six_disabled_mock_jobs_and_replays_only_original_receipts() -> DomainResult<()> {
    let h = setup().await;
    managed::config(&h, 0, true).await?;
    let mut ids = std::collections::BTreeSet::new();
    for kind in ["asset-inventory", "log-pull", "redteam-cruise", "rule-hot-reload", "report", "archive"] {
        let observed = managed::observe(&h).await?;
        let preview = managed::preview(&h, &observed, managed::create(kind), None).await?;
        let request_id = Id::new();
        let result = managed::apply(&h, &preview, request_id).await?;
        managed::safe(&result);
        assert_eq!(result["status"], "accepted");
        assert_eq!(result["completionState"], "complete");
        assert_eq!(result["preview"]["desired"]["enabled"], false);
        assert_eq!(result["originalWrite"]["attempted"], false);
        assert_eq!(result["readback"], "matched");
        let job = result["jobId"]
            .as_str()
            .ok_or_else(|| agf_core::error::DomainError::Internal("owned Mock job ID is absent".into()))?;
        assert!(job.parse::<i64>().is_ok_and(|id| id > 9_007_199_254_741_000));
        assert!(ids.insert(job.to_owned()));
        let before = managed::digest(&h).await?;
        assert_eq!(managed::apply(&h, &preview, request_id).await?, result);
        let readback = managed::get(&h, &managed::receipt(request_id)).await?;
        managed::safe(&readback);
        assert_eq!(readback, result);
        assert_eq!(managed::digest(&h).await?, before);
        assert_eq!(managed::terminal_count(&h, request_id).await?, 1);
    }
    assert_eq!(managed::observe(&h).await?["total"], 12);
    assert!(h.state.configurations.list::<Value>(h.tenant, "integration-operation").await?.is_empty());
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}
