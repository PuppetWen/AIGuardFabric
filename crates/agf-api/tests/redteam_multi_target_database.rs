#![cfg(feature = "test-loopback-transport")]
mod common;
mod redteam_multi_target_database_support;
use agf_core::{error::DomainResult, ids::Id};
use common::*;
use futures::FutureExt;
use redteam_multi_target_database_support::{BASE, Fixture, Pending, key_call, private_free};
use std::panic::AssertUnwindSafe;

#[tokio::test]
#[ignore = "requires exact exclusively owned multi-target SQL database and default-off loopback capability"]
async fn three_actual_targets_relay_and_one_campaign_publish_atomically_then_never_redispatch() -> DomainResult<()> {
    let fixture = Fixture::new("multi-real-chain", true, false).await?;
    let request = Id::new();
    let body = fixture.body(request).await?;
    let second = fixture.second().await?;
    let path = format!("{BASE}/runs");
    let (first, replay) = tokio::join!(
        fixture.call("POST", &path, Some(body.clone())),
        key_call(&second, &fixture.key, "POST", &path, Some(body.clone()))
    );
    assert!(first.status == StatusCode::OK && replay.status == StatusCode::OK);
    let receipt = fixture.call("GET", &format!("{BASE}/runs/{request}"), None).await;
    private_free(&receipt);
    let value = receipt.json();
    assert!(
        value["targets"]
            .as_array()
            .is_some_and(|rows| rows.iter().zip(&fixture.assets).all(|(row, id)| row["assetId"] == json!(id)))
    );
    assert!(value["status"] == "completed" && value["completionState"] == "complete" && value["localFixture"] == true);
    assert!(
        value["defensePassed"] == false
            && value["externalDefenseVerified"] == false
            && value["evidence"].as_array().is_some_and(|rows| rows.len() == 3)
    );
    assert_eq!(fixture.counts()?, [1, 2, 1]);
    assert!(value["findingIds"].as_array().is_some_and(|ids| ids.len() == 1));
    assert_eq!(fixture.terminal_audits(request, true).await?, 1);
    let a = fixture.wires[0].requests()?;
    let mcp = fixture.wires[1].requests()?;
    let b = fixture.wires[2].requests()?;
    assert!(a[0]["messages"][0]["content"].as_str().is_some_and(|text| !text.contains("ProtectedCanary")));
    assert!(mcp[1]["params"]["arguments"]["query"].as_str().is_some_and(|text| text.contains("public-reference-123")));
    assert!(b[0]["messages"][0]["content"].as_str().is_some_and(|text| text.contains("Untrusted fixture instruction")
        && !text.contains(redteam_multi_target_database_support::CANARY)));
    let before = fixture.snapshot().await?;
    let repeated = key_call(&second, &fixture.key, "POST", &path, Some(body.clone())).await;
    assert!(repeated.status == StatusCode::OK && repeated.json() == value);
    let read = key_call(&second, &fixture.key, "GET", &format!("{BASE}/runs/{request}"), None).await;
    assert!(read.status == StatusCode::OK && read.json() == value);
    let mut changed = body;
    changed["confirm_live"] = json!(true);
    assert_eq!(fixture.call("POST", &path, Some(changed)).await.status, StatusCode::CONFLICT);
    let foreign = fixture.case.foreign().await?;
    assert_eq!(foreign.get(&format!("{BASE}/runs/{request}")).await.status, StatusCode::NOT_FOUND);
    assert!(fixture.snapshot().await? == before && fixture.counts()? == [1, 2, 1]);
    fixture.chain().await
}
#[tokio::test]
#[ignore = "requires exact exclusively owned multi-target SQL database and default-off loopback capability"]
async fn terminal_audit_failure_preserves_known_evidence_and_recovery_is_local_on_changed_source() -> DomainResult<()> {
    let fixture = Fixture::new("multi-pending", true, false).await?;
    let request = Id::new();
    let body = fixture.body(request).await?;
    let fault = fixture.case.audit_fault(request, "execute").await?;
    let checked = AssertUnwindSafe(async {
        let result = fixture.call("POST", &format!("{BASE}/runs"), Some(body.clone())).await;
        assert!(result.status == StatusCode::OK && result.json()["completionState"] == "pending_audit");
        private_free(&result);
        assert!(fixture.counts()? == [1, 2, 1] && fixture.terminal_audits(request, true).await? == 0);
        assert!(fixture.case.h.state.store.finding_list_all_durable(fixture.case.h.tenant).await?.is_empty());
        let before = fixture.snapshot().await?;
        assert_eq!(fixture.call("GET", &format!("{BASE}/runs/{request}"), None).await.json(), result.json());
        assert_eq!(fixture.snapshot().await?, before);
        Ok::<(), agf_core::error::DomainError>(())
    })
    .catch_unwind()
    .await;
    fixture.case.clear_fault(&fault).await?;
    match checked {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    let removed = fixture
        .case
        .h
        .request(
            "DELETE",
            &format!("/api/v1/redteam/agent-targets/{}", fixture.ids[0]),
            Some(&fixture.case.h.admin),
            Some(json!({"expected_version":1})),
        )
        .await;
    assert_eq!(removed.status, StatusCode::OK);
    let second = fixture.second().await?;
    let path = format!("{BASE}/runs/{request}/recover");
    let recovered = key_call(&second, &fixture.key, "POST", &path, Some(json!({}))).await;
    assert!(
        recovered.status == StatusCode::OK
            && recovered.json()["status"] == "completed"
            && recovered.json()["sourceCurrent"] == false
    );
    assert!(
        recovered.json()["findingIds"].as_array().is_some_and(|rows| rows.len() == 1)
            && fixture.terminal_audits(request, true).await? == 1
    );
    let before = fixture.snapshot().await?;
    assert_eq!(key_call(&second, &fixture.key, "POST", &path, Some(json!({}))).await.json(), recovered.json());
    assert!(fixture.snapshot().await? == before && fixture.counts()? == [1, 2, 1]);
    fixture.chain().await
}
#[tokio::test]
#[ignore = "requires exact exclusively owned multi-target SQL database and default-off loopback capability"]
async fn explicit_cancel_after_first_actual_send_prevents_follow_on_targets_and_old_response_cannot_overwrite()
-> DomainResult<()> {
    let fixture = Fixture::new("multi-cancel", true, true).await?;
    let request = Id::new();
    let body = fixture.body(request).await?;
    let mut pending = Pending::start(fixture.case.h.clone(), fixture.key.clone(), body);
    let gate = fixture.wires[0].gate.as_ref().ok_or_else(redteam_multi_target_database_support::owned::failure)?;
    let checked = AssertUnwindSafe(async {
        gate.wait().await?;
        let cancelled = fixture.call("POST", &format!("{BASE}/runs/{request}/cancel"), Some(json!({}))).await;
        assert!(cancelled.status == StatusCode::OK && cancelled.json()["status"] == "cancelled");
        let before = fixture.snapshot().await?;
        gate.release();
        let result = pending.finish().await?;
        assert!(result.status == StatusCode::OK && result.json()["status"] == "cancelled");
        assert!(fixture.snapshot().await? == before && fixture.counts()? == [1, 0, 0]);
        assert_eq!(fixture.terminal_audits(request, false).await?, 1);
        fixture.chain().await
    })
    .catch_unwind()
    .await;
    gate.release();
    match checked {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
#[tokio::test]
#[ignore = "requires exact exclusively owned multi-target SQL database and default-off loopback capability"]
async fn unverified_mcp_readonly_contract_is_not_a_negative_attack_result_and_sends_no_tool_or_second_agent()
-> DomainResult<()> {
    let fixture = Fixture::new("multi-readonly", false, false).await?;
    let request = Id::new();
    let body = fixture.body(request).await?;
    let result = fixture.call("POST", &format!("{BASE}/runs"), Some(body)).await;
    private_free(&result);
    assert!(
        result.status == StatusCode::OK
            && result.json()["status"] == "failed"
            && result.json()["defensePassed"].is_null()
    );
    assert!(result.json()["evidence"][1]["protectedCanaryObserved"].is_null() && fixture.counts()? == [1, 1, 0]);
    assert!(fixture.case.h.state.store.finding_list_all_durable(fixture.case.h.tenant).await?.is_empty());
    assert_eq!(fixture.terminal_audits(request, false).await?, 1);
    fixture.chain().await
}
#[tokio::test]
#[ignore = "requires exact exclusively owned multi-target SQL database and default-off loopback capability"]
async fn claim_audit_failure_rolls_back_permanent_fact_capacity_and_all_outbound_dispatch() -> DomainResult<()> {
    let fixture = Fixture::new("multi-claim-fault", true, false).await?;
    let request = Id::new();
    let body = fixture.body(request).await?;
    let before = fixture.snapshot().await?;
    let fault = fixture.case.audit_fault(request, "configure").await?;
    let checked = AssertUnwindSafe(async {
        let rejected = fixture.call("POST", &format!("{BASE}/runs"), Some(body)).await;
        assert!(rejected.status.is_server_error() && fixture.counts()? == [0, 0, 0]);
        assert_eq!(fixture.snapshot().await?, before);
        fixture.chain().await
    })
    .catch_unwind()
    .await;
    fixture.case.clear_fault(&fault).await?;
    match checked {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
#[tokio::test]
#[ignore = "requires exact exclusively owned multi-target SQL database and default-off loopback capability"]
async fn revoking_original_key_during_first_actual_read_never_dispatches_next_targets_or_publishes_success()
-> DomainResult<()> {
    let fixture = Fixture::new("multi-revoke", true, true).await?;
    let request = Id::new();
    let body = fixture.body(request).await?;
    let mut pending = Pending::start(fixture.case.h.clone(), fixture.key.clone(), body);
    let gate = fixture.wires[0].gate.as_ref().ok_or_else(redteam_multi_target_database_support::owned::failure)?;
    let checked = AssertUnwindSafe(async {
        gate.wait().await?;
        let revoked = fixture
            .case
            .h
            .request(
                "DELETE",
                &format!("/api/v1/settings/api-keys/{}", fixture.key_id),
                Some(&fixture.case.h.admin),
                None,
            )
            .await;
        assert!(revoked.status.is_success(), "Actual Key revocation failed");
        gate.release();
        let result = pending.finish().await?;
        assert!(matches!(result.status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED));
        private_free(&result);
        assert!(
            fixture.counts()? == [1, 0, 0]
                && fixture.terminal_audits(request, true).await? == 0
                && fixture.terminal_audits(request, false).await? == 0
        );
        assert!(fixture.case.h.state.store.finding_list_all_durable(fixture.case.h.tenant).await?.is_empty());
        let records: Vec<Value> =
            fixture.case.h.state.configurations.list(fixture.case.h.tenant, "redteam-multi-target-fact").await?;
        assert!(
            records.len() == 1
                && !serde_json::to_string(&records)?.contains(redteam_multi_target_database_support::CANARY)
        );
        let before = fixture.snapshot().await?;
        assert!(matches!(
            fixture.call("GET", &format!("{BASE}/runs/{request}"), None).await.status,
            StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED
        ));
        assert!(fixture.snapshot().await? == before && fixture.counts()? == [1, 0, 0]);
        fixture.chain().await
    })
    .catch_unwind()
    .await;
    gate.release();
    match checked {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
#[tokio::test]
#[ignore = "requires exact exclusively owned multi-target SQL database and default-off loopback capability"]
async fn final_audit_tail_wait_rechecks_original_key_and_rolls_back_fact_findings_and_success_audit() -> DomainResult<()>
{
    let fixture = Fixture::new("multi-audit-key", true, true).await?;
    let request = Id::new();
    let body = fixture.body(request).await?;
    let mut pending = Pending::start(fixture.case.h.clone(), fixture.key.clone(), body);
    let gate = fixture.wires[0].gate.as_ref().ok_or_else(redteam_multi_target_database_support::owned::failure)?;
    gate.wait().await?;
    let held = fixture.case.hold_audit().await?;
    gate.release();
    let checked = AssertUnwindSafe(async {
        fixture.case.wait_audit().await?;
        assert!(fixture.counts()? == [1, 2, 1], "Final audit gate requires all three actual responses first");
        let before = fixture.snapshot().await?;
        // Direct owned fault avoids queueing a normal revocation audit behind this exact tail lock.
        fixture.case.revoke_key_fault(fixture.key_id).await?;
        Ok::<Value, agf_core::error::DomainError>(before)
    })
    .catch_unwind()
    .await;
    if !matches!(&checked, Ok(Ok(_))) {
        pending.abort();
    }
    held.rollback().await.map_err(|_| redteam_multi_target_database_support::owned::failure())?;
    let before = match checked {
        Ok(value) => value?,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    let response = pending.finish().await?;
    assert!(matches!(response.status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED));
    private_free(&response);
    assert!(fixture.snapshot().await? == before && fixture.terminal_audits(request, true).await? == 0);
    assert!(fixture.case.h.state.store.finding_list_all_durable(fixture.case.h.tenant).await?.is_empty());
    assert_eq!(fixture.counts()?, [1, 2, 1]);
    fixture.chain().await
}
