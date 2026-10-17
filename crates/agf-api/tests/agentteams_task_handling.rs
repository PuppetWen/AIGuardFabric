//! Actual HTTP route/collector lifecycle definitions; no telemetry resend is called task replay.
mod agentteams_task_handling_support;
mod common;
use agentteams_task_handling_support::*;
use agf_core::{error::DomainResult, ids::Id};
use common::*;

#[tokio::test]
async fn inbox_is_pure_tenant_filtered_collector_error_evidence_with_authenticated_pages() -> DomainResult<()> {
    let fixture = Fixture::new().await?;
    let first = fixture.push("original-error-a", "error").await?;
    let second = fixture.push("original-error-b", "error").await?;
    fixture.push("original-unknown", "unknown").await?;
    fixture.push("original-success", "success").await?;
    let before = fixture.snapshot().await?;
    let query = fixture.failure_query().await?;
    assert_eq!(query.total, 2);
    assert_eq!(query.records.len(), 2);
    let first_page = fixture.h.get(&format!("{ROOT}?limit=1")).await;
    ok(&first_page, StatusCode::OK);
    assert_eq!(first_page.json()["total"], 2);
    assert_eq!(first_page.json()["category"], "collector_reported_error");
    let cursor = first_page.json()["nextCursor"].as_str().ok_or_else(invalid)?.to_owned();
    let last = fixture.h.get(&format!("{ROOT}?limit=1&cursor={cursor}")).await;
    ok(&last, StatusCode::OK);
    assert_ne!(first_page.json()["items"][0]["id"], last.json()["items"][0]["id"]);
    for page in [first_page.json(), last.json()] {
        assert!(page["items"][0]["messagePreview"].is_string());
        assert_eq!(page["items"][0]["fromTeam"], "my-team");
        assert_eq!(page["items"][0]["fromWorker"], "worker-demo");
        assert!(!page.to_string().contains("synthetic-private-password"));
    }
    for event in [first, second] {
        let detail = fixture.detail(event).await;
        assert_eq!(detail["originalStatus"], "error");
        assert_eq!(detail["cloudExecutionConfirmed"], false);
        assert_eq!(detail["businessReplayImplemented"], false);
        assert!(detail.get("raw").is_none());
        let original = fixture.original(event).await?;
        assert_eq!(detail["messagePreview"], original["message_preview"]);
        assert_eq!(detail["fromTeam"], original["from_team"]);
        assert_eq!(detail["fromWorker"], original["from_worker"]);
        assert!(detail["messagePreview"].as_str().ok_or_else(invalid)?.contains("Collector cannot reach downstream"));
        assert!(!detail.to_string().contains("synthetic-private-password"));
    }
    ok(&fixture.h.get(&format!("{ROOT}?limit=2&cursor={cursor}")).await, StatusCode::BAD_REQUEST);
    ok(&fixture.h.get(&format!("{ROOT}?limit=1&cursor={cursor}tamper")).await, StatusCode::BAD_REQUEST);
    assert_eq!(fixture.snapshot().await?, before);
    Ok(())
}
#[tokio::test]
async fn decisions_are_cas_annotations_and_original_uuid_replay_does_not_rewrite_evidence() -> DomainResult<()> {
    let fixture = Fixture::new().await?;
    let event = fixture.push("resolution-original", "error").await?;
    let original = fixture.original(event).await?;
    let request = Id::new();
    let input = fixture.resolution(event, request, 0, "acknowledged").await;
    let accepted = fixture.resolve(event, input.clone()).await;
    ok(&accepted, StatusCode::OK);
    assert_eq!(accepted.json()["version"], 1);
    assert_eq!(accepted.json()["cloudExecutionConfirmed"], false);
    let committed = fixture.snapshot().await?;
    let replay = fixture.resolve(event, input.clone()).await;
    ok(&replay, StatusCode::OK);
    assert_eq!(replay.json(), accepted.json());
    assert_eq!(fixture.h.get(&format!("{ROOT}/requests/{request}")).await.json(), accepted.json());
    assert_eq!(fixture.snapshot().await?, committed);
    let mut switched = input;
    switched["decision"] = json!("resolved_by_operator");
    ok(&fixture.resolve(event, switched).await, StatusCode::CONFLICT);
    let stale = fixture.resolution(event, Id::new(), 0, "external_action_reported").await;
    ok(&fixture.resolve(event, stale).await, StatusCode::CONFLICT);
    for (version, decision) in [(1, "external_action_reported"), (2, "resolved_by_operator")] {
        ok(
            &fixture.resolve(event, fixture.resolution(event, Id::new(), version, decision).await).await,
            StatusCode::OK,
        );
    }
    assert_eq!(fixture.original(event).await?, original);
    let detail = fixture.detail(event).await;
    assert_eq!(detail["handling"]["history"].as_array().ok_or_else(invalid)?.len(), 3);
    let chain = fixture.h.state.store.audit_verify_durable(fixture.h.tenant).await?;
    assert!(chain.passed);
    Ok(())
}
#[tokio::test]
async fn disabled_source_allows_annotation_only_with_fresh_opaque_source_proof() -> DomainResult<()> {
    let fixture = Fixture::new().await?;
    let event = fixture.push("disabled-source", "error").await?;
    let stale = fixture.resolution(event, Id::new(), 0, "acknowledged").await;
    ok(
        &fixture
            .h
            .request(
                "PATCH",
                &format!("/api/v1/ingest/sources/{}", fixture.source),
                Some(&fixture.h.admin),
                Some(json!({"enabled":false})),
            )
            .await,
        StatusCode::OK,
    );
    let before = fixture.snapshot().await?;
    ok(&fixture.resolve(event, stale).await, StatusCode::CONFLICT);
    assert_eq!(fixture.snapshot().await?, before);
    let fresh = fixture.resolution(event, Id::new(), 0, "acknowledged").await;
    ok(&fixture.resolve(event, fresh).await, StatusCode::OK);
    let detail = fixture.detail(event).await;
    assert_eq!(detail["currentSource"]["sourceEnabled"], false);
    assert_eq!(detail["originalStatus"], "error");
    assert_eq!(detail["handling"]["decision"], "acknowledged");
    Ok(())
}
#[tokio::test]
async fn archive_frees_history_preserves_permanent_requests_and_new_zero_change_receipt_is_audited() -> DomainResult<()>
{
    let fixture = Fixture::new().await?;
    let event = fixture.push("archive-history", "error").await?;
    let resolution_id = Id::new();
    let input = fixture.resolution(event, resolution_id, 0, "resolved_by_operator").await;
    let receipt = fixture.resolve(event, input.clone()).await;
    ok(&receipt, StatusCode::OK);
    let request = Id::new();
    let archive = fixture.archive_input(event, request).await;
    let archived = fixture.h.post(&format!("{ROOT}/archive"), archive.clone()).await;
    ok(&archived, StatusCode::OK);
    assert_eq!(archived.json()["changedCount"], 1);
    let after = fixture.snapshot().await?;
    let replay = fixture.h.post(&format!("{ROOT}/archive"), archive).await;
    ok(&replay, StatusCode::OK);
    assert_eq!(replay.json(), archived.json());
    assert_eq!(fixture.snapshot().await?, after);
    assert_eq!(fixture.h.get(&format!("{ROOT}/requests/{request}")).await.json(), archived.json());
    assert_eq!(fixture.h.get(&format!("{ROOT}/requests/{resolution_id}")).await.json(), receipt.json());
    assert_eq!(fixture.resolve(event, input).await.json(), receipt.json());
    let detail = fixture.detail(event).await;
    assert_eq!(detail["handling"]["archived"], true);
    assert_eq!(detail["handling"]["history"], json!([]));
    assert_eq!(detail["originalStatus"], "error");
    let next = fixture.h.post(&format!("{ROOT}/archive"), fixture.archive_input(event, Id::new()).await).await;
    ok(&next, StatusCode::OK);
    assert_eq!(next.json()["changedCount"], 0);
    assert_eq!(next.json()["generation"], archived.json()["generation"]);
    assert_ne!(fixture.snapshot().await?, after);
    let audits = fixture.h.state.store.audit_chain_durable(fixture.h.tenant, 0, i64::MAX).await?;
    assert_eq!(audits.iter().filter(|row| row.target.kind == "agentteams-task-handling-archive-request").count(), 1);
    Ok(())
}
#[tokio::test]
async fn deleted_source_keeps_original_readable_and_can_archive_but_cannot_annotate() -> DomainResult<()> {
    let fixture = Fixture::new().await?;
    let event = fixture.push("deleted-source-history", "error").await?;
    ok(&fixture.resolve(event, fixture.resolution(event, Id::new(), 0, "acknowledged").await).await, StatusCode::OK);
    let old = fixture.resolution(event, Id::new(), 1, "resolved_by_operator").await;
    ok(
        &fixture
            .h
            .request("DELETE", &format!("/api/v1/ingest/sources/{}", fixture.source), Some(&fixture.h.admin), None)
            .await,
        StatusCode::OK,
    );
    let detail = fixture.detail(event).await;
    assert_eq!(detail["currentSource"]["sourceGone"], true);
    ok(&fixture.resolve(event, old).await, StatusCode::CONFLICT);
    let input = fixture.archive_input(event, Id::new()).await;
    assert!(input["expected_cloud_configuration_version"].is_null());
    ok(&fixture.h.post(&format!("{ROOT}/archive"), input).await, StatusCode::OK);
    Ok(())
}
#[tokio::test]
async fn permissions_unknown_fields_purpose_and_body_limits_cannot_create_fake_task_effects() -> DomainResult<()> {
    let fixture = Fixture::new().await?;
    let event = fixture.push("strict-input", "error").await?;
    let request = Id::new();
    let input = fixture.resolution(event, request, 0, "acknowledged").await;
    let before = fixture.snapshot().await?;
    ok(
        &fixture
            .h
            .request("PUT", &format!("{ROOT}/events/{event}/resolution"), Some(&fixture.h.viewer), Some(input.clone()))
            .await,
        StatusCode::FORBIDDEN,
    );
    let mut fake = input.clone();
    fake["retry"] = json!(true);
    ok(&fixture.resolve(event, fake).await, StatusCode::BAD_REQUEST);
    ok(&fixture.h.get(&format!("{ROOT}?status=failed")).await, StatusCode::BAD_REQUEST);
    let response = fixture
        .h
        .request(
            "PUT",
            &format!("{ROOT}/events/{event}/resolution"),
            Some(&fixture.h.admin),
            Some(json!({"raw":"private-marker".repeat(8192)})),
        )
        .await;
    ok(&response, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!response.text.contains("private-marker"));
    assert_eq!(fixture.snapshot().await?, before);
    ok(&fixture.resolve(event, input).await, StatusCode::OK);
    let conflict = fixture.h.post(&format!("{ROOT}/archive"), fixture.archive_input(event, request).await).await;
    ok(&conflict, StatusCode::CONFLICT);
    Ok(())
}
