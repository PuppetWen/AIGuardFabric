//! Actual router Mock workflow; no cloud registration or callback execution is claimed.
mod common;
mod scheduler_managed_jobs_support;
use agf_core::{error::DomainResult, ids::Id};
use common::*;
use scheduler_managed_jobs_support::*;

async fn setup_mock() -> DomainResult<Harness> {
    let h = setup().await;
    config(&h, 0, true).await?;
    Ok(h)
}

#[tokio::test]
async fn read_metadata_and_unknown_uuid_do_not_initialize_mutate_or_audit() -> DomainResult<()> {
    let h = setup().await;
    let before = digest(&h).await?;
    assert_eq!(h.request("GET", BASE, None, None).await.status, StatusCode::UNAUTHORIZED);
    let state = get(&h, BASE).await?;
    assert_eq!(state["canPrepare"], false);
    assert!(state["target"].is_null());
    assert_eq!(state["operations"], json!([]));
    assert_eq!(state["generation"], 0);
    assert_eq!(state["callbackBindingEnforced"], false);
    assert_eq!(h.get(&receipt(Id::new())).await.status, StatusCode::NOT_FOUND);
    assert_eq!(digest(&h).await?, before);
    safe(&state);
    Ok(())
}
#[tokio::test]
async fn six_explicit_mock_disabled_creations_have_real_ids_unique_receipts_and_no_provider() -> DomainResult<()> {
    let h = setup_mock().await?;
    let mut ids = std::collections::BTreeSet::new();
    for kind in ["asset-inventory", "log-pull", "redteam-cruise", "rule-hot-reload", "report", "archive"] {
        let observed = observe(&h).await?;
        let prepared = preview(&h, &observed, create(kind), None).await?;
        assert_eq!(prepared["desired"]["enabled"], false);
        assert_eq!(prepared["desired"]["http"]["verified"], false);
        let request = Id::new();
        let accepted = apply(&h, &prepared, request).await?;
        assert_eq!(accepted["status"], "accepted");
        assert_eq!(accepted["completionState"], "complete");
        assert_eq!(accepted["originalWrite"]["attempted"], false);
        assert_eq!(accepted["readback"], "matched");
        let job = accepted["jobId"]
            .as_str()
            .ok_or_else(|| agf_core::error::DomainError::Internal("owned job ID missing".into()))?;
        assert!(job.parse::<i64>().is_ok_and(|n| n > 9_007_199_254_741_000));
        assert!(ids.insert(job.to_owned()));
        let before = digest(&h).await?;
        assert_eq!(apply(&h, &prepared, request).await?, accepted);
        assert_eq!(get(&h, &receipt(request)).await?, accepted);
        assert_eq!(digest(&h).await?, before);
        assert_eq!(terminal_count(&h, request).await?, 1);
        safe(&accepted);
    }
    let final_observation = observe(&h).await?;
    assert_eq!(final_observation["total"], 12);
    assert_eq!(get(&h, BASE).await?["definitions"].as_array().map(Vec::len), Some(6));
    let before = digest(&h).await?;
    let duplicate = input(&h, &final_observation, create("report"), None, Id::new()).await?;
    assert_eq!(h.post(&format!("{BASE}/previews"), duplicate).await.status, StatusCode::CONFLICT);
    assert_eq!(digest(&h).await?, before);
    assert!(h.state.configurations.list::<Value>(h.tenant, "integration-operation").await?.is_empty());
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}
#[tokio::test]
async fn update_does_not_enable_and_active_update_requires_a_distinct_disable() -> DomainResult<()> {
    let h = setup_mock().await?;
    let observed = observe(&h).await?;
    let rejected = input(
        &h,
        &observed,
        json!({"action":"update_schedule","patch":{"max_attempt":0}}),
        Some("9007199254741002"),
        Id::new(),
    )
    .await?;
    let before = digest(&h).await?;
    assert_eq!(h.post(&format!("{BASE}/previews"), rejected).await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(digest(&h).await?, before);
    let prepared =
        preview(&h, &observed, json!({"action":"update_schedule","patch":{"max_attempt":0}}), Some("9007199254741001"))
            .await?;
    let original_http = prepared["before"]["http"].clone();
    let result = apply(&h, &prepared, Id::new()).await?;
    assert_eq!(result["preview"]["desired"]["enabled"], false);
    assert_eq!(result["preview"]["desired"]["http"], original_http);
    let observed = observe(&h).await?;
    let enabled = preview(&h, &observed, json!({"action":"enable"}), Some("9007199254741001")).await?;
    let result = apply(&h, &enabled, Id::new()).await?;
    assert_eq!(result["preview"]["desired"]["enabled"], true);
    assert_eq!(get(&h, BASE).await?["operationTotal"], 2);
    Ok(())
}
#[tokio::test]
async fn disable_revokes_same_transaction_and_enable_does_not_readopt_the_role() -> DomainResult<()> {
    let h = setup_mock().await?;
    let observed = observe(&h).await?;
    let bound = h
        .request(
            "PUT",
            &format!("{NATIVE}/bindings"),
            Some(&h.admin),
            Some(json!({"action":"replace","request_id":Id::new(),
        "expected_version":0,"configuration_version":1,"observation_id":id(&observed,"requestId")?,
        "bindings":[{"kind":"report","job_id":"9007199254741002"}],"confirm_local_only":true})),
        )
        .await;
    assert_eq!(bound.status, StatusCode::OK);
    assert_eq!(bound.json()["items"][0]["eligibility"], "eligible");
    let prepared = preview(&h, &observed, json!({"action":"disable"}), Some("9007199254741002")).await?;
    apply(&h, &prepared, Id::new()).await?;
    assert_eq!(get(&h, NATIVE).await?["bindings"]["items"][0]["eligibility"], "revoked");
    let observed = observe(&h).await?;
    let prepared = preview(&h, &observed, json!({"action":"enable"}), Some("9007199254741002")).await?;
    apply(&h, &prepared, Id::new()).await?;
    let binding = get(&h, NATIVE).await?["bindings"].clone();
    assert_eq!(binding["items"][0]["currentEvidence"]["enabled"], true);
    assert_eq!(binding["items"][0]["eligibility"], "revoked");
    assert_eq!(binding["callbackBindingEnforced"], false);
    Ok(())
}
#[tokio::test]
async fn binding_cas_changed_after_preview_is_rejected_without_claim_or_mutation() -> DomainResult<()> {
    let h = setup_mock().await?;
    let observed = observe(&h).await?;
    let prepared = preview(&h, &observed, json!({"action":"enable"}), Some("9007199254741001")).await?;
    let changed = h
        .request(
            "PUT",
            &format!("{NATIVE}/bindings"),
            Some(&h.admin),
            Some(json!({"action":"disable",
        "request_id":Id::new(),"expected_version":0})),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK);
    let before = digest(&h).await?;
    let request = Id::new();
    assert_eq!(
        h.request("PUT", &receipt(request), Some(&h.admin), Some(apply_input(&prepared))).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(digest(&h).await?, before);
    assert_eq!(h.get(&receipt(request)).await.status, StatusCode::NOT_FOUND);
    Ok(())
}
#[tokio::test]
async fn original_uuid_cannot_cross_preview_observation_binding_or_changed_body() -> DomainResult<()> {
    let h = setup_mock().await?;
    let observed = observe(&h).await?;
    let request = Id::new();
    let body = input(&h, &observed, create("report"), None, request).await?;
    let prepared = post(&h, &format!("{BASE}/previews"), body.clone()).await?;
    let before = digest(&h).await?;
    assert_eq!(post(&h, &format!("{BASE}/previews"), body.clone()).await?, prepared);
    let mut changed = body;
    changed["change"]["declaration"]["name"] = json!("different-owned-name");
    assert_eq!(h.post(&format!("{BASE}/previews"), changed).await.status, StatusCode::CONFLICT);
    assert_eq!(
        h.post(
            &format!("{NATIVE}/observe"),
            json!({"request_id":request,"configuration_version":1,
        "initialize_mock_fixture":false,"confirm_live":false})
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        h.request(
            "PUT",
            &format!("{NATIVE}/bindings"),
            Some(&h.admin),
            Some(json!({"action":"disable",
        "request_id":request,"expected_version":0}))
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    let original_observe = id(&observed, "requestId")?;
    let reused = input(&h, &observed, create("archive"), None, original_observe).await?;
    assert_eq!(h.post(&format!("{BASE}/previews"), reused).await.status, StatusCode::CONFLICT);
    assert_eq!(digest(&h).await?, before);
    Ok(())
}
#[tokio::test]
async fn disabled_source_keeps_old_get_recover_archive_and_permanent_replay_readable() -> DomainResult<()> {
    let h = setup_mock().await?;
    let observed = observe(&h).await?;
    let prepared = preview(&h, &observed, create("report"), None).await?;
    let request = Id::new();
    let result = apply(&h, &prepared, request).await?;
    config(&h, 1, false).await?;
    let before = digest(&h).await?;
    assert_eq!(post(&h, &format!("{}/recover", receipt(request)), json!({})).await?["completionState"], "complete");
    get(&h, &receipt(request)).await?;
    assert_eq!(digest(&h).await?, before);
    let view = get(&h, BASE).await?;
    assert_eq!(view["canPrepare"], false);
    let archive = post(
        &h,
        &format!("{BASE}/operations/archive"),
        json!({"expected_generation":number(&view,"generation")?,
        "request_ids":[request],"confirm_loss_of_preview":true}),
    )
    .await?;
    assert_eq!(archive["archivedCount"], 1);
    let tombstone = get(&h, &receipt(request)).await?;
    assert_eq!(tombstone["status"], "archived");
    assert_eq!(tombstone["inputHash"], result["inputHash"]);
    assert_eq!(tombstone["originalWrite"], result["originalWrite"]);
    assert!(tombstone["preview"].is_null());
    let before = digest(&h).await?;
    assert_eq!(apply(&h, &prepared, request).await?, tombstone);
    assert_eq!(digest(&h).await?, before);
    assert_eq!(terminal_count(&h, request).await?, 1);
    safe(&tombstone);
    Ok(())
}
#[tokio::test]
async fn viewer_and_write_scoped_api_key_cannot_manage_user_only_workflow() -> DomainResult<()> {
    let h = setup_mock().await?;
    let observed = observe(&h).await?;
    let input = input(&h, &observed, create("report"), None, Id::new()).await?;
    let before = digest(&h).await?;
    assert_eq!(
        h.request("POST", &format!("{BASE}/previews"), Some(&h.viewer), Some(input.clone())).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(digest(&h).await?, before);
    let issued = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"owned-managed-read-write","scopes":["alicloud:read","alicloud:write"]}),
        )
        .await;
    assert_eq!(issued.status, StatusCode::CREATED);
    let value = issued.json();
    let token =
        value["plaintext"].as_str().ok_or_else(|| agf_core::error::DomainError::Internal("owned key absent".into()))?;
    let before = digest(&h).await?;
    assert_eq!(
        h.request("POST", &format!("{BASE}/previews"), Some(token), Some(input)).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(digest(&h).await?, before);
    Ok(())
}
