mod cms_queue_support;
mod common;
use agf_core::{error::DomainResult, ids::Id};
use cms_queue_support::*;
use common::*;

#[tokio::test]
async fn reads_never_seed_or_send_and_explicit_enqueue_alone_has_no_ack() -> DomainResult<()> {
    let h = setup().await;
    let before = snapshot(&h).await?;
    assert_eq!(get(&h, BASE).await?["source"], Value::Null);
    assert!(snapshot(&h).await? == before, "pure GET changed records");
    configure(&h, 0, true).await?;
    let before = snapshot(&h).await?;
    get(&h, BASE).await?;
    assert!(snapshot(&h).await? == before, "configured GET initialized Mock");
    let receipt = enqueue(&h, Id::new(), 1, true).await?;
    assert_eq!(receipt["originalAttempts"], json!([]));
    assert_eq!(receipt["items"][0]["attemptCount"], 0);
    let rows: Vec<Value> = h.state.configurations.list(h.tenant, "cms-queue-mock").await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(clear(&h, &rows[0])?["value"]["accepted"], json!({}));
    Ok(())
}
#[tokio::test]
async fn mock_acceptance_and_same_uuid_replay_are_atomic_and_never_repeat() -> DomainResult<()> {
    let h = setup().await;
    configure(&h, 0, true).await?;
    let queued = enqueue(&h, Id::new(), 1, true).await?;
    let item = serde_json::from_value(queued["itemIds"][0].clone())?;
    let request = Id::new();
    let body = send_input(&h, item, request).await?;
    let receipt = post(&h, &format!("{BASE}/send"), body.clone()).await?;
    let before = snapshot(&h).await?;
    assert!(post(&h, &format!("{BASE}/send"), body).await? == receipt, "original response changed");
    assert!(get(&h, &format!("{BASE}/requests/{request}")).await? == receipt, "GET original receipt changed");
    assert!(snapshot(&h).await? == before, "replay wrote provider/configuration/audit");
    let next = send_input(&h, item, Id::new()).await?;
    assert_eq!(h.post(&format!("{BASE}/send"), next).await.status, StatusCode::PRECONDITION_FAILED);
    assert!(snapshot(&h).await? == before, "Accepted item was resent");
    let audits = h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await?;
    assert_eq!(audits.iter().filter(|row| row.target.kind == "cms-queue-attempt").count(), 1);
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}
#[tokio::test]
async fn unseeded_mock_and_uuid_purpose_or_body_conflicts_have_no_claim() -> DomainResult<()> {
    let h = setup().await;
    configure(&h, 0, true).await?;
    let original = Id::new();
    let queued = enqueue(&h, original, 1, false).await?;
    let item = serde_json::from_value(queued["itemIds"][0].clone())?;
    let before = snapshot(&h).await?;
    let body = send_input(&h, item, Id::new()).await?;
    assert_eq!(h.post(&format!("{BASE}/send"), body).await.status, StatusCode::PRECONDITION_FAILED);
    let other = send_input(&h, item, original).await?;
    assert_eq!(h.post(&format!("{BASE}/send"), other).await.status, StatusCode::CONFLICT);
    assert!(snapshot(&h).await? == before, "invalid admission created a permanent fact");
    Ok(())
}
#[tokio::test]
async fn disabled_source_keeps_original_ack_and_permissions_do_not_substitute_owner() -> DomainResult<()> {
    let h = setup().await;
    configure(&h, 0, true).await?;
    let (item, request, receipt) = accepted(&h).await?;
    configure(&h, 1, false).await?;
    let before = snapshot(&h).await?;
    let read = get(&h, &format!("{BASE}/requests/{request}")).await?;
    assert_eq!(read["originalAttempts"], receipt["originalAttempts"]);
    assert_eq!(read["items"][0]["sourceCurrent"], false);
    assert!(snapshot(&h).await? == before, "disabled-source pure receipt wrote");
    let other = key(&h, &["alicloud:read", "alicloud:write"]).await?;
    let baseline = snapshot(&h).await?;
    assert_eq!(
        h.request("GET", &format!("{BASE}/requests/{request}"), Some(&other), None).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.request("POST", &format!("{BASE}/items/{item}/recover-local"), Some(&other), Some(json!({}))).await.status,
        StatusCode::FORBIDDEN
    );
    assert!(snapshot(&h).await? == baseline, "foreign original Key changed facts");
    Ok(())
}
#[tokio::test]
async fn archive32_preserves_facts_and_new_zero_change_request_is_audited() -> DomainResult<()> {
    let h = setup().await;
    configure(&h, 0, true).await?;
    let mut items = Vec::new();
    for count in [20, 12] {
        let receipt = enqueue(&h, Id::new(), count, false).await?;
        items.extend(receipt["itemIds"].as_array().ok_or_else(|| error("ids missing"))?.clone());
    }
    let before = get(&h, BASE).await?;
    assert_eq!(before["total"], 32);
    let request = Id::new();
    let body = json!({"request_id":request,"expected_generation":number(&before,"generation")?,"item_ids":items});
    let receipt = post(&h, &format!("{BASE}/archive"), body.clone()).await?;
    assert_eq!(receipt["changedCount"], 32);
    let state = get(&h, BASE).await?;
    assert_eq!(state["total"], 0);
    assert_eq!(state["storedContentBytes"], 0);
    let before = snapshot(&h).await?;
    post(&h, &format!("{BASE}/archive"), body).await?;
    assert!(snapshot(&h).await? == before, "same UUID archive replay wrote");
    let second = post(
        &h,
        &format!("{BASE}/archive"),
        json!({"request_id":Id::new(),"expected_generation":number(&state,"generation")?,"item_ids":items}),
    )
    .await?;
    assert_eq!(second["changedCount"], 0);
    assert_eq!(second["generation"], number(&state, "generation")? + 1);
    assert_eq!(h.state.configurations.list::<Value>(h.tenant, "cms-queue-item").await?.len(), 32);
    assert_eq!(h.state.configurations.list::<Value>(h.tenant, "cms-queue-body").await?.len(), 0);
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}
#[tokio::test]
async fn unknown_fields_readonly_keys_and_wrong_generation_fail_closed() -> DomainResult<()> {
    let h = setup().await;
    configure(&h, 0, true).await?;
    let token = key(&h, &["alicloud:read"]).await?;
    let before = snapshot(&h).await?;
    let body = json!({"request_id":Id::new(),"configuration_version":1,"expected_generation":0,"items":[payload()],"initialize_mock_fixture":true});
    assert_eq!(
        h.request("POST", &format!("{BASE}/enqueue"), Some(&token), Some(body.clone())).await.status,
        StatusCode::FORBIDDEN
    );
    let mut wrong = body;
    wrong["provider_url"] = json!("https://invalid");
    assert_eq!(h.post(&format!("{BASE}/enqueue"), wrong).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.get(&format!("{BASE}?arbitrary=1")).await.status, StatusCode::BAD_REQUEST);
    assert!(snapshot(&h).await? == before, "rejected input changed state");
    Ok(())
}
