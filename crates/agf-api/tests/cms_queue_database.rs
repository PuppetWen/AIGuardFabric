//! Definitions only: the parent runner must supply an exact isolated database owner before migration.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod cms_queue_database_support;
mod cms_queue_support;
mod common;
mod configuration_audit_support;
use agf_core::{error::DomainResult, ids::Id};
use cms_queue_database_support::{
    self as db, Case,
    engine::{self, Mode},
};
use cms_queue_support as queue;
use common::*;

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_CMS_QUEUE_DATABASE_OWNER"]
async fn durable_two_instances_same_uuid_and_restart_have_one_signed_post() -> DomainResult<()> {
    let case = Case::open("cms-claim").await?;
    let (h, engine) = engine::fixture(&case).await?;
    let item = db::enqueue(&h).await?;
    let second = engine::route(case.inner.second_instance().await, &engine)?;
    let request = Id::new();
    let body = queue::send_input(&h, item, request).await?;
    let (gate, release) = engine.hold(1)?;
    let pending = db::Pending::start(h.clone(), format!("{}/send", queue::BASE), h.admin.clone(), body.clone());
    gate.wait_entered().await?;
    let duplicate = second.post(&format!("{}/send", queue::BASE), body.clone()).await;
    assert_eq!(duplicate.status, StatusCode::OK);
    assert_eq!(engine.count()?, 1);
    drop(release);
    assert_eq!(pending.finish().await?.status, StatusCode::OK);
    let original = db::receipt(&h, request).await?;
    assert_eq!(original["originalAttempts"][0]["outcome"]["delivery"], "accepted");
    let before = db::snapshot(&h).await?;
    let restarted = engine::route(case.inner.second_instance().await, &engine)?;
    assert!(db::receipt(&restarted, request).await? == original, "restart changed original receipt");
    queue::post(&restarted, &format!("{}/send", queue::BASE), body).await?;
    assert!(db::snapshot(&restarted).await? == before, "same UUID replay mutated durable records");
    assert_eq!(engine.count()?, 1);
    db::chain(&h).await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_CMS_QUEUE_DATABASE_OWNER"]
async fn accepted_post_terminal_audit_failure_retains_ack_and_disabled_local_recovery_is_network_free()
-> DomainResult<()> {
    let case = Case::open("cms-pending").await?;
    let (h, engine) = engine::fixture(&case).await?;
    let item = db::enqueue(&h).await?;
    let request = Id::new();
    db::fault::terminal(&case, || {
        Box::pin(async {
            let body = queue::send_input(&h, item, request).await?;
            let reply = h.post(&format!("{}/send", queue::BASE), body).await;
            assert!(reply.status.is_server_error(), "terminal audit fault must not claim published success");
            let response = db::receipt(&h, request).await?;
            assert_eq!(response["originalAttempts"][0]["completionState"], "pending_audit");
            assert_eq!(response["originalAttempts"][0]["outcome"]["delivery"], "accepted");
            assert_eq!(engine.count()?, 1);
            Ok(())
        })
    })
    .await?;
    engine::configure(&h, &engine, 1, false).await?;
    let fresh = engine::route(case.inner.second_instance().await, &engine)?;
    let local = db::recovered(&fresh, item).await?;
    assert_eq!(local["lastAttempt"]["completionState"], "complete");
    assert_eq!(local["lastAttempt"]["outcome"]["delivery"], "accepted");
    assert_eq!(engine.count()?, 1);
    let before = db::snapshot(&fresh).await?;
    db::recovered(&fresh, item).await?;
    assert!(db::snapshot(&fresh).await? == before, "duplicate local recovery mutated");
    db::chain(&fresh).await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_CMS_QUEUE_DATABASE_OWNER"]
async fn lost_ack_is_unknown_permanent_and_explicit_recovery_never_dispatches() -> DomainResult<()> {
    let case = Case::open("cms-unknown").await?;
    let (h, engine) = engine::fixture(&case).await?;
    let item = db::enqueue(&h).await?;
    engine.mode(Mode::Lost)?;
    let request = Id::new();
    let original = db::send(&h, item, request).await?;
    assert_eq!(original["originalAttempts"][0]["outcome"]["delivery"], "unknown");
    let before = db::snapshot(&h).await?;
    db::recovered(&h, item).await?;
    assert!(db::snapshot(&h).await? == before, "terminal Unknown was changed");
    let retry = queue::send_input(&h, item, Id::new()).await?;
    assert_eq!(h.post(&format!("{}/send", queue::BASE), retry).await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(engine.count()?, 1);
    db::chain(&h).await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_CMS_QUEUE_DATABASE_OWNER"]
async fn trusted_rejection_allows_only_five_explicit_new_intents() -> DomainResult<()> {
    let case = Case::open("cms-rejected").await?;
    let (h, engine) = engine::fixture(&case).await?;
    let item = db::enqueue(&h).await?;
    engine.mode(Mode::Rejected)?;
    for _ in 0..5 {
        assert_eq!(db::send(&h, item, Id::new()).await?["originalAttempts"][0]["outcome"]["delivery"], "rejected");
    }
    let before = db::snapshot(&h).await?;
    assert_eq!(
        h.post(&format!("{}/send", queue::BASE), queue::send_input(&h, item, Id::new()).await?).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    assert!(db::snapshot(&h).await? == before, "dead letter reused capacity");
    assert_eq!(engine.count()?, 5);
    db::chain(&h).await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_CMS_QUEUE_DATABASE_OWNER"]
async fn claim_audit_failure_rolls_back_before_any_provider_post() -> DomainResult<()> {
    let case = Case::open("cms-claim-fault").await?;
    let (h, engine) = engine::fixture(&case).await?;
    let item = db::enqueue(&h).await?;
    let before = db::snapshot(&h).await?;
    case.check().await?;
    let constraint = case.inner.block_audit().await;
    let reply = h.post(&format!("{}/send", queue::BASE), queue::send_input(&h, item, Id::new()).await?).await;
    case.check().await?;
    case.inner.unblock_audit(&constraint).await;
    assert!(reply.status.is_server_error());
    assert!(db::snapshot(&h).await? == before, "claim audit failure committed state");
    assert_eq!(engine.count()?, 0);
    db::chain(&h).await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_CMS_QUEUE_DATABASE_OWNER"]
async fn original_key_revocation_after_real_audit_wait_rolls_back_claim() -> DomainResult<()> {
    let case = Case::open("cms-revoke").await?;
    let (h, engine) = engine::fixture(&case).await?;
    let reply = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"owned-cms-revoke","scopes":["alicloud:read","alicloud:write"]}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED);
    let value = reply.json();
    let token = value["plaintext"].as_str().ok_or_else(|| db::error("Key absent"))?;
    let key = queue::id(&value["api_key"], "id")?;
    let body =
        json!({"request_id":Id::new(),"configuration_version":1,"expected_generation":0,"items":[queue::payload()]});
    let queued = h.request("POST", &format!("{}/enqueue", queue::BASE), Some(token), Some(body)).await;
    assert_eq!(queued.status, StatusCode::OK);
    let item = serde_json::from_value(queued.json()["itemIds"][0].clone())?;
    db::authority::revoke_while_claim_waits(&case, &h, item, key, token).await?;
    assert_eq!(engine.count()?, 0);
    db::chain(&h).await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_CMS_QUEUE_DATABASE_OWNER"]
async fn cancellation_after_received_post_retains_unknown_and_never_respawns_network() -> DomainResult<()> {
    let case = Case::open("cms-cancel").await?;
    let (h, engine) = engine::fixture(&case).await?;
    let item = db::enqueue(&h).await?;
    let request = Id::new();
    let (gate, release) = engine.hold(1)?;
    let pending = db::Pending::start(
        h.clone(),
        format!("{}/send", queue::BASE),
        h.admin.clone(),
        queue::send_input(&h, item, request).await?,
    );
    gate.wait_entered().await?;
    pending.cancel().await?;
    drop(release);
    tokio::time::timeout(tokio::time::Duration::from_secs(10), async {
        loop {
            let original = db::receipt(&h, request).await?;
            if original["originalAttempts"][0]["completionState"] == "pending_audit" {
                return Ok::<_, agf_core::error::DomainError>(());
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| db::error("cancelled claim did not retain local result"))??;
    assert_eq!(db::recovered(&h, item).await?["lastAttempt"]["outcome"]["delivery"], "unknown");
    let before = db::snapshot(&h).await?;
    db::receipt(&h, request).await?;
    db::recovered(&h, item).await?;
    assert!(db::snapshot(&h).await? == before, "cancelled original request changed after completion");
    assert_eq!(engine.count()?, 1);
    db::chain(&h).await
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_CMS_QUEUE_DATABASE_OWNER"]
async fn actual32_body_archive_batch_preserves_permanent_items_and_original_receipts() -> DomainResult<()> {
    let case = Case::open("cms-archive").await?;
    let h = case.inner.h.clone();
    queue::configure(&h, 0, true).await?;
    let mut items = Vec::new();
    let mut requests = Vec::new();
    for count in [20, 12] {
        let request = Id::new();
        let queued = queue::enqueue(&h, request, count, false).await?;
        items.extend(queued["itemIds"].as_array().ok_or_else(|| db::error("IDs absent"))?.clone());
        requests.push(request);
    }
    let state = db::state(&h).await?;
    let archive = queue::post(
        &h,
        &format!("{}/archive", queue::BASE),
        json!({"request_id":Id::new(),"expected_generation":queue::number(&state,"generation")?,"item_ids":items}),
    )
    .await?;
    assert_eq!(archive["changedCount"], 32);
    assert_eq!(db::state(&h).await?["storedContentBytes"], 0);
    let fresh = case.inner.second_instance().await;
    for request in requests {
        let receipt = db::receipt(&fresh, request).await?;
        assert!(
            receipt["items"]
                .as_array()
                .ok_or_else(|| db::error("items absent"))?
                .iter()
                .all(|item| item["archivedAt"].is_string())
        );
    }
    assert_eq!(fresh.state.configurations.list::<Value>(fresh.tenant, "cms-queue-body").await?.len(), 0);
    assert_eq!(fresh.state.configurations.list::<Value>(fresh.tenant, "cms-queue-item").await?.len(), 32);
    db::chain(&fresh).await
}
