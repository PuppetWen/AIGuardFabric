//! Owned PostgreSQL and genuine signed HTTP; no cloud provider is used.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod configuration_audit_support;
mod privatelink_provisioning_database_support;
mod privatelink_provisioning_support;
use agf_core::{error::DomainResult, ids::Id};
use common::*;
use privatelink_provisioning_database_support::{
    Case,
    engine::{self, Engine, Mode},
    fault,
};
use privatelink_provisioning_support as p;
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL"]
async fn two_instances_same_uuid_claim_only_one_signed_write() -> DomainResult<()> {
    let c = Case::open("privatelink-dual").await?;
    let e = Engine::start().await?;
    let h = engine::route(c.inner.h.clone(), &e)?;
    engine::configure(&h, &e, 0, true, "consumer").await?;
    let p1 = p::preview(&h, json!({"action":"create","target":p::target()})).await?;
    let body = p::apply_body(&h, p::id(&p1, "requestId")?, Id::new(), false).await?;
    let (gate, _release) = e.hold(1)?;
    let pending =
        privatelink_provisioning_database_support::pending(h.clone(), format!("{}/apply", p::BASE), body.clone());
    gate.wait_entered().await?;
    let second = engine::route(c.inner.second_instance().await, &e)?;
    let duplicate = p::post(&second, &format!("{}/apply", p::BASE), body.clone()).await?;
    assert_eq!(duplicate["phase"], "started");
    gate.release();
    let r = pending.finish().await?;
    assert_eq!(r.status, StatusCode::OK);
    let before = p::snapshot(&h).await?;
    p::post(&second, &format!("{}/apply", p::BASE), body).await?;
    assert!(p::snapshot(&h).await? == before, "duplicate changed durable snapshot");
    assert_eq!(e.writes()?, 1);
    p::chain(&h).await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL"]
async fn known_ack_terminal_audit_failure_retains_aad_and_disabled_local_recovery() -> DomainResult<()> {
    let c = Case::open("privatelink-terminal").await?;
    let e = Engine::start().await?;
    let h = engine::route(c.inner.h.clone(), &e)?;
    engine::configure(&h, &e, 0, true, "consumer").await?;
    let preview = p::preview(&h, json!({"action":"create","target":p::target()})).await?;
    let id = Id::new();
    let body = p::apply_body(&h, p::id(&preview, "requestId")?, id, false).await?;
    fault::terminal(&c, "privatelink-provisioning-fact", || async {
        let r = h.post(&format!("{}/apply", p::BASE), body.clone()).await;
        assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
        Ok(())
    })
    .await?;
    let result = p::get(&h, &format!("{}/requests/{id}", p::BASE)).await?;
    assert_eq!(result["completionState"], "pending_audit");
    assert_eq!(result["result"]["delivery"], "acknowledged");
    engine::configure(&h, &e, 1, false, "consumer").await?;
    let second = engine::route(c.inner.second_instance().await, &e)?;
    let r = p::post(&second, &format!("{}/requests/{id}/recover-local", p::BASE), json!({})).await?;
    assert_eq!(r["completionState"], "complete");
    assert_eq!(r["sourceCurrent"], false);
    assert_eq!(e.count()?, 1);
    let before = p::snapshot(&h).await?;
    p::post(&second, &format!("{}/requests/{id}/recover-local", p::BASE), json!({})).await?;
    assert!(p::snapshot(&h).await? == before, "duplicate local recovery changed storage");
    p::chain(&h).await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL"]
async fn unknown_write_cannot_escape_risk_by_account_label_or_source_revision() -> DomainResult<()> {
    let c = Case::open("privatelink-risk").await?;
    let e = Engine::start().await?;
    e.mode(Mode::Lost)?;
    let h = engine::route(c.inner.h.clone(), &e)?;
    engine::configure(&h, &e, 0, true, "consumer-a").await?;
    let preview = p::preview(&h, json!({"action":"create","target":p::target()})).await?;
    let id = Id::new();
    let body = p::apply_body(&h, p::id(&preview, "requestId")?, id, false).await?;
    let r = p::post(&h, &format!("{}/apply", p::BASE), body.clone()).await?;
    assert_eq!(r["result"]["delivery"], "unknown");
    engine::configure(&h, &e, 1, true, "consumer-b").await?;
    let retry = p::preview_body(&h, Id::new(), json!({"action":"create","target":p::target()})).await?;
    assert_eq!(h.post(&format!("{}/preview", p::BASE), retry).await.status, StatusCode::PRECONDITION_FAILED);
    let before = p::snapshot(&h).await?;
    p::post(&h, &format!("{}/apply", p::BASE), body).await?;
    p::post(&h, &format!("{}/requests/{id}/recover-local", p::BASE), json!({})).await?;
    assert!(p::snapshot(&h).await? == before, "Unknown replay changed facts");
    assert_eq!(e.writes()?, 1);
    p::chain(&h).await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL"]
async fn claim_audit_fault_has_zero_provider_and_preserves_preview() -> DomainResult<()> {
    let c = Case::open("privatelink-claim").await?;
    let e = Engine::start().await?;
    let h = engine::route(c.inner.h.clone(), &e)?;
    engine::configure(&h, &e, 0, true, "consumer").await?;
    let preview = p::preview(&h, json!({"action":"create","target":p::target()})).await?;
    let body = p::apply_body(&h, p::id(&preview, "requestId")?, Id::new(), false).await?;
    let before = p::snapshot(&h).await?;
    fault::terminal(&c, "privatelink-provisioning-claim", || async {
        let r = h.post(&format!("{}/apply", p::BASE), body.clone()).await;
        assert!(!r.status.is_success());
        Ok(())
    })
    .await?;
    assert!(p::snapshot(&h).await? == before, "failed claim changed reserve/provider state");
    assert_eq!(e.count()?, 0);
    p::chain(&h).await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL"]
async fn signed_create_then_independent_three_read_observation_and_accept() -> DomainResult<()> {
    let c = Case::open("privatelink-reference").await?;
    let e = Engine::start().await?;
    let h = engine::route(c.inner.h.clone(), &e)?;
    engine::configure(&h, &e, 0, true, "consumer").await?;
    let (original, _, _) = p::created(&h, false).await?;
    let observed = p::observe(&h, original).await?;
    assert_eq!(e.count()?, 4);
    assert_eq!(observed["result"]["requestedResourcesMatch"], true);
    let preview =
        p::preview(&h, json!({"action":"accept","observation_request_id":p::id(&observed,"requestId")?})).await?;
    let body = p::apply_body(&h, p::id(&preview, "requestId")?, Id::new(), false).await?;
    let r = p::post(&h, &format!("{}/apply", p::BASE), body).await?;
    assert_eq!(r["result"]["delivery"], "acknowledged");
    assert_eq!(e.writes()?, 2);
    assert_eq!(e.count()?, 5);
    p::chain(&h).await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL"]
async fn rejected_write_is_terminal_and_an_explicit_new_intent_is_separate() -> DomainResult<()> {
    let c = Case::open("privatelink-rejected").await?;
    let e = Engine::start().await?;
    e.mode(Mode::Rejected)?;
    let h = engine::route(c.inner.h.clone(), &e)?;
    engine::configure(&h, &e, 0, true, "consumer").await?;
    let preview = p::preview(&h, json!({"action":"create","target":p::target()})).await?;
    let id = Id::new();
    let body = p::apply_body(&h, p::id(&preview, "requestId")?, id, false).await?;
    let r = p::post(&h, &format!("{}/apply", p::BASE), body.clone()).await?;
    assert_eq!(r["result"]["delivery"], "rejected");
    e.mode(Mode::Acknowledged)?;
    let old = p::get(&h, &format!("{}/requests/{id}", p::BASE)).await?;
    p::post(&h, &format!("{}/apply", p::BASE), body).await?;
    assert_eq!(e.writes()?, 1);
    assert_eq!(old["result"]["delivery"], "rejected");
    p::created(&h, false).await?;
    assert_eq!(e.writes()?, 2);
    p::chain(&h).await
}
#[tokio::test]
#[ignore = "requires exact owned PostgreSQL"]
async fn canceled_received_write_never_respawns_provider_and_retains_unknown() -> DomainResult<()> {
    let c = Case::open("privatelink-cancel").await?;
    let e = Engine::start().await?;
    let h = engine::route(c.inner.h.clone(), &e)?;
    engine::configure(&h, &e, 0, true, "consumer").await?;
    let preview = p::preview(&h, json!({"action":"create","target":p::target()})).await?;
    let id = Id::new();
    let body = p::apply_body(&h, p::id(&preview, "requestId")?, id, false).await?;
    let (gate, _release) = e.hold(1)?;
    let task =
        privatelink_provisioning_database_support::pending(h.clone(), format!("{}/apply", p::BASE), body.clone());
    gate.wait_entered().await?;
    task.cancel().await?;
    gate.release();
    let r = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let r = p::get(&h, &format!("{}/requests/{id}", p::BASE)).await?;
            if r["result"]["delivery"] == "unknown" {
                break Ok::<_, agf_core::error::DomainError>(r);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| p::error("cancel did not retain original result"))??;
    assert_eq!(r["canRedispatch"], false);
    p::post(&h, &format!("{}/apply", p::BASE), body).await?;
    assert_eq!(e.writes()?, 1);
    p::chain(&h).await
}

#[tokio::test]
#[ignore = "requires exact owned PostgreSQL"]
async fn original_key_revoked_after_real_claim_audit_wait_rolls_back_everything() -> DomainResult<()> {
    let c = Case::open("privatelink-key-tail").await?;
    let e = Engine::start().await?;
    let admin = engine::route(c.inner.h.clone(), &e)?;
    engine::configure(&admin, &e, 0, true, "consumer").await?;
    let response = admin
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"owned-privatelink-sender","scopes":["alicloud:read","alicloud:write"]}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED);
    let data = response.json();
    let key = p::id(&data["api_key"], "id")?;
    let token = data["plaintext"].as_str().ok_or_else(|| p::error("synthetic Key absent"))?;
    let mut h = admin.clone();
    h.admin = token.to_owned();
    let preview = p::preview(&h, json!({"action":"create","target":p::target()})).await?;
    let body = p::apply_body(&h, p::id(&preview, "requestId")?, Id::new(), false).await?;
    privatelink_provisioning_database_support::authority::revoke_while_claim_waits(&c, &h, body, key, token).await?;
    assert_eq!(e.count()?, 0);
    p::chain(&admin).await
}
