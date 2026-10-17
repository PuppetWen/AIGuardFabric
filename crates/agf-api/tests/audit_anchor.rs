//! 真实已认证 HTTP 路由、签名前缀完整性，以及明确的历史及 Mock 语义。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{
    audit::{AgentAuditBatch, AuditAction, AuditActor, AuditLog, AuditOutcome, AuditTarget, SignedAuditAnchor},
    enums::AssetKind,
    ids::Id,
};
use agf_storage::audit_anchor::AuditAnchorSigner;
use common::*;

#[path = "audit_anchor/contract.rs"]
mod contract;

async fn key(h: &Harness) -> (String, Id) {
    assert!(seed_ai_assets(h).await.status.is_success());
    let agent = asset_id_of(h, AssetKind::Agent);
    let response=h.post("/api/v1/settings/api-keys",json!({"name":"owned-audit-agent","scopes":["policies:read"],"bound_agent_id":agent,"expires_in_secs":3600})).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    (response.json()["plaintext"].as_str().unwrap().to_owned(), agent)
}
fn record(previous: &SignedAuditAnchor) -> AuditLog {
    let mut actor = AuditActor::system("agf-agent-mcp");
    actor.kind = "agent".into();
    actor.id = previous.agent_id;
    let mut entry = AuditLog {
        id: Id::new(),
        tenant_id: previous.anchor.tenant_id,
        sequence: previous.anchor.up_to_sequence + 1,
        action: AuditAction::Execute,
        outcome: AuditOutcome::Denied,
        actor,
        target: AuditTarget::new("mcp-policy-decision", None, None),
        before: None,
        after: Some(json!({"allowed":false,"input_sha256":"a".repeat(64)})),
        changed_fields: Vec::new(),
        request_id: None,
        error: None,
        note: "Actual policy denied; prompt omitted".into(),
        prev_hash: previous.anchor.tail_hash.clone(),
        entry_hash: String::new(),
        at: Timestamp::now(),
    };
    entry.seal();
    entry
}
async fn append(h: &Harness, key: &str, batch: &AgentAuditBatch) -> Resp {
    h.request("POST", "/api/v1/runtime/audit/anchors", Some(key), Some(serde_json::to_value(batch).unwrap())).await
}

#[tokio::test]
async fn current_agent_bound_key_bootstraps_appends_and_exact_retry_is_idempotent() {
    let h = setup().await;
    let (key, agent) = key(&h).await;
    let mut batch = AgentAuditBatch { chain_id: Id::new(), previous: None, entries: Vec::new() };
    let initial = append(&h, &key, &batch).await;
    assert_eq!(initial.status, StatusCode::OK, "{}", initial.text);
    assert_eq!(initial.json()["durable"], false);
    let checkpoint: SignedAuditAnchor = serde_json::from_value(initial.json()["checkpoint"].clone()).unwrap();
    assert_eq!(checkpoint.agent_id, Some(agent));
    assert_eq!(checkpoint.anchor.tenant_id, h.tenant);
    let signer = AuditAnchorSigner::from_base64(&h.state.config.security.master_key_b64).unwrap();
    signer.verify(&checkpoint, h.tenant, agf_core::audit::AuditChainKind::AgentRuntime, Some(agent)).unwrap();
    batch.entries.push(record(&checkpoint));
    batch.previous = Some(checkpoint);
    let response = append(&h, &key, &batch).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["checkpoint"]["anchor"]["up_to_sequence"], 1);
    let retry = append(&h, &key, &batch).await;
    assert_eq!(retry.status, StatusCode::OK);
    assert_eq!(retry.json()["replayed"], true);
    assert_eq!(retry.json()["checkpoint"], response.json()["checkpoint"]);
    // 重置本地状态不能重置同一已认证 Agent 的服务端链。
    let reset = append(&h, &key, &AgentAuditBatch { chain_id: Id::new(), previous: None, entries: Vec::new() }).await;
    assert!(reset.status.is_client_error() || reset.status.is_server_error());
}

#[tokio::test]
async fn unbound_identity_spoofed_tenant_hash_tamper_and_bad_signature_never_advance() {
    let h = setup().await;
    let (key, _) = key(&h).await;
    let batch = AgentAuditBatch { chain_id: Id::new(), previous: None, entries: Vec::new() };
    assert_eq!(append(&h, &h.admin, &batch).await.status, StatusCode::FORBIDDEN);
    assert_eq!(append(&h, &h.api_key, &batch).await.status, StatusCode::FORBIDDEN);
    let bootstrap = append(&h, &key, &batch).await;
    let previous: SignedAuditAnchor = serde_json::from_value(bootstrap.json()["checkpoint"].clone()).unwrap();
    let valid = AgentAuditBatch {
        chain_id: batch.chain_id,
        entries: vec![record(&previous)],
        previous: Some(previous.clone()),
    };
    let mut bad = valid.clone();
    bad.entries[0].tenant_id = h.other_tenant;
    bad.entries[0].seal();
    assert!(!append(&h, &key, &bad).await.status.is_success());
    bad = valid.clone();
    bad.entries[0].actor.id = Some(Id::new());
    bad.entries[0].seal();
    assert!(!append(&h, &key, &bad).await.status.is_success());
    bad = valid.clone();
    bad.entries[0].note = "tampered".into();
    assert!(!append(&h, &key, &bad).await.status.is_success());
    bad = valid.clone();
    bad.previous.as_mut().unwrap().anchor.signature = "0".repeat(64);
    assert!(!append(&h, &key, &bad).await.status.is_success());
    assert_eq!(append(&h, &key, &batch).await.json()["checkpoint"], serde_json::to_value(&previous).unwrap());
    assert_eq!(append(&h, &key, &valid).await.status, StatusCode::OK);
}

#[tokio::test]
async fn legacy_management_verify_does_not_create_or_claim_a_signed_checkpoint() {
    let h = setup().await;
    let before = h.state.store.audit_stats_durable(h.tenant).await.unwrap();
    let response = h.get("/api/v1/audit/verify").await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["passed"], true);
    assert_eq!(response.json()["anchoring"]["initial_checkpoint_required"], true);
    assert_eq!(response.json()["anchoring"]["fully_anchored"], false);
    assert_eq!(response.json()["anchoring"]["latest"], Value::Null);
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await.unwrap(), before);
}
