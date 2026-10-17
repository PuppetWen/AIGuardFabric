//! 持久签名检查点、管理员篡改、精确重放及原子回滚回归。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod audit_anchor_database_support;
mod common;
mod configuration_audit_support;
use agf_core::{
    audit::{
        AgentAuditBatch, AuditAction, AuditActor, AuditLog, AuditOutcome, AuditTarget, GENESIS_HASH, SignedAuditAnchor,
    },
    enums::AssetKind,
    error::DomainResult,
    ids::Id,
};
use audit_anchor_database_support::Owned;
use common::*;

fn record(tenant: TenantId) -> AuditLog {
    AuditLog {
        id: Id::new(),
        tenant_id: tenant,
        sequence: 0,
        action: AuditAction::Configure,
        outcome: AuditOutcome::Success,
        actor: AuditActor::system("owned-anchor-test"),
        target: AuditTarget::new("owned-audit-anchor", None, None),
        before: None,
        after: Some(json!({"enabled":true})),
        changed_fields: Vec::new(),
        request_id: None,
        error: None,
        note: "Original".into(),
        prev_hash: GENESIS_HASH.into(),
        entry_hash: String::new(),
        at: Timestamp::now(),
    }
}
async fn add(owned: &Owned) -> DomainResult<()> {
    owned.case.h.state.store.audit_append_durable(record(owned.case.h.tenant)).await?;
    Ok(())
}
async fn append(h: &Harness, key: &str, batch: &AgentAuditBatch) -> Resp {
    h.request("POST", "/api/v1/runtime/audit/anchors", Some(key), Some(serde_json::to_value(batch).unwrap())).await
}
async fn key(h: &Harness) -> (String, Id) {
    assert!(seed_ai_assets(h).await.status.is_success());
    let agent = asset_id_of(h, AssetKind::Agent);
    let response=h.post("/api/v1/settings/api-keys",json!({"name":"owned-anchor-agent","scopes":["policies:read"],"bound_agent_id":agent,"expires_in_secs":3600})).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    (response.json()["plaintext"].as_str().unwrap().to_owned(), agent)
}

#[path = "audit_anchor_database/agent.rs"]
mod agent;
#[path = "audit_anchor_database/authority.rs"]
mod authority;
#[path = "audit_anchor_database/management.rs"]
mod management;

#[path = "audit_anchor_database/pool.rs"]
mod pool;
