//! 真实 MCP 入口及公开读取；不访问外部目标或伪造接入记录。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod runtime_audit_persistence_support;
use common::*;
use runtime_audit_persistence_support::*;

#[tokio::test]
async fn real_runtime_route_saves_sanitized_audit_and_keeps_public_array() {
    let h = setup().await;
    let reply = check(&h, "persist-route").await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    assert_eq!(reply.json()["allowed"], true);
    let records = records(&h).await;
    assert!(!records.is_empty());
    let facts = facts(&h).await;
    assert_eq!(facts.len(), records.len());
    assert!(!serde_json::to_string(&facts).unwrap().contains("owned-private-MCP-marker"));
    for record in &records {
        let id = record.id.to_string();
        let fact = facts.iter().find(|row| row.target.id.as_deref() == Some(id.as_str())).unwrap();
        assert_eq!(fact.after.as_ref().unwrap()["record_sha256"], record_hash(record));
        let proof = integrity(&h, record).await;
        assert_eq!(proof.status, StatusCode::OK, "{}", proof.text);
        assert_eq!(proof.json()["summary_matches"], true);
        assert_eq!(proof.json()["checkpoint_verified"], false);
        assert_eq!(proof.json()["audit_sequence"], fact.sequence);
    }
    let before = snapshot(&h).await;
    let events = h.get("/api/v1/runtime/events").await;
    assert_eq!(events.status, StatusCode::OK);
    let events = events.json();
    assert!(events.is_array());
    assert!(events.as_array().unwrap().iter().any(|row| row["id"] == records[0].id.to_string()));
    assert_eq!(snapshot(&h).await, before, "公开读取不得创建审计或重写记录");
}

#[tokio::test]
async fn exact_saved_record_retry_is_noop_and_different_bytes_conflict() {
    let h = setup().await;
    assert_eq!(check(&h, "persist-repeat").await.status, StatusCode::OK);
    let mut record = records(&h).await.remove(0);
    let principal = actor(&h).await;
    let before = snapshot(&h).await;
    let (first, second) = tokio::join!(
        agf_api::runtime_audit::persist(&h.state, &principal, &record),
        agf_api::runtime_audit::persist(&h.state, &principal, &record)
    );
    first.unwrap();
    second.unwrap();
    assert_eq!(snapshot(&h).await, before);
    record.reason.push_str("changed");
    record.entry_hash = record.compute_hash();
    assert!(matches!(
        agf_api::runtime_audit::persist(&h.state, &principal, &record).await,
        Err(agf_core::error::DomainError::Conflict(_))
    ));
    assert_eq!(snapshot(&h).await, before);
}

#[tokio::test]
async fn runtime_sink_rejects_wrong_tenant_or_invalid_record_hash() {
    let h = setup().await;
    assert_eq!(check(&h, "persist-invalid").await.status, StatusCode::OK);
    let mut record = records(&h).await.remove(0);
    let principal = actor(&h).await;
    let before = snapshot(&h).await;
    record.reason.push_str("tampered");
    assert!(agf_api::runtime_audit::persist(&h.state, &principal, &record).await.is_err());
    record.tenant_id = h.other_tenant;
    record.entry_hash = record.compute_hash();
    assert!(agf_api::runtime_audit::persist(&h.state, &principal, &record).await.is_err());
    assert_eq!(snapshot(&h).await, before);
}

#[tokio::test]
async fn offline_new_record_concurrency_commits_once_and_tamper_or_removed_proof_is_visible() {
    let h = setup().await;
    assert_eq!(check(&h, "persist-race").await.status, StatusCode::OK);
    let mut record = records(&h).await.remove(0);
    record.id = agf_core::ids::Id::new();
    record.seal();
    let principal = actor(&h).await;
    let count = facts(&h).await.len();
    let (first, second) = tokio::join!(
        agf_api::runtime_audit::persist(&h.state, &principal, &record),
        agf_api::runtime_audit::persist(&h.state, &principal, &record)
    );
    first.unwrap();
    second.unwrap();
    assert_eq!(facts(&h).await.len(), count + 1);
    let original: Value =
        h.state.configurations.get(h.tenant, "runtime-interception", record.id).await.unwrap().unwrap();
    let mut altered = record.clone();
    altered.reason.push_str("configuration-only rewrite");
    altered.seal();
    let mut raw = serde_json::to_value(&altered).unwrap();
    raw["_agf_management_audit_v1"] = original["_agf_management_audit_v1"].clone();
    h.state.configurations.put(h.tenant, "runtime-interception", record.id, &raw).await.unwrap();
    assert_eq!(integrity(&h, &record).await.json()["summary_matches"], false);
    raw.as_object_mut().unwrap().remove("_agf_management_audit_v1");
    h.state.configurations.put(h.tenant, "runtime-interception", record.id, &raw).await.unwrap();
    assert_eq!(integrity(&h, &record).await.json()["status"], "missing-proof");
    assert!(agf_api::runtime_audit::persist(&h.state, &principal, &altered).await.is_err());
    assert_eq!(facts(&h).await.len(), count + 1);
}

#[tokio::test]
async fn runtime_integrity_openapi_auth_and_current_api_key_path_match_the_real_routes() {
    let h = setup().await;
    let created =
        h.post("/api/v1/settings/api-keys", json!({"name":"owned-mcp-fact-key","scopes":["policies:read"]})).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let token = created.json()["plaintext"].as_str().unwrap().to_owned();
    let response = h
        .request_with(
            "POST",
            "/api/v1/runtime/mcp/check",
            &[("X-AGF-Key", &token)],
            Some(json!({"session_id":"real-key","frame":{"jsonrpc":"2.0","id":1,"method":"tools/list"}})),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let record = records(&h).await.remove(0);
    let path = format!("/api/v1/runtime/events/{}/integrity", record.id);
    assert_eq!(h.request("GET", &path, None, None).await.status, StatusCode::UNAUTHORIZED);
    let verified = h.request_with("GET", &path, &[("X-AGF-Key", &token)], None).await;
    assert_eq!(verified.status, StatusCode::OK, "{}", verified.text);
    assert_eq!(verified.json()["summary_matches"], true);
    let specification = h.get("/api/v1/openapi.json").await.json();
    let operation = &specification["paths"]["/api/v1/runtime/events/{id}/integrity"]["get"];
    assert_eq!(operation["x-required-permissions"], json!(["policies:read"]));
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/RecordIntegrity"
    );
    assert!(specification["components"]["schemas"]["RecordIntegrity"]["properties"]["checkpoint_verified"].is_object());
}
