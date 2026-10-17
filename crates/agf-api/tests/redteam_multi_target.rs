mod common;
use agf_core::{asset::Asset, enums::AssetKind, error::DomainResult, ids::Id};
use common::*;
const BASE: &str = "/api/v1/redteam/multi-target";
async fn selections(h: &Harness) -> DomainResult<Value> {
    let mut rows = Vec::new();
    for (kind, asset_kind, ordinal) in
        [("agent", AssetKind::Agent, 0), ("mcp", AssetKind::McpServer, 1), ("agent", AssetKind::Agent, 2)]
    {
        let asset = Asset::new(h.tenant, asset_kind, format!("Preview {ordinal}"), "owned-test");
        h.state.store.asset_upsert(&asset)?;
        let mut body = json!({"id":Id::new(),"expected_version":0,"asset_id":asset.id,"name":"Explicit registered target",
            "url":format!("https://example.org/target{ordinal}"),"enabled":true,"protected_canary":"ProtectedPreview_123456"});
        if kind == "agent" {
            body["model"] = json!("owned-model");
        } else {
            body["tool_name"] = json!("safe_query");
            body["argument_name"] = json!("query");
        }
        let saved = h.post(&format!("/api/v1/redteam/{kind}-targets"), body).await;
        assert!(saved.status == StatusCode::OK, "Registered preview fixture was rejected");
        rows.push(json!({"kind":format!("{kind}-http"),"profile_id":saved.json()["id"],"expected_version":1}));
    }
    Ok(json!(rows))
}
fn run_body(targets: Value, preview: &Value) -> Value {
    json!({"request_id":Id::new(),"targets":targets,
    "reviewed_topology_sha256":preview["topologySha256"],"confirm_registered_targets":true,"confirm_live":true})
}
#[tokio::test]
async fn metadata_and_preview_are_pure_and_offline_execution_is_explicitly_unavailable() -> DomainResult<()> {
    let h = setup().await;
    let targets = selections(&h).await?;
    let before = h.state.store.audit_stats_durable(h.tenant).await?;
    let configurations: Vec<Value> = h.state.configurations.list(h.tenant, "redteam-multi-target-fact").await?;
    assert!(configurations.is_empty());
    let metadata = h.get(&format!("{BASE}/playbook")).await;
    assert_eq!(metadata.status, StatusCode::OK);
    let preview = h.post(&format!("{BASE}/preview"), json!({"targets":targets})).await;
    assert_eq!(preview.status, StatusCode::OK);
    assert!(
        preview.json()["requiresDatabase"] == true
            && preview.json()["topology"]["targets"].as_array().is_some_and(|rows| rows.len() == 3)
    );
    let rejected = h.post(&format!("{BASE}/runs"), run_body(targets, &preview.json())).await;
    assert!(rejected.status == StatusCode::PRECONDITION_FAILED, "Offline execution must not call an external target");
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await?, before);
    let after: Vec<Value> = h.state.configurations.list(h.tenant, "redteam-multi-target-fact").await?;
    assert!(after.is_empty());
    Ok(())
}
#[tokio::test]
async fn strict_confirmation_and_target_versions_fail_before_any_claim() -> DomainResult<()> {
    let h = setup().await;
    let mut targets = selections(&h).await?;
    let preview = h.post(&format!("{BASE}/preview"), json!({"targets":targets})).await;
    assert_eq!(preview.status, StatusCode::OK);
    let before = h.state.store.audit_stats_durable(h.tenant).await?;
    let mut body = run_body(targets.clone(), &preview.json());
    body["confirm_registered_targets"] = json!(false);
    assert_eq!(h.post(&format!("{BASE}/runs"), body).await.status, StatusCode::PRECONDITION_FAILED);
    targets[0]["expected_version"] = json!(2);
    assert_eq!(h.post(&format!("{BASE}/preview"), json!({"targets":targets})).await.status, StatusCode::CONFLICT);
    assert_eq!(
        h.post(&format!("{BASE}/preview"), json!({"targets":[],"prompt":"not supported"})).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await?, before);
    Ok(())
}
#[tokio::test]
async fn anonymous_and_foreign_uuid_receipts_never_initialize_a_run() -> DomainResult<()> {
    let h = setup().await;
    let anonymous = h.request("GET", &format!("{BASE}/playbook"), None, None).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    let before = h.state.store.audit_stats_durable(h.tenant).await?;
    assert_eq!(h.get(&format!("{BASE}/runs/{}", Id::new())).await.status, StatusCode::NOT_FOUND);
    let key = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("redteam:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "no-target-read", Timestamp::now())
    });
    h.state.store.api_key_insert(key.record)?;
    assert_eq!(
        h.request_with("GET", &format!("{BASE}/playbook"), &[("x-agf-key", &key.plaintext)], None).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await?, before);
    let rows: Vec<Value> = h.state.configurations.list(h.tenant, "redteam-multi-target-fact").await?;
    assert!(rows.is_empty());
    Ok(())
}
#[tokio::test]
async fn actual_openapi_lists_all_six_safe_routes_and_strict_confirmations() -> DomainResult<()> {
    let h = setup().await;
    let before = h.state.store.audit_stats_durable(h.tenant).await?;
    let response = h.get("/api/v1/openapi.json").await;
    assert_eq!(response.status, StatusCode::OK);
    let document = response.json();
    for (suffix, method) in [
        ("/playbook", "get"),
        ("/preview", "post"),
        ("/runs", "post"),
        ("/runs/{id}", "get"),
        ("/runs/{id}/cancel", "post"),
        ("/runs/{id}/recover", "post"),
    ] {
        let operation = &document["paths"][format!("{BASE}{suffix}")][method];
        assert!(operation["x-required-permissions"].as_array().is_some_and(|items| items.len() == 3));
        let reference = operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
            .as_str()
            .ok_or_else(|| agf_core::error::DomainError::Internal("Response schema reference absent".into()))?;
        assert!(document.pointer(reference.trim_start_matches('#')).is_some());
        if method == "post" {
            assert_eq!(
                operation["requestBody"]["content"]["application/json"]["schema"]["additionalProperties"],
                false
            );
        }
    }
    assert_eq!(
        document["components"]["schemas"]["RedteamMultiRun"]["properties"]["externalDefenseVerified"]["const"],
        false
    );
    for (suffix, method) in [
        ("/runs", "get"),
        ("/runs/{id}/archive", "post"),
        ("/profiles/{kind}/{id}/transport", "get"),
        ("/profiles/{kind}/{id}/transport", "put"),
    ] {
        let op = &document["paths"][format!("{BASE}{suffix}")][method];
        assert_eq!(op["x-never-dispatches"], true);
        let name = op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
            .as_str()
            .ok_or_else(|| agf_core::error::DomainError::Internal("Compatibility schema missing".into()))?;
        assert!(document.pointer(name.trim_start_matches('#')).is_some());
    }
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await?, before);
    Ok(())
}
#[tokio::test]
async fn owner_recent_get_never_initializes_capacity_index_fact_or_audit() -> DomainResult<()> {
    let h = setup().await;
    let before = h.state.store.audit_stats_durable(h.tenant).await?;
    let list = h.get(&format!("{BASE}/runs?limit=50&offset=255")).await;
    assert!(
        list.status == StatusCode::OK && list.json()["items"] == json!([]) && list.json()["completeHistory"] == false
    );
    assert_eq!(h.request("GET", &format!("{BASE}/runs"), None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.get(&format!("{BASE}/runs?limit=1&limit=2")).await.status, StatusCode::BAD_REQUEST);
    for kind in [
        "redteam-multi-target-fact",
        "redteam-multi-target-capacity",
        "redteam-multi-target-owner-index",
        "redteam-multi-managed-profile",
    ] {
        let rows: Vec<Value> = h.state.configurations.list(h.tenant, kind).await?;
        assert!(rows.is_empty());
    }
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await?, before);
    Ok(())
}
#[tokio::test]
async fn transport_read_is_exact_registered_metadata_and_offline_save_cannot_create_approval() -> DomainResult<()> {
    let h = setup().await;
    let targets = selections(&h).await?;
    let id = targets[1]["profile_id"]
        .as_str()
        .ok_or_else(|| agf_core::error::DomainError::Internal("Owned profile ID missing".into()))?;
    let path = format!("{BASE}/profiles/mcp-http/{id}/transport");
    let before = h.state.store.audit_stats_durable(h.tenant).await?;
    let result = h.get(&path).await;
    assert!(
        result.status == StatusCode::OK
            && result.json()["profileId"] == id
            && result.json()["version"] == 0
            && result.json()["defaultPrivateAccess"] == false
            && result.json()["settings"].is_null()
    );
    let saved = h
        .request(
            "PUT",
            &path,
            Some(&h.admin),
            Some(json!({"expected_version":0,"profile_version":1,
        "url":result.json()["url"],"enabled":true,"mcp_protocol_revision":"2025-11-25","private_network":null})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::PRECONDITION_FAILED);
    let rows: Vec<Value> = h.state.configurations.list(h.tenant, "redteam-multi-managed-profile").await?;
    assert!(rows.is_empty() && h.state.store.audit_stats_durable(h.tenant).await? == before);
    Ok(())
}
