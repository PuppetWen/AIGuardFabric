//! Offline compatibility and honest SQL-only management boundaries, through the real HTTP router.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{asset::Asset, enums::AssetKind, ids::Id};
use common::*;

const BASE: &str = "/api/v1/alicloud/agentteams/role-mappings";
const MARKER: &str = "agf.agentteams.role_governed";

#[tokio::test]
async fn offline_catalog_does_not_invent_role_uuids_or_write_during_get() {
    let h = setup().await;
    let before = h.state.store.audit_stats_durable(h.tenant).await.unwrap();
    let response = h.get(BASE).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["catalogAvailable"], false);
    assert_eq!(response.json()["canManage"], false);
    assert_eq!(response.json()["roles"], json!([]));
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await.unwrap(), before);
    assert_eq!(h.request("GET", BASE, Some(&h.viewer), None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.request("GET", BASE, None, None).await.status, StatusCode::UNAUTHORIZED);
    let refused=h.request("PUT",&format!("{BASE}/{}",Id::new()),Some(&h.admin),
        Some(json!({"request_id":Id::new(),"expected_version":0,"confirm_local_constraint":true,"change":{"action":"disable"}}))).await;
    assert_eq!(refused.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await.unwrap(), before);
}
#[tokio::test]
async fn unmanaged_bound_and_unbound_keys_keep_original_scope_without_cloud_or_catalog() {
    let h = setup().await;
    assert_eq!(h.request("GET", "/api/v1/assets", Some(&h.api_key), None).await.status, StatusCode::OK);
    let asset = Asset::new(h.tenant, AssetKind::Agent, "owned-local-agent", "owned-unmanaged-role-compat");
    h.state.store.asset_upsert(&asset).unwrap();
    let issued = h.state.api_keys.issue(ApiKeyIssueRequest {
        bound_agent_id: Some(asset.id),
        scopes: vec![Permission::from_raw("assets:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "unmanaged", Timestamp::now())
    });
    h.state.store.api_key_insert(issued.record).unwrap();
    assert_eq!(h.request("GET", "/api/v1/assets", Some(&issued.plaintext), None).await.status, StatusCode::OK);
    assert_eq!(h.request("GET", BASE, Some(&issued.plaintext), None).await.status, StatusCode::FORBIDDEN);
    assert!(h.state.configurations.list::<Value>(h.tenant, "agentteams-role-governance").await.unwrap().is_empty());
}
#[tokio::test]
async fn governed_marker_without_directory_or_record_cannot_restore_original_key_permissions() {
    let h = setup().await;
    let mut asset = Asset::new(h.tenant, AssetKind::Agent, "owned-governed-agent", "owned-role-marker-only");
    asset.attributes.insert(MARKER.into(), json!(true));
    h.state.store.asset_upsert(&asset).unwrap();
    let issued = h.state.api_keys.issue(ApiKeyIssueRequest {
        bound_agent_id: Some(asset.id),
        scopes: vec![Permission::from_raw("*")],
        ..ApiKeyIssueRequest::named(h.tenant, "missing-mapping", Timestamp::now())
    });
    h.state.store.api_key_insert(issued.record).unwrap();
    assert_eq!(h.request("GET", "/api/v1/assets", Some(&issued.plaintext), None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.state.store.asset_get_durable(h.tenant, asset.id).await.unwrap().unwrap().attributes[MARKER], true);
}
