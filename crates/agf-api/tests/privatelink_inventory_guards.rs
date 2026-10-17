//! Exact request facts, current credentials and explicit archival are exercised through HTTP.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod privatelink_inventory_support;
use agf_core::{
    audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget},
    enums::LifecycleState,
    ids::Id,
};
use common::*;
use privatelink_inventory_support::*;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn strict_inputs_and_missing_explicit_endpoint_fail_before_dispatch() {
    let f = Fixture::new(false).await;
    let mut request = body(1);
    request["tenant_id"] = json!(f.h.other_tenant);
    assert_eq!(f.h.post(SYNC, request).await.status, StatusCode::BAD_REQUEST);
    let mut request = body(1);
    request["request_id"] = json!(Id::nil());
    assert_eq!(f.h.post(SYNC, request).await.status, StatusCode::BAD_REQUEST);
    let mut request = body(1);
    request["confirm_live"] = json!(false);
    assert_eq!(f.h.post(SYNC, request).await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(f.h.request("POST", SYNC, Some(&f.h.viewer), Some(body(1))).await.status, StatusCode::FORBIDDEN);
    let mut settings = f.settings.clone();
    settings.as_object_mut().unwrap().remove("endpoint_id");
    f.change(1, true, false, settings).await;
    assert_eq!(f.h.post(SYNC, body(2)).await.status, StatusCode::BAD_REQUEST);
    let mut settings = f.settings.clone();
    settings.as_object_mut().unwrap().remove("region_id");
    f.change(2, true, false, settings).await;
    assert_eq!(f.h.post(SYNC, body(3)).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(f.count(), 0);
    assert!(ledger(&f.h).await.is_none());
}

#[tokio::test]
async fn an_unknown_mock_target_is_not_synthesized_and_never_touches_the_loopback_provider() {
    let f = Fixture::new(true).await;
    let mut settings = f.settings.clone();
    settings["endpoint_id"] = json!("not-in-mock-directory");
    f.change(1, true, true, settings).await;
    let response = f.h.post(SYNC, body(2)).await;
    assert!(!response.status.is_success());
    assert_eq!(f.count(), 0);
    assert_eq!(publications(&f.h).await, 0);
    assert_eq!(assets(&f.h).await, json!([]));
    assert_eq!(f.h.get(VIEW).await.json()["topologyAvailable"], false);
}

#[tokio::test]
async fn identical_source_after_version_refresh_keeps_asset_identity_but_effective_mode_hides_old_topology() {
    let f = Fixture::new(false).await;
    success(&f.h, body(1)).await;
    let original = f.h.get(VIEW).await.json();
    let id = original["endpoint"]["assetId"].clone();
    f.change(1, true, false, f.settings.clone()).await;
    let unavailable = f.h.get(VIEW).await.json();
    assert_eq!(unavailable["topologyAvailable"], false);
    assert!(unavailable["endpoint"].is_null());
    success(&f.h, body(2)).await;
    let current = f.h.get(VIEW).await.json();
    assert_eq!(current["endpoint"]["assetId"], id);
    assert_ne!(current["scopeId"], original["scopeId"]);
    let mut shadow = f.h.clone();
    Arc::make_mut(&mut shadow.state.config).mock_mode = true;
    let tenant = shadow.tenant;
    shadow.app =
        build_router(shadow.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
            request.headers_mut().insert("x-agf-tenant", tenant.to_string().parse().unwrap());
            async move { request }
        }));
    assert_eq!(shadow.get(VIEW).await.json()["topologyAvailable"], false);
    assert_eq!(f.h.get(VIEW).await.json()["topologyAvailable"], true);
}

#[tokio::test]
async fn revoked_key_or_expired_lease_during_a_read_prevents_next_dispatch_and_publication() {
    for change in ["key", "lease"] {
        let mut f = Fixture::new(false).await;
        success(&f.h, body(1)).await;
        f.wait(GROUPS).await;
        let before = snapshot(&f.h).await;
        let published = publications(&f.h).await;
        let key = f.h.state.api_keys.issue(ApiKeyIssueRequest {
            scopes: vec![
                Permission::from_raw("alicloud:read"),
                Permission::from_raw("alicloud:write"),
                Permission::from_raw("assets:write"),
            ],
            ..ApiKeyIssueRequest::named(f.h.tenant, "owned-privatelink-reader", Timestamp::now())
        });
        f.h.state.store.api_key_create_durable(&key.record).await.unwrap();
        *f.blocked.lock().unwrap() = ZONES.into();
        let request = body(1);
        let h = f.h.clone();
        let token = key.plaintext.clone();
        let input = request.clone();
        let task = tokio::spawn(async move { h.request("POST", SYNC, Some(&token), Some(input)).await });
        f.wait(ZONES).await;
        if change == "key" {
            let revoked =
                f.h.request("DELETE", &format!("/api/v1/settings/api-keys/{}", key.record.id), Some(&f.h.admin), None)
                    .await;
            assert!(revoked.status.is_success(), "{}", revoked.text);
        } else {
            let mut row = ledger(&f.h).await.unwrap();
            row["active"]["expires_at"] = json!(Timestamp::now().offset_secs(-1));
            f.h.state
                .configurations
                .put(f.h.tenant, KIND, agf_api::integration_store::id(f.h.tenant, NAME), &row)
                .await
                .unwrap();
        }
        f.gate.add_permits(1);
        assert!(!task.await.unwrap().status.is_success());
        assert_eq!(snapshot(&f.h).await, before);
        assert_eq!(publications(&f.h).await, published);
        assert_eq!(f.count(), 5);
        let calls = f.count();
        assert_eq!(f.h.post(SYNC, request).await.status, StatusCode::OK);
        assert_eq!(f.count(), calls);
    }
}

#[tokio::test]
async fn explicit_user_removal_is_not_undone_by_rediscovery() {
    let f = Fixture::new(true).await;
    success(&f.h, body(1)).await;
    let previous = snapshot(&f.h).await;
    let published = publications(&f.h).await;
    let id: Id = serde_json::from_value(f.h.get(VIEW).await.json()["endpoint"]["assetId"].clone()).unwrap();
    let mut asset = f.h.state.store.asset_get(f.h.tenant, id).unwrap().unwrap();
    asset.lifecycle = LifecycleState::Archived;
    f.h.state.store.asset_upsert(&asset).unwrap();
    let audit = AppState::audit_entry(
        f.h.tenant,
        AuditAction::Delete,
        AuditOutcome::Success,
        AuditActor::system("owned-privatelink-removal"),
        AuditTarget::new("asset", Some(id.to_string()), None),
        "Owned explicit removal",
    );
    f.h.state
        .store
        .asset_remove_durable(f.h.tenant, id, asset.updated_at, &asset.name, "Owned user deletion", "owned-user", audit)
        .await
        .unwrap();
    assert_eq!(f.h.post(SYNC, body(1)).await.status, StatusCode::CONFLICT);
    assert!(f.h.state.store.asset_get(f.h.tenant, id).unwrap().is_none());
    assert_eq!(snapshot(&f.h).await, previous);
    assert_eq!(publications(&f.h).await, published);
}

async fn fill_capacity(h: &Harness) -> Vec<Value> {
    // Clone terminal evidence only to reach the bound; every claim/archive/replay still goes through actual HTTP.
    let mut record = ledger(h).await.unwrap();
    let template = record["runs"].as_object().unwrap().values().next().unwrap().clone();
    let mut inputs = Vec::new();
    while record["runs"].as_object().unwrap().len() < 512 {
        let input = body(1);
        let id = input["request_id"].as_str().unwrap();
        let mut run = template.clone();
        run["request_id"] = json!(id);
        run["request_hash"] = json!(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&json!({"input":input,"scope":run["scope"]})).unwrap())
        ));
        record["runs"][id] = run;
        inputs.push(input);
    }
    record["generation"] = json!(512);
    h.state.configurations.put(h.tenant, KIND, agf_api::integration_store::id(h.tenant, NAME), &record).await.unwrap();
    inputs
}

#[tokio::test]
async fn archive_frees_full_capacity_preserves_snapshot_and_keeps_each_old_uuid_permanently_read_only() {
    let f = Fixture::new(true).await;
    success(&f.h, body(1)).await;
    let inputs = fill_capacity(&f.h).await;
    let previous = snapshot(&f.h).await;
    let original = assets(&f.h).await;
    assert_eq!(f.h.post(SYNC, body(1)).await.status, StatusCode::PRECONDITION_FAILED);
    let ids = inputs.iter().take(100).map(|input| input["request_id"].clone()).collect::<Vec<_>>();
    let archived = archive(&f.h, ids.clone()).await;
    assert_eq!(archived.status, StatusCode::OK, "{}", archived.text);
    assert_eq!(archived.json()["archivedCount"], 100);
    assert_eq!(ledger(&f.h).await.unwrap()["runs"].as_object().unwrap().len(), 412);
    assert_eq!(snapshot(&f.h).await, previous);
    assert_eq!(assets(&f.h).await, original);
    let replay = f.h.post(SYNC, inputs[0].clone()).await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(replay.json()["status"], "archived");
    assert_eq!(replay.json()["originalStatus"], "succeeded");
    assert_eq!(archive(&f.h, ids).await.status, StatusCode::OK);
    success(&f.h, body(1)).await;
    let mut changed = inputs[0].clone();
    changed["confirm_live"] = json!(false);
    assert_eq!(f.h.post(SYNC, changed).await.status, StatusCode::CONFLICT);
    f.change(1, false, true, f.settings.clone()).await;
    assert_eq!(archive(&f.h, vec![inputs[100]["request_id"].clone()]).await.status, StatusCode::OK);
    assert_eq!(f.h.post(SYNC, inputs[100].clone()).await.status, StatusCode::CONFLICT);
    assert_eq!(f.count(), 0);
}
