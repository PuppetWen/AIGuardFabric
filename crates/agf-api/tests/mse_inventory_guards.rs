//! Current authority, lease expiry, strict inputs and offline removals never become published source success.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod mse_inventory_support;
use agf_core::{
    audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget},
    enums::LifecycleState,
    ids::Id,
};
use common::*;
use mse_inventory_support::*;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn revoked_key_or_expired_lease_after_provider_send_preserves_previous_snapshot() {
    for change in ["key", "lease"] {
        let mut f = Fixture::new(false).await;
        success(&f.h, body(1)).await;
        f.wait(1).await;
        let previous = snapshot(&f.h).await;
        let count = publications(&f.h).await;
        let key = f.h.state.api_keys.issue(ApiKeyIssueRequest {
            scopes: vec![
                Permission::from_raw("alicloud:read"),
                Permission::from_raw("alicloud:write"),
                Permission::from_raw("assets:write"),
            ],
            ..ApiKeyIssueRequest::named(f.h.tenant, "owned-mse-worker", Timestamp::now())
        });
        f.h.state.store.api_key_create_durable(&key.record).await.unwrap();
        f.blocked.store(1, Ordering::SeqCst);
        let request = body(1);
        let id = request["request_id"].as_str().unwrap().to_owned();
        let h = f.h.clone();
        let input = request.clone();
        let token = key.plaintext.clone();
        let task = tokio::spawn(async move { h.request("POST", SYNC, Some(&token), Some(input)).await });
        f.wait(1).await;
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
                .put(f.h.tenant, KIND, agf_api::integration_store::id(f.h.tenant, "alicloud-mse"), &row)
                .await
                .unwrap();
        }
        f.gate.add_permits(1);
        let rejected = task.await.unwrap();
        assert!(!rejected.status.is_success(), "{}", rejected.text);
        assert_eq!(snapshot(&f.h).await, previous);
        assert_eq!(publications(&f.h).await, count);
        let restored = f.h.get(&format!("{VIEW}/operations/{id}")).await;
        assert_eq!(restored.status, StatusCode::OK);
        assert_eq!(restored.json()["published"], false);
        let calls = f.count();
        let replay = f.h.post(SYNC, request).await;
        assert_eq!(replay.status, StatusCode::OK);
        assert_eq!(f.count(), calls);
    }
}

#[tokio::test]
async fn strict_configuration_and_input_fail_before_dispatch_or_claim() {
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
    let mut settings = f.settings.clone();
    settings.as_object_mut().unwrap().remove("namespace_id");
    f.change(1, true, false, settings).await;
    assert_eq!(f.h.post(SYNC, body(2)).await.status, StatusCode::BAD_REQUEST);
    assert!(ledger(&f.h).await.is_none());
    assert_eq!(f.count(), 0);
}

#[tokio::test]
async fn ordinary_offline_user_removal_is_not_undone_by_rediscovery() {
    let f = Fixture::new(true).await;
    success(&f.h, body(1)).await;
    let previous = snapshot(&f.h).await;
    let count = publications(&f.h).await;
    let id: Id = serde_json::from_value(f.h.get(VIEW).await.json()["items"][0]["assetId"].clone()).unwrap();
    let mut asset = f.h.state.store.asset_get(f.h.tenant, id).unwrap().unwrap();
    asset.lifecycle = LifecycleState::Archived;
    f.h.state.store.asset_upsert(&asset).unwrap();
    let audit = AppState::audit_entry(
        f.h.tenant,
        AuditAction::Delete,
        AuditOutcome::Success,
        AuditActor::system("owned-user-removal"),
        AuditTarget::new("asset", Some(id.to_string()), None),
        "Owned explicit removal",
    );
    f.h.state
        .store
        .asset_remove_durable(f.h.tenant, id, asset.updated_at, &asset.name, "Owned user deletion", "owned-user", audit)
        .await
        .unwrap();
    let response = f.h.post(SYNC, body(1)).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.text);
    assert!(f.h.state.store.asset_get(f.h.tenant, id).unwrap().is_none());
    assert_eq!(snapshot(&f.h).await, previous);
    assert_eq!(publications(&f.h).await, count);
}
