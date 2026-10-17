//! Real routing, persistent Mock reconciliation, alert lifecycle and bound SDK enforcement.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{
    asset::Asset,
    enums::{AlertState, AssetKind, LifecycleState},
    ids::Id,
};
use common::*;

const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-agentteams";
const INVENTORY: &str = "/api/v1/alicloud/agentteams/sync";
const BASE: &str = "/api/v1/alicloud/agentteams/worker-quotas";
const KIND: &str = "agentteams-worker-quota";

struct Fixture {
    h: Harness,
    asset: Id,
    quota: Id,
}

async fn fixture() -> Fixture {
    let h = setup().await;
    let config = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true,"mock":true,
        "settings":{"instance_id":format!("quota-{}",Id::new())}})),
        )
        .await;
    assert_eq!(config.status, StatusCode::OK, "{}", config.text);
    let sync = h.post(INVENTORY, json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":false})).await;
    assert_eq!(sync.status, StatusCode::OK, "{}", sync.text);
    let inventory = agf_api::cloud_inventory::load(&h.state, h.tenant).await.unwrap().unwrap();
    let asset = inventory.assets["worker-demo"];
    let saved = h
        .post(
            "/api/v1/quotas",
            json!({"name":"worker-only","scope":"agent","target_id":asset,
        "dimension":"tokens","window":"day","limit":100,"on_exceed":"deny","expected_version":0}),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let quota = Id::parse(saved.json()["quota"]["id"].as_str().unwrap()).unwrap();
    let result = h
        .request(
            "PUT",
            &format!("{BASE}/{asset}"),
            Some(&h.admin),
            Some(json!({
        "expected_version":0,"quota_id":quota,"quota_version":1,"enabled":true})),
        )
        .await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
    assert_eq!(result.json()["state"], "unverified");
    Fixture { h, asset, quota }
}

fn observe_body(request: Id) -> Value {
    json!({"request_id":request,"expected_binding_version":1,"expected_quota_version":1,
        "configuration_version":1,"confirm_live":false})
}
fn sync_body(preview: Id, request: Id) -> Value {
    let mut body = observe_body(request);
    body["preview_id"] = json!(preview);
    body
}
async fn observe(f: &Fixture, request: Id) -> Resp {
    f.h.post(&format!("{BASE}/{}/observe", f.asset), observe_body(request)).await
}
async fn sync(f: &Fixture, body: Value) -> Resp {
    f.h.post(&format!("{BASE}/{}/sync", f.asset), body).await
}
async fn row(f: &Fixture) -> Value {
    let response = f.h.get(BASE).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response.json()["items"][0].clone()
}

#[tokio::test]
async fn preview_sync_readback_alert_resolution_and_retry_are_real_and_idempotent() {
    let f = fixture().await;
    let preview = Id::new();
    let first = observe(&f, preview).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    assert_eq!(first.json()["binding"]["state"], "drift");
    let alert = Id::parse(first.json()["binding"]["driftAlertId"].as_str().unwrap()).unwrap();
    let stored = f.h.state.store.alert_get(f.h.tenant, alert).unwrap().unwrap();
    assert_eq!(stored.asset_ids, vec![f.asset]);
    assert!(stored.tags.contains(&"quota-drift".into()));
    assert_eq!(stored.dedup_count, 1);
    assert_eq!(observe(&f, Id::new()).await.status, StatusCode::OK);
    assert_eq!(f.h.state.store.alert_get(f.h.tenant, alert).unwrap().unwrap().dedup_count, 1);
    let current = row(&f).await;
    let current_preview = Id::parse(current["observation"]["id"].as_str().unwrap()).unwrap();
    let request = Id::new();
    let body = sync_body(current_preview, request);
    let result = sync(&f, body.clone()).await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
    assert_eq!(result.json()["operation"]["status"], "verified");
    assert_eq!(result.json()["operation"]["mocked"], true);
    assert_eq!(result.json()["operation"]["changed"], true);
    assert_eq!(result.json()["binding"]["state"], "in-sync");
    assert_eq!(result.json()["binding"]["observation"]["usageLimit"], 100);
    assert_eq!(result.json()["binding"]["observation"]["previewUsable"], false);
    for private in ["used_previews", "active", "observation_request_id", "cloud_id"] {
        assert!(result.json()["binding"].get(private).is_none(), "private storage field {private} must not leak");
    }
    assert!(result.json()["operation"].get("request_hash").is_none());
    assert_eq!(f.h.state.store.alert_get(f.h.tenant, alert).unwrap().unwrap().state, AlertState::Closed);
    assert_eq!(sync(&f, body).await.json()["operation"], result.json()["operation"]);
    let current = row(&f).await;
    assert_eq!(sync(&f, sync_body(current_preview, Id::new())).await.status, StatusCode::CONFLICT);
    assert_eq!(
        observe(&f, current_preview).await.status,
        StatusCode::CONFLICT,
        "consumed read request cannot reactivate preview"
    );
    assert_eq!(row(&f).await, current, "rejected consumed observe request must preserve verified readback");
    let fresh = observe(&f, Id::new()).await;
    assert_eq!(fresh.status, StatusCode::OK, "{}", fresh.text);
    assert_eq!(fresh.json()["observation"]["usageLimit"], 100, "fresh GetWorker must read stored Mock UpdateWorker");
    let runs = agf_api::integration_receipts::history(&f.h.state, f.h.tenant, "alicloud-agentteams").await.unwrap();
    assert_eq!(runs.iter().filter(|run| run["operation"] == "UpdateWorker").count(), 1);
    assert!(!result.text.contains("access_key_secret"));
}

#[tokio::test]
async fn stale_preview_quota_identity_and_cloud_version_never_update_a_worker() {
    let f = fixture().await;
    let preview = Id::new();
    assert_eq!(observe(&f, preview).await.status, StatusCode::OK);
    f.h.state
        .configurations
        .mutate::<Value, _>(f.h.tenant, KIND, f.asset, |row| {
            row["observation"]["observed_at"] = json!(Timestamp::now().offset_secs(-301));
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(sync(&f, sync_body(preview, Id::new())).await.status, StatusCode::CONFLICT);
    let preview = Id::new();
    assert_eq!(observe(&f, preview).await.status, StatusCode::OK);
    let changed =
        f.h.post(
            "/api/v1/quotas",
            json!({"name":"worker-only","scope":"agent","target_id":f.asset,
        "dimension":"tokens","window":"day","limit":101,"expected_version":1}),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    assert_eq!(row(&f).await["state"], "unverified");
    assert_eq!(sync(&f, sync_body(preview, Id::new())).await.status, StatusCode::CONFLICT);
    let update =
        f.h.request(
            "PUT",
            CONFIG,
            Some(&f.h.admin),
            Some(json!({"expected_version":1,"enabled":true,
        "mock":true,"settings":{"instance_id":"different-account-instance"}})),
        )
        .await;
    assert_eq!(update.status, StatusCode::OK, "{}", update.text);
    let list = f.h.get(BASE).await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.text);
    assert_eq!(list.json()["inventoryAvailable"], false);
    assert_eq!(list.json()["cloudVersion"], 2);
    assert_eq!(list.json()["items"][0]["state"], "stale");
    let disabled =
        f.h.request(
            "PUT",
            &format!("{BASE}/{}", f.asset),
            Some(&f.h.admin),
            Some(json!({
        "expected_version":1,"quota_id":f.quota,"quota_version":1,"enabled":false})),
        )
        .await;
    assert_eq!(disabled.status, StatusCode::OK, "{}", disabled.text);
    assert_eq!(disabled.json()["state"], "disabled");
    assert!(agf_api::quota_definitions::list(&f.h.state, f.h.tenant).await.unwrap()[0].enabled);
    let runs = agf_api::integration_receipts::history(&f.h.state, f.h.tenant, "alicloud-agentteams").await.unwrap();
    assert!(runs.iter().all(|run| run["operation"] != "UpdateWorker"));
}

#[tokio::test]
async fn expired_interrupted_run_can_be_observed_but_old_request_cannot_be_replayed() {
    let f = fixture().await;
    let request = Id::new();
    let run = agf_core::ids::deterministic_id("agf.worker-quota.run", &format!("{}:{}:{request}", f.h.tenant, f.asset));
    let body = sync_body(Id::new(), request);
    use sha2::{Digest, Sha256};
    let hash = format!("{:x}", Sha256::digest(serde_json::to_vec(&body).unwrap()));
    f.h.state
        .configurations
        .put(
            f.h.tenant,
            "agentteams-worker-quota-run",
            run,
            &json!({"id":run,
        "request_id":request,"request_hash":hash,"status":"started","started_at":Timestamp::now().offset_secs(-121),
        "finished_at":null,"mocked":true,"changed":false,"error":null,"observation":null}),
        )
        .await
        .unwrap();
    f.h.state
        .configurations
        .mutate::<Value, _>(f.h.tenant, KIND, f.asset, |row| {
            row["last_operation"] = json!(run);
            row["active"] = json!({"run_id":run,"expires_at":Timestamp::now().offset_secs(-1)});
            Ok(())
        })
        .await
        .unwrap();
    let current = row(&f).await;
    assert_eq!(current["busy"], false);
    assert_eq!(current["canObserve"], true);
    assert_eq!(current["lastOperation"]["status"], "uncertain");
    assert_eq!(sync(&f, body).await.status, StatusCode::CONFLICT);
    assert_eq!(observe(&f, Id::new()).await.status, StatusCode::OK);
    f.h.state
        .configurations
        .mutate::<Value, _>(f.h.tenant, KIND, f.asset, |row| {
            row["active"]["expires_at"] = json!(Timestamp::now().offset_secs(60));
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(row(&f).await["busy"], true);
    assert_eq!(observe(&f, Id::new()).await.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn same_preview_has_one_sync_winner_and_archived_worker_cannot_be_sent() {
    let f = fixture().await;
    let preview = Id::new();
    assert_eq!(observe(&f, preview).await.status, StatusCode::OK);
    let (a, b) = tokio::join!(sync(&f, sync_body(preview, Id::new())), sync(&f, sync_body(preview, Id::new())));
    assert_eq!(
        [a.status, b.status].iter().filter(|status| **status == StatusCode::OK).count(),
        1,
        "{} / {}",
        a.text,
        b.text
    );
    assert_eq!([a.status, b.status].iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    let preview = Id::new();
    assert_eq!(observe(&f, preview).await.status, StatusCode::OK);
    let mut asset = f.h.state.store.asset_get(f.h.tenant, f.asset).unwrap().unwrap();
    asset.lifecycle = LifecycleState::Archived;
    f.h.state.store.asset_upsert(&asset).unwrap();
    assert_eq!(row(&f).await["state"], "stale");
    assert_eq!(sync(&f, sync_body(preview, Id::new())).await.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn binding_requires_both_permissions_and_never_crosses_tenants() {
    let f = fixture().await;
    assert_eq!(f.h.request("GET", BASE, None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        f.h.request(
            "POST",
            &format!("{BASE}/{}/sync", f.asset),
            Some(&f.h.viewer),
            Some(sync_body(Id::new(), Id::new()))
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    let token = format!("Bearer {}", f.h.admin);
    let other = f.h.other_tenant.to_string();
    let headers = [("authorization", token.as_str()), ("x-agf-tenant", other.as_str())];
    let isolated = f.h.request_with("GET", BASE, &headers, None).await;
    assert_eq!(isolated.status, StatusCode::OK, "{}", isolated.text);
    assert_eq!(isolated.json()["items"], json!([]));
    let denied =
        f.h.request_with(
            "PUT",
            &format!("{BASE}/{}", f.asset),
            &headers,
            Some(json!({"expected_version":0,
        "quota_id":f.quota,"quota_version":1,"enabled":true})),
        )
        .await;
    assert!(!denied.status.is_success());
}

#[tokio::test]
async fn general_mock_partial_limit_updates_preserve_other_fields_and_unsupported_period_cannot_sync() {
    let f = fixture().await;
    let inventory = agf_api::cloud_inventory::load(&f.h.state, f.h.tenant).await.unwrap().unwrap();
    for (input, expected) in [(json!({"UsageLimit":200}), "day"), (json!({"PeriodType":"week"}), "week")] {
        let receipt = agf_api::cloud_runtime::execute(
            &f.h.state,
            f.h.tenant,
            "alicloud-agentteams",
            "mock-partial-test".into(),
            agf_api::cloud_runtime::Request {
                request_id: Id::new(),
                configuration_version: 1,
                action: "UpdateWorker".into(),
                parameters: json!({"Name":"worker-demo","InstanceId":inventory.instance_id,"LimitConfig":input}),
                confirm_live: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(receipt["status"], "succeeded");
        let preview = Id::new();
        let observed = observe(&f, preview).await;
        assert_eq!(observed.status, StatusCode::OK, "{}", observed.text);
        assert_eq!(observed.json()["observation"]["usageLimit"], 200);
        assert_eq!(observed.json()["observation"]["limitType"], "token");
        assert_eq!(observed.json()["observation"]["periodType"], expected);
        if expected == "week" {
            assert_eq!(sync(&f, sync_body(preview, Id::new())).await.status, StatusCode::PRECONDITION_FAILED);
        }
    }
}

#[tokio::test]
async fn openapi_documents_real_worker_routes_strict_requests_and_defined_bearer_security() {
    let h = setup().await;
    let response = h.get("/api/v1/openapi.json").await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let spec = response.json();
    assert_eq!(spec["components"]["securitySchemes"]["bearerAuth"]["scheme"], "bearer");
    assert_portable_json_keys(&spec);
    for (path, method, id) in [
        (BASE.into(), "get", "listWorkerQuotas"),
        (format!("{BASE}/{{id}}"), "put", "bindWorkerQuota"),
        (format!("{BASE}/{{id}}/observe"), "post", "observeWorkerQuota"),
        (format!("{BASE}/{{id}}/sync"), "post", "syncWorkerQuota"),
    ] {
        let op = &spec["paths"][&path][method];
        assert_eq!(op["operationId"], id);
        assert_eq!(op["security"], json!([{"bearerAuth":[]},{"apiKey":[]}]));
        assert_eq!(op["x-required-permissions"].as_array().unwrap().len(), 2);
        if method != "get" {
            assert_eq!(op["requestBody"]["content"]["application/json"]["schema"]["additionalProperties"], false);
        }
    }
    let sync =
        &spec["paths"][format!("{BASE}/{{id}}/sync")]["post"]["requestBody"]["content"]["application/json"]["schema"];
    assert!(sync["required"].as_array().unwrap().contains(&json!("preview_id")));
    assert_eq!(sync["properties"]["preview_id"]["format"], "uuid");
}

fn assert_portable_json_keys(value: &Value) {
    match value {
        Value::Object(fields) => {
            let normalized: std::collections::BTreeSet<_> =
                fields.keys().map(|name| name.to_ascii_lowercase()).collect();
            assert_eq!(
                normalized.len(),
                fields.len(),
                "case-insensitive clients must parse these keys: {:?}",
                fields.keys()
            );
            fields.values().for_each(assert_portable_json_keys);
        }
        Value::Array(items) => items.iter().for_each(assert_portable_json_keys),
        _ => {}
    }
}

#[tokio::test]
async fn bound_worker_sdk_requests_consume_platform_tokens_and_return_429_without_affecting_other_worker() {
    let f = fixture().await;
    let endpoint =
        f.h.post(
            "/api/v1/gateway/endpoints",
            json!({"name":"worker-sdk","provider":"mock",
        "model":"worker-model","base_url":"http://mock.invalid","local_deployment":true}),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let key =
        f.h.post(
            "/api/v1/settings/api-keys",
            json!({"name":"worker-sdk","bound_agent_id":f.asset,
        "scopes":["models:read","models:write"]}),
        )
        .await;
    assert_eq!(key.status, StatusCode::CREATED, "{}", key.text);
    let token = key.json()["plaintext"].as_str().unwrap().to_owned();
    let body = json!({"model":"auto","max_tokens":4,"messages":[{"role":"user","content":"hello"}]});
    let mut spent = 0;
    let mut rejected = false;
    for _ in 0..100 {
        let response = f.h.request("POST", "/v1/chat/completions", Some(&token), Some(body.clone())).await;
        if response.status == StatusCode::TOO_MANY_REQUESTS {
            rejected = true;
            break;
        }
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        spent += response.json()["usage"]["total_tokens"].as_i64().unwrap();
    }
    assert!(rejected, "bound Worker SDK must encounter a real gateway429");
    assert!(spent > 0);
    assert_eq!(agf_api::runtime_quota::usage(&f.h.state, f.h.tenant).await.unwrap()[&f.quota], spent);
    let other = Asset::new(f.h.tenant, AssetKind::Agent, "other-worker", "other-worker");
    f.h.state.store.asset_upsert(&other).unwrap();
    let key =
        f.h.post(
            "/api/v1/settings/api-keys",
            json!({"name":"other-sdk","bound_agent_id":other.id,
        "scopes":["models:read","models:write"]}),
        )
        .await;
    assert_eq!(key.status, StatusCode::CREATED, "{}", key.text);
    let other_token = key.json()["plaintext"].as_str().unwrap().to_owned();
    assert_eq!(
        f.h.request("POST", "/v1/chat/completions", Some(&other_token), Some(body)).await.status,
        StatusCode::OK
    );
    assert_eq!(agf_api::runtime_quota::usage(&f.h.state, f.h.tenant).await.unwrap()[&f.quota], spent);
}
