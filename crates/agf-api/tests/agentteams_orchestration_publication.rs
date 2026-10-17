#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::ids::Id;
use common::*;
const BASE: &str = "/api/v1/alicloud/agentteams/orchestration-definitions";
const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-agentteams";
const KIND: &str = "agentteams-application-orchestration";
async fn snapshot(h: &Harness) -> Value {
    json!({"definition":h.state.configurations.list::<Value>(h.tenant,KIND).await.unwrap(),
        "connection":h.state.configurations.list::<Value>(h.tenant,"cloud-integration").await.unwrap(),
        "inventory":h.state.configurations.list::<Value>(h.tenant,"cloud-inventory").await.unwrap(),
        "audit":h.state.store.audit_stats_durable(h.tenant).await.unwrap()})
}

async fn prepared() -> (Harness, Value) {
    let h = setup().await;
    let configured = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true,"mock":true,
        "settings":{"instance_id":"owned-orchestration","region_id":"cn-hangzhou","account_id":"owned-no-cloud"}})),
        )
        .await;
    assert_eq!(configured.status, StatusCode::OK, "{}", configured.text);
    let sync = h
        .post(
            "/api/v1/alicloud/agentteams/sync",
            json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":false}),
        )
        .await;
    assert_eq!(sync.status, StatusCode::OK, "{}", sync.text);
    let state = h.get(BASE).await;
    assert_eq!(state.status, StatusCode::OK, "{}", state.text);
    assert_eq!(state.json()["modeSupported"], true);
    let target = state.json()["teams"][0].clone();
    (h, target)
}
fn path(target: &Value) -> String {
    format!("{BASE}/teams/{}", target["teamName"].as_str().unwrap())
}
fn body(target: &Value, version: u64, change: Value) -> Value {
    json!({"request_id":Id::new(),"expected_version":version,"configuration_version":target["source"]["configurationVersion"],
        "inventory_fingerprint":target["source"]["inventoryFingerprint"],"change":change,
        "confirm_application_owned":true,"confirm_mock_sync":true,"confirm_source_change":false})
}
fn document(target: &Value, name: &str) -> Value {
    let mut doc = target["template"].clone();
    doc["nodes"] = json!([{"node_id":"first","name":name,
        "agent_ids":[target["workers"][0]["name"]],"depends_on":[],"trigger":"manual"}]);
    doc
}
async fn save(h: &Harness, target: &Value, body: Value) -> Resp {
    h.request("PUT", &path(target), Some(&h.admin), Some(body)).await
}
#[tokio::test]
async fn local_save_push_changed_local_then_pull_is_explicit_and_original_get_never_reapplies() {
    let (h, target) = prepared().await;
    let first = body(&target, 0, json!({"action":"save_definition","definition":document(&target,"Original")}));
    let audit_before = h.state.store.audit_stats_durable(h.tenant).await.unwrap();
    let initial = snapshot(&h).await;
    let preview = h.post(&format!("{}/preview", path(&target)), first.clone()).await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.text);
    assert!(h.state.configurations.list::<Value>(h.tenant, KIND).await.unwrap().is_empty());
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await.unwrap(), audit_before);
    assert_eq!(snapshot(&h).await, initial);
    let original = save(&h, &target, first.clone()).await;
    assert_eq!(original.status, StatusCode::OK, "{}", original.text);
    assert_eq!(original.json()["receiverHash"], Value::Null);
    assert_eq!(original.json()["consumerApplied"], Value::Null);
    assert_eq!(original.json()["providerCalled"], false);
    assert_eq!(original.json()["durable"], false);
    let push = save(&h, &target, body(&target, 1, json!({"action":"sync","direction":"push"}))).await;
    assert_eq!(push.status, StatusCode::OK, "{}", push.text);
    assert_eq!(push.json()["localHash"], push.json()["receiverHash"]);
    assert_eq!(
        save(
            &h,
            &target,
            body(&target, 2, json!({"action":"save_definition","definition":document(&target,"New local")}))
        )
        .await
        .status,
        StatusCode::OK
    );
    let pull = save(&h, &target, body(&target, 3, json!({"action":"sync","direction":"pull"}))).await;
    assert_eq!(pull.status, StatusCode::OK, "{}", pull.text);
    let current = h.get(&path(&target)).await;
    assert_eq!(current.json()["local"]["nodes"][0]["name"], "Original");
    let before = h.state.configurations.list::<Value>(h.tenant, KIND).await.unwrap();
    let audit = h.state.store.audit_stats_durable(h.tenant).await.unwrap();
    let readonly = snapshot(&h).await;
    let receipt = h.get(&format!("{BASE}/requests/{}", first["request_id"].as_str().unwrap())).await;
    assert_eq!(receipt.json(), original.json());
    assert_eq!(save(&h, &target, first).await.json(), original.json());
    assert_eq!(h.state.configurations.list::<Value>(h.tenant, KIND).await.unwrap(), before);
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await.unwrap(), audit);
    assert_eq!(snapshot(&h).await, readonly);
    assert!(h.state.store.audit_verify_durable(h.tenant).await.unwrap().passed);
}
#[tokio::test]
async fn cas_unknown_receiver_invalid_import_and_reused_purpose_do_not_publish_a_success_audit() {
    let (h, target) = prepared().await;
    assert_eq!(
        save(&h, &target, body(&target, 0, json!({"action":"sync","direction":"pull"}))).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    let first = body(&target, 0, json!({"action":"save_definition","definition":document(&target,"Original")}));
    assert_eq!(save(&h, &target, first.clone()).await.status, StatusCode::OK);
    let before = h.state.configurations.list::<Value>(h.tenant, KIND).await.unwrap();
    let audit = h.state.store.audit_stats_durable(h.tenant).await.unwrap();
    assert_eq!(
        save(
            &h,
            &target,
            body(&target, 0, json!({"action":"save_definition","definition":document(&target,"Conflict")}))
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    let mut reused = first;
    reused["change"] = json!({"action":"sync","direction":"push"});
    assert_eq!(save(&h, &target, reused).await.status, StatusCode::CONFLICT);
    let mut unknown = document(&target, "Invalid");
    unknown["nodes"][0]["agent_ids"] = json!(["not-observed"]);
    assert_eq!(
        save(&h, &target, body(&target, 1, json!({"action":"save_definition","definition":unknown}))).await.status,
        StatusCode::BAD_REQUEST
    );
    let mut cycle = document(&target, "Cycle");
    cycle["nodes"][0]["depends_on"] = json!(["first"]);
    assert_eq!(
        save(&h, &target, body(&target, 1, json!({"action":"save_definition","definition":cycle}))).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(h.state.configurations.list::<Value>(h.tenant, KIND).await.unwrap(), before);
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await.unwrap(), audit);
}
#[tokio::test]
async fn readonly_permissions_and_disabled_source_keep_historical_receipts_without_writes() {
    let (h, target) = prepared().await;
    let first = body(&target, 0, json!({"action":"save_definition","definition":document(&target,"Original")}));
    let original = save(&h, &target, first.clone()).await;
    assert_eq!(original.status, StatusCode::OK);
    let uri = format!("{BASE}/requests/{}", first["request_id"].as_str().unwrap());
    assert_eq!(h.request("GET", BASE, None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h.request("PUT", &path(&target), Some(&h.viewer), Some(first.clone())).await.status,
        StatusCode::FORBIDDEN
    );
    let disabled = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":1,"enabled":false,"mock":true,
        "settings":{"instance_id":"owned-orchestration","region_id":"cn-hangzhou","account_id":"owned-no-cloud"}})),
        )
        .await;
    assert_eq!(disabled.status, StatusCode::OK, "{}", disabled.text);
    let before = h.state.configurations.list::<Value>(h.tenant, KIND).await.unwrap();
    let audit = h.state.store.audit_stats_durable(h.tenant).await.unwrap();
    assert_eq!(h.get(&uri).await.json(), original.json());
    assert_eq!(save(&h, &target, first).await.json(), original.json());
    assert_eq!(
        save(&h, &target, body(&target, 1, json!({"action":"sync","direction":"push"}))).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(h.state.configurations.list::<Value>(h.tenant, KIND).await.unwrap(), before);
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await.unwrap(), audit);
}

#[tokio::test]
async fn invalid_connection_aead_rejects_preview_and_commit_but_original_receipt_remains_pure() {
    let (h, target) = prepared().await;
    let first = body(&target, 0, json!({"action":"save_definition","definition":document(&target,"Original")}));
    let original = save(&h, &target, first.clone()).await;
    assert_eq!(original.status, StatusCode::OK);
    let receipt_uri = format!("{BASE}/requests/{}", first["request_id"].as_str().unwrap());
    let id = agf_api::integration_store::id(h.tenant, "alicloud-agentteams");
    let good = h
        .state
        .configurations
        .get::<agf_api::integration_store::Stored>(h.tenant, "cloud-integration", id)
        .await
        .unwrap()
        .unwrap();
    for key in ["aad", "ciphertext_b64"] {
        let mut invalid = good.clone();
        if key == "aad" {
            invalid.private.aad = Some("foreign-tenant-and-source".into());
        } else {
            invalid.private.ciphertext_b64 = "AAAA".into();
        }
        h.state.configurations.put(h.tenant, "cloud-integration", id, &invalid).await.unwrap();
        let before = snapshot(&h).await;
        let next = body(&target, 1, json!({"action":"save_definition","definition":document(&target,"Rejected")}));
        assert_eq!(
            h.post(&format!("{}/preview", path(&target)), next.clone()).await.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid connection AEAD must reject preview"
        );
        assert_eq!(
            save(&h, &target, next.clone()).await.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid connection AEAD must reject new publication"
        );
        assert_eq!(
            h.get(&format!("{BASE}/requests/{}", next["request_id"].as_str().unwrap())).await.status,
            StatusCode::NOT_FOUND
        );
        let historical = h.get(&receipt_uri).await;
        assert_eq!(historical.status, StatusCode::OK);
        assert_eq!(historical.json(), original.json());
        assert_eq!(historical.json()["providerCalled"], false);
        assert!(
            snapshot(&h).await == before,
            "rejected operations and history GET must leave all records and audit unchanged"
        );
        h.state.configurations.put(h.tenant, "cloud-integration", id, &good).await.unwrap();
    }
    assert!(h.state.store.audit_verify_durable(h.tenant).await.unwrap().passed);
}
