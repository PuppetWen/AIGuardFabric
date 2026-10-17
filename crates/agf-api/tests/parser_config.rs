//! Parser changes affect real ingestion, survive registry rebuilds and remain tenant-scoped.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

fn input() -> Value {
    json!({"definition":{"key":"customer-test-parser","name":"Custom event","engine":"json-path","pattern":"$",
        "required_fields":["customer_signal"],"mapping":{"map":{"customer_signal":"event.action"}}},
        "sample":"{\"customer_signal\":\"created\"}", "enabled":true,"priority":1})
}
#[tokio::test]
async fn parser_authoring_is_validated_versioned_and_scoped() {
    let h = setup().await;
    assert_eq!(
        h.request("POST", "/api/v1/parsers", Some(&h.viewer), Some(input())).await.status,
        StatusCode::FORBIDDEN
    );
    let before = h.state.ingest_sink.event_count(h.tenant).await.unwrap();
    assert_eq!(h.post("/api/v1/parsers/validate", input()).await.status, StatusCode::OK);
    assert_eq!(h.state.ingest_sink.event_count(h.tenant).await.unwrap(), before);
    let created = h.post("/api/v1/parsers", input()).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let id = created.json()["id"].as_str().unwrap().to_owned();
    let uri = format!("/api/v1/parsers/{id}");
    let preview = h.get(&format!("{uri}/preview")).await.json();
    assert_eq!(preview["editable"], true);
    assert_eq!(preview["outcome"]["matched"], true);
    assert_eq!(h.post("/api/v1/parsers", input()).await.status, StatusCode::CONFLICT);
    assert_eq!(h.get("/api/v1/parsers?q=customer-test-parser").await.json()["total"], 1);
    let other = h
        .request_with(
            "GET",
            &format!("{uri}/preview"),
            &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.other_tenant.to_string())],
            None,
        )
        .await;
    assert_eq!(other.status, StatusCode::NOT_FOUND);
    let mut edited = input();
    edited["definition"]["name"] = json!("Changed");
    edited["expected_version"] = json!(1);
    let saved = h.request("PUT", &uri, Some(&h.admin), Some(edited.clone())).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["version"], 2);
    assert_eq!(h.request("PUT", &uri, Some(&h.admin), Some(edited)).await.status, StatusCode::CONFLICT);
    assert_eq!(h.get(&format!("{uri}/history")).await.json()["items"].as_array().unwrap().len(), 2);
    let restored = h.post(&format!("{uri}/restore"), json!({"version":1,"expected_version":2})).await;
    assert_eq!(restored.status, StatusCode::OK, "{}", restored.text);
    assert_eq!(restored.json()["version"], 3);
    assert_eq!(h.get(&uri).await.json()["parser"]["name"], "Custom event");
    assert_eq!(
        h.request("DELETE", &uri, Some(&h.admin), Some(json!({"expected_version":2}))).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        h.request("DELETE", &uri, Some(&h.admin), Some(json!({"expected_version":3}))).await.status,
        StatusCode::OK
    );
    assert_eq!(h.get(&uri).await.status, StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn parser_updates_reload_live_source_without_resetting_ingest() {
    let h = setup().await;
    let created = h.post("/api/v1/parsers", input()).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let parser_id = created.json()["id"].as_str().unwrap().to_owned();
    let source =
        h.post("/api/v1/ingest/sources", json!({"name":"custom","protocol":"http-webhook","parserId":parser_id})).await;
    assert_eq!(source.status, StatusCode::CREATED, "{}", source.text);
    let uri = format!("/api/v1/ingest/sources/{}/events", source.json()["id"].as_str().unwrap());
    assert_eq!(h.post(&uri, json!({"customer_signal":"first"})).await.json()["matched"], 1);
    let mut edited = input();
    edited["definition"]["required_fields"] = json!(["customer_next"]);
    edited["definition"]["mapping"]["map"] = json!({"customer_next":"event.action"});
    edited["sample"] = json!("{\"customer_next\":\"new\"}");
    edited["expected_version"] = json!(1);
    let parser_uri = format!("/api/v1/parsers/{parser_id}");
    assert_eq!(h.request("PUT", &parser_uri, Some(&h.admin), Some(edited.clone())).await.status, StatusCode::OK);
    let new = h.post(&uri, json!({"customer_next":"second"})).await;
    assert_eq!(new.json()["matched"], 1, "{}", new.text);
    let list = h.get("/api/v1/parsers?q=customer-test-parser").await.json();
    assert_eq!(list["items"][0]["success_count"], 2, "{list}");
    let registry = agf_api::parser_store::registry(&h.state, h.tenant).await.unwrap();
    assert_eq!(registry.find_key("customer-test-parser").unwrap().definition.version, 2);
    let foreign = agf_api::parser_store::registry(&h.state, h.other_tenant).await.unwrap();
    assert!(foreign.find_key("customer-test-parser").is_none());
    edited["enabled"] = json!(false);
    edited["expected_version"] = json!(2);
    assert_eq!(h.request("PUT", &parser_uri, Some(&h.admin), Some(edited)).await.status, StatusCode::OK);
    assert_eq!(h.post(&uri, json!({"customer_next":"disabled"})).await.status, StatusCode::PRECONDITION_FAILED);
}
#[tokio::test]
async fn parser_rejects_bad_samples_plugins_and_system_overwrites() {
    let h = setup().await;
    let mut bad = input();
    bad["sample"] = json!("not-json");
    assert_eq!(h.post("/api/v1/parsers", bad).await.status, StatusCode::BAD_REQUEST);
    let mut bad = input();
    bad["definition"]["engine"] = json!("plugin");
    assert_eq!(h.post("/api/v1/parsers", bad).await.status, StatusCode::BAD_REQUEST);
    let mut bad = input();
    bad["definition"]["key"] = json!("aliyun-waf-webhook");
    assert_eq!(h.post("/api/v1/parsers", bad).await.status, StatusCode::CONFLICT);
}
