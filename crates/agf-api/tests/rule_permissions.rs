//! Rule edits reject stale revisions atomically; readers receive matching capabilities.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::ids::Id;
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

fn yaml(key: &str, name: &str) -> String {
    format!(
        "key: {key}\nname: {name}\ndomain: prompt-attack\nseverity: high\nkind: keyword\ntarget: prompt\naction: deny\ndetection:\n  type: keyword\n  any: [tenantMarker]\nsamples:\n  positive: [tenantMarker]\n  negative: [clean]\n"
    )
}
async fn call(h: &Harness, method: &str, path: &str, body: Option<Value>) -> Resp {
    h.request_with(
        method,
        path,
        &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.tenant.to_string())],
        body,
    )
    .await
}
async fn verify(h: &Harness) {
    let key = "VERSIONED-RULE";
    let path = format!("/api/v1/rules/{key}");
    let body = json!({"yaml":yaml(key,"Original"),"expectedVersion":0});
    assert_eq!(call(h, "POST", "/api/v1/rules", Some(body.clone())).await.status, StatusCode::OK);
    assert_eq!(call(h, "POST", "/api/v1/rules", Some(body)).await.status, StatusCode::CONFLICT);
    let reader = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("rules:read"), Permission::from_raw("findings:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "governance-reader", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&reader.record).await.unwrap();
    let headers = [("x-agf-key", reader.plaintext.as_str())];
    let rules = h.request_with("GET", "/api/v1/rules", &headers, None).await.json();
    assert_eq!(rules["can_write"], false);
    assert!(rules["items"].as_array().unwrap().iter().all(|r| r["read_only"] == true));
    assert_eq!(h.request_with("GET", &path, &headers, None).await.json()["can_write"], false);
    assert_eq!(h.request_with("GET", "/api/v1/findings", &headers, None).await.json()["can_write"], false);
    for (method, url, body) in [
        ("PATCH", path.clone(), json!({"enabled":false})),
        ("POST", format!("{path}/test"), json!({})),
        ("POST", format!("{path}/versions/1/restore"), json!({})),
        ("POST", format!("/api/v1/findings/{}/status", Id::new()), json!({"status":"fixed"})),
    ] {
        assert_eq!(h.request_with(method, &url, &headers, Some(body)).await.status, StatusCode::FORBIDDEN, "{url}");
    }
    assert_eq!(call(h, "GET", "/api/v1/rules", None).await.json()["can_write"], true);
    assert_eq!(call(h, "GET", "/api/v1/findings", None).await.json()["can_write"], true);
    let patch = json!({"rolloutPercent":25,"expectedVersion":1});
    let edit = json!({"yaml":yaml(key,"Concurrent editor"),"sourceKey":key,"expectedVersion":1});
    let (first, second) =
        tokio::join!(call(h, "PATCH", &path, Some(patch)), call(h, "POST", "/api/v1/rules", Some(edit)));
    let mut codes = [first.status.as_u16(), second.status.as_u16()];
    codes.sort_unstable();
    assert_eq!(codes, [200, 409]);
    assert_eq!(call(h, "GET", &path, None).await.json()["rule"]["version"], 2);
    assert_eq!(
        call(h, "POST", &format!("{path}/versions/1/restore?expectedVersion=1"), Some(json!({}))).await.status,
        StatusCode::CONFLICT
    );
    let rename = json!({"yaml":yaml("RENAMED","Wrong key"),"sourceKey":key,"expectedVersion":2});
    assert_eq!(call(h, "POST", "/api/v1/rules", Some(rename)).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(call(h, "GET", "/api/v1/rules/RENAMED", None).await.status, StatusCode::NOT_FOUND);
    let restored = call(h, "POST", &format!("{path}/versions/1/restore?expectedVersion=2"), Some(json!({}))).await;
    assert_eq!(restored.status, StatusCode::OK, "{}", restored.text);
    assert_eq!(restored.json()["rule"]["name"], "Original");
    assert_eq!(restored.json()["rule"]["version"], 3);
    assert_eq!(call(h, "GET", &format!("{path}/versions"), None).await.json()["items"].as_array().unwrap().len(), 3);
}
#[tokio::test]
async fn offline_rule_conflicts_and_read_capabilities() {
    verify(&setup().await).await;
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn sql_rule_conflicts_survive_a_new_configuration_store() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let db = Database::from_pool(sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap());
    db.migrate().await.unwrap();
    let store = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store.clone())));
    h.tenant = agf_api::tenant_directory::save(
        &h.state,
        agf_api::tenant_directory::new(format!("rule-{}", Id::new()), "Rule verification".into()),
        true,
    )
    .await
    .unwrap()
    .id;
    h.app = build_router(h.state.clone());
    verify(&h).await;
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store)));
    h.app = build_router(h.state.clone());
    assert_eq!(call(&h, "GET", "/api/v1/rules/VERSIONED-RULE", None).await.json()["rule"]["version"], 3);
    let stale = json!({"yaml":yaml("VERSIONED-RULE","Old editor"),"expectedVersion":2});
    assert_eq!(call(&h, "POST", "/api/v1/rules", Some(stale)).await.status, StatusCode::CONFLICT);
}
