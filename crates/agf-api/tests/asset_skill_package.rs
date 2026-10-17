//! Directory observations keep a recovery baseline, reject partial hashes and survive SQL reloads.
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
use agf_core::ids::Id;
use agf_ingest::pipeline::SqlSink;
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

async fn request(h: &Harness, method: &str, path: &str, body: Option<Value>) -> Resp {
    h.request_with(
        method,
        path,
        &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.tenant.to_string())],
        body,
    )
    .await
}

async fn verify(h: Harness, reader: Harness) {
    let mut body = json!({"collector_id":"package-collector","hostname":"package-host",
        "report":{"collector_id":"package-collector","collected_at":Timestamp::now(),"hostname":"package-host",
            "os":"windows/x86_64","agents":[],"mcp_configs":[],"credential_hits":[],"scan_scope":[],"agent_version":"0.1.0"},
        "extras":{"skills":[{"name":"Directory verification skill","kind":"skill","source_path":"fixture/SKILL.md",
            "content_sha256":"a".repeat(64),"content_hash_status":"verified"}]}});
    let ingested = request(&h, "POST", "/api/v1/ingest/agent", Some(body.clone())).await;
    assert_eq!(ingested.status, StatusCode::OK, "{}", ingested.text);
    let assets = request(&reader, "GET", "/api/v1/assets?q=Directory%20verification%20skill", None).await.json();
    let id = assets["items"][0]["id"].as_str().unwrap();
    let uri = format!("/api/v1/assets/{id}");
    let package =
        json!({"algorithm":"sha256-tree-v1","status":"verified","sha256":"B".repeat(64),"files":2,"bytes":46});
    body["extras"]["skills"][0]["package"] = package.clone();
    assert_eq!(request(&h, "POST", "/api/v1/ingest/agent", Some(body.clone())).await.status, StatusCode::OK);
    let first = request(&reader, "GET", &uri, None).await.json();
    assert_eq!(first["package_observation"]["current"]["sha256"], "b".repeat(64));
    assert_eq!(first["package_observation"]["current"]["files"], 2);
    assert!(
        first["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["field"] == "skill_package_observation" && row["risky"] == false)
    );
    assert!(!first["changes"].as_array().unwrap().iter().any(|row| row["field"] == "skill_package_sha256"));
    assert_eq!(request(&h, "POST", "/api/v1/ingest/agent", Some(body.clone())).await.status, StatusCode::OK);
    assert_eq!(
        request(&reader, "GET", &uri, None).await.json()["changes"],
        first["changes"],
        "heartbeat is not a change"
    );

    let latest = request(&reader, "GET", &uri, None).await.json();
    body["extras"]["skills"][0].as_object_mut().unwrap().remove("package");
    assert_eq!(request(&h, "POST", "/api/v1/ingest/agent", Some(body.clone())).await.status, StatusCode::OK);
    assert_eq!(
        request(&reader, "GET", &uri, None).await.json()["package_observation"],
        latest["package_observation"],
        "old collectors must not erase the directory observation or advance its timestamp"
    );

    body["extras"]["skills"][0]["package"] = json!({"algorithm":"sha256-tree-v1","status":"unreadable"});
    assert_eq!(request(&h, "POST", "/api/v1/ingest/agent", Some(body.clone())).await.status, StatusCode::OK);
    let unavailable = request(&reader, "GET", &uri, None).await.json();
    assert!(unavailable["package_observation"]["current"]["sha256"].is_null());
    assert_eq!(unavailable["package_observation"]["last_verified"]["sha256"], "b".repeat(64));
    assert_eq!(unavailable["package_observation"]["last_verified_at"], latest["package_observation"]["received_at"]);

    for invalid in [
        json!({"algorithm":"sha256-tree-v1","status":"unreadable","sha256":"c".repeat(64)}),
        json!({"algorithm":"sha256-tree-v1","status":"verified","sha256":"c".repeat(64),"files":4097,"bytes":1}),
        json!({"algorithm":"sha256-tree-v1","status":"verified","sha256":"c".repeat(64),"files":1,"bytes":67_108_865}),
        json!({"algorithm":"sha256-tree-v2","status":"verified","sha256":"c".repeat(64),"files":1,"bytes":1}),
        json!({"algorithm":"sha256-tree-v1","status":"unknown"}),
    ] {
        body["extras"]["skills"][0]["package"] = invalid;
        assert_eq!(
            request(&h, "POST", "/api/v1/ingest/agent", Some(body.clone())).await.status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(request(&reader, "GET", &uri, None).await.json()["changes"], unavailable["changes"]);
    }
    body["extras"]["skills"][0]["package"] = package;
    body["extras"]["skills"][0]["package"]["sha256"] = json!("c".repeat(64));
    assert_eq!(request(&h, "POST", "/api/v1/ingest/agent", Some(body.clone())).await.status, StatusCode::OK);
    let changed = request(&reader, "GET", &uri, None).await.json();
    assert_eq!(changed["content_observation"]["sha256"], "a".repeat(64), "manifest did not change");
    assert_eq!(changed["package_observation"]["current"]["sha256"], "c".repeat(64));
    assert_eq!(changed["package_observation"]["last_verified"]["sha256"], "c".repeat(64));
    assert!(changed["changes"].as_array().unwrap().iter().any(|row| row["field"] == "skill_package_sha256"
        && row["old_value"] == "b".repeat(64)
        && row["new_value"] == "c".repeat(64)
        && row["risky"] == true));
    assert_eq!(request(&h, "POST", "/api/v1/ingest/agent", Some(body)).await.status, StatusCode::OK);
    assert_eq!(request(&reader, "GET", &uri, None).await.json()["changes"], changed["changes"]);
}

#[tokio::test]
async fn offline_directory_observation_contract_and_recovery() {
    let h = setup().await;
    verify(h.clone(), h).await;
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn sql_directory_observations_are_visible_to_fresh_instances() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let database = Database::from_pool(pool);
    database.migrate().await.unwrap();
    let db = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.ingest_sink = Arc::new(SqlSink::new(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    let tenant =
        agf_api::tenant_directory::new(format!("package-durability-{}", Id::new()), "Package SQL checks".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.tenant = tenant.id;
    h.app = build_router(h.state.clone());
    let mut reader = h.clone();
    reader.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    reader.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db)));
    reader.app = build_router(reader.state.clone());
    verify(h, reader).await;
}
