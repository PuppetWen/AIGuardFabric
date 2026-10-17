//! Model endpoint configuration, asset projection and success audit share one commit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::ids::Id;
use agf_storage::{AuditRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;

async fn call(h: &Harness, method: &str, path: &str, body: Option<Value>) -> Resp {
    h.request_with(
        method,
        path,
        &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.tenant.to_string())],
        body,
    )
    .await
}

fn input(name: &str, version: Option<u64>) -> Value {
    let mut value = json!({"name":name,"provider":"mock","model":"offline","base_url":"http://mock.invalid/v1"});
    if let Some(version) = version {
        value["expected_version"] = json!(version);
    }
    value
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn model_mutations_roll_back_when_success_audit_fails() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let database = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(database.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(database.clone())));
    let tenant = agf_api::tenant_directory::new(format!("model-audit-{}", Id::new()), "Model audit validation".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.tenant = tenant.id;
    h.app = build_router(h.state.clone());

    let constraint = format!("agf_test_model_audit_{}", Id::new().as_uuid().simple());
    let block = format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        tenant.id
    );
    sqlx::query(&block).execute(&pool).await.unwrap();
    let rejected_create = call(&h, "POST", "/api/v1/gateway/endpoints", Some(input("not committed", None))).await;
    assert!(!rejected_create.status.is_success(), "{}", rejected_create.text);
    assert_eq!(call(&h, "GET", "/api/v1/gateway/endpoints", None).await.json()["items"], json!([]));
    assert_eq!(call(&h, "GET", "/api/v1/models/endpoints", None).await.json()["total"], 0);
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();

    let created = call(&h, "POST", "/api/v1/gateway/endpoints", Some(input("committed model", None))).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let id = created.json()["id"].as_str().unwrap().to_owned();
    let path = format!("/api/v1/gateway/endpoints/{id}");
    let asset_path = format!("/api/v1/assets/{id}");
    let mut tx = database.db().begin_tenant(tenant.id).await.unwrap();
    let audit_before = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    sqlx::query(&block).execute(&pool).await.unwrap();
    let rejected_update = call(&h, "PUT", &path, Some(input("not committed", Some(1)))).await;
    let rejected_delete = call(&h, "DELETE", &format!("{path}?expected_version=1"), None).await;
    for response in [&rejected_update, &rejected_delete] {
        assert!(!response.status.is_success(), "audit failure cannot report success: {}", response.text);
    }
    let listed = call(&h, "GET", "/api/v1/gateway/endpoints", None).await.json();
    assert_eq!(listed["items"][0]["name"], "committed model");
    assert_eq!(listed["items"][0]["version"], 1);
    let asset = call(&h, "GET", &asset_path, None).await.json();
    assert_eq!(asset["asset"]["name"], "committed model");
    assert_eq!(asset["asset"]["attributes"]["enabled"], true);
    let mut tx = database.db().begin_tenant(tenant.id).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), audit_before);
    tx.commit().await.unwrap();
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();

    let updated = call(&h, "PUT", &path, Some(input("updated model", Some(1)))).await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text);
    assert_eq!(updated.json()["version"], 2);
    let deleted = call(&h, "DELETE", &format!("{path}?expected_version=2"), None).await;
    assert_eq!(deleted.status, StatusCode::OK, "{}", deleted.text);
    assert_eq!(call(&h, "GET", "/api/v1/gateway/endpoints", None).await.json()["items"], json!([]));
    pool.close().await;
}
