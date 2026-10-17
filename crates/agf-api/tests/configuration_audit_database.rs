//! Vendor and cloud settings must roll back if their success audit cannot be stored.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::{cloud_store, integration_store};
use agf_core::ids::Id;
use agf_storage::{AuditRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;

const VENDOR: &str = "/api/v1/integrations/adapters/webhook/configuration";
const CLOUD: &str = "/api/v1/alicloud/connections/alicloud-cms";

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn vendor_and_cloud_configuration_roll_back_when_audit_fails() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store)));
    let tenant =
        agf_api::tenant_directory::new(format!("configuration-audit-{}", Id::new()), "Configuration audit test".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.app = build_router(h.state.clone());
    let token = format!("Bearer {}", h.admin);
    let tenant_id = tenant.id.to_string();
    let headers = [("authorization", token.as_str()), ("x-agf-tenant", tenant_id.as_str())];

    let vendor = json!({"expected_version":0,"enabled":true,"mock":true,"settings":{},
        "secrets":{"webhook_url":"http://127.0.0.1:18088/audit-test"}});
    let cloud = json!({"expected_version":0,"enabled":true,"mock":true,
        "settings":{"region_id":"cn-hangzhou"}});
    for (path, body) in [(VENDOR, &vendor), (CLOUD, &cloud)] {
        let response = h.request_with("PUT", path, &headers, Some(body.clone())).await;
        assert_eq!(response.status, StatusCode::OK, "{path}: {}", response.text);
        assert_eq!(response.json()["version"], 1);
    }
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    let before = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    let constraint = format!("agf_test_config_audit_{}", Id::new().as_uuid().simple());
    let sql = format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        tenant.id
    );
    sqlx::query(&sql).execute(&pool).await.unwrap();
    let updates = [(VENDOR, vendor), (CLOUD, cloud)].map(|(path, mut body)| {
        body["expected_version"] = json!(1);
        body["enabled"] = json!(false);
        (path, body)
    });
    for (path, body) in &updates {
        let failed = h.request_with("PUT", path, &headers, Some(body.clone())).await;
        assert!(!failed.status.is_success(), "{path}: {}", failed.text);
        let (kind, id) = if *path == VENDOR {
            (integration_store::KIND, integration_store::id(tenant.id, "webhook"))
        } else {
            (cloud_store::KIND, integration_store::id(tenant.id, "alicloud-cms"))
        };
        let stored =
            h.state.configurations.get::<integration_store::Stored>(tenant.id, kind, id).await.unwrap().unwrap();
        assert_eq!(stored.version, 1, "{path}");
        assert!(stored.enabled, "{path}");
        let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
        assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), before);
        tx.commit().await.unwrap();
    }
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();
    for (path, body) in updates {
        let saved = h.request_with("PUT", path, &headers, Some(body)).await;
        assert_eq!(saved.status, StatusCode::OK, "{path}: {}", saved.text);
        assert_eq!(saved.json()["version"], 2);
    }
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    assert_ne!(AuditRepo::chain_stats(&mut tx).await.unwrap(), before);
    tx.commit().await.unwrap();
    pool.close().await;
}
