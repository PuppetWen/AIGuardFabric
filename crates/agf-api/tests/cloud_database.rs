//! 使用专用 PostgreSQL 验证云配置、快照、回执与资产跨进程保存。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{audit::AuditActor, ids::Id};
use agf_storage::{AssetRepo, AuditRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;

fn test_actor() -> AuditActor {
    AuditActor {
        id: None,
        kind: "service".into(),
        name: "cloud-inventory-test".into(),
        source_ip: None,
        user_agent: None,
        session_id: None,
    }
}

#[tokio::test]
#[ignore = "requires AGF_TEST_DATABASE_URL pointing to the isolated requirements database"]
async fn cloud_inventory_and_receipts_survive_fresh_instances() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut first = setup().await;
    first.state.configurations = Arc::new(agf_api::config_store::ConfigStore::new(Some(store.clone())));
    first.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    let name = agf_api::cloud_inventory::NAME;
    let version =
        agf_api::cloud_store::load(&first.state, first.tenant, name).await.unwrap().map_or(0, |row| row.version);
    let account = Id::new().to_string();
    let cfg = serde_json::from_value(json!({"expected_version":version,"enabled":true,"mock":true,
        "settings":{"instance_id":"inst-demo","account_id":account}}))
    .unwrap();
    agf_api::cloud_store::save(&first.state, first.tenant, name, cfg).await.unwrap();
    let request_id = Id::new();
    let sync_request = || agf_api::cloud_inventory::SyncRequest {
        request_id,
        configuration_version: version + 1,
        confirm_live: false,
    };
    let synced =
        agf_api::cloud_inventory::sync(&first.state, first.tenant, "test".into(), test_actor(), sync_request())
            .await
            .unwrap();
    assert_eq!(synced["assets"], 1);
    let snapshot = agf_api::cloud_inventory::load(&first.state, first.tenant).await.unwrap().unwrap();
    let asset_id = snapshot.assets["worker-demo"];
    let mut tx = store.db().begin_tenant(first.tenant).await.unwrap();
    let asset = AssetRepo::get(&mut tx, asset_id).await.unwrap().unwrap();
    assert_eq!(asset.attributes["mock_mode"], true);
    let audits = AuditRepo::load_chain(&mut tx, 0, 1_000).await.unwrap();
    assert!(audits.iter().any(|entry| {
        entry.target.kind == "cloud-integration"
            && entry.target.name.as_deref() == Some(name)
            && entry.actor.name == "cloud-inventory-test"
    }));
    tx.commit().await.unwrap();
    let mut second = setup().await;
    second.state.configurations = Arc::new(agf_api::config_store::ConfigStore::new(Some(store.clone())));
    second.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    let loaded = agf_api::cloud_inventory::load(&second.state, first.tenant).await.unwrap().unwrap();
    assert_eq!(loaded.assets["worker-demo"], asset_id);
    agf_api::cloud_inventory::sync(&second.state, first.tenant, "test".into(), test_actor(), sync_request())
        .await
        .unwrap();
    assert_eq!(second.state.store.asset_list_all(first.tenant).unwrap().len(), 1);
    let history = second.state.configurations.list::<Value>(first.tenant, "integration-operation").await.unwrap();
    assert!(!history.is_empty());
    let mut foreign = store.db().begin_tenant(first.other_tenant).await.unwrap();
    assert!(AssetRepo::get(&mut foreign, asset_id).await.unwrap().is_none());
    foreign.commit().await.unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires AGF_TEST_DATABASE_URL pointing to the isolated requirements database"]
async fn cloud_snapshot_failure_rolls_back_discovered_assets() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.configurations = Arc::new(agf_api::config_store::ConfigStore::new(Some(store.clone())));
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    let name = agf_api::cloud_inventory::NAME;
    let version = agf_api::cloud_store::load(&h.state, h.tenant, name).await.unwrap().map_or(0, |row| row.version);
    let instance = format!("inst-rollback-{}", Id::new());
    let cfg = serde_json::from_value(json!({"expected_version":version,"enabled":true,"mock":true,
        "settings":{"instance_id":instance,"account_id":Id::new().to_string()}}))
    .unwrap();
    agf_api::cloud_store::save(&h.state, h.tenant, name, cfg).await.unwrap();
    let fingerprint = format!("agentteams:mock:cn-hangzhou:{instance}:worker:worker-demo");
    let mut tx = store.db().begin_tenant(h.tenant).await.unwrap();
    assert!(AssetRepo::get_by_fingerprint(&mut tx, &fingerprint).await.unwrap().is_none());
    tx.commit().await.unwrap();
    let snapshot_id = agf_api::integration_store::id(h.tenant, name);
    let before = h.state.configurations.get::<Value>(h.tenant, "cloud-inventory", snapshot_id).await.unwrap();

    // Force a database error only when this test tenant publishes its snapshot.
    let constraint = format!("agf_test_cloud_{}", Id::new().as_uuid().simple());
    let create = format!(
        "ALTER TABLE console_configurations ADD CONSTRAINT {constraint}
        CHECK (NOT (tenant_id = '{}'::uuid AND kind = 'cloud-inventory')) NOT VALID",
        h.tenant
    );
    sqlx::query(&create).execute(&pool).await.unwrap();
    let result = agf_api::cloud_inventory::sync(
        &h.state,
        h.tenant,
        "rollback-test".into(),
        test_actor(),
        agf_api::cloud_inventory::SyncRequest {
            request_id: Id::new(),
            configuration_version: version + 1,
            confirm_live: false,
        },
    )
    .await;
    let drop_constraint = format!("ALTER TABLE console_configurations DROP CONSTRAINT {constraint}");
    sqlx::query(&drop_constraint).execute(&pool).await.unwrap();
    assert!(result.is_err(), "snapshot failure must be reported");
    let mut tx = store.db().begin_tenant(h.tenant).await.unwrap();
    assert!(AssetRepo::get_by_fingerprint(&mut tx, &fingerprint).await.unwrap().is_none());
    tx.commit().await.unwrap();
    let after = h.state.configurations.get::<Value>(h.tenant, "cloud-inventory", snapshot_id).await.unwrap();
    assert_eq!(after, before, "old snapshot must remain unchanged");
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires AGF_TEST_DATABASE_URL pointing to the isolated requirements database"]
async fn cloud_audit_failure_rolls_back_assets_and_snapshot() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.configurations = Arc::new(agf_api::config_store::ConfigStore::new(Some(store.clone())));
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    let name = agf_api::cloud_inventory::NAME;
    let version = agf_api::cloud_store::load(&h.state, h.tenant, name).await.unwrap().map_or(0, |row| row.version);
    let instance = format!("inst-audit-{}", Id::new());
    let cfg = serde_json::from_value(json!({"expected_version":version,"enabled":true,"mock":true,
        "settings":{"instance_id":instance,"account_id":Id::new().to_string()}}))
    .unwrap();
    agf_api::cloud_store::save(&h.state, h.tenant, name, cfg).await.unwrap();
    let fingerprint = format!("agentteams:mock:cn-hangzhou:{instance}:worker:worker-demo");
    let snapshot_id = agf_api::integration_store::id(h.tenant, name);
    let before = h.state.configurations.get::<Value>(h.tenant, "cloud-inventory", snapshot_id).await.unwrap();
    let mut tx = store.db().begin_tenant(h.tenant).await.unwrap();
    let audit_before = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    // The business transaction must fail if its success audit cannot be sealed.
    let constraint = format!("agf_test_cloud_audit_{}", Id::new().as_uuid().simple());
    let create = format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint}
        CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        h.tenant
    );
    sqlx::query(&create).execute(&pool).await.unwrap();
    let result = agf_api::cloud_inventory::sync(
        &h.state,
        h.tenant,
        "audit-rollback-test".into(),
        test_actor(),
        agf_api::cloud_inventory::SyncRequest {
            request_id: Id::new(),
            configuration_version: version + 1,
            confirm_live: false,
        },
    )
    .await;
    let drop_constraint = format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}");
    sqlx::query(&drop_constraint).execute(&pool).await.unwrap();
    assert!(result.is_err(), "audit failure must reject cloud publication");
    let mut tx = store.db().begin_tenant(h.tenant).await.unwrap();
    assert!(AssetRepo::get_by_fingerprint(&mut tx, &fingerprint).await.unwrap().is_none());
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), audit_before);
    tx.commit().await.unwrap();
    let after = h.state.configurations.get::<Value>(h.tenant, "cloud-inventory", snapshot_id).await.unwrap();
    assert_eq!(after, before, "failed audit must not publish a new snapshot");
    pool.close().await;
}
