//! Dedicated PostgreSQL validation of quota versions, competing instances and audit rollback.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::{model_routes::tenant_record_id, quota_definitions, runtime_quota, tenant_directory};
use agf_core::{ids::Id, quota::QuotaConsumption};
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

const PATH: &str = "/api/v1/quotas";
const KIND: &str = "quota-definitions";

async fn instance(store: Arc<Store>) -> Harness {
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store)));
    h.app = build_router(h.state.clone());
    h
}

async fn write(h: &Harness, tenant: TenantId, name: &str, version: u64, limit: i64) -> Resp {
    let token = format!("Bearer {}", h.admin);
    let selected = tenant.to_string();
    h.request_with("POST", PATH, &[("authorization", token.as_str()), ("x-agf-tenant", selected.as_str())],
        Some(json!({"name":name,"dimension":"requests","scope":"tenant","window":"total","limit":limit,"expected_version":version}))).await
}

async fn record(h: &Harness, tenant: TenantId) -> Option<Value> {
    h.state.configurations.get(tenant, KIND, tenant_record_id(tenant)).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a dedicated owned AGF_TEST_DATABASE_URL created by run-quota-configuration-validation.ps1"]
async fn competing_quota_writes_survive_restart_and_failed_audits_roll_back() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_quota_config_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        owner.is_some_and(|value| value.starts_with("AIGuardFabric quota config validation ")),
        "database ownership marker missing"
    );
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let first = instance(store.clone()).await;
    let second = instance(store.clone()).await;
    let tenant = tenant_directory::new(format!("quota-config-{}", Id::new()), "Quota config validation".into());
    tenant_directory::save(&first.state, tenant.clone(), true).await.unwrap();
    let name = format!("persistent-{}", Id::new());
    let created = write(&first, tenant.id, &name, 0, 3).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let original = created.json()["quota"].clone();
    let quota_id = Id::parse(original["id"].as_str().unwrap()).unwrap();
    let lease = runtime_quota::Lease::acquire(
        &first.state,
        tenant.id,
        None,
        "sql-version",
        "quota-test",
        &QuotaConsumption::one_request(),
    )
    .await
    .unwrap();
    lease.finish(None).await.unwrap();
    let before = record(&first, tenant.id).await;
    let before_chain = first.state.store.audit_stats_durable(tenant.id).await.unwrap();
    let constraint = format!("agf_test_quota_audit_{}", Id::new().as_uuid().simple());
    sqlx::query(&format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        tenant.id
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = write(&first, tenant.id, &name, 1, 100).await;
    assert!(!failed.status.is_success(), "{}", failed.text);
    assert_eq!(record(&first, tenant.id).await, before, "quota and version must roll back with failed success audit");
    assert_eq!(first.state.store.audit_stats_durable(tenant.id).await.unwrap(), before_chain);
    assert_eq!(runtime_quota::usage(&second.state, tenant.id).await.unwrap()[&quota_id], 1);
    assert_eq!(
        first.state.store.quota_list(tenant.id).unwrap().iter().find(|row| row.id == quota_id).unwrap().limit,
        3,
        "failed transaction must not refresh the quota cache"
    );
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();

    let (left, right) = tokio::join!(write(&first, tenant.id, &name, 1, 1), write(&second, tenant.id, &name, 1, 2));
    let statuses = [left.status, right.status];
    assert_eq!(
        statuses.iter().filter(|status| **status == StatusCode::OK).count(),
        1,
        "{} / {}",
        left.text,
        right.text
    );
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    let winner = if left.status == StatusCode::OK { left.json() } else { right.json() };
    assert_eq!(winner["quota"]["id"], original["id"]);
    assert_eq!(winner["quota"]["version"], 2);
    assert_eq!(first.state.store.audit_stats_durable(tenant.id).await.unwrap().0, before_chain.0 + 1);
    let restarted = instance(store.clone()).await;
    let loaded = quota_definitions::list_versioned(&restarted.state, tenant.id).await.unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(serde_json::to_value(&loaded[0]).unwrap(), winner["quota"]);
    assert_eq!(runtime_quota::usage(&restarted.state, tenant.id).await.unwrap()[&quota_id], 1);
    assert_eq!(write(&restarted, tenant.id, &name, 1, 100).await.status, StatusCode::CONFLICT);
    let isolated = tenant_directory::new(format!("quota-isolation-{}", Id::new()), "Quota isolation validation".into());
    tenant_directory::save(&first.state, isolated.clone(), true).await.unwrap();
    assert!(quota_definitions::list_versioned(&restarted.state, isolated.id).await.unwrap().is_empty());

    // Even the very first failed save must leave no empty registry or success audit behind.
    let untouched = tenant_directory::new(format!("quota-first-fail-{}", Id::new()), "First save validation".into());
    tenant_directory::save(&first.state, untouched.clone(), true).await.unwrap();
    assert!(record(&first, untouched.id).await.is_none());
    let untouched_chain = first.state.store.audit_stats_durable(untouched.id).await.unwrap();
    sqlx::query(&format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        untouched.id
    ))
    .execute(&pool)
    .await
    .unwrap();
    let denied = write(&first, untouched.id, "never-created", 0, 1).await;
    assert!(!denied.status.is_success(), "{}", denied.text);
    assert!(record(&first, untouched.id).await.is_none());
    assert_eq!(first.state.store.audit_stats_durable(untouched.id).await.unwrap(), untouched_chain);
    assert!(first.state.store.quota_list(untouched.id).unwrap().is_empty());
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();
    assert_eq!(write(&first, untouched.id, "never-created", 0, 1).await.status, StatusCode::OK);
    pool.close().await;
}
