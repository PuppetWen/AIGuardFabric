//! Tenant profile, gateway quotas and password policy must roll back with failed success audits.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::{auth_policy, gateway_quota, model_routes::tenant_record_id, tenant_directory};
use agf_core::ids::Id;
use agf_storage::{AuditRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;

const PROFILE: &str = "/api/v1/settings/tenant";
const QUOTAS: &str = "/api/v1/settings/quotas";
const POLICY: &str = "/api/v1/settings/password-policy";

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn tenant_settings_roll_back_when_audit_fails() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store)));
    let tenant = tenant_directory::new(format!("settings-audit-{}", Id::new()), "Settings audit test".into());
    tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.app = build_router(h.state.clone());
    let token = format!("Bearer {}", h.admin);
    let tenant_id = tenant.id.to_string();
    let headers = [("authorization", token.as_str()), ("x-agf-tenant", tenant_id.as_str())];

    let profile = json!({"expectedVersion":0,"name":"Profile One","plan":"enterprise","region":"local",
        "whiteLabel":{"productName":"Guard","logoText":"AGF","primaryColor":"#123abc"}});
    let quotas = json!({"expectedVersion":0,"tenantTokensPerDay":1000,"agentTokensPerHour":100,
        "sessionTokensPerTurn":50,"maxConcurrentSessions":2});
    let policy_read = h.request_with("GET", POLICY, &headers, None).await;
    assert_eq!(policy_read.status, StatusCode::OK, "{}", policy_read.text);
    let mut policy = policy_read.json();
    policy["min_length"] = json!(12);
    for (path, body) in [(PROFILE, &profile), (QUOTAS, &quotas), (POLICY, &policy)] {
        let saved = h.request_with("PUT", path, &headers, Some(body.clone())).await;
        assert_eq!(saved.status, StatusCode::OK, "{path}: {}", saved.text);
        assert_eq!(saved.json()["version"], 1, "{path}");
    }
    let key = tenant_record_id(tenant.id);
    let kinds = ["tenant-profile", gateway_quota::QUOTAS, auth_policy::KIND];
    let mut before_records = Vec::new();
    for kind in kinds {
        let record: Value = h.state.configurations.get(tenant.id, kind, key).await.unwrap().unwrap();
        before_records.push(record);
    }
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    let before_chain = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    let constraint = format!("agf_test_settings_audit_{}", Id::new().as_uuid().simple());
    sqlx::query(&format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        tenant.id
    ))
    .execute(&pool)
    .await
    .unwrap();
    let mut next_profile = profile;
    next_profile["expectedVersion"] = json!(1);
    next_profile["name"] = json!("Profile Two");
    let mut next_quotas = quotas;
    next_quotas["expectedVersion"] = json!(1);
    next_quotas["tenantTokensPerDay"] = json!(2000);
    let mut next_policy = policy;
    next_policy["expected_version"] = json!(1);
    next_policy["min_length"] = json!(14);
    let updates = [(PROFILE, next_profile), (QUOTAS, next_quotas), (POLICY, next_policy)];
    for (path, body) in &updates {
        let failed = h.request_with("PUT", path, &headers, Some(body.clone())).await;
        assert!(!failed.status.is_success(), "{path}: {}", failed.text);
        for (kind, before) in kinds.iter().zip(&before_records) {
            let stored: Value = h.state.configurations.get(tenant.id, kind, key).await.unwrap().unwrap();
            assert_eq!(&stored, before, "{path} changed {kind} without an audit");
        }
        let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
        assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), before_chain);
        tx.commit().await.unwrap();
    }
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();
    for (path, body) in updates {
        let saved = h.request_with("PUT", path, &headers, Some(body)).await;
        assert_eq!(saved.status, StatusCode::OK, "{path}: {}", saved.text);
        assert_eq!(saved.json()["version"], 2, "{path}");
    }
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    assert_ne!(AuditRepo::chain_stats(&mut tx).await.unwrap(), before_chain);
    tx.commit().await.unwrap();
    pool.close().await;
}
