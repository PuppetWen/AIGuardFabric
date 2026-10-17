//! SQL ownership, independent routers and scoped platform keys; no database fixture shortcuts.
#![allow(dead_code, unused_imports, unreachable_pub)]
use crate::{common::*, team_management_helpers::*};
use agf_core::ids::Id;
use agf_storage::{Database, Store, configuration::ConfigStore, objectstore::MemoryObjectStore};
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe};

pub struct FixtureSql {
    pub f: Fixture,
    pub db: Arc<Store>,
    pub key: String,
}
pub async fn instance(db: Arc<Store>, tenant: TenantId, key: &str) -> Fixture {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(ConfigStore::new(Some(db)));
    h.admin = key.into();
    h.tenant = tenant;
    h.app = build_router(h.state.clone());
    Fixture { h, mocked: true }
}
pub async fn fixture() -> FixtureSql {
    let connection = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&connection).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&connection).await.unwrap();
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(owner.is_some_and(|owner| owner.starts_with("AIGuardFabric ")), "database ownership marker missing");
    let database = Database::from_pool(pool);
    database.migrate().await.unwrap();
    let db = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(ConfigStore::new(Some(db.clone())));
    h.app = build_router(h.state.clone());
    let tenant = agf_api::tenant_directory::new(format!("team-sql-{}", Id::new()), "Team management SQL".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    let issued = result(
        scoped(
            &h,
            tenant.id,
            "POST",
            "/api/v1/settings/api-keys",
            Some(json!({"name":"team-sql-key",
        "scopes":["alicloud:read","alicloud:write","assets:read","assets:write"]})),
        )
        .await,
    );
    let key = issued["plaintext"].as_str().unwrap().to_owned();
    h.admin = key.clone();
    h.tenant = tenant.id;
    let f = Fixture::configured(h, true, None).await;
    FixtureSql { f, db, key }
}
pub async fn record(f: &Fixture) -> Value {
    let rows = f.h.state.configurations.list::<Value>(f.h.tenant, STATE_KIND).await.unwrap();
    rows.into_iter().find(|row| row["team_name"] == TEAM).unwrap()
}
pub async fn audits(f: &FixtureSql) -> (i64, String) {
    let mut tx = f.db.db().begin_tenant(f.f.h.tenant).await.unwrap();
    let before = agf_storage::AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    before
}
pub async fn fault<F: Future<Output = ()>>(f: &FixtureSql, table: &str, predicate: String, check: F) {
    assert!(matches!(table, "audit_logs" | "console_configurations"));
    let constraint = format!("agf_test_team_{}", Id::new().as_uuid().simple());
    assert!(constraint.len() <= 63 && constraint.bytes().all(|value| value.is_ascii_alphanumeric() || value == b'_'));
    sqlx::query(&format!("ALTER TABLE {table} ADD CONSTRAINT {constraint} CHECK (NOT ({predicate})) NOT VALID"))
        .execute(f.db.db().pool())
        .await
        .unwrap();
    let outcome = AssertUnwindSafe(check).catch_unwind().await;
    sqlx::query(&format!("ALTER TABLE {table} DROP CONSTRAINT {constraint}")).execute(f.db.db().pool()).await.unwrap();
    if let Err(error) = outcome {
        std::panic::resume_unwind(error);
    }
}
