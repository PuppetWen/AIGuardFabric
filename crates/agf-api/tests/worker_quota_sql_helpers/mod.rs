//! Dedicated, ownership-checked PostgreSQL fixtures shared by Worker quota regressions.
use super::common::*;
use agf_core::ids::Id;
use agf_storage::{Database, Store, configuration::ConfigStore, objectstore::MemoryObjectStore};
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe};

pub(super) const BASE: &str = "/api/v1/alicloud/agentteams/worker-quotas";
pub(super) const KIND: &str = "agentteams-worker-quota";
pub(super) const RUNS: &str = "agentteams-worker-quota-run";
pub(super) struct Fixture {
    pub(super) h: Harness,
    pub(super) db: Arc<Store>,
    pub(super) tenant: TenantId,
    pub(super) asset: Id,
    pub(super) quota: Id,
}

pub(super) async fn instance(db: Arc<Store>) -> Harness {
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(ConfigStore::new(Some(db)));
    h.app = build_router(h.state.clone());
    h
}

pub(super) async fn call(h: &Harness, tenant: TenantId, method: &str, uri: &str, body: Option<Value>) -> Resp {
    let token = format!("Bearer {}", h.admin);
    let selected = tenant.to_string();
    h.request_with(method, uri, &[("authorization", &token), ("x-agf-tenant", &selected)], body).await
}

pub(super) async fn fixture() -> Fixture {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(owner.is_some_and(|value| value.starts_with("AIGuardFabric ")), "database ownership marker missing");
    let db = Database::from_pool(pool);
    db.migrate().await.unwrap();
    let db = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
    let h = instance(db.clone()).await;
    let tenant = agf_api::tenant_directory::new(format!("worker-quota-sql-{}", Id::new()), "Worker quota SQL".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    let configured = call(
        &h,
        tenant.id,
        "PUT",
        "/api/v1/alicloud/connections/alicloud-agentteams",
        Some(json!({"expected_version":0,"enabled":true,"mock":true,
            "settings":{"instance_id":format!("quota-sql-{}",Id::new()),"account_id":Id::new().to_string()}})),
    )
    .await;
    assert_eq!(configured.status, StatusCode::OK, "{}", configured.text);
    let synced = call(
        &h,
        tenant.id,
        "POST",
        "/api/v1/alicloud/agentteams/sync",
        Some(json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":false})),
    )
    .await;
    assert_eq!(synced.status, StatusCode::OK, "{}", synced.text);
    let snapshot = agf_api::cloud_inventory::load(&h.state, tenant.id).await.unwrap().unwrap();
    let asset = snapshot.assets["worker-demo"];
    let saved = quota(&h, tenant.id, asset, 0, 100).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let quota = Id::parse(saved.json()["quota"]["id"].as_str().unwrap()).unwrap();
    Fixture { h, db, tenant: tenant.id, asset, quota }
}

pub(super) async fn quota(h: &Harness, tenant: TenantId, asset: Id, version: u64, limit: i64) -> Resp {
    call(
        h,
        tenant,
        "POST",
        "/api/v1/quotas",
        Some(json!({"name":"worker-only","scope":"agent",
        "target_id":asset,"dimension":"tokens","window":"day","limit":limit,"on_exceed":"deny",
        "expected_version":version})),
    )
    .await
}

pub(super) async fn bind(f: &Fixture, h: &Harness, version: u64, enabled: bool) -> Resp {
    call(
        h,
        f.tenant,
        "PUT",
        &format!("{BASE}/{}", f.asset),
        Some(json!({"expected_version":version,
        "quota_id":f.quota,"quota_version":1,"enabled":enabled})),
    )
    .await
}

pub(super) async fn observe(f: &Fixture, h: &Harness, request: Id) -> Resp {
    call(
        h,
        f.tenant,
        "POST",
        &format!("{BASE}/{}/observe", f.asset),
        Some(json!({"request_id":request,
        "expected_binding_version":1,"expected_quota_version":1,"configuration_version":1,
        "confirm_live":false})),
    )
    .await
}

pub(super) fn sync_body(preview: Id, request: Id) -> Value {
    json!({"request_id":request,"preview_id":preview,"expected_binding_version":1,
        "expected_quota_version":1,"configuration_version":1,"confirm_live":false})
}

pub(super) async fn sync(f: &Fixture, h: &Harness, body: Value) -> Resp {
    call(h, f.tenant, "POST", &format!("{BASE}/{}/sync", f.asset), Some(body)).await
}

pub(super) async fn record(f: &Fixture) -> Option<Value> {
    f.h.state.configurations.get(f.tenant, KIND, f.asset).await.unwrap()
}

pub(super) async fn audits(f: &Fixture, prefix: Option<&str>) -> i64 {
    let mut tx = f.db.db().begin_tenant(f.tenant).await.unwrap();
    let count = sqlx::query_scalar(
        "SELECT count(*) FROM audit_logs WHERE target->>'kind'=$1
        AND outcome='success' AND ($2::text IS NULL OR note LIKE $2)",
    )
    .bind(KIND)
    .bind(prefix)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    count
}

pub(super) async fn alerts(f: &Fixture) -> i64 {
    let mut tx = f.db.db().begin_tenant(f.tenant).await.unwrap();
    let count = sqlx::query_scalar("SELECT count(*) FROM alerts WHERE title='Worker 配额限制冲突 (quota-drift)'")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    count
}

/// Remove only this case's UUID-named constraint even when an assertion panics.
pub(super) async fn fault<F: Future<Output = ()>>(f: &Fixture, table: &str, predicate: String, check: F) {
    assert!(matches!(table, "audit_logs" | "alerts" | "console_configurations"));
    let name = format!("agf_test_worker_quota_{}", Id::new().as_uuid().simple());
    assert!(name.len() <= 63 && name.bytes().all(|value| value.is_ascii_alphanumeric() || value == b'_'));
    sqlx::query(&format!("ALTER TABLE {table} ADD CONSTRAINT {name} CHECK (NOT ({predicate})) NOT VALID"))
        .execute(f.db.db().pool())
        .await
        .unwrap();
    let outcome = AssertUnwindSafe(check).catch_unwind().await;
    sqlx::query(&format!("ALTER TABLE {table} DROP CONSTRAINT {name}")).execute(f.db.db().pool()).await.unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

pub(super) async fn sdk_key(f: &Fixture, asset: Id, name: &str) -> String {
    let response = call(
        &f.h,
        f.tenant,
        "POST",
        "/api/v1/settings/api-keys",
        Some(json!({"name":name,
        "bound_agent_id":asset,"scopes":["models:read","models:write"]})),
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    response.json()["plaintext"].as_str().unwrap().to_owned()
}

pub(super) async fn chat(h: &Harness, key: &str) -> Resp {
    h.request(
        "POST",
        "/v1/chat/completions",
        Some(key),
        Some(json!({"model":"auto","max_tokens":4,
        "messages":[{"role":"user","content":"hello"}]})),
    )
    .await
}

pub(super) async fn wait_for_receipt_lock(
    f: &Fixture,
    task: &tokio::task::JoinHandle<agf_core::error::DomainResult<Value>>,
    hash: i64,
) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            assert!(!task.is_finished(), "completion bypassed the claim advisory lock while a retry held Started");
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory'
                AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND objsubid=1
                AND classid::bigint=(($1::bigint >> 32) & 4294967295) AND objid::bigint=($1::bigint & 4294967295)
                AND NOT granted)",
            )
            .bind(hash)
            .fetch_one(f.db.db().pool())
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the completion transaction must wait for the same claim lock");
}
