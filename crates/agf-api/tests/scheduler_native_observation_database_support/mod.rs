//! Migrations and every durable fault require this run's exact local database name, comment and OID.
use crate::common::*;
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome},
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
};
use agf_storage::{Database, Store, configuration::ConfigStore, objectstore::MemoryObjectStore};

pub(crate) mod authority;
pub(crate) mod capacity;
pub(crate) mod gate;
pub(crate) mod lifecycle;
pub(crate) mod provider;
pub(crate) mod publication;
mod signature;
pub(crate) mod wire;

pub(crate) const BASE: &str = "/api/v1/alicloud/schedulerx3/native";
pub(crate) const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-schedulerx3";
pub(crate) const NAME: &str = "alicloud-schedulerx3";
pub(crate) const STATE: &str = "scheduler-native-state";
pub(crate) const FACT: &str = "scheduler-native-fact";
pub(crate) const BODY: &str = "scheduler-native-observation";
pub(crate) const BINDING: &str = "scheduler-native-bindings";
const OWNER_ENV: &str = "AGF_SCHEDULER_NATIVE_DATABASE_OWNER";
const PREFIX: &str = "AIGuardFabric Scheduler native observation SQL ";
pub(crate) fn sql(_: sqlx::Error) -> DomainError {
    wire::fixture_error("owned SQL operation failed")
}
fn identity() -> DomainResult<(String, String)> {
    let owner = std::env::var(OWNER_ENV).map_err(|_| wire::fixture_error("database owner required"))?;
    let run = owner
        .strip_prefix(PREFIX)
        .filter(|run| run.len() == 32 && run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .ok_or_else(|| wire::fixture_error("database owner format invalid"))?;
    Ok((format!("agf_requirements_test_scheduler_native_{}", &run[..12]), owner))
}
#[derive(Clone)]
pub(crate) struct Owner {
    pub(crate) pool: sqlx::PgPool,
    oid: i64,
}
impl Owner {
    pub(crate) async fn check(&self) -> DomainResult<()> {
        let actual:(String,Option<String>,i64)=sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database'),oid::bigint FROM pg_database WHERE datname=current_database()")
            .fetch_one(&self.pool).await.map_err(sql)?;
        let (name, comment) = identity()?;
        if actual != (name, Some(comment), self.oid) || self.oid <= 0 {
            return Err(wire::fixture_error("database name, owner or OID changed"));
        }
        Ok(())
    }
}
pub(crate) struct SqlCase {
    pub(crate) h: Harness,
    pub(crate) owner: Owner,
    store: Arc<Store>,
}
impl SqlCase {
    pub(crate) async fn open(label: &str) -> DomainResult<Self> {
        assert!(!label.is_empty() && label.len() + 37 <= 64);
        let raw = std::env::var("AGF_TEST_DATABASE_URL").map_err(|_| wire::fixture_error("database URL required"))?;
        let url = url::Url::parse(&raw).map_err(|_| wire::fixture_error("database URL invalid"))?;
        let (name, comment) = identity()?;
        if !matches!(url.scheme(), "postgres" | "postgresql")
            || url.host_str() != Some("127.0.0.1")
            || url.port() != Some(5432)
            || url.path() != format!("/{name}")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(wire::fixture_error("database must be the exact owned literal-loopback PostgreSQL database"));
        }
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(12)
            .acquire_timeout(std::time::Duration::from_secs(20))
            .connect(&raw)
            .await
            .map_err(sql)?;
        // No migration, helper setup, tenant creation or fault occurs before this read-only identity check.
        let actual:(String,Option<String>,i64)=sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database'),oid::bigint FROM pg_database WHERE datname=current_database()")
            .fetch_one(&pool).await.map_err(sql)?;
        if actual.0 != name || actual.1 != Some(comment) || actual.2 <= 0 {
            return Err(wire::fixture_error("foreign database rejected before migrations"));
        }
        let owner = Owner { pool: pool.clone(), oid: actual.2 };
        owner.check().await?;
        let db = Database::from_pool(pool);
        db.migrate().await?;
        let store = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
        let tenant = agf_api::tenant_directory::new(format!("{label}-{}", Id::new()), label.into());
        let h = instance(store.clone(), tenant.id).await?;
        agf_api::tenant_directory::save(&h.state, tenant, true).await?;
        Ok(Self { h, owner, store })
    }
    pub(crate) async fn second(&self) -> DomainResult<Harness> {
        self.owner.check().await?;
        instance(self.store.clone(), self.h.tenant).await
    }
    pub(crate) async fn foreign(&self) -> DomainResult<Harness> {
        self.owner.check().await?;
        let tenant =
            agf_api::tenant_directory::new(format!("foreign-{}", Id::new()), "Owned Scheduler foreign tenant".into());
        agf_api::tenant_directory::save(&self.h.state, tenant.clone(), true).await?;
        instance(self.store.clone(), tenant.id).await
    }
}
async fn instance(store: Arc<Store>, tenant: TenantId) -> DomainResult<Harness> {
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(ConfigStore::new(Some(store)));
    for_tenant(h, tenant)
}
pub(crate) fn for_tenant(mut h: Harness, tenant: TenantId) -> DomainResult<Harness> {
    let header = tenant
        .to_string()
        .parse::<axum::http::HeaderValue>()
        .map_err(|_| wire::fixture_error("tenant header invalid"))?;
    h.tenant = tenant;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        request.headers_mut().insert("x-agf-tenant", header.clone());
        async move { request }
    }));
    Ok(h)
}
pub(crate) fn number(value: &Value, field: &str) -> DomainResult<u64> {
    value[field].as_u64().ok_or_else(|| wire::fixture_error("numeric DTO field absent"))
}
pub(crate) fn identifier(value: &Value, field: &str) -> DomainResult<Id> {
    serde_json::from_value(value[field].clone()).map_err(Into::into)
}
pub(crate) async fn read(h: &Harness, path: &str) -> DomainResult<Value> {
    let reply = h.get(path).await;
    assert_eq!(reply.status, StatusCode::OK, "owned GET status");
    serde_json::from_slice(&reply.bytes).map_err(Into::into)
}
pub(crate) async fn post(h: &Harness, path: &str, body: Value) -> DomainResult<Value> {
    let reply = h.post(path, body).await;
    assert_eq!(reply.status, StatusCode::OK, "owned POST status");
    serde_json::from_slice(&reply.bytes).map_err(Into::into)
}
pub(crate) fn observe(id: Id, initialize: bool) -> Value {
    json!({"request_id":id,"configuration_version":1,"confirm_live":false,"initialize_mock_fixture":initialize})
}
pub(crate) fn receipt(id: Id) -> String {
    format!("{BASE}/observations/{id}")
}
pub(crate) fn settings() -> Value {
    json!({"region_id":"cn-hangzhou","cluster_id":"cluster-agf-demo","app_name":"app-agf-demo","account_id":"owned-scheduler-sql"})
}
pub(crate) async fn mock(h: &Harness, version: u64, enabled: bool) -> DomainResult<()> {
    let reply = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":version,"enabled":enabled,"mock":true,"settings":settings(),"secrets":{}})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "owned Mock source status");
    assert_eq!(reply.json()["version"], version + 1);
    Ok(())
}
pub(crate) async fn bindings(h: &Harness, id: Id, observation: Id, version: u64) -> DomainResult<Value> {
    let reply=h.request("PUT",&format!("{BASE}/bindings"),Some(&h.admin),Some(json!({"action":"replace","request_id":id,"expected_version":version,"configuration_version":1,
        "observation_id":observation,"bindings":[{"kind":"report","job_id":"9007199254741002"}],"confirm_local_only":true}))).await;
    assert_eq!(reply.status, StatusCode::OK, "owned association status");
    Ok(reply.json())
}
pub(crate) async fn archive(h: &Harness, ids: &[Id]) -> DomainResult<Value> {
    let view = read(h, BASE).await?;
    post(
        h,
        &format!("{BASE}/observations/archive"),
        json!({"expected_generation":number(&view,"generation")?,"request_ids":ids}),
    )
    .await
}
pub(crate) fn record_id(h: &Harness, kind: &str, request: Id) -> Id {
    deterministic_id("agf.scheduler.native.record", &format!("{}:{kind}:{request}", h.tenant))
}
pub(crate) fn main_id(h: &Harness) -> Id {
    agf_api::integration_store::id(h.tenant, NAME)
}
pub(crate) async fn rows(h: &Harness, kind: &str) -> DomainResult<Vec<Value>> {
    h.state.configurations.list(h.tenant, kind).await
}
pub(crate) async fn row(h: &Harness, kind: &str, id: Id) -> DomainResult<Option<Value>> {
    h.state.configurations.get(h.tenant, kind, id).await
}
pub(crate) async fn snapshot(h: &Harness) -> DomainResult<Value> {
    let mut configuration = BTreeMap::new();
    for kind in
        [STATE, FACT, BODY, BINDING, "scheduler-native-driver-mock", "cloud-integration", "integration-operation"]
    {
        configuration.insert(kind, rows(h, kind).await?);
    }
    Ok(json!({"configuration":configuration,"audit":h.state.store.audit_chain_durable(h.tenant,0,i64::MAX).await?}))
}
pub(crate) async fn audits(h: &Harness, id: Id, kind: &str) -> DomainResult<Vec<AuditLog>> {
    let id = id.to_string();
    Ok(h.state
        .store
        .audit_chain_durable(h.tenant, 0, i64::MAX)
        .await?
        .into_iter()
        .filter(|a| a.target.kind == kind && a.target.id.as_deref() == Some(id.as_str()))
        .collect())
}
pub(crate) async fn terminal(h: &Harness, id: Id, outcome: AuditOutcome) -> DomainResult<()> {
    let entries = audits(h, id, "scheduler-native-observation").await?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action, AuditAction::Read);
    assert_eq!(entries[0].outcome, outcome);
    chain(h).await
}
pub(crate) async fn chain(h: &Harness) -> DomainResult<()> {
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}
pub(crate) async fn key(h: &Harness) -> DomainResult<(String, Id)> {
    let reply = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":format!("owned-scheduler-{}",Id::new()),"scopes":["alicloud:read"]}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED);
    let value = reply.json();
    let token = value["plaintext"].as_str().ok_or_else(|| wire::fixture_error("key credential absent"))?.to_owned();
    Ok((token, identifier(&value["api_key"], "id")?))
}
