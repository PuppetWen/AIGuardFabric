//! This suite refuses migration or fault DDL outside one full-UUID loopback database.
use crate::common::*;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use agf_storage::{Database, Store, configuration::ConfigStore, objectstore::MemoryObjectStore};
pub(crate) const OWNER_ENV: &str = "AGF_RULE_SKILL_PUBLICATION_DATABASE_OWNER";
pub(crate) const OID_ENV: &str = "AGF_RULE_SKILL_PUBLICATION_DATABASE_OID";
const PREFIX: &str = "AIGuardFabric rule Skill publication SQL ";
fn failure(message: &str) -> DomainError {
    DomainError::PreconditionFailed(message.into())
}
fn sql(error: sqlx::Error) -> DomainError {
    DomainError::Internal(format!("Owned rule Skill SQL: {error}"))
}

fn identity() -> DomainResult<(String, String, i64)> {
    let owner = std::env::var(OWNER_ENV).map_err(|_| failure("Owned rule Skill marker required"))?;
    let run = owner
        .strip_prefix(PREFIX)
        .filter(|run| run.len() == 32 && run.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        .ok_or_else(|| failure("Invalid rule Skill owner marker"))?;
    let database = format!("agf_test_rule_skill_{run}");
    let oid = std::env::var(OID_ENV)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| (1..=i64::from(u32::MAX)).contains(value))
        .ok_or_else(|| failure("Owned database OID required"))?;
    Ok((database, owner, oid))
}
pub(crate) async fn check(pool: &sqlx::PgPool) -> DomainResult<()> {
    let actual:(String,Option<String>,i64)=sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database'),oid::bigint FROM pg_database WHERE datname=current_database()")
        .fetch_one(pool).await.map_err(sql)?;
    let (database, owner, oid) = identity()?;
    if actual != (database, Some(owner), oid) {
        return Err(failure("Rule Skill database identity or owner changed"));
    }
    Ok(())
}

pub(crate) struct SqlCase {
    pub(crate) h: Harness,
    pub(crate) pool: sqlx::PgPool,
    store: Arc<Store>,
}
impl SqlCase {
    pub(crate) async fn open(label: &str) -> DomainResult<Self> {
        let raw = std::env::var("AGF_TEST_DATABASE_URL").map_err(|_| failure("Owned rule Skill URL required"))?;
        let url = url::Url::parse(&raw)?;
        let (name, _, _) = identity()?;
        if url.scheme() != "postgres" && url.scheme() != "postgresql" {
            return Err(failure("PostgreSQL URL required"));
        }
        if url.host_str() != Some("127.0.0.1")
            || url.path() != format!("/{name}")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(failure("Exact numeric loopback owned database URL required"));
        }
        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&raw).await.map_err(sql)?;
        check(&pool).await?;
        let database = Database::from_pool(pool.clone());
        // Both this target session and the runner's admin session check COMMENT + OID before migration.
        database.migrate().await?;
        check(&pool).await?;
        let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
        let tenant = agf_api::tenant_directory::new(format!("{label}-{}", Id::new()), label.into());
        let h = instance(store.clone(), tenant.id).await?;
        agf_api::tenant_directory::save(&h.state, tenant, true).await?;
        Ok(Self { h, pool, store })
    }
    pub(crate) async fn second(&self) -> DomainResult<Harness> {
        instance(self.store.clone(), self.h.tenant).await
    }
    pub(crate) async fn reject_audit(&self) -> DomainResult<String> {
        check(&self.pool).await?;
        let name = format!("agf_test_rule_skill_audit_{}", Id::new().as_uuid().simple());
        sqlx::query(&format!(
            "ALTER TABLE audit_logs ADD CONSTRAINT {name} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
            self.h.tenant
        ))
        .execute(&self.pool)
        .await
        .map_err(sql)?;
        Ok(name)
    }
    pub(crate) async fn release_audit(&self, name: &str) -> DomainResult<()> {
        check(&self.pool).await?;
        if !name.starts_with("agf_test_rule_skill_audit_")
            || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(failure("Unexpected owned audit constraint"));
        }
        sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {name}"))
            .execute(&self.pool)
            .await
            .map_err(sql)?;
        Ok(())
    }
}
async fn instance(store: Arc<Store>, tenant: TenantId) -> DomainResult<Harness> {
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(ConfigStore::new(Some(store)));
    h.tenant = tenant;
    let value = axum::http::HeaderValue::from_str(&tenant.to_string()).map_err(|error| failure(&error.to_string()))?;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        request.headers_mut().insert("x-agf-tenant", value.clone());
        async move { request }
    }));
    Ok(h)
}
