//! An exact database owner is checked before migrations, DDL and each injected durable change.
use crate::common::*;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use agf_storage::{Database, Store, configuration::ConfigStore, objectstore::MemoryObjectStore};

pub(crate) mod gate;
pub(crate) const OWNER_ENV: &str = "AGF_APIG_CONFIGURATION_DATABASE_OWNER";
const PREFIX: &str = "AIGuardFabric APIG configuration publication SQL ";
pub(crate) fn sql(error: sqlx::Error) -> DomainError {
    DomainError::Internal(format!("owned APIG SQL: {error}"))
}
fn identity() -> DomainResult<(String, String)> {
    let owner =
        std::env::var(OWNER_ENV).map_err(|_| DomainError::PreconditionFailed("owned APIG marker required".into()))?;
    let run = owner
        .strip_prefix(PREFIX)
        .filter(|run| run.len() == 32 && run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .ok_or_else(|| DomainError::PreconditionFailed("invalid owned APIG marker".into()))?;
    Ok((format!("agf_requirements_test_apig_configuration_{}", &run[..12]), owner))
}
pub(crate) async fn check(pool: &sqlx::PgPool) -> DomainResult<()> {
    let actual: (String, Option<String>) = sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()")
        .fetch_one(pool).await.map_err(sql)?;
    let (database, owner) = identity()?;
    if actual != (database, Some(owner)) {
        return Err(DomainError::Forbidden("database is not owned by this APIG test run".into()));
    }
    Ok(())
}
pub(crate) async fn database_oid(pool: &sqlx::PgPool) -> DomainResult<i64> {
    let oid: i64 = sqlx::query_scalar("SELECT oid::bigint FROM pg_database WHERE datname=current_database()")
        .fetch_one(pool)
        .await
        .map_err(sql)?;
    if !(1..=i64::from(u32::MAX)).contains(&oid) {
        return Err(DomainError::Forbidden("owned database OID is invalid".into()));
    }
    Ok(oid)
}
pub(crate) struct SqlCase {
    pub(crate) h: Harness,
    pub(crate) pool: sqlx::PgPool,
    pub(crate) oid: i64,
    store: Arc<Store>,
}
impl SqlCase {
    pub(crate) async fn open(label: &str) -> DomainResult<Self> {
        assert!(!label.is_empty() && label.len() + 37 <= 64);
        let url = std::env::var("AGF_TEST_DATABASE_URL")
            .map_err(|_| DomainError::PreconditionFailed("owned APIG URL required".into()))?;
        let (database, _) = identity()?;
        if url::Url::parse(&url)?.path() != format!("/{database}") {
            return Err(DomainError::Forbidden("unexpected APIG database URL".into()));
        }
        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.map_err(sql)?;
        check(&pool).await?;
        let oid = database_oid(&pool).await?;
        let database = Database::from_pool(pool.clone());
        database.migrate().await?;
        let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
        let tenant = agf_api::tenant_directory::new(format!("{label}-{}", Id::new()), label.into());
        let h = instance(store.clone(), tenant.id).await?;
        agf_api::tenant_directory::save(&h.state, tenant, true).await?;
        Ok(Self { h, pool, oid, store })
    }
    pub(crate) async fn check(&self) -> DomainResult<()> {
        check(&self.pool).await?;
        let oid = database_oid(&self.pool).await?;
        if oid != self.oid {
            return Err(DomainError::Forbidden("owned database OID changed".into()));
        }
        Ok(())
    }
    pub(crate) async fn second_instance(&self) -> DomainResult<Harness> {
        instance(self.store.clone(), self.h.tenant).await
    }
    pub(crate) async fn foreign_instance(&self) -> DomainResult<Harness> {
        let tenant =
            agf_api::tenant_directory::new(format!("foreign-{}", Id::new()), "Owned foreign APIG tenant".into());
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

fn for_tenant(mut h: Harness, tenant: TenantId) -> DomainResult<Harness> {
    let value = tenant
        .to_string()
        .parse::<axum::http::HeaderValue>()
        .map_err(|_| DomainError::Internal("owned tenant header".into()))?;
    h.tenant = tenant;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut r: Request<Body>| {
        r.headers_mut().insert("x-agf-tenant", value.clone());
        async move { r }
    }));
    Ok(h)
}
