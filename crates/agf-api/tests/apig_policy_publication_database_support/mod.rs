//! An exact database owner is checked before migrations, DDL and each injected durable change.
use crate::common::*;
use agf_core::{
    audit::AuditLog,
    error::{DomainError, DomainResult},
    ids::Id,
};
use agf_storage::{Database, Store, configuration::ConfigStore, objectstore::MemoryObjectStore};

mod authority;
mod completion;
mod fixture;
pub(crate) mod gate;
mod lifecycle;
mod records;
pub(crate) mod wire;
pub(crate) use fixture::*;
pub(crate) use records::{assert_package, configurations, content_id, external_edit, fact_id, provider, snapshot};
pub(crate) const OWNER_ENV: &str = "AGF_APIG_POLICY_PUBLICATION_DATABASE_OWNER";
const PREFIX: &str = "AIGuardFabric APIG policy publication SQL ";
pub(crate) const MAIN: &str = "apig-policy-publication-state";
pub(crate) const FACT: &str = "apig-policy-publication-fact";
pub(crate) const DETAIL: &str = "apig-policy-publication-detail";
pub(crate) const PENDING: &str = "apig-policy-publication-pending";
pub(crate) const PREVIEW: &str = "apig-policy-publication-preview";

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
    Ok((format!("agf_requirements_test_apig_policy_publication_{}", &run[..12]), owner))
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
pub(crate) struct SqlCase {
    pub(crate) h: Harness,
    pub(crate) pool: sqlx::PgPool,
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
        let database = Database::from_pool(pool.clone());
        database.migrate().await?;
        let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
        let tenant = agf_api::tenant_directory::new(format!("{label}-{}", Id::new()), label.into());
        let h = instance(store.clone(), tenant.id).await?;
        agf_api::tenant_directory::save(&h.state, tenant, true).await?;
        Ok(Self { h, pool, store })
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
pub(crate) async fn chain(h: &Harness) -> DomainResult<()> {
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}
pub(crate) async fn audits(h: &Harness, request: Id, kind: &str) -> DomainResult<Vec<AuditLog>> {
    let request = request.to_string();
    Ok(h.state
        .store
        .audit_chain_durable(h.tenant, 0, i64::MAX)
        .await?
        .into_iter()
        .filter(|audit| audit.target.kind == kind && audit.target.id.as_deref() == Some(request.as_str()))
        .collect())
}
pub(crate) async fn row(h: &Harness, kind: &str, id: Id) -> DomainResult<Value> {
    h.state
        .configurations
        .get(h.tenant, kind, id)
        .await?
        .ok_or_else(|| DomainError::Internal("missing owned APIG row".into()))
}
pub(crate) async fn key(h: &Harness) -> DomainResult<(String, Id)> {
    let response = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":format!("owned-apig-key-{}", Id::new()),
        "scopes":["alicloud:read","alicloud:write","policies:read"]}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED); // Plaintext credentials are never printed.
    Ok((text(&response.json(), "plaintext")?, identifier(&response.json()["api_key"], "id")?))
}
pub(crate) async fn revoke(pool: &sqlx::PgPool, tenant: TenantId, key: Id, scope_only: bool) -> DomainResult<()> {
    check(pool).await?;
    let query = if scope_only {
        "UPDATE api_keys SET scopes=scopes-'alicloud:write',updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked AND deleted_at IS NULL"
    } else {
        "UPDATE api_keys SET revoked=true,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked AND deleted_at IS NULL"
    };
    assert_eq!(
        sqlx::query(query).bind(tenant.as_uuid()).bind(key.as_uuid()).execute(pool).await.map_err(sql)?.rows_affected(),
        1
    );
    Ok(())
}
pub(crate) async fn replace_owned_row(
    h: &Harness,
    pool: &sqlx::PgPool,
    kind: &str,
    id: Id,
    value: &Value,
) -> DomainResult<()> {
    check(pool).await?;
    assert!([PENDING, PREVIEW].contains(&kind) && !id.is_nil());
    assert_eq!(value["tenant"], json!(h.tenant));
    h.state.configurations.put(h.tenant, kind, id, value).await?;
    Ok(())
}
pub(crate) async fn archive(h: &Harness, request: Id) -> DomainResult<Value> {
    let state = read(h, BASE).await?;
    post(
        h,
        &format!("{BASE}/operations/archive"),
        json!({"expected_generation":number(&state,"generation")?,"request_ids":[request]}),
    )
    .await
}
