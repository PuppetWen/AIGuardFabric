//! Minimal shared owned-database identity; no other target's tests are imported.
use crate::common::*;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
pub(crate) mod authority;
pub(crate) mod crypto;
pub(crate) mod fault;
pub(crate) mod provider;
mod signature;
mod wire;
const PREFIX: &str = "AIGuardFabric Scheduler native observation SQL ";
fn identity() -> DomainResult<(String, String)> {
    let owner = std::env::var("AGF_SCHEDULER_NATIVE_DATABASE_OWNER").map_err(|_| error())?;
    let run = owner
        .strip_prefix(PREFIX)
        .filter(|run| run.len() == 32 && run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .ok_or_else(error)?;
    Ok((format!("agf_requirements_test_scheduler_native_{}", &run[..12]), owner))
}
pub(crate) fn error() -> DomainError {
    DomainError::Internal("Owned Scheduler database fixture rejected; details withheld".into())
}
pub(crate) fn sql(_: sqlx::Error) -> DomainError {
    error()
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
        let (name, owner) = identity()?;
        if actual != (name, Some(owner), self.oid) || self.oid <= 0 {
            return Err(error());
        }
        Ok(())
    }
}
pub(crate) struct Case {
    pub(crate) h: Harness,
    pub(crate) owner: Owner,
    store: Arc<Store>,
}
impl Case {
    pub(crate) async fn open(label: &str) -> DomainResult<Self> {
        if label.is_empty() || label.len() + 37 > 64 {
            return Err(error());
        }
        let raw = std::env::var("AGF_TEST_DATABASE_URL").map_err(|_| error())?;
        let url = url::Url::parse(&raw).map_err(|_| error())?;
        let (name, owner) = identity()?;
        if !matches!(url.scheme(), "postgres" | "postgresql")
            || url.host_str() != Some("127.0.0.1")
            || url.port() != Some(5432)
            || url.path() != format!("/{name}")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(error());
        }
        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(12).connect(&raw).await.map_err(sql)?;
        // Before migrations, accounts, tenants or faults, verify exact database comment and OID.
        let actual:(String,Option<String>,i64)=sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database'),oid::bigint FROM pg_database WHERE datname=current_database()")
            .fetch_one(&pool).await.map_err(sql)?;
        if actual.0 != name || actual.1 != Some(owner) || actual.2 <= 0 {
            return Err(error());
        }
        let owner = Owner { pool: pool.clone(), oid: actual.2 };
        owner.check().await?;
        let db = Database::from_pool(pool);
        db.migrate().await?;
        let store = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
        let tenant = agf_api::tenant_directory::new(format!("{label}-{}", Id::new()), label.into());
        let state = AppState::with_database(test_config(), store.clone())?;
        agf_api::tenant_directory::save(&state, tenant.clone(), true).await?;
        Ok(Self { h: instance(store.clone(), tenant.id).await?, owner, store })
    }
    pub(crate) async fn second(&self) -> DomainResult<Harness> {
        self.owner.check().await?;
        instance(self.store.clone(), self.h.tenant).await
    }
    pub(crate) async fn foreign(&self) -> DomainResult<Harness> {
        self.owner.check().await?;
        let tenant = agf_api::tenant_directory::new(format!("managed-foreign-{}", Id::new()), "Owned foreign".into());
        agf_api::tenant_directory::save(&self.h.state, tenant.clone(), true).await?;
        instance(self.store.clone(), tenant.id).await
    }
}
async fn instance(store: Arc<Store>, tenant: TenantId) -> DomainResult<Harness> {
    let state = AppState::with_database(test_config(), store)?;
    let saved = state.ensure_bootstrap_admin(tenant, "admin", "admin@owned.test", Some(ADMIN_PWD), false).await?;
    let user = match saved {
        BootstrapOutcome::Created { user, .. } | BootstrapOutcome::AlreadyExists { user } => user,
    };
    let admin = state.auth.issue_for_user(&user, tenant, vec!["superadmin".into()])?.access_token;
    let mut viewer = User::new_local(tenant, "viewer", "viewer@owned.test");
    viewer.must_change_password = false;
    let viewer = match state.auth_backend.find_user_with_secret(tenant, "viewer").await? {
        Some(saved) => saved.user,
        None => {
            let hash = state.auth.hasher().hash_checked(VIEWER_PWD, "viewer")?;
            state.auth_backend.save_account(&viewer, Some(&hash), &["viewer".into()]).await?;
            viewer
        }
    };
    let viewer = state.auth.issue_for_user(&viewer, tenant, vec!["viewer".into()])?.access_token;
    // This real SQL principal supplies its tenant normally; no forced-tenant router middleware.
    Ok(Harness {
        app: build_router(state.clone()),
        state,
        admin,
        viewer,
        api_key: String::new(),
        tenant,
        other_tenant: tenant,
    })
}
