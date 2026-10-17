use crate::common::*;
use agf_core::error::{DomainError, DomainResult};
use agf_storage::{Database, Store, configuration::ConfigStore, objectstore::MemoryObjectStore};
pub(crate) fn failure() -> DomainError {
    DomainError::Internal("Owned multi-target fixture failed; private details omitted".into())
}
fn sql(_: sqlx::Error) -> DomainError {
    failure()
}
fn identity() -> DomainResult<(String, String)> {
    let owner = std::env::var("AGF_REDTEAM_MULTI_DATABASE_OWNER").map_err(|_| failure())?;
    let run = owner
        .strip_prefix("AIGuardFabric multi-target redteam SQL ")
        .filter(|run| run.len() == 32 && run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .ok_or_else(failure)?;
    Ok((format!("agf_requirements_test_redteam_multi_{}", &run[..12]), owner))
}
pub(crate) struct Case {
    pub(crate) h: Harness,
    pub(crate) pool: sqlx::PgPool,
    store: Arc<Store>,
    oid: i64,
}
impl Case {
    #[allow(dead_code, reason = "Shared audit gate used by the multi-target database test binary")]
    pub(crate) async fn hold_audit(&self) -> DomainResult<sqlx::Transaction<'static, sqlx::Postgres>> {
        self.check().await?;
        let mut held = self.pool.begin().await.map_err(sql)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("{}:audit-chain", self.h.tenant))
            .execute(&mut *held)
            .await
            .map_err(sql)?;
        Ok(held)
    }
    #[allow(dead_code, reason = "Shared audit gate used by the multi-target database test binary")]
    pub(crate) async fn wait_audit(&self) -> DomainResult<()> {
        self.check().await?;
        let key = format!("{}:audit-chain", self.h.tenant);
        tokio::time::timeout(std::time::Duration::from_secs(20),async {
            loop {
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=((hashtextextended($1,0)>>32)&4294967295)::oid AND objid=(hashtextextended($1,0)&4294967295)::oid AND objsubid=1)")
                    .bind(&key).fetch_one(&self.pool).await.map_err(sql)?;
                if waiting{return Ok(());}tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }).await.map_err(|_|failure())?
    }
    #[allow(dead_code, reason = "Shared fault injection used by the multi-target database test binary")]
    pub(crate) async fn revoke_key_fault(&self, key: agf_core::ids::Id) -> DomainResult<()> {
        self.check().await?;
        let changed=sqlx::query("UPDATE api_keys SET revoked=true,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked AND deleted_at IS NULL")
            .bind(self.h.tenant.as_uuid()).bind(key.as_uuid()).execute(&self.pool).await.map_err(sql)?.rows_affected();
        if changed != 1 {
            return Err(failure());
        }
        Ok(())
    }
    pub(crate) async fn open(label: &str) -> DomainResult<Self> {
        if label.is_empty() || label.len() + 37 > 64 {
            return Err(failure());
        }
        let raw = std::env::var("AGF_TEST_DATABASE_URL").map_err(|_| failure())?;
        let url = url::Url::parse(&raw).map_err(|_| failure())?;
        let (name, comment) = identity()?;
        if !matches!(url.scheme(), "postgres" | "postgresql")
            || url.host_str() != Some("127.0.0.1")
            || url.port() != Some(5432)
            || url.path() != format!("/{name}")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(failure());
        }
        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(12).connect(&raw).await.map_err(sql)?;
        let actual:(String,Option<String>,i64)=sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database'),oid::bigint FROM pg_database WHERE datname=current_database()")
            .fetch_one(&pool).await.map_err(sql)?;
        if actual.0 != name || actual.1 != Some(comment) || actual.2 <= 0 {
            return Err(failure());
        }
        // Ownership before migrations, API fixture setup, DDL or direct fault injection.
        let db = Database::from_pool(pool.clone());
        db.migrate().await?;
        let store = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
        let tenant = agf_api::tenant_directory::new(format!("{label}-{}", agf_core::ids::Id::new()), label.into());
        let h = instance(store.clone(), tenant.id).await;
        agf_api::tenant_directory::save(&h.state, tenant, true).await?;
        Ok(Self { h, pool, store, oid: actual.2 })
    }
    pub(crate) async fn check(&self) -> DomainResult<()> {
        let actual:(String,Option<String>,i64)=sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database'),oid::bigint FROM pg_database WHERE datname=current_database()")
            .fetch_one(&self.pool).await.map_err(sql)?;
        let (name, comment) = identity()?;
        if actual != (name, Some(comment), self.oid) {
            return Err(failure());
        }
        Ok(())
    }
    pub(crate) async fn second(&self) -> DomainResult<Harness> {
        self.check().await?;
        Ok(instance(self.store.clone(), self.h.tenant).await)
    }
    pub(crate) async fn foreign(&self) -> DomainResult<Harness> {
        self.check().await?;
        let tenant =
            agf_api::tenant_directory::new(format!("foreign-{}", agf_core::ids::Id::new()), "Foreign redteam".into());
        agf_api::tenant_directory::save(&self.h.state, tenant.clone(), true).await?;
        Ok(instance(self.store.clone(), tenant.id).await)
    }
    #[allow(dead_code, reason = "Shared fault injection used by the multi-target database test binary")]
    pub(crate) async fn audit_fault(&self, request: agf_core::ids::Id, action: &str) -> DomainResult<String> {
        self.check().await?;
        if !matches!(action, "configure" | "execute") {
            return Err(failure());
        }
        let name = format!("agf_rt_multi_{}", agf_core::ids::Id::new().as_uuid().simple());
        sqlx::query(&format!("ALTER TABLE audit_logs ADD CONSTRAINT {name} CHECK (NOT (tenant_id='{}'::uuid AND target->>'kind'='redteam-multi-target' AND target->>'id'='{request}' AND action='{action}')) NOT VALID",self.h.tenant))
            .execute(&self.pool).await.map_err(sql)?;
        Ok(name)
    }
    #[allow(dead_code, reason = "Shared fault cleanup used by the multi-target database test binary")]
    pub(crate) async fn clear_fault(&self, name: &str) -> DomainResult<()> {
        self.check().await?;
        if !name.starts_with("agf_rt_multi_")
            || name.len() != 45
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(failure());
        }
        sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {name}"))
            .execute(&self.pool)
            .await
            .map_err(sql)?;
        Ok(())
    }
}
async fn instance(store: Arc<Store>, tenant: TenantId) -> Harness {
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(ConfigStore::new(Some(store)));
    h.tenant = tenant;
    rebuild(&mut h);
    h
}
pub(crate) fn rebuild(h: &mut Harness) {
    let tenant = h.tenant;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        // HeaderValue::from_str accepts canonical UUIDs without any user text.
        if let Ok(value) = tenant.to_string().parse() {
            request.headers_mut().insert("x-agf-tenant", value);
        }
        async move { request }
    }));
}
