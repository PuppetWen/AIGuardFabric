//! Exact owner/comment/OID checks precede migrations and every durable fixture.
use super::ownership::Scratch;
use agf_storage::{Database, Store, objectstore::LocalFileObjectStore};
use std::sync::Arc;

pub(super) struct Owned {
    pub(super) store: Arc<Store>,
    pub(super) scratch: Scratch,
    pool: sqlx::PgPool,
    name: String,
    owner: String,
    oid: i64,
}
impl Owned {
    pub(super) async fn finish(self) -> anyhow::Result<()> {
        self.check().await?;
        self.pool.close().await;
        self.scratch.clean()
    }
    pub(super) async fn open() -> anyhow::Result<Self> {
        let owner = std::env::var("AGF_SCHEDULER_CALLBACK_BUSINESS_DATABASE_OWNER")?;
        let run = owner
            .strip_prefix("AIGuardFabric Scheduler callback business SQL ")
            .filter(|run| {
                run.len() == 32 && run.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| anyhow::anyhow!("exact callback business database owner required"))?
            .to_owned();
        let name = format!("agf_requirements_test_scheduler_callback_business_{}", &run[..12]);
        let raw = std::env::var("AGF_TEST_DATABASE_URL")?;
        let url = reqwest::Url::parse(&raw).map_err(|_| anyhow::anyhow!("owned database URL invalid"))?;
        anyhow::ensure!(
            matches!(url.scheme(), "postgres" | "postgresql")
                && url.host_str() == Some("127.0.0.1")
                && url.port() == Some(5432)
                && url.path() == format!("/{name}")
                && url.query().is_none()
                && url.fragment().is_none(),
            "database is not the exact owned loopback database"
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(12)
            .acquire_timeout(std::time::Duration::from_secs(20))
            .connect(&raw)
            .await
            .map_err(|_| anyhow::anyhow!("owned database connection failed"))?;
        let actual:(String,Option<String>,i64)=sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database'),oid::bigint FROM pg_database WHERE datname=current_database()")
            .fetch_one(&pool).await?;
        anyhow::ensure!(
            actual.0 == name && actual.1.as_deref() == Some(&owner) && actual.2 > 0,
            "foreign database rejected before migrations"
        );
        let database = Database::from_pool(pool.clone());
        database.migrate().await?;
        let scratch = Scratch::new(&run, &name)?;
        let objects = Arc::new(LocalFileObjectStore::new(scratch.path("objects"))?);
        Ok(Self { store: Arc::new(Store::new(database, None, objects)), scratch, pool, name, owner, oid: actual.2 })
    }
    pub(super) async fn check(&self) -> anyhow::Result<()> {
        let actual:(String,Option<String>,i64)=sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database'),oid::bigint FROM pg_database WHERE datname=current_database()")
            .fetch_one(&self.pool).await?;
        anyhow::ensure!(actual == (self.name.clone(), Some(self.owner.clone()), self.oid), "database owner changed");
        Ok(())
    }
    pub(super) async fn count(&self, tenant: agf_core::ids::TenantId, table: &str) -> anyhow::Result<i64> {
        self.check().await?;
        let query = match table {
            "raw_logs" => "SELECT count(*) FROM raw_logs WHERE tenant_id=$1",
            "events" => "SELECT count(*) FROM events WHERE tenant_id=$1",
            _ => anyhow::bail!("undeclared fixture count table"),
        };
        Ok(sqlx::query_scalar(query).bind(tenant.as_uuid()).fetch_one(&self.pool).await?)
    }
    pub(super) async fn rows(&self, tenant: agf_core::ids::TenantId) -> anyhow::Result<serde_json::Value> {
        self.check().await?;
        let raw:serde_json::Value=sqlx::query_scalar("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY received_at,id),'[]'::jsonb) FROM raw_logs r WHERE tenant_id=$1")
            .bind(tenant.as_uuid()).fetch_one(&self.pool).await?;
        let events: serde_json::Value = sqlx::query_scalar(
            "SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY time,id),'[]'::jsonb) FROM events e WHERE tenant_id=$1",
        )
        .bind(tenant.as_uuid())
        .fetch_one(&self.pool)
        .await?;
        Ok(serde_json::json!({"raw":raw,"events":events}))
    }
}
