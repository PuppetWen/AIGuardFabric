//! Exact database ownership is verified before the legacy SqlCase can migrate anything.
use crate::{
    agentteams_task_handling_support::{self as support, Fixture},
    common::*,
    configuration_audit_support::SqlCase,
};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use agf_ingest::pipeline::SqlSink;
mod gate;
pub(crate) use gate::{Gate, key, revoke};
pub(crate) struct Case {
    pub(crate) sql: SqlCase,
    pub(crate) fixture: Fixture,
    pub(crate) owner: Owner,
}
pub(crate) struct Owner {
    name: String,
    comment: String,
    oid: i64,
}
impl Owner {
    pub(crate) async fn preflight() -> DomainResult<Self> {
        let raw = std::env::var("AGF_TEST_DATABASE_URL").map_err(|_| support::invalid())?;
        let url = url::Url::parse(&raw).map_err(|_| support::invalid())?;
        let name = url.path().strip_prefix('/').ok_or_else(support::invalid)?.to_owned();
        let suffix = name.strip_prefix("agf_requirements_test_wp4_").ok_or_else(support::invalid)?;
        let comment = std::env::var("AGF_WP4_DATABASE_OWNER").map_err(|_| support::invalid())?;
        let owner = comment.strip_prefix("AIGuardFabric WP4 handling SQL ").ok_or_else(support::invalid)?;
        if !hex(suffix, 12) || !hex(owner, 32) || url.fragment().is_some() {
            return Err(support::invalid());
        }
        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&raw).await.map_err(sql_error)?;
        let (actual,oid,marker):(String,i64,Option<String>)=sqlx::query_as(
            "SELECT datname,oid::bigint,shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()")
            .fetch_one(&pool).await.map_err(sql_error)?;
        pool.close().await;
        if actual != name || marker.as_deref() != Some(comment.as_str()) || oid <= 0 {
            return Err(support::invalid());
        }
        Ok(Self { name, comment, oid })
    }
    pub(crate) async fn verify(&self, pool: &sqlx::PgPool) -> DomainResult<()> {
        let (name,oid,marker):(String,i64,Option<String>)=sqlx::query_as(
            "SELECT datname,oid::bigint,shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()")
            .fetch_one(pool).await.map_err(sql_error)?;
        if name != self.name || oid != self.oid || marker.as_deref() != Some(self.comment.as_str()) {
            return Err(support::invalid());
        }
        Ok(())
    }
}
impl Case {
    pub(crate) async fn open(label: &str) -> DomainResult<Self> {
        let owner = Owner::preflight().await?;
        if label.len() > 26 {
            return Err(support::invalid());
        }
        let sql = SqlCase::open(label).await;
        owner.verify(&sql.pool).await?;
        let mut h = sql.h.clone();
        let store = h.state.store.database().ok_or_else(support::invalid)?.clone();
        h.state.ingest_sink = Arc::new(SqlSink::new(store).with_event_outbox(true));
        let fixture = Fixture::from_harness(h).await?;
        Ok(Self { sql, fixture, owner })
    }
    pub(crate) async fn second(&self) -> DomainResult<Harness> {
        let mut h = self.sql.second_instance().await;
        let store = h.state.store.database().ok_or_else(support::invalid)?.clone();
        h.state.ingest_sink = Arc::new(SqlSink::new(store).with_event_outbox(true));
        Arc::make_mut(&mut h.state.config).mock_mode = false;
        let tenant_header: axum::http::HeaderValue = h.tenant.to_string().parse().map_err(|_| support::invalid())?;
        h.app =
            build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
                request.headers_mut().insert("x-agf-tenant", tenant_header.clone());
                async move { request }
            }));
        Ok(h)
    }
    pub(crate) async fn fault(&self) -> DomainResult<String> {
        self.owner.verify(&self.sql.pool).await?;
        let name = format!("agf_wp4_audit_{}", Id::new().as_uuid().simple());
        let tenant = self.fixture.h.tenant;
        sqlx::query(&format!("ALTER TABLE audit_logs ADD CONSTRAINT {name} CHECK (tenant_id <> '{tenant}'::uuid OR target->>'kind' NOT LIKE 'agentteams-task-handling%') NOT VALID"))
            .execute(&self.sql.pool).await.map_err(sql_error)?;
        Ok(name)
    }
    pub(crate) async fn unfault(&self, name: &str) -> DomainResult<()> {
        self.owner.verify(&self.sql.pool).await?;
        if !name.starts_with("agf_wp4_audit_") || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(support::invalid());
        }
        sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {name}"))
            .execute(&self.sql.pool)
            .await
            .map_err(sql_error)?;
        Ok(())
    }
    pub(crate) async fn source_lock(&self) -> DomainResult<(sqlx::Transaction<'_, sqlx::Postgres>, i32)> {
        self.owner.verify(&self.sql.pool).await?;
        let mut tx = self.sql.pool.begin().await.map_err(sql_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("{}:log-source:{}", self.fixture.h.tenant, self.fixture.source))
            .execute(&mut *tx)
            .await
            .map_err(sql_error)?;
        let pid = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *tx).await.map_err(sql_error)?;
        Ok((tx, pid))
    }
    pub(crate) async fn wait_source(&self, pid: i32) -> DomainResult<()> {
        tokio::time::timeout(std::time::Duration::from_secs(20),async {
            loop {
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_locks w JOIN pg_locks h ON w.locktype=h.locktype AND w.database=h.database AND w.classid=h.classid AND w.objid=h.objid AND w.objsubid=h.objsubid WHERE w.locktype='advisory' AND NOT w.granted AND h.granted AND h.pid=$1 AND w.pid<>h.pid AND w.database=(SELECT oid FROM pg_database WHERE datname=current_database()))")
                    .bind(pid).fetch_one(&self.sql.pool).await.map_err(sql_error)?;
                if waiting{return Ok(());}
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }).await.map_err(|_|support::invalid())?
    }
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn sql_error(error: sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("owned_wp4_fixture", &error)
}
