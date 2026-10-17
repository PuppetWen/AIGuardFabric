use crate::{common::*, configuration_audit_support::SqlCase, privatelink_provisioning_support as p};
use agf_core::error::{DomainError, DomainResult};
pub(crate) mod authority;
pub(crate) mod engine;
pub(crate) mod fault;
mod wire;
pub(crate) struct Case {
    pub(crate) inner: SqlCase,
    name: String,
    owner: String,
    oid: i64,
}
pub(crate) fn error(s: &str) -> DomainError {
    DomainError::PreconditionFailed(format!("owned PrivateLink SQL: {s}"))
}
pub(crate) fn sql(_: sqlx::Error) -> DomainError {
    DomainError::Internal("owned PrivateLink SQL operation failed".into())
}
async fn inspect(pool: &sqlx::PgPool) -> DomainResult<(String, i64, Option<String>)> {
    sqlx::query_as("SELECT datname,oid::bigint,shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()").fetch_one(pool).await.map_err(sql)
}
impl Case {
    pub(crate) async fn open(label: &str) -> DomainResult<Self> {
        let owner = std::env::var("AGF_PRIVATELINK_PROVISIONING_DATABASE_OWNER")
            .map_err(|_| error("owned database owner is required"))?;
        let run = owner
            .strip_prefix("AIGuardFabric PrivateLink provisioning SQL ")
            .filter(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            .ok_or_else(|| error("owner mismatch"))?;
        let name = format!("agf_requirements_test_privatelink_provisioning_{}", &run[..12]);
        let raw = std::env::var("AGF_TEST_DATABASE_URL").map_err(|_| error("database URL required"))?;
        let url = url::Url::parse(&raw)?;
        if !matches!(url.scheme(), "postgres" | "postgresql")
            || url.host_str() != Some("127.0.0.1")
            || url.port() != Some(5432)
            || url.path() != format!("/{name}")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(error("target differs"));
        }
        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&raw).await.map_err(sql)?;
        let result = inspect(&pool).await;
        pool.close().await;
        let (actual, oid, comment) = result?;
        if actual != name || comment.as_deref() != Some(&owner) {
            return Err(error("ownership differs before migration"));
        }
        let case = Self { inner: SqlCase::open(label).await, name, owner, oid };
        case.check().await?;
        Ok(case)
    }
    pub(crate) async fn check(&self) -> DomainResult<()> {
        if inspect(&self.inner.pool).await? != (self.name.clone(), self.oid, Some(self.owner.clone())) {
            return Err(error("ownership/OID changed"));
        }
        Ok(())
    }
}

pub(crate) fn pending(h: Harness, path: String, body: Value) -> wire::Pending {
    let token = h.admin.clone();
    wire::Pending::start(h, path, token, body)
}
