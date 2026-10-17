//! Exact URL, comment and OID precede any migration or fixture mutation.
use super::{invalid, sql_error};
use agf_core::error::DomainResult;

pub(super) struct Owner {
    name: String,
    comment: String,
    oid: i64,
}
impl Owner {
    pub(super) async fn preflight() -> DomainResult<Self> {
        let raw = std::env::var("AGF_TEST_DATABASE_URL").map_err(|_| invalid())?;
        let url = url::Url::parse(&raw).map_err(|_| invalid())?;
        let comment = std::env::var("AGF_BLACKLIST_DATABASE_OWNER").map_err(|_| invalid())?;
        let run = comment.strip_prefix("AIGuardFabric blacklist publication SQL ").ok_or_else(invalid)?;
        if run.len() != 32 || !run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(invalid());
        }
        let name = format!("agf_requirements_test_blacklist_{}", &run[..12]);
        if !matches!(url.scheme(), "postgres" | "postgresql")
            || url.host_str() != Some("127.0.0.1")
            || url.port() != Some(5432)
            || url.path() != format!("/{name}")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid());
        }
        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&raw).await.map_err(sql_error)?;
        let result=sqlx::query_as::<_,(String,i64,Option<String>)>(
            "SELECT datname,oid::bigint,shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()"
        ).fetch_one(&pool).await;
        pool.close().await;
        let (actual, oid, marker) = result.map_err(sql_error)?;
        if actual != name || oid <= 0 || marker.as_deref() != Some(comment.as_str()) {
            return Err(invalid());
        }
        Ok(Self { name, comment, oid })
    }
    pub(super) async fn verify(&self, pool: &sqlx::PgPool) -> DomainResult<()> {
        let (name,oid,marker):(String,i64,Option<String>)=sqlx::query_as(
            "SELECT datname,oid::bigint,shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()"
        ).fetch_one(pool).await.map_err(sql_error)?;
        if name != self.name || oid != self.oid || marker.as_deref() != Some(self.comment.as_str()) {
            return Err(invalid());
        }
        Ok(())
    }
}
