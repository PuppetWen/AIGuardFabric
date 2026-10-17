//! Exact literal127 database/COMMENT/OID identity precedes every migration or fault write.
use super::*;
use sqlx::{PgPool, postgres::PgPoolOptions};
#[derive(Clone)]
pub(super) struct Owner {
    name: String,
    comment: String,
    oid: i64,
}
impl Owner {
    async fn capture(pool: &PgPool) -> DomainResult<Self> {
        let comment = std::env::var("AGF_GATEWAY_STREAM_SETTLEMENT_DATABASE_OWNER").map_err(|_| invalid())?;
        let run = comment.strip_prefix("AIGuardFabric gateway stream settlement SQL ").ok_or_else(invalid)?;
        if run.len() != 32 || !run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(invalid());
        }
        let name = format!("agf_requirements_test_gateway_stream_{}", &run[..12]);
        let row: (String, i64, Option<String>) = sqlx::query_as("SELECT current_database(),oid::bigint,shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()")
            .fetch_one(pool).await.map_err(sql)?;
        if row.0 != name || row.1 <= 0 || row.2.as_deref() != Some(comment.as_str()) {
            return Err(invalid());
        }
        Ok(Self { name, comment, oid: row.1 })
    }
    pub(super) async fn verify(&self, pool: &PgPool) -> DomainResult<()> {
        let current = Self::capture(pool).await?;
        if (current.name, current.comment, current.oid) != (self.name.clone(), self.comment.clone(), self.oid) {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) async fn preflight() -> DomainResult<(PgPool, Self)> {
        let raw = std::env::var("AGF_TEST_DATABASE_URL").map_err(|_| invalid())?;
        let url = url::Url::parse(&raw).map_err(|_| invalid())?;
        if !matches!(url.scheme(), "postgres" | "postgresql")
            || url.host_str() != Some("127.0.0.1")
            || url.port() != Some(5432)
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid());
        }
        let pool = PgPoolOptions::new().max_connections(1).connect(&raw).await.map_err(sql)?;
        let result = Self::capture(&pool)
            .await
            .and_then(|owner| if url.path() != format!("/{}", owner.name) { Err(invalid()) } else { Ok(owner) });
        match result {
            Ok(owner) => Ok((pool, owner)),
            Err(error) => {
                pool.close().await;
                Err(error)
            }
        }
    }
}
