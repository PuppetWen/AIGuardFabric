//! Exact owned-tenant terminal audit failure; finally cleanup preserves the original panic/error.
use super::*;
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe};
pub(crate) struct Fault {
    pool: PgPool,
    owner: owner::Owner,
    name: String,
}
impl Fault {
    pub(crate) async fn terminal(owned: &Owned) -> DomainResult<Self> {
        owned.verify().await?;
        let name = format!("agf_stream_audit_fault_{}", Id::new().as_uuid().simple());
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conname=$1)")
            .bind(&name)
            .fetch_one(&owned.case.pool)
            .await
            .map_err(sql)?;
        if exists {
            return Err(invalid());
        }
        sqlx::query(&format!("ALTER TABLE audit_logs ADD CONSTRAINT {name} CHECK(NOT(tenant_id='{}'::uuid AND target->>'kind'='gateway-attempt' AND action='execute')) NOT VALID",owned.case.h.tenant))
            .execute(&owned.case.pool).await.map_err(sql)?;
        Ok(Self { pool: owned.case.pool.clone(), owner: owned.owner.clone(), name })
    }
    async fn close(self) -> DomainResult<()> {
        self.owner.verify(&self.pool).await?;
        sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {}", self.name))
            .execute(&self.pool)
            .await
            .map_err(sql)?;
        let remains: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conname=$1)")
            .bind(&self.name)
            .fetch_one(&self.pool)
            .await
            .map_err(sql)?;
        if remains {
            return Err(invalid());
        }
        Ok(())
    }
}
pub(crate) async fn with_fault<T, F: Future<Output = DomainResult<T>>>(fault: Fault, run: F) -> DomainResult<T> {
    let result = AssertUnwindSafe(run).catch_unwind().await;
    fault.close().await?;
    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
