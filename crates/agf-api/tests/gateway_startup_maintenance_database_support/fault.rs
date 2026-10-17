//! A scoped fresh-tenant constraint rejects a real audit insert, not a simulated route result.
use super::*;
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe};

pub(crate) struct AuditFault {
    pool: PgPool,
    ownership: Ownership,
    name: String,
}
impl AuditFault {
    pub(crate) async fn install(owned: &Owned, target: &str, action: &str) -> DomainResult<Self> {
        owned.ownership.verify(&owned.case.pool).await?;
        if !matches!((target, action), ("gateway-admission", "configure") | ("gateway-attempt", "execute")) {
            return Err(invalid());
        }
        let name = format!("agf_gw_settlement_fault_{}", Id::new().as_uuid().simple());
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conname=$1)")
            .bind(&name)
            .fetch_one(&owned.case.pool)
            .await
            .map_err(|e| sql(&e))?;
        if exists {
            return Err(invalid());
        }
        sqlx::query(&format!("ALTER TABLE audit_logs ADD CONSTRAINT {name} CHECK(NOT(tenant_id='{}'::uuid AND target->>'kind'='{target}' AND action='{action}')) NOT VALID",owned.case.h.tenant))
            .execute(&owned.case.pool).await.map_err(|e|sql(&e))?;
        Ok(Self { pool: owned.case.pool.clone(), ownership: owned.ownership.clone(), name })
    }
    async fn close(self) -> DomainResult<()> {
        self.ownership.verify(&self.pool).await?;
        sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {}", self.name))
            .execute(&self.pool)
            .await
            .map_err(|e| sql(&e))?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conname=$1)")
            .bind(self.name)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| sql(&e))?;
        if exists {
            return Err(invalid());
        }
        Ok(())
    }
}
pub(crate) async fn with_fault<T, F: Future<Output = DomainResult<T>>>(fault: AuditFault, run: F) -> DomainResult<T> {
    let result = AssertUnwindSafe(run).catch_unwind().await;
    fault.close().await?;
    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
