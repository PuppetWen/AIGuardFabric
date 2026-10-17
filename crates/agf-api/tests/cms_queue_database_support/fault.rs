use super::{Case, error, sql};
use agf_core::{error::DomainResult, ids::Id};
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe};
pub(crate) async fn terminal<T, F, Fut>(case: &Case, work: F) -> DomainResult<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = DomainResult<T>>,
{
    case.check().await?;
    let name = format!("cms_queue_owned_fault_{}", Id::new().as_uuid().simple());
    sqlx::query(&format!("ALTER TABLE audit_logs ADD CONSTRAINT {name} CHECK (tenant_id <> '{}'::uuid OR target->>'kind' <> 'cms-queue-attempt') NOT VALID",case.inner.h.tenant))
        .execute(&case.inner.pool).await.map_err(sql)?;
    let result = AssertUnwindSafe(work()).catch_unwind().await;
    case.check().await?;
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {name}"))
        .execute(&case.inner.pool)
        .await
        .map_err(sql)?;
    match result {
        Ok(value) => value,
        Err(_) => Err(error("CMS case panicked after owned fault cleanup")),
    }
}
