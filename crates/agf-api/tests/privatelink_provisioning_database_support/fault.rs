use super::{Case, error, sql};
use agf_core::{error::DomainResult, ids::Id};
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe};
pub(crate) async fn terminal<T, F, Fut>(case: &Case, kind: &str, work: F) -> DomainResult<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = DomainResult<T>>,
{
    case.check().await?;
    if !["privatelink-provisioning-claim", "privatelink-provisioning-fact"].contains(&kind) {
        return Err(error("fault target differs"));
    }
    let name = format!("privatelink_owned_fault_{}", Id::new().as_uuid().simple());
    sqlx::query(&format!("ALTER TABLE audit_logs ADD CONSTRAINT {name} CHECK (tenant_id <> '{}'::uuid OR target->>'kind' <> '{kind}') NOT VALID",case.inner.h.tenant))
        .execute(&case.inner.pool).await.map_err(sql)?;
    let result = AssertUnwindSafe(work()).catch_unwind().await;
    case.check().await?;
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {name}"))
        .execute(&case.inner.pool)
        .await
        .map_err(sql)?;
    match result {
        Ok(value) => value,
        Err(_) => Err(error("PrivateLink case panicked after owned fault cleanup")),
    }
}
