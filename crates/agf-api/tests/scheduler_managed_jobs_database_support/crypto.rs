use super::{Case, error};
use crate::{common::*, scheduler_managed_jobs_support::*};
use agf_core::{
    error::DomainResult,
    ids::{Id, deterministic_id},
};
use agf_storage::crypto::FieldCipher;
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe};
const PREVIEW: &str = "scheduler-managed-job-preview";
const PENDING: &str = "scheduler-managed-job-pending";
fn record(tenant: TenantId, id: Id, kind: &str) -> Id {
    deterministic_id("agf.scheduler.native.record", &format!("{tenant}:{kind}:{id}"))
}
async fn with_record<F, Fut>(case: &Case, kind: &str, id: Id, changed: &Value, action: F) -> DomainResult<()>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = DomainResult<()>>,
{
    case.owner.check().await?;
    let original: Value = case.h.state.configurations.get(case.h.tenant, kind, id).await?.ok_or_else(error)?;
    case.h.state.configurations.put(case.h.tenant, kind, id, changed).await?;
    let result = AssertUnwindSafe(action()).catch_unwind().await;
    case.owner.check().await?;
    let restored = case.h.state.configurations.put(case.h.tenant, kind, id, &original).await;
    match result {
        Ok(value) => {
            restored?;
            value
        }
        Err(panic) => {
            if restored.is_err() {
                tracing::error!("Owned Scheduler corruption restoration failed; details withheld");
            }
            std::panic::resume_unwind(panic)
        }
    }
}
pub(crate) async fn corrupt_then_restore(case: &Case, id: Id) -> DomainResult<()> {
    let key = record(case.h.tenant, id, PREVIEW);
    let original: Value = case.h.state.configurations.get(case.h.tenant, PREVIEW, key).await?.ok_or_else(error)?;
    let mut changed = original.clone();
    changed["secret"]["aad"] = json!(FieldCipher::make_aad(&TenantId::new(), &key));
    with_record(case, PREVIEW, key, &changed, || async {
        let before = digest(&case.h).await?;
        assert_eq!(case.h.get(&format!("{BASE}/previews/{id}")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(digest(&case.h).await?, before);
        Ok(())
    })
    .await
}
pub(crate) async fn copy_then_restore(case: &Case, a: Id, b: Id) -> DomainResult<()> {
    let a_key = record(case.h.tenant, a, PREVIEW);
    let b_key = record(case.h.tenant, b, PREVIEW);
    let mut copied: Value = case.h.state.configurations.get(case.h.tenant, PREVIEW, a_key).await?.ok_or_else(error)?;
    // Shape and outer identity are valid; the embedded authenticated AAD still belongs to A.
    copied["id"] = json!(b_key);
    with_record(case, PREVIEW, b_key, &copied, || async {
        let before = digest(&case.h).await?;
        assert_eq!(case.h.get(&format!("{BASE}/previews/{b}")).await.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(digest(&case.h).await?, before);
        Ok(())
    })
    .await
}
pub(crate) async fn pending(case: &Case, h: &Harness, id: Id) -> DomainResult<()> {
    let key = record(h.tenant, id, PENDING);
    let original: Value = h.state.configurations.get(h.tenant, PENDING, key).await?.ok_or_else(error)?;
    let mut changed = original.clone();
    changed["secret"]["aad"] = json!(FieldCipher::make_aad(&TenantId::new(), &key));
    with_record(case, PENDING, key, &changed, || async {
        let before = digest(h).await?;
        assert_eq!(h.get(&receipt(id)).await.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            h.post(&format!("{}/recover", receipt(id)), json!({})).await.status,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(digest(h).await?, before);
        Ok(())
    })
    .await
}
