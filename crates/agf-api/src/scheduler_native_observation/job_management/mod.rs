//! Durable explicit job control is separate from observation, binding and callback execution.
mod archive;
mod baseline;
mod claim;
mod codec;
mod completion;
mod current;
mod input;
mod mock;
mod mock_commit;
pub(super) mod model;
mod mutation;
mod observe;
mod plan;
mod preview;
mod routes;
mod staging;
mod views;
mod workflow;

pub(super) use codec::request_key;
pub(super) use routes::router;
pub(super) async fn require_vacant(
    state: &crate::state::AppState,
    tenant: agf_core::ids::TenantId,
    id: agf_core::ids::Id,
) -> agf_core::error::DomainResult<()> {
    if super::store::get::<serde_json::Value>(state, tenant, &request_key(tenant, id)).await?.is_some() {
        return Err(conflict());
    }
    Ok(())
}
pub(super) fn vacant(
    values: &super::records::Values,
    key: &(String, agf_core::ids::Id),
) -> agf_core::error::DomainResult<()> {
    if values.get(key).and_then(Option::as_ref).is_some() {
        return Err(conflict());
    }
    Ok(())
}
fn conflict() -> agf_core::error::DomainError {
    agf_core::error::DomainError::Conflict("原 Scheduler 请求 UUID 已永久用于其他动作或参数，不能重派".into())
}
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_sizes;
