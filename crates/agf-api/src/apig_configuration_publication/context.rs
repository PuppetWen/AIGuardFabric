//! Local binding reads never initialize or query a provider.
use super::{
    contract::{Scope, TransportMode},
    util,
};
use crate::{cloud_store, integration_store::Stored, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
};

pub(super) async fn current(state: &AppState, tenant: TenantId, version: Option<u64>) -> DomainResult<Scope> {
    let row = configured(state, tenant)
        .await?
        .filter(|row| row.enabled)
        .ok_or_else(|| DomainError::PreconditionFailed("请保存并启用明确的APIG内容/模型配置绑定".into()))?;
    if version.is_some_and(|expected| expected != row.version) {
        return Err(util::stale());
    }
    super::scope::from_row(state, tenant, &row)
}
pub(super) fn confirm(scope: &Scope, confirmed: bool) -> DomainResult<()> {
    if scope.target.transport_mode == TransportMode::Live && !confirmed {
        return Err(DomainError::PreconditionFailed("请明确确认此Live目标操作；Mock和隔离loopback不代表云授权".into()));
    }
    Ok(())
}
pub(super) async fn configured(state: &AppState, tenant: TenantId) -> DomainResult<Option<Stored>> {
    cloud_store::load(state, tenant, super::NAME).await
}
