//! Binding reads never query or initialize the provider or workflow state.
use super::{contract::Scope, util};
use crate::{cloud_store, integration_store::Stored, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
};

pub(super) async fn current(state: &AppState, tenant: TenantId, version: Option<u64>) -> DomainResult<Scope> {
    let row = cloud_store::load(state, tenant, super::NAME)
        .await?
        .filter(|row| row.enabled)
        .ok_or_else(|| DomainError::PreconditionFailed("请保存并启用明确的MSE专用配置发布绑定".into()))?;
    let scope = super::scope::from_row(state, tenant, &row, &state.mse_config_publication)?;
    if version.is_some_and(|version| version != row.version) {
        return Err(util::stale());
    }
    Ok(scope)
}
pub(super) fn confirm(scope: &Scope, confirmed: bool) -> DomainResult<()> {
    if scope.target.transport_mode == super::contract::TransportMode::Live && !confirmed {
        return Err(DomainError::PreconditionFailed("请明确确认此Live目标操作；隔离loopback能力不是云Live授权".into()));
    }
    Ok(())
}
pub(super) async fn configured(state: &AppState, tenant: TenantId) -> DomainResult<Option<Stored>> {
    cloud_store::load(state, tenant, super::NAME).await
}
