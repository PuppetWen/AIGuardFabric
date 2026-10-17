//! Only authorization fields are fenced; telemetry timestamps do not revoke a call.
use super::store;
use crate::state::AppState;
use agf_core::{
    asset::Asset,
    enums::{AssetKind, DataClass},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct AgentSafety {
    tenant: TenantId,
    id: Id,
    data_class: DataClass,
    department: Option<String>,
}
impl AgentSafety {
    pub(super) fn from_asset(tenant: TenantId, id: Id, asset: &Asset) -> DomainResult<Self> {
        if asset.tenant_id != tenant || asset.id != id || asset.kind != AssetKind::Agent || asset.deleted_at.is_some() {
            return Err(store::missing());
        }
        Ok(Self { tenant, id, data_class: asset.data_class, department: asset.department.clone() })
    }
    pub(super) async fn capture(state: &AppState, tenant: TenantId, id: Option<Id>) -> DomainResult<Option<Self>> {
        let Some(id) = id else {
            return Ok(None);
        };
        let asset = state.store.asset_get_durable(tenant, id).await?.ok_or_else(store::missing)?;
        Self::from_asset(tenant, id, &asset).map(Some)
    }
    pub(super) async fn current(&self, state: &AppState) -> DomainResult<()> {
        let changed = || DomainError::Conflict("Gateway original Agent classification or department changed".into());
        let asset = state.store.asset_get_durable(self.tenant, self.id).await?.ok_or_else(changed)?;
        let current = Self::from_asset(self.tenant, self.id, &asset).map_err(|_| changed())?;
        if current != *self {
            return Err(changed());
        }
        Ok(())
    }
    pub(super) fn raise_class(&self, hint: DataClass) -> DataClass {
        std::cmp::max(self.data_class, hint)
    }
}
