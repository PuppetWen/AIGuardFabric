//! Every gateway mutation uses the existing tenant governance transaction and real configuration keys.
use super::{codec, records::*};
use crate::{model_routes::tenant_record_id, state::AppState, store::asset_transaction::AssetTransaction};
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

pub(super) async fn read(tx: &AssetTransaction<'_>, kind: &str, id: Id) -> DomainResult<Option<Value>> {
    tx.configuration_lock(kind, id).await?;
    tx.configuration(kind, id).await
}

pub(super) fn decode<T: DeserializeOwned>(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    kind: &str,
    value: Value,
) -> DomainResult<T> {
    codec::decode(state, tenant, id, kind, &serde_json::from_value::<SecretMaterial>(value)?)
}

pub(super) fn encoded<T: Serialize>(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    kind: &str,
    value: &T,
) -> DomainResult<Value> {
    serde_json::to_value(codec::encode(state, tenant, id, kind, value)?).map_err(Into::into)
}

pub(super) async fn active(
    state: &AppState,
    tx: &AssetTransaction<'_>,
    tenant: TenantId,
) -> DomainResult<ActiveAttempts> {
    read(tx, ACTIVE, tenant_record_id(tenant))
        .await?
        .map(|value| decode(state, tenant, tenant_record_id(tenant), ACTIVE, value))
        .transpose()
        .map(Option::unwrap_or_default)
}

pub(super) fn missing() -> DomainError {
    DomainError::PreconditionFailed("Gateway attempt evidence is missing, inconsistent or exceeds its bound".into())
}
