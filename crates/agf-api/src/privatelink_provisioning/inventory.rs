use super::{
    authority::Submission,
    model::{Evidence, Values},
    source::Source,
    util,
};
use crate::state::AppState;
use agf_core::{error::DomainResult, ids::Id};
pub(super) async fn selection(
    state: &AppState,
    submission: &Submission,
    id: Id,
) -> DomainResult<crate::privatelink_inventory::provisioning_selection::Selection> {
    super::authority::bounded(
        submission.deadline,
        crate::privatelink_inventory::provisioning_selection::load(state, submission.principal.tenant, id),
    )
    .await
}
pub(super) fn locked(
    state: &AppState,
    source: &Source,
    id: Id,
    expected_hash: &str,
    values: &Values,
) -> DomainResult<Evidence> {
    let key = crate::privatelink_inventory::provisioning_selection::key(source.tenant);
    let value = values.get(&(key.0.into(), key.1)).and_then(Option::as_ref).ok_or_else(util::conflict)?;
    let cloud = values
        .get(&(crate::cloud_store::KIND.into(), source.id))
        .and_then(Option::as_ref)
        .ok_or_else(util::conflict)?;
    let row: crate::integration_store::Stored = serde_json::from_value(cloud.clone()).map_err(|_| util::corrupt())?;
    let current = crate::privatelink_inventory::provisioning_scope(state, source.tenant, &row)?;
    let selected =
        crate::privatelink_inventory::provisioning_selection::from_locked(state, source.tenant, id, &current, value)?;
    if selected.payload_hash != expected_hash {
        return Err(util::conflict());
    }
    Ok(Evidence {
        plan: Box::new(selected.plan),
        observation: selected.observation,
        checked_at: selected.checked_at,
        original_create_id: None,
        inventory_scope_id: Some(selected.scope_id),
        inventory_payload_hash: Some(selected.payload_hash),
    })
}

pub(super) async fn available(
    state: &AppState,
    tenant: agf_core::ids::TenantId,
) -> DomainResult<Option<serde_json::Value>> {
    let Some(row) = crate::cloud_store::load(state, tenant, super::NAME).await?.filter(|r| r.enabled) else {
        return Ok(None);
    };
    let scope = match crate::privatelink_inventory::provisioning_scope(state, tenant, &row) {
        Ok(scope) => scope,
        Err(agf_core::error::DomainError::Validation(_) | agf_core::error::DomainError::PreconditionFailed(_)) => {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    match crate::privatelink_inventory::provisioning_selection::load(state, tenant, scope.id).await {
        Ok(s) => Ok(Some(
            serde_json::json!({"scopeId":s.scope_id,"endpointId":s.observation.endpoint_id,"serviceId":s.plan.service_id,"vpcId":s.plan.vpc_id,"checkedAt":s.checked_at}),
        )),
        Err(agf_core::error::DomainError::PreconditionFailed(_) | agf_core::error::DomainError::Validation(_)) => {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}
