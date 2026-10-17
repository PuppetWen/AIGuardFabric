use super::super::{
    binding, claim, observation, proof,
    records::{BindingRecord, BodyRecord, Fact, Journal, Values},
    safe::SafeSnapshot,
    scope::SourceTarget,
    util,
};
use super::{
    codec,
    model::{Index, Purpose},
};
use crate::state::AppState;
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId},
    time::Timestamp,
};

pub(super) fn native_keys(tenant: TenantId, id: Id) -> Vec<(String, Id)> {
    vec![
        util::fact_key(tenant, id),
        super::super::callback_execution::request_key(tenant, id),
        codec::request_key(tenant, id),
    ]
}
pub(super) fn vacancy(values: &Values, tenant: TenantId, id: Id) -> DomainResult<()> {
    if native_keys(tenant, id).iter().any(|key| values.get(key).and_then(Option::as_ref).is_some()) {
        return Err(super::conflict());
    }
    Ok(())
}
pub(super) async fn vacancy_external(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<()> {
    for key in native_keys(tenant, id).into_iter().take(2) {
        if super::super::store::get::<serde_json::Value>(state, tenant, &key).await?.is_some() {
            return Err(super::conflict());
        }
    }
    Ok(())
}
pub(super) fn prior(
    state: &AppState,
    values: &Values,
    tenant: TenantId,
    id: Id,
    purpose: Purpose,
    actor: Id,
    hash: &str,
) -> DomainResult<bool> {
    if let Some(index) = codec::snapshot::<Index>(state, tenant, values, &codec::request_key(tenant, id))? {
        codec::index(&index, tenant, id, purpose, actor, hash)?;
        return Ok(true);
    }
    vacancy(values, tenant, id)?;
    Ok(false)
}
pub(super) fn observed(
    state: &AppState,
    values: &Values,
    target: &SourceTarget,
    input: &super::input::PreviewInput,
) -> DomainResult<(SafeSnapshot, BindingRecord)> {
    let tenant = target.tenant;
    let bindings: BindingRecord = util::read(values, &util::binding_key(tenant))?.unwrap_or_default();
    binding::validate(&bindings, tenant)?;
    proof::restore(state, &bindings, tenant)?;
    if bindings.version != input.expected_binding_version {
        return Err(util::stale());
    }
    let journal: Journal = util::read(values, &util::state_key(tenant))?.unwrap_or_default();
    let fact: Fact = util::read(values, &util::fact_key(tenant, input.observation_id))?.ok_or_else(util::stale)?;
    claim::validate(&fact, tenant, input.observation_id)?;
    let now = Timestamp::now();
    if journal.latest != Some(input.observation_id)
        || fact.target.as_ref() != Some(target)
        || fact.finished_at.is_none_or(|at| at > now || at.offset_secs(300) < now)
    {
        return Err(util::stale());
    }
    let body: BodyRecord =
        util::read(values, &util::body_key(tenant, input.observation_id))?.ok_or_else(util::stale)?;
    Ok((observation::decode(state, tenant, input.observation_id, &body, &fact)?, bindings))
}
pub(super) fn actor(submission: &super::super::authority::Submission) -> DomainResult<Id> {
    submission.principal.subject_id.filter(|id| !id.is_nil()).ok_or_else(util::corrupt)
}
