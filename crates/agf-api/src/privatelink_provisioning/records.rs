use super::{
    FACT,
    authority::Submission,
    codec,
    model::{Fact, Journal, Phase, Purpose, ResultData, Values},
    store, util,
};
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
pub(super) fn validate(row: &Fact, tenant: TenantId, id: Id) -> DomainResult<()> {
    if row.tenant != tenant
        || row.id != id
        || id.is_nil()
        || row.claim_id.is_nil()
        || row.owner.tenant != tenant
        || row.owner.identity_tenant.as_uuid().is_nil()
        || row.owner.subject.is_none_or(|s| s.is_nil())
        || row.owner.agent.is_some_and(|id| id.is_nil())
        || row.input_hash.len() != 64
        || !row.input_hash.bytes().all(|b| b.is_ascii_hexdigit())
        || row.admitted_at < row.submitted_at
        || row.lease_expires_at != row.admitted_at.offset_secs(120)
        || row.started_at.is_some_and(|at| at < row.admitted_at)
        || (row.phase == Phase::Admitted && (row.started_at.is_some() || row.result.is_some()))
        || (row.phase == Phase::Started && row.started_at.is_none())
        || (row.phase == Phase::Complete && row.result.is_none())
    {
        return Err(util::corrupt());
    }
    if let Some(s) = &row.source {
        super::source::validate(s, tenant)?;
    }
    if let Some(intent) = &row.intent {
        intent.prepare(row.id)?;
        if let super::model::Intent::Accept { target, planned, observation_id } = intent {
            agf_alicloud::privatelink::provisioning::validate_reference(planned, &target.endpoint_id)?;
            if observation_id.is_nil()
                || target.region_id != planned.region_id
                || target.service_id != planned.service_id
            {
                return Err(util::corrupt());
            }
        }

        if row.source.as_ref().is_none_or(|s| s.region != intent.planned().region_id) {
            return Err(util::corrupt());
        }
    }
    if let Some(ResultData::Observed { evidence }) = &row.result {
        self::evidence(evidence)?;
    }
    match (&row.purpose, &row.result) {
        (Purpose::Apply, Some(ResultData::Write { outcome })) => {
            if outcome.finished_at < row.admitted_at || outcome.provider_request_id.is_some_and(|id| id.is_nil()) {
                return Err(util::corrupt());
            }
            if outcome.delivery == super::model::Delivery::Acknowledged
                && (outcome.provider_request_id.is_none()
                    || outcome.endpoint_id.as_ref().is_none_or(|s| !s.starts_with("ep-") || s.len() > 67))
            {
                return Err(util::corrupt());
            }
        }
        (Purpose::Preview, Some(ResultData::Preview { .. }))
        | (Purpose::Observe, Some(ResultData::Observed { .. } | ResultData::FailedRead))
        | (Purpose::Archive, Some(ResultData::Archived { .. }))
        | (_, None) => {}
        _ => return Err(util::corrupt()),
    }
    util::bound(row, 64 * 1024)?;
    Ok(())
}
pub(super) fn new(
    submission: &Submission,
    id: Id,
    purpose: Purpose,
    input_hash: String,
    source: Option<super::source::Source>,
    intent: Option<super::model::Intent>,
    reference: Option<Id>,
) -> DomainResult<Fact> {
    if id.is_nil() {
        return Err(util::invalid());
    }
    let now = Timestamp::now();
    Ok(Fact {
        tenant: submission.principal.tenant,
        id,
        owner: submission.owner(),
        purpose,
        input_hash,
        source,
        intent,
        reference,
        submitted_at: submission.submitted_at,
        admitted_at: now,
        lease_expires_at: now.offset_secs(120),
        claim_id: Id::new(),
        phase: Phase::Admitted,
        started_at: None,
        result: None,
        archived_at: None,
    })
}
pub(super) async fn load(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Fact> {
    let row = store::get(state, tenant, &util::key(FACT, id))
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "PrivateLink provisioning request", id: id.to_string() })?;
    validate(&row, tenant, id)?;
    Ok(row)
}
pub(super) fn read(state: &AppState, tenant: TenantId, values: &Values, id: Id) -> DomainResult<Fact> {
    let row = codec::read(state, tenant, values, &util::key(FACT, id))?.ok_or_else(util::corrupt)?;
    validate(&row, tenant, id)?;
    Ok(row)
}
pub(super) fn evidence(row: &super::model::Evidence) -> DomainResult<()> {
    agf_alicloud::privatelink::provisioning::validate_reference(&row.plan, &row.observation.endpoint_id)?;
    if row.checked_at > Timestamp::now()
        || !["Creating", "Active", "Pending", "Deleting", "Deleted", "Failed", "Unknown"]
            .contains(&row.observation.endpoint_state.as_str())
        || !["Disconnected", "Connecting", "Connected", "Disconnecting", "Unknown"]
            .contains(&row.observation.connection_state.as_str())
        || !row.observation.requested_resources_match
        || row.observation.connectivity_verified
        || !row.observation.endpoint_id.starts_with("ep-")
        || row.observation.endpoint_id.len() > 67
        || row.original_create_id.is_some() == row.inventory_scope_id.is_some()
        || row.inventory_scope_id.is_some() != row.inventory_payload_hash.is_some()
        || row
            .inventory_payload_hash
            .as_ref()
            .is_some_and(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(util::corrupt());
    }
    Ok(())
}
pub(super) fn claim_hash(row: &Fact) -> DomainResult<String> {
    let mut copy = row.clone();
    copy.phase = Phase::Admitted;
    copy.started_at = None;
    copy.result = None;
    copy.archived_at = None;
    util::fingerprint(&copy)
}
pub(super) fn replay(submission: &Submission, row: &Fact, purpose: Purpose, hash: &str) -> DomainResult<()> {
    submission.own(&row.owner)?;
    if row.purpose != purpose || row.input_hash != hash {
        return Err(util::conflict());
    }
    Ok(())
}
pub(super) fn add(journal: &mut Journal, tenant: TenantId, id: Id) -> DomainResult<()> {
    if journal.items.len() >= super::MAX_ITEMS {
        return Err(util::capacity());
    }
    journal.items.push(id);
    util::bump(journal, tenant, 1)
}
