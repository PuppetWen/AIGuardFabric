use super::{
    ATTEMPT, ITEM, REQUEST,
    authority::Submission,
    codec,
    model::{Attempt, Delivery, Item, Phase, Purpose, Request, Values},
    store, util,
};
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use std::collections::BTreeSet;

pub(super) fn item(row: &Item, tenant: TenantId, id: Id) -> DomainResult<()> {
    super::source::validate(&row.source, tenant)?;
    if row.tenant != tenant
        || row.id != id
        || row.owner.tenant != tenant
        || row.source.tenant != tenant
        || row.owner.subject.is_none_or(|id| id.is_nil())
        || row.owner.identity_tenant.as_uuid().is_nil()
        || row.owner.agent.is_some_and(|id| id.is_nil())
        || row.enqueue_id.is_nil()
        || row.name.is_empty()
        || row.name.len() > 128
        || row.name.chars().any(char::is_control)
        || !["PutCustomEvent", "PutCustomMetric"].contains(&row.action.as_str())
        || row.attempts.len() > super::MAX_ATTEMPTS as usize
        || row.attempts.iter().any(Id::is_nil)
        || row.attempts.iter().collect::<BTreeSet<_>>().len() != row.attempts.len()
        || row.payload_bytes > super::MAX_BODY as u64
        || row.payload_hash.len() != 64
        || !row.payload_hash.bytes().all(|b| b.is_ascii_hexdigit())
        || row.payload_bytes == 0
        || row.archived_at.is_some_and(|at| at < row.queued_at)
    {
        return Err(util::corrupt());
    }
    Ok(())
}
pub(super) fn attempt(row: &Attempt, item: &Item) -> DomainResult<()> {
    let item_matches = row.item_id == item.id;
    let identity = !row.id.is_nil()
        && row.tenant == item.tenant
        && item_matches
        && row.owner == item.owner
        && row.source == item.source
        && item.attempts.contains(&row.id);
    let timing = row.lease_expires_at > row.admitted_at && row.lease_expires_at <= row.admitted_at.offset_secs(110);
    let phase = match row.phase {
        Phase::Admitted => row.started_at.is_none() && row.outcome.is_none(),
        Phase::Started => {
            row.started_at.is_some_and(|t| t >= row.admitted_at && t <= row.lease_expires_at) && row.outcome.is_none()
        }
        Phase::Complete => row.outcome.as_ref().is_some_and(|outcome| {
            outcome.finished_at >= row.admitted_at
                && (outcome.delivery == Delivery::NotSent || row.started_at.is_some())
                && (outcome.delivery != Delivery::Accepted
                    || outcome.provider_request_id.as_ref().is_some_and(|id| safe_id(id)))
                && outcome.provider_request_id.as_ref().is_none_or(|id| safe_id(id))
        }),
    };
    if !identity
        || !timing
        || !phase
        || row.request_id.is_nil()
        || row.started_at.is_some_and(|at| at < row.admitted_at || at > row.lease_expires_at)
    {
        return Err(util::corrupt());
    }
    Ok(())
}
pub(super) fn safe_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
}
pub(super) async fn load_item(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Item> {
    let row: Item = store::get(state, tenant, &util::key(ITEM, id)).await?.ok_or_else(|| missing(id))?;
    item(&row, tenant, id)?;
    Ok(row)
}
pub(super) fn latest(
    state: &AppState,
    tenant: TenantId,
    values: &Values,
    item: &Item,
) -> DomainResult<Option<Attempt>> {
    let row = item
        .attempts
        .last()
        .map(|id| codec::read::<Attempt>(state, tenant, values, &util::key(ATTEMPT, *id)))
        .transpose()?
        .flatten();
    if let Some(row) = &row {
        attempt(row, item)?;
    } else if !item.attempts.is_empty() {
        return Err(util::corrupt());
    }
    Ok(row)
}
pub(super) fn retryable(item: &Item, last: Option<&Attempt>) -> bool {
    item.archived_at.is_none()
        && item.attempts.len() < super::MAX_ATTEMPTS as usize
        && last.is_none_or(|row| {
            row.phase == Phase::Complete
                && row.outcome.as_ref().is_some_and(|o| matches!(o.delivery, Delivery::NotSent | Delivery::Rejected))
        })
}
pub(super) fn replay(
    state: &AppState,
    submission: &Submission,
    values: &Values,
    id: Id,
    purpose: Purpose,
    hash: &str,
) -> DomainResult<Option<Request>> {
    let row: Option<Request> = codec::read(state, submission.principal.tenant, values, &util::key(REQUEST, id))?;
    if let Some(row) = &row {
        request_identity(submission, row, id, purpose, hash)?;
    }
    Ok(row)
}
pub(super) fn request_identity(
    submission: &Submission,
    row: &Request,
    id: Id,
    purpose: Purpose,
    hash: &str,
) -> DomainResult<()> {
    if row.tenant != submission.principal.tenant
        || row.id != id
        || row.owner.tenant != row.tenant
        || row.item_ids.is_empty()
        || row.item_ids.len() > 32
        || row.item_ids.iter().any(Id::is_nil)
        || row.item_ids.iter().collect::<BTreeSet<_>>().len() != row.item_ids.len()
        || row.attempt_ids.len() > 20
        || row.attempt_ids.iter().any(Id::is_nil)
        || row.attempt_ids.iter().collect::<BTreeSet<_>>().len() != row.attempt_ids.len()
        || row.owner.subject.is_none_or(|id| id.is_nil())
        || row.input_hash.len() != 64
        || !row.input_hash.bytes().all(|b| b.is_ascii_hexdigit())
        || (row.purpose == Purpose::Send && row.attempt_ids.len() != row.item_ids.len())
        || (row.purpose != Purpose::Send && !row.attempt_ids.is_empty())
        || row.changed_count > row.item_ids.len() as u64
        || row.generation == 0
    {
        return Err(util::corrupt());
    }
    submission.own(&row.owner)?;
    if row.purpose != purpose || row.input_hash != hash {
        return Err(util::conflict());
    }
    Ok(())
}
pub(super) fn missing(id: Id) -> DomainError {
    DomainError::NotFound { entity: "cms-queue-item", id: id.to_string() }
}
pub(super) fn expired(row: &Attempt) -> bool {
    row.lease_expires_at <= Timestamp::now()
}
