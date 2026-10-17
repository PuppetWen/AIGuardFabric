use super::super::{
    authority::Submission,
    claim,
    records::Values,
    scope::SourceTarget,
    store::{self, Mutation, Plan},
    util,
};
use super::{
    codec,
    model::{Journal, Operation},
};
use crate::state::AppState;
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::DomainResult,
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::Serialize;

pub(super) fn options<'a>(
    submission: &'a Submission,
    source: Option<&'a SourceTarget>,
    mut keys: Vec<(String, Id)>,
) -> Mutation<'a> {
    let tenant = submission.principal.tenant;
    let main = codec::state_key(tenant);
    keys.extend([main.clone(), util::state_key(tenant)]);
    keys.sort();
    keys.dedup();
    Mutation { submission, source, main, declared: keys }
}
pub(super) fn journal(state: &AppState, tenant: TenantId, values: &Values) -> DomainResult<Journal> {
    let journal = codec::snapshot(state, tenant, values, &codec::state_key(tenant))?.unwrap_or_default();
    super::model::validate_journal(&journal, tenant)?;
    Ok(journal)
}
pub(super) fn put<T: Serialize>(
    state: &AppState,
    tenant: TenantId,
    values: &mut Values,
    key: (String, Id),
    row: &T,
) -> DomainResult<usize> {
    let value = codec::seal(state, tenant, &key, row)?;
    let bytes = util::bound(&value, super::model::MAX_DETAIL)?;
    values.insert(key, Some(value));
    Ok(bytes)
}
pub(super) fn operation(state: &AppState, values: &mut Values, row: &mut Operation) -> DomainResult<()> {
    operation_at(state, values, row, Timestamp::now())
}
pub(super) fn operation_at(
    state: &AppState,
    values: &mut Values,
    row: &mut Operation,
    encrypted_at: Timestamp,
) -> DomainResult<()> {
    let key = codec::key(row.tenant, row.request_id, super::model::OPERATION);
    // A fresh nonce remains mandatory. Keep the same captured encryption time across
    // size iterations: RFC3339 fractional precision otherwise changes the envelope size.
    for _ in 0..4 {
        let value = codec::seal_at(state, row.tenant, &key, row, encrypted_at)?;
        let bytes = util::bound(&value, super::model::MAX_DETAIL)?;
        values.insert(key.clone(), Some(value));
        if row.detail_bytes == bytes {
            return Ok(());
        }
        row.detail_bytes = bytes;
    }
    Err(util::corrupt())
}
pub(super) fn account(journal: &mut Journal, old: usize, new: usize) -> DomainResult<()> {
    journal.stored_bytes = journal
        .stored_bytes
        .checked_sub(old)
        .and_then(|bytes| bytes.checked_add(new))
        .filter(|bytes| *bytes <= super::model::MAX_STORED)
        .ok_or_else(util::capacity)?;
    Ok(())
}
pub(super) fn finish(
    state: &AppState,
    submission: &Submission,
    journal: &mut Journal,
    mut writes: Values,
    id: Id,
    action: AuditAction,
    outcome: AuditOutcome,
    note: &str,
) -> DomainResult<Plan> {
    super::model::bump(journal, submission.principal.tenant)?;
    super::model::validate_journal(journal, submission.principal.tenant)?;
    put(state, submission.principal.tenant, &mut writes, codec::state_key(submission.principal.tenant), journal)?;
    Ok(Plan { writes, audit: Box::new(claim::audit(submission, id, "scheduler-managed-job", action, outcome, note)) })
}
pub(super) fn encoded_bytes(values: &Values, key: &(String, Id)) -> DomainResult<usize> {
    values.get(key).and_then(Option::as_ref).map_or(Ok(0), |value| util::bound(value, super::model::MAX_DETAIL))
}
pub(super) fn can_add(journal: &Journal, preview: bool) -> DomainResult<()> {
    if (if preview { journal.previews.len() } else { journal.operations.len() }) >= super::model::MAX_RUNS {
        return Err(util::capacity());
    }
    Ok(())
}
pub(super) async fn apply<T: Send, F>(state: &AppState, options: Mutation<'_>, body: F) -> DomainResult<T>
where
    F: FnOnce(&Values) -> DomainResult<(T, Option<Plan>)> + Send,
{
    store::mutate(state, options, body).await
}
