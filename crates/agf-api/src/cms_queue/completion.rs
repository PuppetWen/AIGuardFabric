use super::{
    ATTEMPT, ITEM, PENDING, audit,
    authority::Submission,
    codec,
    model::{Attempt, Delivery, Item, Journal, Outcome, Pending, Phase, Values},
    records, staging,
    store::{self, Mutation, Plan},
    util,
};
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};

pub(super) async fn recover(state: &AppState, submission: &Submission, id: Id) -> DomainResult<Attempt> {
    super::authority::bounded(submission.deadline, Box::pin(recover_inner(state, submission, id))).await
}
async fn recover_inner(state: &AppState, submission: &Submission, id: Id) -> DomainResult<Attempt> {
    submission.authorize(state).await?;
    let item = records::load_item(state, submission.principal.tenant, id).await?;
    submission.own(&item.owner)?;
    let attempt_id = *item
        .attempts
        .last()
        .ok_or_else(|| DomainError::PreconditionFailed("This CMS item has no claimed delivery to settle".into()))?;
    let row: Attempt =
        store::get(state, item.tenant, &util::key(ATTEMPT, attempt_id)).await?.ok_or_else(util::corrupt)?;
    records::attempt(&row, &item)?;
    if row.phase == Phase::Complete {
        return Ok(row);
    }
    let known = staging::read(state, &row, &item).await?;
    if known.is_none() && !records::expired(&row) {
        return Err(DomainError::PreconditionFailed(
            "Wait for the original delivery lease or its retained local result".into(),
        ));
    }
    let outcome = known.map_or(
        Outcome {
            delivery: if row.phase == Phase::Admitted { Delivery::NotSent } else { Delivery::Unknown },
            provider_request_id: None,
            finished_at: Timestamp::now(),
        },
        |p| p.outcome,
    );
    finish(state, submission, &row, outcome).await
}
pub(super) async fn finish(
    state: &AppState,
    submission: &Submission,
    original: &Attempt,
    outcome: Outcome,
) -> DomainResult<Attempt> {
    let tenant = original.tenant;
    let item_key = util::key(ITEM, original.item_id);
    let attempt_key = util::key(ATTEMPT, original.id);
    let pending_key = util::key(PENDING, original.id);
    let keys = vec![util::state_key(tenant), item_key.clone(), attempt_key.clone(), pending_key.clone()];
    Box::pin(store::mutate(state, Mutation { submission, source: None, keys }, |values| {
        let item: Item = codec::read(state, tenant, values, &item_key)?.ok_or_else(util::corrupt)?;
        records::item(&item, tenant, original.item_id)?;
        submission.own(&item.owner)?;
        let mut row: Attempt = codec::read(state, tenant, values, &attempt_key)?.ok_or_else(util::corrupt)?;
        records::attempt(&row, &item)?;
        if !super::provider::same_claim(&row, original)? {
            return Err(util::conflict());
        }
        if row.phase == Phase::Complete {
            return Ok((row, None));
        }
        if item.archived_at.is_some() || item.attempts.last() != Some(&row.id) {
            return Err(util::conflict());
        }
        if let Some(pending) = codec::read::<Pending>(state, tenant, values, &pending_key)? {
            staging::validate(&pending, &row, &item)?;
            if pending.outcome != outcome {
                return Err(util::conflict());
            }
        } else if !records::expired(&row) {
            return Err(DomainError::PreconditionFailed(
                "CMS result is not retained and the original lease is active".into(),
            ));
        }
        row.phase = Phase::Complete;
        row.outcome = Some(outcome.clone());
        records::attempt(&row, &item)?;
        let mut journal: Journal =
            codec::read(state, tenant, values, &util::state_key(tenant))?.ok_or_else(util::corrupt)?;
        util::bump(&mut journal, tenant, 0)?;
        let mut writes = Values::new();
        codec::put(state, tenant, &mut writes, attempt_key, &row)?;
        writes.insert(pending_key, None);
        codec::put(state, tenant, &mut writes, util::state_key(tenant), &journal)?;
        Ok((row.clone(), Some(Plan { writes, audit: Box::new(audit::terminal(submission, &row, &outcome)) })))
    }))
    .await
}
