use super::{
    BODY, FACT, PENDING, audit,
    authority::Submission,
    codec, input,
    model::{Fact, Journal, Marker, Phase, Purpose, ResultData, Values},
    records,
    store::{self, Mutation, Plan},
    util,
};
use crate::state::AppState;
use agf_core::{audit::AuditAction, error::DomainResult, time::Timestamp};
use serde_json::json;
use std::collections::BTreeSet;
pub(super) async fn archive(state: &AppState, submission: &Submission, input: input::Archive) -> DomainResult<Fact> {
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let hash = util::fingerprint(&input)?;
    if let Some(row) = store::get::<Fact>(state, tenant, &util::key(FACT, input.request_id)).await? {
        records::replay(submission, &row, Purpose::Archive, &hash)?;
        return Ok(row);
    }
    if input.request_id.is_nil()
        || input.request_ids.is_empty()
        || input.request_ids.len() > 32
        || input.request_ids.contains(&input.request_id)
        || input.request_ids.iter().any(agf_core::Id::is_nil)
        || input.request_ids.iter().collect::<BTreeSet<_>>().len() != input.request_ids.len()
    {
        return Err(util::invalid());
    }
    let mut keys = vec![util::state_key(tenant), util::key(FACT, input.request_id)];
    for id in &input.request_ids {
        keys.extend([util::key(FACT, *id), util::key(BODY, *id), util::key(PENDING, *id)]);
    }
    Box::pin(store::mutate(state, Mutation { submission, source: None, guards: vec![], keys }, |values| {
        if let Some(row) = codec::read::<Fact>(state, tenant, values, &util::key(FACT, input.request_id))? {
            records::replay(submission, &row, Purpose::Archive, &hash)?;
            return Ok((row, None));
        }
        let mut journal: Journal = codec::read(state, tenant, values, &util::state_key(tenant))?.unwrap_or_default();
        util::validate_journal(&journal, tenant)?;
        if journal.generation != input.expected_generation {
            return Err(util::conflict());
        }
        let mut writes = Values::new();
        let now = Timestamp::now();
        let mut count = 0;
        for id in &input.request_ids {
            let mut row = records::read(state, tenant, values, *id)?;
            submission.own(&row.owner)?;
            if row.phase != Phase::Complete
                || codec::read::<super::model::Pending>(state, tenant, values, &util::key(PENDING, *id))?.is_some()
            {
                return Err(util::conflict());
            }
            if row.archived_at.is_some() {
                continue;
            }
            if !journal.items.contains(id) {
                return Err(util::corrupt());
            }
            let body_key = util::key(BODY, *id);
            if let Some(value) = values.get(&body_key).and_then(Option::as_ref) {
                journal.stored_bytes = journal
                    .stored_bytes
                    .checked_sub(util::bound(value, 1024 * 1024)? as u64)
                    .ok_or_else(util::corrupt)?;
            }
            codec::put(state, tenant, &mut writes, body_key, &Marker { tenant, id: *id, archived_at: now })?;
            row.archived_at = Some(now);
            codec::put(state, tenant, &mut writes, util::key(FACT, *id), &row)?;
            journal.items.retain(|old| old != id);
            count += 1;
        }
        if journal.facts >= super::MAX_FACTS {
            return Err(util::capacity());
        }
        util::bump(&mut journal, tenant, 1)?;
        let mut receipt = records::new(submission, input.request_id, Purpose::Archive, hash.clone(), None, None, None)?;
        receipt.phase = Phase::Complete;
        receipt.result = Some(ResultData::Archived { changed_count: count, generation: journal.generation });
        codec::put(state, tenant, &mut writes, util::key(FACT, receipt.id), &receipt)?;
        codec::put(state, tenant, &mut writes, util::state_key(tenant), &journal)?;
        Ok((
            receipt.clone(),
            Some(Plan {
                writes,
                audit: Box::new(audit::change(
                    submission,
                    receipt.id,
                    AuditAction::Create,
                    "privatelink-provisioning-archive-request",
                    json!({"changedCount":count,"generation":journal.generation,"cloudDeleted":false}),
                )),
            }),
        ))
    }))
    .await
}
