use super::{
    FACT, PENDING, audit,
    authority::Submission,
    codec,
    model::{Delivery, Fact, Journal, Pending, Phase, Purpose, ResultData, Values, Write},
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
pub(super) async fn recover(state: &AppState, submission: &Submission, id: Id) -> DomainResult<Fact> {
    submission.authorize(state).await?;
    let row = records::load(state, submission.principal.tenant, id).await?;
    submission.own(&row.owner)?;
    if row.phase == Phase::Complete {
        return Ok(row);
    }
    let pending = store::get::<Pending>(state, row.tenant, &util::key(PENDING, row.id)).await?;
    if let Some(p) = &pending {
        staging::validate(p, &row)?;
    }
    if pending.is_none() && row.lease_expires_at > Timestamp::now() {
        return Err(DomainError::PreconditionFailed(
            "Original PrivateLink lease remains active; local recovery never sends a cloud request".into(),
        ));
    }
    let outcome = pending.map_or_else(
        || match row.purpose {
            Purpose::Apply => ResultData::Write {
                outcome: Write {
                    delivery: if row.phase == Phase::Admitted { Delivery::NotSent } else { Delivery::Unknown },
                    provider_request_id: None,
                    endpoint_id: row.intent.as_ref().and_then(|i| i.endpoint()).map(str::to_owned),
                    finished_at: Timestamp::now(),
                },
            },
            _ => ResultData::FailedRead,
        },
        |p| p.outcome,
    );
    finish(state, submission, &row, outcome).await
}
pub(super) async fn finish(
    state: &AppState,
    submission: &Submission,
    original: &Fact,
    outcome: ResultData,
) -> DomainResult<Fact> {
    let tenant = original.tenant;
    Box::pin(store::mutate(
        state,
        Mutation {
            submission,
            source: None,
            guards: vec![],
            keys: vec![util::state_key(tenant), util::key(FACT, original.id), util::key(PENDING, original.id)],
        },
        |values| {
            let mut row = records::read(state, tenant, values, original.id)?;
            submission.own(&row.owner)?;
            if records::claim_hash(&row)? != records::claim_hash(original)? {
                return Err(util::conflict());
            }
            if row.phase == Phase::Complete {
                return Ok((row, None));
            }
            if row.archived_at.is_some() {
                return Err(util::conflict());
            }
            if let Some(pending) = codec::read::<Pending>(state, tenant, values, &util::key(PENDING, row.id))? {
                staging::validate(&pending, &row)?;
                if pending.outcome != outcome {
                    return Err(util::conflict());
                }
            } else if row.lease_expires_at > Timestamp::now() {
                return Err(util::conflict());
            }
            row.phase = Phase::Complete;
            row.result = Some(outcome.clone());
            records::validate(&row, tenant, row.id)?;
            let mut journal: Journal =
                codec::read(state, tenant, values, &util::state_key(tenant))?.ok_or_else(util::corrupt)?;
            if let Some(intent) = &row.intent {
                let key = util::resource(tenant, intent)?;
                if journal.risks.get(&key) != Some(&row.id) && row.purpose == Purpose::Apply {
                    return Err(util::corrupt());
                }
                if matches!(
                    outcome,
                    ResultData::Write {
                        outcome: Write {
                            delivery: Delivery::NotSent | Delivery::Rejected | Delivery::Acknowledged,
                            ..
                        }
                    }
                ) {
                    journal.risks.remove(&key);
                }
            }
            util::bump(&mut journal, tenant, 0)?;
            let mut writes = Values::new();
            codec::put(state, tenant, &mut writes, util::key(FACT, row.id), &row)?;
            writes.insert(util::key(PENDING, row.id), None);
            codec::put(state, tenant, &mut writes, util::state_key(tenant), &journal)?;
            Ok((row.clone(), Some(Plan { writes, audit: Box::new(audit::terminal(submission, &row)) })))
        },
    ))
    .await
}
