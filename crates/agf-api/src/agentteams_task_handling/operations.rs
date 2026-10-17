//! Every new annotation/archive UUID creates one permanent local fact; replay is never a cloud retry.
use super::{
    ArchiveInput, ArchivePlan, FailureEvidence, Handling, ResolutionInput, ResolutionPlan, audit,
    authority::{self, Submission},
    codec::{self, Values},
    reducer, source,
    store::{self, Mutation, Plan},
    util,
};
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) async fn evidence(state: &AppState, submission: &Submission, id: Id) -> DomainResult<FailureEvidence> {
    if id.is_nil() {
        return Err(util::invalid());
    }
    let tenant = submission.principal.tenant;
    let row = authority::bounded(submission.deadline, state.ingest_sink.agentteams_failure_record(tenant, id))
        .await?
        .ok_or_else(|| missing(id))?;
    FailureEvidence::derive(tenant, &row)
}
pub(super) async fn resolve(
    state: &AppState,
    submission: &Submission,
    id: Id,
    input: ResolutionInput,
) -> DomainResult<super::model::ResolutionReceipt> {
    input.validate()?;
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let original = evidence(state, submission, id).await?;
    let actor = submission.actor()?;
    let record = codec::record_key(tenant, id);
    let request = codec::request_key(tenant, input.request_id);
    Box::pin(store::mutate(
        state,
        Mutation {
            submission,
            source_ids: vec![original.source_id],
            evidence: vec![original.clone()],
            declared: vec![record.clone(), request.clone()],
        },
        |snapshot| {
            let journal = codec::journal(state, tenant, &snapshot.records)?;
            let handling = codec::handling(state, tenant, id, &snapshot.records)?;
            let previous = codec::request(state, tenant, input.request_id, &snapshot.records)?;
            let checked = if previous.is_none() {
                Some(source::verify(
                    state,
                    tenant,
                    original.source_id,
                    &input.expected_source_fingerprint,
                    snapshot.cloud.as_ref(),
                    snapshot.sources.get(&original.source_id).and_then(Option::as_ref),
                )?)
            } else {
                None
            };
            match reducer::resolve(
                reducer::ResolutionContext {
                    tenant,
                    actor: &actor,
                    now: Timestamp::now(),
                    journal: &journal,
                    evidence: &original,
                    current: handling.as_ref(),
                    previous_request: previous.as_ref(),
                    source: checked.as_ref(),
                },
                &input,
            )? {
                ResolutionPlan::Replay(receipt) => Ok((receipt, None)),
                ResolutionPlan::Write(change) => {
                    let receipt = change.request_fact.resolution()?.clone();
                    let mut writes = Values::new();
                    writes.insert(
                        codec::state_key(tenant),
                        Some(codec::encode(state, tenant, &codec::state_key(tenant), &change.journal)?),
                    );
                    writes.insert(record.clone(), Some(codec::encode(state, tenant, &record, &change.handling)?));
                    writes.insert(request.clone(), Some(codec::encode(state, tenant, &request, &change.request_fact)?));
                    Ok((receipt, Some(Plan { writes, audit: Box::new(audit::entry(submission, &change.audit)) })))
                }
            }
        },
    ))
    .await
}

pub(super) async fn archive(
    state: &AppState,
    submission: &Submission,
    input: ArchiveInput,
) -> DomainResult<super::model::ArchiveReceipt> {
    input.validate()?;
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let actor = submission.actor()?;
    let mut originals = BTreeMap::new();
    for id in &input.event_ids {
        let key = codec::record_key(tenant, *id);
        let value = authority::bounded(submission.deadline, store::get(state, tenant, &key))
            .await?
            .ok_or_else(|| missing(*id))?;
        let row: Handling = codec::decode(state, tenant, &key, &value)?;
        row.validate(&row.evidence)?;
        if row.evidence.tenant != tenant || row.evidence.event_id != *id {
            return Err(util::corrupt());
        }
        let original = evidence(state, submission, *id).await?;
        if original != row.evidence {
            return Err(util::corrupt());
        }
        originals.insert(*id, original);
    }
    let source_ids = originals.values().map(|row| row.source_id).collect::<BTreeSet<_>>().into_iter().collect();
    let request = codec::request_key(tenant, input.request_id);
    let mut declared = input.event_ids.iter().map(|id| codec::record_key(tenant, *id)).collect::<Vec<_>>();
    declared.push(request.clone());
    Box::pin(store::mutate(
        state,
        Mutation { submission, source_ids, evidence: originals.values().cloned().collect(), declared },
        |snapshot| {
            let journal = codec::journal(state, tenant, &snapshot.records)?;
            let rows = input
                .event_ids
                .iter()
                .map(|id| {
                    let row = codec::handling(state, tenant, *id, &snapshot.records)?.ok_or_else(|| missing(*id))?;
                    if row.evidence != originals[id] {
                        return Err(util::corrupt());
                    }
                    Ok((*id, row))
                })
                .collect::<DomainResult<BTreeMap<_, _>>>()?;
            let previous = codec::request(state, tenant, input.request_id, &snapshot.records)?;
            let sources = if previous.is_none() {
                source::archive_sources(state, tenant, &originals, &input, snapshot.cloud.as_ref(), &snapshot.sources)?
            } else {
                BTreeMap::new()
            };
            match reducer::archive(
                reducer::ArchiveContext {
                    tenant,
                    actor: &actor,
                    now: Timestamp::now(),
                    journal: &journal,
                    rows: &rows,
                    previous_request: previous.as_ref(),
                    sources: &sources,
                },
                &input,
            )? {
                ArchivePlan::Replay(receipt) => Ok((receipt, None)),
                ArchivePlan::Write(change) => {
                    let receipt = change.request_fact.archive()?.clone();
                    let mut writes = Values::new();
                    let main = codec::state_key(tenant);
                    writes.insert(main.clone(), Some(codec::encode(state, tenant, &main, &change.journal)?));
                    for row in change.tombstones {
                        let key = codec::record_key(tenant, row.evidence.event_id);
                        writes.insert(key.clone(), Some(codec::encode(state, tenant, &key, &row)?));
                    }
                    writes.insert(request.clone(), Some(codec::encode(state, tenant, &request, &change.request_fact)?));
                    Ok((receipt, Some(Plan { writes, audit: Box::new(audit::entry(submission, &change.audit)) })))
                }
            }
        },
    ))
    .await
}
fn missing(id: Id) -> DomainError {
    DomainError::NotFound { entity: "collector-task-error", id: id.to_string() }
}
