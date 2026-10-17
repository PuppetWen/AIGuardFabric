//! Safe operator projections preserve original collector identities and immutable receipts.
use super::{
    FailureEvidence, Handling,
    authority::{self, Submission},
    codec::{self, Values},
    model::{Receipt, Revision},
    operations, query, source, source_proof, store, util,
};
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use serde_json::{Value, json};

pub(super) async fn list(state: &AppState, submission: &Submission, input: query::Query) -> DomainResult<Value> {
    let page = query::load(state, submission, &input).await?;
    let tenant = submission.principal.tenant;
    let mut items = Vec::new();
    for original in page.snapshot.records.iter().skip(page.offset).take(page.limit) {
        let evidence = FailureEvidence::derive(tenant, original)?;
        items.push(event(state, submission, &evidence, false).await?);
    }
    let journal = journal(state, submission).await?;
    submission.authorize(state).await?;
    Ok(json!({"items":items,"total":page.snapshot.total,"nextCursor":page.next,"truncated":page.snapshot.truncated,
        "windowFrom":page.query.from,"windowTo":page.query.until,"asOfReceivedAt":page.query.received_until,
        "evidenceLimit":2000,"consistency":"statement","complete":false,"category":"collector_reported_error",
        "generation":journal.generation,"activeHandledCount":journal.active_event_ids.len(),"archivedCount":journal.archived_count,
        "businessReplayImplemented":false,"limits":{"pageSize":100,"windowDays":30,"activeHandled":128,
            "revisionsPerEvent":20,"archiveBatch":99,"sourceGuards":31}}))
}
pub(super) async fn detail(state: &AppState, submission: &Submission, id: Id) -> DomainResult<Value> {
    submission.authorize(state).await?;
    let evidence = operations::evidence(state, submission, id).await?;
    let value = event(state, submission, &evidence, true).await?;
    submission.authorize(state).await?;
    Ok(value)
}
pub(super) async fn request(state: &AppState, submission: &Submission, id: Id) -> DomainResult<Value> {
    submission.authorize(state).await?;
    if id.is_nil() {
        return Err(util::invalid());
    }
    let tenant = submission.principal.tenant;
    let key = codec::request_key(tenant, id);
    let value = authority::bounded(submission.deadline, store::get(state, tenant, &key))
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "task-handling-request", id: id.to_string() })?;
    let values = Values::from([(key, Some(value))]);
    let row = codec::request(state, tenant, id, &values)?.ok_or_else(util::corrupt)?;
    submission.authorize(state).await?;
    Ok(match row.receipt {
        Receipt::Resolution(row) => resolution(&row),
        Receipt::Archive(row) => archive(&row),
    })
}
pub(super) fn resolution(row: &super::model::ResolutionReceipt) -> Value {
    json!({"purpose":"operator-resolution","requestId":row.request_id,"eventId":row.event_id,
        "version":row.version,"decision":row.decision,"updatedAt":row.updated_at,
        "evidenceIdentityHash":row.evidence_identity_hash,"cloudExecutionConfirmed":false,"businessReplay":false})
}
pub(super) fn archive(row: &super::model::ArchiveReceipt) -> Value {
    json!({"purpose":"operator-archive","requestId":row.request_id,"generation":row.generation,
        "archivedCount":row.archived_count,"eventIds":row.event_ids,"changedCount":row.changed_count,
        "evidenceIdentityHash":row.evidence_identity_hash,"cloudExecutionConfirmed":false,"businessReplay":false})
}
async fn event(
    state: &AppState,
    submission: &Submission,
    evidence: &FailureEvidence,
    history: bool,
) -> DomainResult<Value> {
    let tenant = submission.principal.tenant;
    let key = codec::record_key(tenant, evidence.event_id);
    let value = authority::bounded(submission.deadline, store::get(state, tenant, &key)).await?;
    let values = Values::from([(key, value)]);
    let handling = codec::handling(state, tenant, evidence.event_id, &values)?;
    if handling.as_ref().is_some_and(|row| row.evidence != *evidence) {
        return Err(util::corrupt());
    }
    let current_source = source_view(state, submission, evidence.source_id).await?;
    let principal = submission.authorize(state).await?;
    let can_write =
        principal.require(state, "alicloud", "write").is_ok() && principal.require(state, "sources", "write").is_ok();
    let archived = handling.as_ref().is_some_and(|row| row.archived_at.is_some());
    let mut actions = vec!["read"];
    if can_write && !archived && current_source["sourceExists"] == true && current_source["fingerprint"].is_string() {
        actions.push("annotate");
    }
    if can_write && handling.is_some() && !archived {
        actions.push("archive");
    }
    Ok(json!({"id":evidence.event_id,"category":"collector_reported_error","originalStatus":"error",
        "externalEventId":evidence.external_event_id,"sourceId":evidence.source_id,"scopeId":evidence.scope_id,
        "bindingId":evidence.binding_id,"eventTime":evidence.event_time,"receivedAt":evidence.received_at,
        "taskId":evidence.task_id,"traceId":evidence.trace_id,"mocked":evidence.mocked,
        "messagePreview":evidence.message_preview,"fromTeam":evidence.from_team,"fromWorker":evidence.from_worker,
        "evidenceIdentityHash":evidence.hash()?,"handling":handling.as_ref().map(|row|handling_view(row,history)),
        "currentSource":current_source,"allowedActions":actions,"cloudExecutionConfirmed":false,"businessReplayImplemented":false}))
}
fn handling_view(row: &Handling, history: bool) -> Value {
    json!({"version":row.current.version,"decision":row.current.decision,"updatedAt":row.current.at,
        "subjectId":row.current.subject_id,"subjectKind":row.current.subject_kind,"archived":row.archived_at.is_some(),
        "archivedAt":row.archived_at,"history":if history {row.history.iter().map(revision).collect::<Vec<_>>()}else{Vec::new()},
        "revisionCount":row.current.version})
}
fn revision(row: &Revision) -> Value {
    json!({"requestId":row.request_id,"version":row.version,"decision":row.decision,"subjectId":row.subject_id,
        "subjectKind":row.subject_kind,"updatedAt":row.at})
}
async fn source_view(state: &AppState, submission: &Submission, id: Id) -> DomainResult<Value> {
    let tenant = submission.principal.tenant;
    let current: Option<agf_core::source::SourceRecord> =
        authority::bounded(submission.deadline, state.configurations.get(tenant, crate::source_store::KIND, id))
            .await?;
    let cloud: Option<crate::integration_store::Stored> = authority::bounded(
        submission.deadline,
        state.configurations.get(tenant, crate::cloud_store::KIND, source::cloud_id(tenant)),
    )
    .await?;
    let original = current.as_ref().and_then(|row| row.source.as_ref());
    if original.is_some_and(|row| row.id != id || row.tenant_id != tenant) {
        return Err(util::corrupt());
    }
    let token = if original.is_some() {
        cloud
            .as_ref()
            .zip(current.as_ref())
            .map(|(cloud, row)| source_proof::issue(&crate::model_gateway::cipher(state)?, tenant, cloud, row))
            .transpose()?
    } else {
        None
    };
    Ok(
        json!({"sourceExists":original.is_some(),"sourceGone":original.is_none(),"sourceEnabled":original.map(|row|row.enabled),
        "sourceName":original.map(|row|row.name.as_str()),"cloudConfigurationVersion":cloud.as_ref().map(|row|row.version),
        "cloudEnabled":cloud.as_ref().map(|row|row.enabled),"fingerprint":token,
        "annotationAllowedWhenDisabled":true,"businessReplay":false}),
    )
}
async fn journal(state: &AppState, submission: &Submission) -> DomainResult<super::Journal> {
    let tenant = submission.principal.tenant;
    let key = codec::state_key(tenant);
    let value = authority::bounded(submission.deadline, store::get(state, tenant, &key)).await?;
    codec::journal(state, tenant, &Values::from([(key, value)]))
}
