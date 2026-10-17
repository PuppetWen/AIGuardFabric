use super::super::{authority::Submission, store, util};
use super::{
    current, evidence, identity,
    model::{Fact, RequestIndex, State},
    staging,
};
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde_json::{Value, json};

pub(super) async fn load(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Fact> {
    if id.is_nil() {
        return Err(super::input::invalid());
    }
    let row = store::get::<Fact>(state, tenant, &identity::fact_key(id))
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "Scheduler callback execution", id: id.to_string() })?;
    if row.id != id || row.context.tenant != tenant {
        return Err(util::corrupt());
    }
    evidence::verify_fact(state, &row)?;
    Ok(row)
}
pub(super) fn state(row: &Fact, now: Timestamp) -> &'static str {
    match row.state {
        State::Admitted if now >= row.start_expires_at => "uncertain",
        State::Running if row.execution_expires_at.is_none_or(|at| now >= at) => "uncertain",
        State::Admitted => "admitted",
        State::Running => "running",
        State::Succeeded => "succeeded",
        State::Failed => "failed",
    }
}
pub(super) async fn load_request(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Fact> {
    if id.is_nil() {
        return Err(super::input::invalid());
    }
    let index = store::get::<RequestIndex>(state, tenant, &identity::request_key(tenant, id))
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "Scheduler callback request", id: id.to_string() })?;
    util::bound(&index, 8 * 1024)?;
    if (index.tenant, index.request_id) != (tenant, id) || index.fact_id.is_nil() || !util::digest(&index.input_hash) {
        return Err(util::corrupt());
    }
    let row = load(state, tenant, index.fact_id).await?;
    if row.input_hash != index.input_hash {
        return Err(util::corrupt());
    }
    Ok(row)
}
pub(super) async fn receipt(
    app: &AppState,
    submission: &Submission,
    row: &Fact,
    may_confirm_start: bool,
    may_execute: bool,
) -> DomainResult<Value> {
    super::super::authority::bounded(
        submission.deadline,
        Box::pin(project(app, submission, row, may_confirm_start, may_execute)),
    )
    .await
}
async fn project(
    app: &AppState,
    submission: &Submission,
    row: &Fact,
    may_confirm_start: bool,
    may_execute: bool,
) -> DomainResult<Value> {
    current::owner(app, submission, &row.context.owner).await?;
    evidence::verify_fact(app, row)?;
    let pending = staging::read(app, row.context.tenant, row).await?;
    let terminal = matches!(row.state, State::Succeeded | State::Failed);
    if terminal && pending.as_ref().is_none_or(|known| row.outcome.as_ref() != Some(&known.outcome)) {
        return Err(util::corrupt());
    }
    let source_current =
        super::super::views::source(app, row.context.tenant).await?.as_ref() == Some(&row.context.target);
    current::owner(app, submission, &row.context.owner).await?;
    submission.budget()?;
    let now = Timestamp::now();
    let may_confirm_start =
        may_confirm_start && source_current && row.state == State::Admitted && now < row.start_expires_at;
    let may_execute = may_execute
        && source_current
        && row.state == State::Running
        && row.execution_expires_at.is_some_and(|at| now < at);
    Ok(json!({
        "factId":row.id,"claimId":row.claim_id,"requestId":row.request_id,"tenantId":row.context.tenant,
        "kind":row.context.kind,"appId":row.context.app_id,"jobId":row.context.job_id,
        "jobExecutionId":row.context.job_execution_id,"partitionIndex":row.partition_index,
        "partitionTotal":row.context.partition_total,"bindingVersion":row.context.binding_version,
        "adoptionVersion":row.context.adoption_version,"originalTarget":row.context.target,
        "submittedAt":row.submitted_at,"startLeaseExpiresAt":row.start_expires_at,
        "startedAt":row.started_at,"executionLeaseExpiresAt":row.execution_expires_at,"finishedAt":row.finished_at,
        "state":state(row,now),"mayConfirmStart":may_confirm_start,"mayExecute":may_execute,
        "outcome":row.outcome.as_ref().or_else(||pending.as_ref().map(|known|&known.outcome)),
        "completionState":if terminal {"complete"}else if pending.is_some() {"pending_audit"}else{"admitted"},
        "sourceCurrent":source_current
    }))
}
