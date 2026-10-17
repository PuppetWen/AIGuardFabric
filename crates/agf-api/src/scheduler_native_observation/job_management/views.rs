//! Bounded local projections; GET never seeds, repairs, extends a lease or reads the provider.
use super::super::{
    authority::Submission,
    scope::{self, SourceTarget},
    util,
};
use super::{
    codec,
    model::{Operation, PreviewRecord, State},
};
use crate::state::AppState;
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId},
    rbac::SubjectKind,
    time::Timestamp,
};
use serde_json::{Value, json};

pub(super) async fn load_preview(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<PreviewRecord> {
    let row = codec::load(state, tenant, &codec::key(tenant, id, super::model::PREVIEW))
        .await?
        .ok_or_else(|| util::missing(id))?;
    codec::preview_record(&row, tenant, id)?;
    Ok(row)
}
pub(super) async fn load_operation(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Operation> {
    let row = codec::load(state, tenant, &codec::key(tenant, id, super::model::OPERATION))
        .await?
        .ok_or_else(|| util::missing(id))?;
    codec::operation(&row, tenant, id)?;
    Ok(row)
}
pub(super) fn manage(state: &AppState, submission: &Submission) -> bool {
    submission.principal.subject_kind == SubjectKind::User
        && [("platform", "admin"), ("alicloud", "read"), ("alicloud", "write")]
            .iter()
            .all(|(resource, action)| submission.principal.require(state, resource, action).is_ok())
}
pub(super) async fn preview(state: &AppState, submission: &Submission, row: &PreviewRecord) -> DomainResult<Value> {
    submission.authorize(state).await?;
    let (target, _) = current_target(state, submission.principal.tenant).await;
    let can_manage = manage(state, submission);
    let can_apply = match row {
        PreviewRecord::Content(row) => applicable(state, submission, row, target.as_ref()).await?,
        PreviewRecord::Archived(_) => false,
    };
    Ok(match row {
        PreviewRecord::Content(row) => json!({"id":row.id,"actorId":row.actor,"target":row.target,
            "configurationVersion":row.target.configuration_version,"createdAt":row.created_at,"expiresAt":row.expires_at,
            "input":row.input,"appId":row.app_id,"baselineFingerprint":row.baseline_fingerprint,
            "before":row.before,"desired":row.desired,"fingerprint":row.fingerprint,"operationId":row.operation_id,
            "archived":false,"canApply":can_apply,
            "archivable":can_manage && row.operation_id.is_none() && row.expires_at<=Timestamp::now(),
            "cloudCasAvailable":false,"callbackConfigured":null,"callbackBindingEnforced":false,"deploymentVerified":null}),
        PreviewRecord::Archived(row) => json!({"id":row.id,"actorId":row.actor,"target":row.target,
            "configurationVersion":row.target.configuration_version,"createdAt":row.created_at,"archivedAt":row.archived_at,
            "fingerprint":row.fingerprint,"operationId":row.operation_id,"archived":true,"canApply":false,"archivable":false,
            "cloudCasAvailable":false,"callbackConfigured":null,"callbackBindingEnforced":false,"deploymentVerified":null}),
    })
}
async fn applicable(
    state: &AppState,
    submission: &Submission,
    row: &super::model::Preview,
    target: Option<&SourceTarget>,
) -> DomainResult<bool> {
    if !manage(state, submission)
        || row.operation_id.is_some()
        || row.expires_at <= Timestamp::now()
        || target != Some(&row.target)
        || submission.principal.subject_id != Some(row.actor)
    {
        return Ok(false);
    }
    let tenant = row.tenant;
    let journal = codec::journal(state, tenant).await?;
    if journal.active.is_some() {
        return Ok(false);
    }
    let mut values = super::super::records::Values::new();
    for key in [
        super::super::util::state_key(tenant),
        super::super::util::binding_key(tenant),
        super::super::util::fact_key(tenant, row.input.observation_id),
        super::super::util::body_key(tenant, row.input.observation_id),
    ] {
        values.insert(key.clone(), super::super::store::get::<Value>(state, tenant, &key).await?);
    }
    // These are statement-consistency indicators, never a substitute for claim's locked fences.
    match super::baseline::observed(state, &values, &row.target, &row.input) {
        Ok((data, _)) if data.fingerprint() == row.baseline_fingerprint => {}
        Ok(_) => return Ok(false),
        Err(agf_core::error::DomainError::Conflict(_) | agf_core::error::DomainError::PreconditionFailed(_)) => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    }
    if row.target.mocked && super::mock::load(state, &row.target).await?.fingerprint() != row.baseline_fingerprint {
        return Ok(false);
    }
    Ok(true)
}
pub(super) async fn receipt(state: &AppState, submission: &Submission, id: Id) -> DomainResult<Value> {
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let row = load_operation(state, tenant, id).await?;
    let journal = codec::journal(state, tenant).await?;
    let (target, _) = current_target(state, tenant).await;
    operation(state, submission, &row, target.as_ref(), journal.active.as_ref()).await
}
async fn operation(
    state: &AppState,
    submission: &Submission,
    row: &Operation,
    target: Option<&SourceTarget>,
    active: Option<&super::model::Active>,
) -> DomainResult<Value> {
    let known = super::staging::read(state, row).await?;
    if row.state == State::Complete && known.is_some() {
        return Err(util::corrupt());
    }
    let pending = known.is_some();
    let expired = row.expires_at <= Timestamp::now();
    let can_manage = manage(state, submission);
    let source_current = target.map(|target| target == &row.target);
    let write = known.as_ref().map(|known| &known.write).or(row.write.as_ref());
    let status = if row.archived_at.is_some() {
        "archived"
    } else if row.state != State::Complete {
        if pending || expired { "uncertain" } else { "started" }
    } else {
        match row.write.as_ref().ok_or_else(util::corrupt)?.status {
            agf_alicloud::schedulerx3::managed_jobs::WriteStatus::Accepted => "accepted",
            agf_alicloud::schedulerx3::managed_jobs::WriteStatus::Rejected => "rejected",
            agf_alicloud::schedulerx3::managed_jobs::WriteStatus::Unknown => "uncertain",
        }
    };
    let completion = if row.state == State::Complete {
        "complete"
    } else if pending {
        "pending_audit"
    } else {
        "running"
    };
    let mut actions = vec!["read_receipt"];
    if can_manage && row.state != State::Complete && (pending || expired) {
        actions.push("recover_local");
    }
    if can_manage && row.state == State::Complete && row.archived_at.is_none() && source_current == Some(true) {
        actions.push("observe");
    }
    let archivable = can_manage
        && row.state == State::Complete
        && row.archived_at.is_none()
        && active.is_none_or(|active| active.request_id != row.request_id);
    Ok(json!({"requestId":row.request_id,"actorId":row.actor,"claimId":row.claim_id,"inputHash":row.input_hash,
        "configurationVersion":row.target.configuration_version,"target":row.target,"previewId":row.input.preview_id,
        "action":row.action,"kind":row.kind,"runtimeName":row.kind.runtime_name(),"jobId":row.job_id,
        "startedAt":row.started_at,"submittedAt":row.submitted_at,"expiresAt":row.expires_at,"finishedAt":row.finished_at,
        "status":status,"completionState":completion,"originalWrite":write,"readback":row.readback,
        "readbackAt":row.readback_at,"readbackFingerprint":row.readback_fingerprint,
        "sourceCurrent":source_current,"currentConfigurationVersion":target.map(|t|t.configuration_version),
        "archived":row.archived_at.is_some(),"archivedAt":row.archived_at,"archivable":archivable,"allowedActions":actions,
        "consumerApplied":null,"callbackConfigured":null,"callbackBindingEnforced":false,"deploymentVerified":null,
        "cloudCasAvailable":false,"preview":row.preview.as_ref().map(|p|json!({"before":p.before,"desired":p.desired,
            "fingerprint":p.fingerprint,"baselineFingerprint":p.baseline_fingerprint}))}))
}
pub(super) async fn list(state: &AppState, submission: &Submission) -> DomainResult<Value> {
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let (target, source_state) = current_target(state, tenant).await;
    let journal = codec::journal(state, tenant).await?;
    let native = super::super::store::journal(state, tenant).await?;
    let bindings: super::super::records::BindingRecord =
        super::super::store::get(state, tenant, &util::binding_key(tenant)).await?.unwrap_or_default();
    super::super::binding::validate(&bindings, tenant)?;
    super::super::proof::restore(state, &bindings, tenant)?;
    let mut previews = Vec::new();
    for id in journal.previews.iter().rev().take(50) {
        previews.push(preview(state, submission, &load_preview(state, tenant, *id).await?).await?);
    }
    let mut operations = Vec::new();
    for id in journal.operations.iter().rev().take(50) {
        operations.push(
            operation(
                state,
                submission,
                &load_operation(state, tenant, *id).await?,
                target.as_ref(),
                journal.active.as_ref(),
            )
            .await?,
        );
    }
    let can_manage = manage(state, submission);
    Ok(
        json!({"target":target,"sourceState":source_state,"canManage":can_manage,"canPrepare":can_manage && target.is_some(),
        "stateVersion":journal.version,"generation":journal.generation,"archivedCount":journal.archived_count,
        "storedContentBytes":journal.stored_bytes,"activeRequestId":journal.active.map(|a|a.request_id),
        "latestObservationId":native.latest,"bindingVersion":bindings.version,"definitions":journal.definitions,
        "unknownScopes":journal.unknown,"previews":previews,"operations":operations,"consistency":"statement",
        "previewTotal":journal.previews.len(),"operationTotal":journal.operations.len(),
        "previewsTruncated":journal.previews.len()>50,"operationsTruncated":journal.operations.len()>50,
        "limits":{"maxPreviews":128,"maxOperations":128,"maxStoredBytes":super::model::MAX_STORED,
            "maxDetailBytes":super::model::MAX_DETAIL,"maxArchive":48,"pageSize":50,"maxMockJobs":128,"previewSeconds":120},
        "cloudCasAvailable":false,"callbackBindingEnforced":false,"callbackConfigured":null,"deploymentVerified":null}),
    )
}
async fn current_target(state: &AppState, tenant: TenantId) -> (Option<SourceTarget>, &'static str) {
    match scope::current(state, tenant).await {
        Ok(Some(target)) => (Some(target), "available"),
        Ok(None) => (None, "disabled_or_missing"),
        // An unavailable current source never hides an independently AEAD verified old receipt.
        Err(_) => (None, "unavailable"),
    }
}
