use super::{
    authority::Submission,
    binding, claim, eligibility,
    input::PageQuery,
    observation, proof,
    records::{BindingRecord, BodyRecord, Fact, Journal},
    scope::{self, SourceTarget},
    store, util,
};
use crate::{cloud_store, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
    time::Timestamp,
};
use serde_json::{Value, json};
use std::cmp::Reverse;

pub(super) async fn source(state: &AppState, tenant: agf_core::ids::TenantId) -> DomainResult<Option<SourceTarget>> {
    match scope::current(state, tenant).await {
        Ok(target) => Ok(target),
        Err(DomainError::Validation(_) | DomainError::PreconditionFailed(_)) => Ok(None),
        Err(error) => Err(error),
    }
}
pub(super) async fn list(state: &AppState, submission: &Submission) -> DomainResult<Value> {
    let principal = submission.authorize(state).await?;
    let can_write = principal.require(state, "alicloud", "write").is_ok();
    let tenant = submission.principal.tenant;
    let journal = store::journal(state, tenant).await?;
    let configuration = cloud_store::load(state, tenant, super::NAME).await?;
    let current = source(state, tenant).await?;
    let bindings = store::get::<BindingRecord>(state, tenant, &util::binding_key(tenant)).await?.unwrap_or_default();
    binding::validate(&bindings, tenant)?;
    let mut runs = Vec::new();
    for id in &journal.observations {
        runs.push(claim::fact(state, tenant, *id).await?.ok_or_else(util::corrupt)?);
    }
    runs.sort_by_key(|fact| Reverse((fact.started_at, fact.request_id)));
    runs.truncate(50);
    let recent = runs
        .iter()
        .map(|fact| summary(fact, None, &journal, current.as_ref(), can_write))
        .collect::<DomainResult<Vec<_>>>()?;
    let latest = if let Some(id) = journal.latest {
        let fact = claim::fact(state, tenant, id).await?.ok_or_else(util::corrupt)?;
        let body = store::get::<BodyRecord>(state, tenant, &util::body_key(tenant, id)).await?;
        Some(summary(&fact, body.as_ref(), &journal, current.as_ref(), can_write)?)
    } else {
        None
    };
    let current_bindings = bindings.target.as_ref().is_some_and(|target| Some(target) == current.as_ref());
    let bindings_dto = binding_dto(state, tenant, &bindings, current_bindings)?;
    let busy = journal.active.as_ref().is_some_and(|active| active.expires_at > Timestamp::now());
    Ok(
        json!({"tenantId":tenant,"configured":configuration.is_some(),"enabled":configuration.as_ref().is_some_and(|row|row.enabled),
        "sourceTarget":current,"stateVersion":journal.version,"generation":journal.generation,"busy":busy,
        "leaseExpiresAt":journal.active.as_ref().map(|active|active.expires_at),"canObserve":current.is_some() && !busy,
        "canInitMock":can_write && current.as_ref().is_some_and(|target|target.mocked),"canBind":can_write && current.is_some(),
        "latestObservation":latest,"bindings":bindings_dto,"recentObservations":recent,
        "detailedObservationCount":journal.observations.len(),"archivedCount":journal.archived_count,"storedContentBytes":journal.stored_bytes,
        "callbackBindingEnforced":false,"deploymentVerified":null,"callbackConfigured":null,
        "limits":{"maxJobs":2000,"maxPages":20,"cloudPageSize":100,"pageSize":100,"maxObservations":128,"maxArchive":100,
        "maxObservationBytes":super::MAX_BODY_BYTES,"maxEncryptedEnvelopeBytes":4 * 1024 * 1024,"maxStoredBytes":super::MAX_STORED_BYTES,
        "maxSeconds":110,"observationFreshSeconds":300,"bindingKinds":super::KINDS}}),
    )
}
pub(super) fn binding_dto(
    state: &AppState,
    tenant: agf_core::ids::TenantId,
    row: &BindingRecord,
    source_current: bool,
) -> DomainResult<Value> {
    binding::validate(row, tenant)?;
    let proofs = proof::restore(state, row, tenant)?;
    Ok(binding_projection(row, &proofs, source_current))
}
pub(super) fn binding_projection(row: &BindingRecord, proofs: &[proof::Provenance], source_current: bool) -> Value {
    let qualification = if row.eligibility.iter().any(|item| item.status == eligibility::Eligibility::Revoked) {
        "revoked"
    } else if eligibility::all_eligible(row) {
        "eligible"
    } else {
        "unverified"
    };
    let status = if !row.enabled {
        "disabled"
    } else if !source_current {
        "stale"
    } else if qualification != "eligible" {
        qualification
    } else if row.items.len() < 6 {
        "partial"
    } else {
        "associated"
    };
    let items =
        row.items
            .iter()
            .enumerate()
            .map(|(offset, item)| {
                let evidence = row.eligibility.get(offset);
                let adopted = proofs.get(offset).map(|proof| {
                    json!({
                        "proofId":proof.proof_id,"adoptionVersion":proof.adoption_version,"sourceTarget":proof.source,
                        "observationId":proof.observation_id,"observedAt":proof.observed_at,"appId":proof.app_id,
                        "jobId":proof.assignment.job_id,"kind":proof.assignment.kind,"httpJob":true,"enabled":true
                    })
                });
                let current_evidence = evidence.map(|item| json!({
            "observationId":item.evidence.observation_id,"observedAt":item.evidence.observed_at,
            "sourceTarget":row.target,"appId":item.evidence.app_id,"jobPresent":item.evidence.job_present,
            "jobKind":item.evidence.job_kind,"httpJob":item.evidence.http_job,"enabled":item.evidence.enabled
        }));
                json!({"kind":item.kind,"runtimeName":util::runtime_kind(&item.kind),"jobId":item.job_id,
            "eligibility":evidence.map_or(json!("unverified"),|item|json!(item.status)),
            "reason":evidence.map_or(json!("proof_unavailable"),|item|json!(item.reason)),
            "decisionObservationId":evidence.map(|item|item.decision_observation_id),
            "decisionAt":evidence.map(|item|item.decision_at),
            "adoptedProof":adopted,"currentEvidence":current_evidence})
            })
            .collect::<Vec<_>>();
    json!({"version":row.version,"adoptionVersion":row.adoption_version,"locallyEnabled":row.enabled,"status":status,
        "eligibility":qualification,"qualificationVerified":row.adoption_version>0,"sourceCurrent":source_current,
        "current":row.enabled && source_current && qualification=="eligible","evidenceFresh":row.verified_at.is_some_and(|at|at<=Timestamp::now() && at.offset_secs(300)>=Timestamp::now()),
        "observationId":row.observation_id,"appId":row.app_id,"verifiedAt":row.verified_at,"sourceTarget":row.target,
        "items":items,"callbackBindingEnforced":false,"deploymentVerified":null,"callbackConfigured":null})
}
pub(super) async fn binding_result(
    state: &AppState,
    submission: &Submission,
    row: &BindingRecord,
) -> DomainResult<Value> {
    let current = source(state, submission.principal.tenant).await?;
    let stored = store::get::<BindingRecord>(
        state,
        submission.principal.tenant,
        &util::binding_key(submission.principal.tenant),
    )
    .await?
    .unwrap_or_default();
    binding::validate(&stored, submission.principal.tenant)?;
    proof::restore(state, &stored, submission.principal.tenant)?;
    binding_dto(
        state,
        submission.principal.tenant,
        row,
        stored.version == row.version && row.target.as_ref().is_some_and(|target| Some(target) == current.as_ref()),
    )
}
fn summary(
    fact: &Fact,
    body: Option<&BodyRecord>,
    journal: &Journal,
    current: Option<&SourceTarget>,
    can_write: bool,
) -> DomainResult<Value> {
    let archived = match body {
        Some(BodyRecord::Archived { tenant, request_id, archived_at, original_status }) => {
            let expected_status = if fact.status == "reading" { "interrupted" } else { fact.status.as_str() };
            if (*tenant, *request_id) != (fact.tenant, fact.request_id)
                || *archived_at < fact.started_at
                || original_status != expected_status
            {
                return Err(util::corrupt());
            }
            Some((*archived_at, original_status.as_str()))
        }
        _ => None,
    };
    let reading = fact.status == "reading";
    let expired = reading && fact.expires_at <= Timestamp::now();
    let status = if archived.is_some() {
        "archived"
    } else if expired {
        "interrupted"
    } else {
        fact.status.as_str()
    };
    let available = archived.is_none() && fact.status == "observed" && journal.observations.contains(&fact.request_id);
    let source_current = fact.target.as_ref().is_some_and(|target| Some(target) == current);
    let can_archive =
        can_write && archived.is_none() && journal.observations.contains(&fact.request_id) && (!reading || expired);
    let application_scope = fact.target.as_ref().zip(fact.app_id.as_ref()).map(|(target, app)| {
        deterministic_id("agf.scheduler.native.application", &format!("{}:{app}", target.scope_id))
    });
    Ok(
        json!({"requestId":fact.request_id,"status":status,"originalStatus":archived.map(|(_,status)|status).unwrap_or(fact.status.as_str()),
        "originalTarget":fact.target,"applicationScopeId":application_scope,"claimId":fact.claim_id,"submittedAt":fact.submitted_at,
        "startedAt":fact.started_at,"finishedAt":fact.finished_at,"observedAt":if fact.status=="observed" {fact.finished_at} else {None},
        "leaseExpiresAt":fact.expires_at,"archived":archived.is_some(),"archivedAt":archived.map(|(at,_)|at),
        "available":available,"current":source_current,"archivable":can_archive,"reason":fact.reason,
        "total":fact.total,"appId":fact.app_id,"fingerprint":fact.fingerprint,"listingComplete":fact.status=="observed",
        "strongSnapshot":false,"callbackBindingEnforced":false,"deploymentVerified":null,"callbackConfigured":null,"authorizationAllowed":null,
        "callbackReachability":null,"allowedActions":if can_archive {vec!["read_receipt","archive"]} else {vec!["read_receipt"]}}),
    )
}
pub(super) async fn receipt(
    state: &AppState,
    submission: &Submission,
    id: Id,
    page: &PageQuery,
) -> DomainResult<Value> {
    page.validate()?;
    let principal = submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let fact = claim::fact(state, tenant, id).await?.ok_or_else(|| util::missing(id))?;
    if fact.purpose != super::records::Purpose::Observe {
        return Err(util::missing(id));
    }
    let journal = store::journal(state, tenant).await?;
    let current = source(state, tenant).await?;
    let body = store::get::<BodyRecord>(state, tenant, &util::body_key(tenant, id)).await?;
    let mut dto = summary(
        &fact,
        body.as_ref(),
        &journal,
        current.as_ref(),
        principal.require(state, "alicloud", "write").is_ok(),
    )?;
    if fact.status == "observed" && !matches!(body, Some(BodyRecord::Archived { .. })) {
        let data = observation::decode(state, tenant, id, body.as_ref().ok_or_else(util::corrupt)?, &fact)?;
        let pages = data.jobs().len().div_ceil(page.page_size as usize).max(1);
        if page.page as usize > pages {
            return Err(DomainError::Validation("观察页码超出此完整快照".into()));
        }
        let start = (page.page as usize - 1) * page.page_size as usize;
        dto["observation"] = json!({"scope":data.value()["scope"],"app":data.value()["app"],"pagination":data.value()["pagination"],
            "fingerprint":data.fingerprint(),"jobs":data.jobs().iter().skip(start).take(page.page_size as usize).collect::<Vec<_>>(),
            "page":page.page,"pageSize":page.page_size,"total":data.total(),"totalPages":pages});
    } else {
        dto["observation"] = Value::Null;
    }
    Ok(dto)
}
