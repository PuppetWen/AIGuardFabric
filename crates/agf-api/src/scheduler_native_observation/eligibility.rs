//! Complete observations can revoke qualification; positive later evidence never silently readopts a job.
use super::{input::Assignment, records::BindingRecord, safe::SafeSnapshot, scope::SourceTarget, util};
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Eligibility {
    Eligible,
    Revoked,
    Unverified,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Reason {
    AppChanged,
    JobMissing,
    JobDisabled,
    JobNotHttp,
    JobTypeUnknown,
    JobStatusUnknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Evidence {
    pub observation_id: Id,
    pub observed_at: Timestamp,
    pub source_scope_id: Id,
    pub source_fingerprint: String,
    pub configuration_version: u64,
    pub app_id: String,
    pub job_present: bool,
    pub job_kind: Option<String>,
    pub http_job: Option<bool>,
    pub enabled: Option<bool>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Qualification {
    pub assignment: Assignment,
    pub status: Eligibility,
    pub reason: Option<Reason>,
    pub decision_observation_id: Id,
    pub decision_at: Timestamp,
    pub evidence: Evidence,
}

// Exact documented CreateJob.JobType enums in reference/schedulerx3-api.json, version 2024-06-24.
fn http_kind(kind: Option<&str>) -> Option<bool> {
    match kind {
        Some("http") => Some(true),
        Some(
            "xxljob" | "dify_workflow" | "script_groovy" | "script_shell" | "script_python" | "script_php"
            | "script_nodejs" | "script_powershell" | "status_branch" | "condition_branch" | "dependent" | "manual"
            | "callback_branch" | "script_cmd" | "sql" | "dify_agent" | "openclaw" | "bailian" | "a2a" | "langgraph"
            | "hermes" | "matrix" | "qwenpaw" | "elastic",
        ) => Some(false),
        _ => None,
    }
}
fn evidence(
    assignment: &Assignment,
    data: &SafeSnapshot,
    target: &SourceTarget,
    request: Id,
    at: Timestamp,
) -> Evidence {
    let job = data.jobs().iter().find(|job| job["id"] == assignment.job_id);
    let kind = job.and_then(|job| job["kind"].as_str());
    Evidence {
        observation_id: request,
        observed_at: at,
        source_scope_id: target.scope_id,
        source_fingerprint: target.fingerprint.clone(),
        configuration_version: target.configuration_version,
        app_id: data.app_id().into(),
        job_present: job.is_some(),
        job_kind: kind.map(str::to_owned),
        http_job: http_kind(kind),
        enabled: job.and_then(|job| job["enabled"].as_bool()),
    }
}
fn evaluated(adopted_app: &str, evidence: &Evidence) -> (Eligibility, Option<Reason>) {
    if evidence.app_id != adopted_app {
        (Eligibility::Revoked, Some(Reason::AppChanged))
    } else if !evidence.job_present {
        (Eligibility::Revoked, Some(Reason::JobMissing))
    } else if evidence.enabled == Some(false) {
        (Eligibility::Revoked, Some(Reason::JobDisabled))
    } else if evidence.http_job == Some(false) {
        (Eligibility::Revoked, Some(Reason::JobNotHttp))
    } else if evidence.http_job.is_none() {
        (Eligibility::Unverified, Some(Reason::JobTypeUnknown))
    } else if evidence.enabled.is_none() {
        (Eligibility::Unverified, Some(Reason::JobStatusUnknown))
    } else {
        (Eligibility::Eligible, None)
    }
}
pub(super) fn adopt(
    row: &BindingRecord,
    data: &SafeSnapshot,
    request: Id,
    at: Timestamp,
) -> DomainResult<Vec<Qualification>> {
    let target = row.target.as_ref().ok_or_else(util::corrupt)?;
    row.items
        .iter()
        .map(|assignment| {
            let evidence = evidence(assignment, data, target, request, at);
            let (status, reason) = evaluated(row.app_id.as_deref().ok_or_else(util::corrupt)?, &evidence);
            if status != Eligibility::Eligible {
                return Err(util::stale());
            }
            Ok(Qualification {
                assignment: assignment.clone(),
                status,
                reason,
                decision_observation_id: request,
                decision_at: at,
                evidence,
            })
        })
        .collect()
}

/// Update safe current evidence without modifying immutable adoption proofs or user intent.
pub(super) fn refresh(
    row: &mut BindingRecord,
    data: &SafeSnapshot,
    target: &SourceTarget,
    request: Id,
    at: Timestamp,
) -> DomainResult<Vec<String>> {
    if row.adoption_version == 0 || row.target.as_ref() != Some(target) {
        return Ok(Vec::new());
    }
    validate_record(row, target.tenant)?;
    let app = row.app_id.as_deref().ok_or_else(util::corrupt)?;
    let mut changed = Vec::new();
    for qualification in &mut row.eligibility {
        let current = evidence(&qualification.assignment, data, target, request, at);
        let (mut status, mut reason) = evaluated(app, &current);
        if qualification.status == Eligibility::Revoked
            || (qualification.status == Eligibility::Unverified && status != Eligibility::Revoked)
        {
            status = qualification.status;
            reason = qualification.reason;
        }
        if (qualification.status, qualification.reason) != (status, reason) {
            changed.push(qualification.assignment.kind.clone());
            qualification.decision_observation_id = request;
            qualification.decision_at = at;
        }
        qualification.status = status;
        qualification.reason = reason;
        qualification.evidence = current;
    }
    if !changed.is_empty() {
        row.version = row.version.checked_add(1).ok_or_else(util::capacity)?;
    }
    validate_record(row, target.tenant)?;
    Ok(changed)
}
pub(super) fn validate_record(row: &BindingRecord, tenant: TenantId) -> DomainResult<()> {
    if row.eligibility.len() != row.items.len() {
        return Err(util::corrupt());
    }
    for (assignment, qualification) in row.items.iter().zip(&row.eligibility) {
        let evidence = &qualification.evidence;
        if &qualification.assignment != assignment
            || evidence.observation_id.is_nil()
            || qualification.decision_observation_id.is_nil()
            || row.target.as_ref().is_none_or(|target| {
                target.tenant != tenant
                    || (target.scope_id, target.fingerprint.as_str(), target.configuration_version)
                        != (
                            evidence.source_scope_id,
                            evidence.source_fingerprint.as_str(),
                            evidence.configuration_version,
                        )
            })
            || row.verified_at.is_none_or(|at| evidence.observed_at < at)
            || row.verified_at.is_none_or(|at| qualification.decision_at < at)
            || qualification.decision_at > evidence.observed_at
            || !util::positive_id(&evidence.app_id)
            || (qualification.status == Eligibility::Eligible) != qualification.reason.is_none()
            || evidence.http_job != http_kind(evidence.job_kind.as_deref())
            || evidence.job_kind.as_deref().is_some_and(|kind| !util::text(kind, 64))
            || (!evidence.job_present && (evidence.job_kind.is_some() || evidence.enabled.is_some()))
        {
            return Err(util::corrupt());
        }
        let (actual, _) = evaluated(row.app_id.as_deref().ok_or_else(util::corrupt)?, evidence);
        if qualification.status == Eligibility::Eligible && actual != Eligibility::Eligible {
            return Err(util::corrupt());
        }
    }
    Ok(())
}
pub(super) fn all_eligible(row: &BindingRecord) -> bool {
    row.adoption_version > 0
        && !row.items.is_empty()
        && row.eligibility.len() == row.items.len()
        && row.items.iter().all(|item| qualified(row, &item.kind, &item.job_id))
}
/// Per-job predicate used only after authenticating both adoption and current qualification seals.
pub(super) fn qualified(row: &BindingRecord, kind: &str, job_id: &str) -> bool {
    row.adoption_version > 0
        && row.eligibility.iter().any(|item| {
            (item.assignment.kind.as_str(), item.assignment.job_id.as_str()) == (kind, job_id)
                && item.status == Eligibility::Eligible
        })
}
