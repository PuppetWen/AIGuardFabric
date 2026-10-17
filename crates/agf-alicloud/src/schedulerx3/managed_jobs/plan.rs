use super::{Change, Selection, validate};
use crate::schedulerx3::native_observation::{JobObservation, Observation, Scope};
use agf_core::error::{DomainError, DomainResult};
use serde_json::{Value, json};

/// A single reviewed write constructed from typed, complete provider evidence.
///
/// The enclosing API must still prove the current actor, source and binding version.
#[derive(Debug, Clone)]
pub struct PreparedChange {
    pub(super) scope: Scope,
    pub(super) selection: Selection,
    pub(super) before: JobObservation,
    pub(super) change: Change,
    pub(super) action: &'static str,
    pub(super) input: Value,
}
impl PreparedChange {
    /// Exactly one documented vendor action; an update never implies enable/disable.
    #[must_use]
    pub const fn action(&self) -> &'static str {
        self.action
    }
    /// Only whitelisted public control-plane fields, without HTTP carrier contents.
    #[must_use]
    pub fn input(&self) -> &Value {
        &self.input
    }
    /// The original reviewed selection including its stable string JobId.
    #[must_use]
    pub const fn selection(&self) -> &Selection {
        &self.selection
    }
}

/// Prepare one change to an explicitly selected current HTTP job.
///
/// Updating or enabling requires an explicitly disabled job. An active job must be
/// disabled through an independent intent first. Live creation is always unavailable.
/// # Errors
/// Incomplete/stale evidence, bad IDs, unsupported HTTP creation or an unsafe state.
pub fn prepare(observed: &Observation, selected: &Selection, change: &Change) -> DomainResult<PreparedChange> {
    if matches!(change, Change::CreateDisabled { .. }) {
        return Err(DomainError::PreconditionFailed(
            "Live HTTP job creation has no verified carrier contract; no CreateJob will be sent".into(),
        ));
    }
    observed.scope().validate()?;
    let job_id = validate::identifier(&selected.job_id)?;
    validate::identifier(&selected.app_id)?;
    if !validate::digest(&selected.observation_fingerprint)
        || observed.fingerprint() != selected.observation_fingerprint
        || observed.app().id != selected.app_id
        || !observed.pagination().listing_complete
    {
        return Err(validate::precondition());
    }
    let before = observed.jobs().iter().find(|job| job.id == selected.job_id).ok_or_else(validate::precondition)?;
    if !before.http_job || before.kind.as_deref() != Some("http") {
        return Err(validate::precondition());
    }
    let scope = observed.scope();
    let mut input = json!({"ClusterId":scope.cluster_id,"AppName":scope.app_name});
    let action = match change {
        Change::UpdateSchedule { patch } => {
            if before.enabled != Some(false) || before.status != Some(0) {
                return Err(validate::precondition());
            }
            patch.validate()?;
            input["JobId"] = json!(job_id);
            for (name, value) in [
                ("TimeType", json!(patch.time_type)),
                ("TimeExpression", json!(patch.time_expression)),
                ("Calendar", json!(patch.calendar)),
                ("Timezone", json!(patch.timezone)),
                ("MaxAttempt", json!(patch.max_attempt)),
                ("AttemptInterval", json!(patch.attempt_interval)),
            ] {
                if !value.is_null() {
                    input[name] = value;
                }
            }
            let time_type = patch.time_type.or(before.schedule.kind);
            let expression = patch.time_expression.as_deref().or(before.schedule.expression.as_deref());
            if time_type.is_none_or(|kind| !matches!(kind, -1 | 1 | 3 | 5 | 100))
                || (time_type.is_some_and(|kind| matches!(kind, 1 | 3 | 5))
                    && expression.is_none_or(|value| !validate::text(value, 256, false)))
                || (time_type.is_some_and(|kind| matches!(kind, -1 | 100))
                    && expression.is_some_and(|value| !value.is_empty()))
            {
                return Err(validate::invalid());
            }
            "UpdateJob"
        }
        Change::Disable | Change::Enable => {
            let expected = matches!(change, Change::Disable);
            if before.enabled != Some(expected) || before.status != Some(i32::from(expected)) {
                return Err(validate::precondition());
            }
            input["JobIds"] = json!([job_id]);
            if expected { "OperateDisableJobs" } else { "OperateEnableJobs" }
        }
        Change::CreateDisabled { .. } => return Err(validate::precondition()),
    };
    Ok(PreparedChange {
        scope: scope.clone(),
        selection: selected.clone(),
        before: before.clone(),
        change: change.clone(),
        action,
        input,
    })
}
