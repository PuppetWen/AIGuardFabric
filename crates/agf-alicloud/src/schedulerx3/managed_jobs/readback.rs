use super::{Change, PreparedChange};
use crate::schedulerx3::native_observation::Observation;
use serde::{Deserialize, Serialize};

/// Readback matches only public control-plane evidence, not consumers or a cloud CAS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Readback {
    Matched,
    Different,
    Unknown,
}

/// Compare a separately obtained complete observation against the reviewed mutation.
///
/// The original write status is never upgraded by this independent observation.
#[must_use]
pub fn compare_readback(plan: &PreparedChange, observed: &Observation) -> Readback {
    if observed.scope() != &plan.scope || observed.app().id != plan.selection.app_id {
        return Readback::Unknown;
    }
    let Some(job) = observed.jobs().iter().find(|job| job.id == plan.selection.job_id) else {
        return Readback::Different;
    };
    if !job.http_job
        || job.kind.as_deref() != Some("http")
        || job.http != plan.before.http
        || job.app_name != plan.before.app_name
        || job.app_id != plan.before.app_id
        || job.name != plan.before.name
        || job.route_strategy != plan.before.route_strategy
    {
        return Readback::Different;
    }
    let matched = match &plan.change {
        Change::UpdateSchedule { patch } => {
            let before = &plan.before;
            job.enabled == Some(false)
                && job.status == Some(0)
                && job.schedule.kind == patch.time_type.or(before.schedule.kind)
                && job.schedule.expression
                    == patch.time_expression.clone().or_else(|| before.schedule.expression.clone())
                && job.schedule.calendar == patch.calendar.clone().or_else(|| before.schedule.calendar.clone())
                && job.schedule.zone == patch.timezone.clone().or_else(|| before.schedule.zone.clone())
                && job.max_attempt == patch.max_attempt.or(before.max_attempt)
                && job.attempt_interval == patch.attempt_interval.or(before.attempt_interval)
        }
        Change::Enable | Change::Disable => {
            let enabled = matches!(plan.change, Change::Enable);
            job.enabled == Some(enabled)
                && job.status == Some(i32::from(enabled))
                && job.schedule == plan.before.schedule
                && job.max_attempt == plan.before.max_attempt
                && job.attempt_interval == plan.before.attempt_interval
        }
        Change::CreateDisabled { .. } => false,
    };
    if matched { Readback::Matched } else { Readback::Different }
}
