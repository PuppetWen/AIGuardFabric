//! Pure control-plane differences. Safe observations confer no callback authority.
use super::super::{safe::SafeSnapshot, util};
use super::{input::PreviewInput, model::Journal};
use agf_alicloud::schedulerx3::managed_jobs::{Change, Kind, SchedulePatch};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use serde_json::{Value, json};

pub(super) fn summary(change: &Change, selected: Option<Kind>) -> DomainResult<(&'static str, Kind)> {
    Ok(match change {
        Change::CreateDisabled { declaration } => ("create_disabled", declaration.kind),
        Change::UpdateSchedule { .. } => ("update_schedule", selected.ok_or_else(util::corrupt)?),
        Change::Disable => ("disable", selected.ok_or_else(util::corrupt)?),
        Change::Enable => ("enable", selected.ok_or_else(util::corrupt)?),
    })
}
pub(super) fn desired(
    input: &PreviewInput,
    data: &SafeSnapshot,
    journal: &Journal,
    scope: Id,
    mocked: bool,
) -> DomainResult<(Option<Value>, Value)> {
    input.validate()?;
    if let Change::CreateDisabled { declaration } = &input.change {
        if !mocked {
            return Err(DomainError::PreconditionFailed(
                "真实云 HTTP carrier 未被官方契约证明；不调用 CreateJob".into(),
            ));
        }
        if data.jobs().len() >= super::model::MAX_MOCK_JOBS
            || journal.definitions.iter().any(|slot| slot.scope_id == scope && slot.kind == declaration.kind)
        {
            return Err(DomainError::Conflict("此 Mock 来源的任务类型已经受管，或已达到任务容量".into()));
        }
        declaration.validate()?;
        let id = data
            .jobs()
            .iter()
            .map(|job| job["id"].as_str().ok_or_else(util::corrupt)?.parse::<i64>().map_err(|_| util::corrupt()))
            .collect::<DomainResult<Vec<_>>>()?
            .into_iter()
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .filter(|id| *id > 0)
            .ok_or_else(util::capacity)?
            .to_string();
        let http_hash = util::canonical_hash(&json!({"domain":"agf.scheduler.managed.mock-carrier.v1",
            "scope":scope,"id":id,"kind":declaration.kind}))?;
        let mut desired = json!({"id":id,"appName":data.value()["app"]["name"],"appId":data.app_id(),
            "name":declaration.name,"kind":"http","httpJob":true,"status":0,"enabled":false,
            "schedule":{"kind":null,"expression":null,"calendar":null,"zone":null,"utc":null},
            "maxAttempt":null,"attemptInterval":null,"routeStrategy":null,"shardCount":null,"updateTimeNative":null,
            "http":{"verified":false,"parameters":"empty","handler":"empty","attributes":"empty",
                "script":"empty","fingerprint":http_hash}});
        schedule(&mut desired, &declaration.schedule)?;
        return Ok((None, desired));
    }
    let selected = input.selection.as_ref().ok_or_else(util::corrupt)?;
    if selected.app_id != data.app_id() || selected.observation_fingerprint != data.fingerprint() {
        return Err(util::stale());
    }
    let before = data.jobs().iter().find(|job| job["id"] == selected.job_id).ok_or_else(util::stale)?;
    if before["httpJob"] != true || before["kind"] != "http" {
        return Err(util::stale());
    }
    let mut desired = before.clone();
    match &input.change {
        Change::UpdateSchedule { patch } => {
            if before["enabled"] != false || before["status"] != 0 {
                return Err(disable_first());
            }
            schedule(&mut desired, patch)?;
        }
        Change::Disable | Change::Enable => {
            let enabled = matches!(input.change, Change::Disable);
            if before["enabled"] != enabled || before["status"] != i32::from(enabled) {
                return Err(util::stale());
            }
            desired["enabled"] = json!(!enabled);
            desired["status"] = json!(i32::from(!enabled));
        }
        Change::CreateDisabled { .. } => return Err(util::corrupt()),
    }
    Ok((Some(before.clone()), desired))
}
fn schedule(job: &mut Value, patch: &SchedulePatch) -> DomainResult<()> {
    patch.validate()?;
    for (key, value) in [
        ("kind", json!(patch.time_type)),
        ("expression", json!(patch.time_expression)),
        ("calendar", json!(patch.calendar)),
        ("zone", json!(patch.timezone)),
    ] {
        if !value.is_null() {
            job["schedule"][key] = value;
        }
    }
    for (key, value) in [("maxAttempt", json!(patch.max_attempt)), ("attemptInterval", json!(patch.attempt_interval))] {
        if !value.is_null() {
            job[key] = value;
        }
    }
    job["schedule"]["utc"] = job["schedule"]["zone"].as_str().map_or(Value::Null, |zone| json!(zone == "UTC"));
    let kind = job["schedule"]["kind"].as_i64();
    let expression = job["schedule"]["expression"].as_str();
    if kind.is_none_or(|kind| !matches!(kind, -1 | 1 | 3 | 5 | 100))
        || (kind.is_some_and(|kind| matches!(kind, 1 | 3 | 5))
            && expression.is_none_or(|value| !util::text(value, 256)))
        || (kind.is_some_and(|kind| matches!(kind, -1 | 100)) && expression.is_some_and(|value| !value.is_empty()))
    {
        return Err(super::input::invalid());
    }
    Ok(())
}
fn disable_first() -> DomainError {
    DomainError::PreconditionFailed(
        "先通过独立意图明确停用启用中的 Job，才可以编辑调度/重试；编辑不会隐式停用或启用".into(),
    )
}

pub(super) fn readback(
    preview: &super::model::Preview,
    current: &SafeSnapshot,
) -> agf_alicloud::schedulerx3::managed_jobs::Readback {
    use agf_alicloud::schedulerx3::managed_jobs::Readback;
    let Some(job) = current.jobs().iter().find(|job| job["id"] == preview.desired["id"]) else {
        return Readback::Different;
    };
    if current.app_id() != preview.app_id {
        return Readback::Different;
    }
    let mut actual = job.clone();
    let mut wanted = preview.desired.clone();
    // Native UpdateTime can change independently; every reviewed scheduling/carrier field remains compared.
    actual["updateTimeNative"] = Value::Null;
    wanted["updateTimeNative"] = Value::Null;
    if actual == wanted { Readback::Matched } else { Readback::Different }
}
