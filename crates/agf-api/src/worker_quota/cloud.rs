use super::{context::Resolved, contract::CloudLimit};
use crate::{Principal, cloud_runtime::Request, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
    time::Timestamp,
};
use serde_json::{Value, json};

pub(super) struct Step<'a> {
    pub request: Id,
    pub phase: &'a str,
    pub action: &'a str,
    pub parameters: Value,
    pub confirm_live: bool,
}

pub(super) async fn call(
    state: &AppState,
    principal: &Principal,
    resolved: &Resolved,
    step: Step<'_>,
) -> DomainResult<Value> {
    let action = if step.phase == "observe" { "read" } else { "write" };
    let issued_at = if action == "write" {
        let run = deterministic_id(
            "agf.worker-quota.run",
            &format!("{}:{}:{}", principal.tenant, resolved.asset, step.request),
        );
        state
            .configurations
            .get::<super::contract::Operation>(principal.tenant, super::RUNS, run)
            .await?
            .ok_or_else(super::stale)?
            .started_at
    } else {
        Timestamp::now()
    };
    let guard = super::write_guard::QuotaPermission { state, principal, action, issued_at };
    let request_id =
        deterministic_id("agf.worker-quota.phase", &format!("{}:{}:{}", resolved.asset, step.request, step.phase));
    Box::pin(crate::cloud_runtime::execute_guarded_authorized(
        state,
        principal,
        crate::cloud_inventory::NAME,
        Request {
            request_id,
            configuration_version: resolved.cloud.cloud.version,
            action: step.action.into(),
            parameters: step.parameters,
            confirm_live: step.confirm_live,
        },
        &guard,
    ))
    .await
}

pub(super) fn identity(resolved: &Resolved) -> Value {
    json!({"Name":resolved.worker,"InstanceId":resolved.cloud.snapshot.instance_id})
}

pub(super) fn response(mut run: Value, resolved: &Resolved) -> Option<Value> {
    if run["status"] != "succeeded" {
        return None;
    }
    let mut body = run["receipt"]["response"].take();
    if resolved.cloud.snapshot.mocked {
        // Public example InstanceId is inst-demo; inventory also scopes examples to this test instance.
        if let Some(data) = body.get_mut("Data").and_then(Value::as_object_mut) {
            data.insert("InstanceId".into(), json!(resolved.cloud.snapshot.instance_id));
        }
    }
    Some(body)
}

pub(super) fn writable(limit: &CloudLimit, value: i64) -> Value {
    // These are the complete writable LimitConfig fields in the audited catalog. RuleStatus,
    // UsedAmount and OverLimit are read-only observations and must never be sent to UpdateWorker.
    json!({"UsageLimit":value,"LimitType":limit.limit_type,"PeriodType":limit.period_type})
}

pub(super) async fn read(
    state: &AppState,
    principal: &Principal,
    resolved: &Resolved,
    request: Id,
    phase: &str,
    confirm_live: bool,
) -> DomainResult<(CloudLimit, Timestamp)> {
    let run = call(
        state,
        principal,
        resolved,
        Step { request, phase, action: "GetWorker", parameters: identity(resolved), confirm_live },
    )
    .await?;
    let at = serde_json::from_value::<Timestamp>(run["finished_at"].clone())?;
    let body = response(run, resolved).ok_or_else(|| DomainError::DependencyUnavailable {
        dependency: "GetWorker".into(),
        cause: "云端读取失败，请检查该次云操作回执；未确认配额限制".into(),
    })?;
    Ok((super::context::limit(&body, resolved)?, at))
}

pub(super) struct Write<'a> {
    pub previous: &'a CloudLimit,
    pub wanted: i64,
    pub guard: super::write_guard::WriteGuard<'a>,
}
pub(super) async fn write(
    state: &AppState,
    principal: &Principal,
    resolved: &Resolved,
    write: Write<'_>,
) -> DomainResult<Value> {
    let request = write.guard.input.request_id;
    let mut parameters = identity(resolved);
    parameters["LimitConfig"] = writable(write.previous, write.wanted);
    parameters["ClientToken"] = json!(deterministic_id(
        "agf.worker-quota.write",
        &format!("{}:{}:{request}", principal.tenant, resolved.asset)
    ));
    let request_id = deterministic_id("agf.worker-quota.phase", &format!("{}:{request}:write", resolved.asset));
    Box::pin(crate::cloud_runtime::execute_guarded_authorized(
        state,
        principal,
        crate::cloud_inventory::NAME,
        Request {
            request_id,
            configuration_version: resolved.cloud.cloud.version,
            action: "UpdateWorker".into(),
            parameters,
            confirm_live: write.guard.input.confirm_live,
        },
        &write.guard,
    ))
    .await
}
