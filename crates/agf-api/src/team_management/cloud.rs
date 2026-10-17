use super::{
    contract::{Scope, TeamObservation, UserOption},
    validation,
};
use crate::{
    Principal,
    cloud_inventory::NAME,
    cloud_runtime::{self, Request, WritePrecondition},
    state::AppState,
};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(super) fn request(
    scope: &Scope,
    parent: Id,
    phase: &str,
    action: &str,
    parameters: Value,
    live: bool,
) -> DomainResult<Request> {
    Ok(Request {
        request_id: deterministic_id(
            "agf.team-management.cloud",
            &serde_json::to_string(&(parent, phase, action, &parameters))?,
        ),
        configuration_version: scope.configuration_version,
        action: action.into(),
        parameters,
        confirm_live: live,
    })
}
pub(super) async fn call(
    state: &AppState,
    principal: &Principal,
    scope: &Scope,
    parent: Id,
    phase: &str,
    action: &str,
    parameters: Value,
    live: bool,
) -> DomainResult<Value> {
    let result = Box::pin(cloud_runtime::execute_read_authorized(
        state,
        principal,
        NAME,
        request(scope, parent, phase, action, parameters, live)?,
    ))
    .await?;
    response(result)
}
pub(super) fn response(result: Value) -> DomainResult<Value> {
    if result["status"] != "succeeded" {
        return Err(DomainError::DependencyUnavailable {
            dependency: "AgentTeams".into(),
            cause: format!("云读取未成功，请查看回执 {}", result["id"]),
        });
    }
    Ok(result["receipt"]["response"].clone())
}
pub(super) async fn resource(
    state: &AppState,
    principal: &Principal,
    scope: &Scope,
    parent: Id,
    phase: &str,
    action: &str,
    name: &str,
    live: bool,
) -> DomainResult<Option<Value>> {
    let result = Box::pin(cloud_runtime::execute_resource_observation(
        state,
        principal,
        NAME,
        request(scope, parent, phase, action, json!({"Name":name}), live)?,
    ))
    .await?;
    if result["status"] != "succeeded" {
        return Err(DomainError::DependencyUnavailable {
            dependency: action.into(),
            cause: "资源观察失败；不能把失败当成资源不存在".into(),
        });
    }
    match result["receipt"]["resourceState"].as_str() {
        Some("absent") => Ok(None),
        Some("present") => Ok(Some(result["receipt"]["response"]["Data"].clone())),
        _ => Err(DomainError::Parse("资源观察回执无明确存在性证据".into())),
    }
}
pub(super) async fn team(
    state: &AppState,
    principal: &Principal,
    scope: &Scope,
    parent: Id,
    phase: &str,
    name: &str,
    live: bool,
) -> DomainResult<Option<TeamObservation>> {
    resource(state, principal, scope, parent, phase, "GetTeam", name, live)
        .await?
        .map(|value| validation::team(&value, name, &scope.instance_id))
        .transpose()
}
pub(super) async fn users(
    state: &AppState,
    principal: &Principal,
    scope: &Scope,
    parent: Id,
    phase: &str,
    names: &[String],
    live: bool,
) -> DomainResult<Vec<UserOption>> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for name in names {
        if !seen.insert(name) {
            continue;
        }
        let value = resource(state, principal, scope, parent, phase, "GetUser", name, live)
            .await?
            .ok_or_else(|| DomainError::PreconditionFailed(format!("选中的云用户 {name} 已不存在；请重新选择")))?;
        out.push(validation::user(&value, &scope.instance_id, Some(name))?);
    }
    Ok(out)
}
pub(super) async fn pages(
    state: &AppState,
    principal: &Principal,
    scope: &Scope,
    parent: Id,
    phase: &str,
    action: &str,
    mut parameters: Value,
    live: bool,
) -> DomainResult<Vec<Value>> {
    parameters["MaxResults"] = json!(100);
    let mut out = Vec::new();
    let mut tokens = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut total = None;
    for _ in 0..20 {
        let body = call(state, principal, scope, parent, phase, action, parameters.clone(), live).await?;
        let items = body["Items"].as_array().ok_or_else(|| DomainError::Parse("列表缺少 Items 数组".into()))?;
        if items.len() > 100 {
            return Err(DomainError::Parse("单页资源超过请求的100条".into()));
        }
        if let Some(value) = body.get("TotalCount").filter(|v| !v.is_null()) {
            let count = value.as_u64().ok_or_else(|| DomainError::Parse("TotalCount 无效".into()))?;
            if total.is_some_and(|old| old != count) {
                return Err(DomainError::Parse("分页总数改变".into()));
            }
            total = Some(count);
        }
        for item in items {
            let key = if action == "ListTeamTasks" { &item["TaskId"] } else { &item["Name"] };
            let key = key.as_str().ok_or_else(|| DomainError::Parse("列表资源缺少身份".into()))?;
            validation::name(key)?;
            if !ids.insert(key.to_owned()) {
                return Err(DomainError::Parse("列表返回重复身份".into()));
            }
            out.push(item.clone());
        }
        let next = match body.get("NextToken").filter(|v| !v.is_null()) {
            None => "",
            Some(v) => v.as_str().ok_or_else(|| DomainError::Parse("分页令牌无效".into()))?,
        };
        if total.is_some_and(|count| count < out.len() as u64) {
            return Err(DomainError::Parse("返回数量超过分页总数".into()));
        }
        if next.is_empty() {
            if total.is_some_and(|count| count != out.len() as u64) {
                return Err(DomainError::Parse("列表提前结束".into()));
            }
            return Ok(out);
        }
        if next.len() > 4096 || !tokens.insert(next.to_owned()) {
            return Err(DomainError::Parse("分页令牌过大或重复".into()));
        }
        parameters["NextToken"] = json!(next);
    }
    Err(DomainError::PreconditionFailed("列表超过20页，未接受不完整基线".into()))
}
pub(super) async fn write(
    state: &AppState,
    principal: &Principal,
    scope: &Scope,
    run: Id,
    action: &str,
    parameters: Value,
    live: bool,
    guard: &dyn WritePrecondition,
) -> DomainResult<Value> {
    Box::pin(cloud_runtime::execute_guarded_authorized(
        state,
        principal,
        NAME,
        request(scope, run, "write", action, parameters, live)?,
        guard,
    ))
    .await
}
