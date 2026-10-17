//! Persistent Team simulation. No input can manufacture an existing user or a live network client.
use super::{
    contract::Scope,
    mock_actions as actions,
    mock_store::{self as store, Instance},
};
use crate::{cloud_store, integration_store::Stored, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
};
use serde_json::{Value, json};

pub(crate) fn supports(action: &str) -> bool {
    matches!(
        action,
        "ListUsers"
            | "GetUser"
            | "ListTeams"
            | "GetTeam"
            | "CreateTeam"
            | "UpdateTeam"
            | "DeleteTeam"
            | "ListWorkers"
            | "GetWorker"
            | "UpdateWorker"
            | "ListTeamTasks"
    )
}

pub(crate) async fn response(
    state: &AppState,
    tenant: TenantId,
    config: &Stored,
    action: &str,
    input: &Value,
    fixture: Value,
) -> DomainResult<Value> {
    if !supports(action) {
        return Ok(fixture);
    }
    let (id, instance) = store::scope(state, tenant, config)?;
    if input["InstanceId"] != instance {
        return Err(DomainError::PreconditionFailed("模拟请求必须属于当前配置实例".into()));
    }
    let mut response = Value::Null;
    state
        .configurations
        .mutate::<Instance, _>(tenant, store::KIND, id, |current| {
            store::initialize(current, &instance)?;
            response = dispatch(current, action, input, &instance, &fixture)?;
            store::bound(current)
        })
        .await?;
    Ok(response)
}

pub(super) async fn resource_direct(
    state: &AppState,
    tenant: TenantId,
    scope: &Scope,
    action: &str,
    name: &str,
) -> DomainResult<Option<Value>> {
    if !scope.mocked || !matches!(action, "GetTeam" | "GetUser") {
        return Err(DomainError::PreconditionFailed("本地存在性读取仅支持模拟GetTeam/GetUser".into()));
    }
    let config = cloud_store::load(state, tenant, crate::cloud_inventory::NAME)
        .await?
        .filter(|config| config.enabled && config.id == scope.cloud_id && config.version == scope.configuration_version)
        .ok_or_else(super::stale)?;
    let private = crate::integration_store::decrypt(state, tenant, &config)?;
    if scope.region != cloud_store::setting(&private, "region_id", "cn-hangzhou")
        || scope.instance_id != cloud_store::setting(&private, "instance_id", "")
    {
        return Err(super::stale());
    }
    let result =
        response(state, tenant, &config, action, &json!({"InstanceId":scope.instance_id,"Name":name}), Value::Null)
            .await?;
    if result["__agfMockFault"] == true && result["Code"] == "Resource.NotFound" {
        Ok(None)
    } else {
        let data = result
            .get("Data")
            .filter(|value| value.is_object())
            .ok_or_else(|| DomainError::Parse("本地资源响应无效".into()))?;
        Ok(Some(data.clone()))
    }
}

fn dispatch(
    current: &mut Instance,
    action: &str,
    input: &Value,
    instance: &str,
    fixture: &Value,
) -> DomainResult<Value> {
    let name = input["Name"].as_str().unwrap_or_default();
    match action {
        "CreateTeam" | "UpdateTeam" | "DeleteTeam" => actions::write(current, action, input, instance),
        "GetTeam" => {
            store::advance_deletion(current, name);
            Ok(current.teams.get(name).map_or_else(actions::absent, |data| actions::envelope(json!({"Data":data}))))
        }
        "GetUser" => {
            Ok(current.users.get(name).map_or_else(actions::absent, |data| actions::envelope(json!({"Data":data}))))
        }
        "ListUsers" | "ListTeams" | "ListWorkers" => {
            let values = match action {
                "ListUsers" => &current.users,
                "ListTeams" => &current.teams,
                _ => &current.workers,
            };
            let filter = input.get("NameLike").and_then(Value::as_str).unwrap_or_default();
            actions::page(
                values
                    .iter()
                    .filter(|(name, _)| name.contains(filter))
                    .map(|(_, value)| {
                        let mut item = value.clone();
                        // ListWorkers does not observe quota; GetWorker owns its current configuration.
                        if action == "ListWorkers"
                            && let Some(fields) = item.as_object_mut()
                        {
                            fields.remove("LimitConfig");
                        }
                        item
                    })
                    .collect(),
                input,
            )
        }
        "ListTeamTasks" => {
            let team = input["Team"].as_str().unwrap_or_default();
            if !current.teams.contains_key(team) {
                return Ok(actions::absent());
            }
            actions::page(current.tasks.get(team).cloned().unwrap_or_default(), input)
        }
        "GetWorker" | "UpdateWorker" => {
            let Some(worker) = current.workers.get(name) else { return Ok(actions::absent()) };
            let mut worker = worker.clone();
            // Quota owns LimitConfig; this local simulator only owns Team/Worker relations.
            if fixture["Data"]["Name"] == name {
                if let Some(limit) = fixture["Data"].get("LimitConfig") {
                    worker["LimitConfig"] = limit.clone();
                }
            }
            Ok(actions::envelope(json!({"Data":worker})))
        }
        _ => Err(DomainError::Validation("本地模拟器不支持此动作".into())),
    }
}
