//! One persistent local instance; SQL and offline memory use the same atomic record.
use crate::{
    cloud_store,
    integration_store::{Stored, decrypt},
    state::AppState,
};
use agf_alicloud::openapi::fixture;
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) const KIND: &str = "agentteams-team-mock";

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Instance {
    pub initialized: bool,
    pub teams: BTreeMap<String, Value>,
    pub users: BTreeMap<String, Value>,
    pub workers: BTreeMap<String, Value>,
    pub tasks: BTreeMap<String, Vec<Value>>,
    pub deletions: BTreeMap<String, Deletion>,
    pub tokens: BTreeMap<String, Token>,
}
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Deletion {
    pub observations: u8,
    pub absent: bool,
}
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Token {
    pub hash: String,
    pub response: Value,
}

pub(super) fn scope(state: &AppState, tenant: TenantId, config: &Stored) -> DomainResult<(Id, String)> {
    if !state.config.mock_mode && !config.mock {
        return Err(DomainError::PreconditionFailed("本地模拟器不能读取真实云实例".into()));
    }
    let private = decrypt(state, tenant, config)?;
    let instance = cloud_store::setting(&private, "instance_id", "").to_owned();
    let region = cloud_store::setting(&private, "region_id", "cn-hangzhou");
    let encoded = serde_json::to_string(&(tenant, config.id, config.version, region, &instance, true))?;
    Ok((deterministic_id("agf.team-management.mock-instance", &encoded), instance))
}

pub(super) fn initialize(value: &mut Instance, instance: &str) -> DomainResult<()> {
    if value.initialized {
        return Ok(());
    }
    let team = fixture(AliCloudService::AgentTeams, "GetTeam")?["Data"].clone();
    let worker = fixture(AliCloudService::AgentTeams, "GetWorker")?["Data"].clone();
    let directory = fixture(AliCloudService::AgentTeams, "ListUsers")?;
    let tasks = fixture(AliCloudService::AgentTeams, "ListTeamTasks")?;
    insert(&mut value.teams, team, instance)?;
    insert(&mut value.workers, worker, instance)?;
    for user in directory["Items"].as_array().ok_or_else(|| DomainError::Config("模拟人员种子无效".into()))? {
        insert(&mut value.users, user.clone(), instance)?;
    }
    let team_name = value.teams.keys().next().cloned().ok_or_else(|| DomainError::Config("模拟团队种子无效".into()))?;
    value.tasks.insert(
        team_name,
        tasks["Items"].as_array().ok_or_else(|| DomainError::Config("模拟任务种子无效".into()))?.clone(),
    );
    value.initialized = true;
    Ok(())
}

fn insert(target: &mut BTreeMap<String, Value>, mut value: Value, instance: &str) -> DomainResult<()> {
    let name = value["Name"]
        .as_str()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| DomainError::Config("模拟种子缺少身份".into()))?
        .to_owned();
    if !value.is_object() {
        return Err(DomainError::Config("模拟种子不是对象".into()));
    }
    value["InstanceId"] = Value::String(instance.into());
    if target.insert(name, value).is_some() {
        return Err(DomainError::Config("模拟种子身份重复".into()));
    }
    Ok(())
}

pub(super) fn advance_deletion(value: &mut Instance, team: &str) {
    let Some(deletion) = value.deletions.get_mut(team) else { return };
    if deletion.absent {
        return;
    }
    if deletion.observations == 0 {
        deletion.observations = 1;
        return;
    }
    deletion.absent = true;
    value.teams.remove(team);
    value.tasks.remove(team);
    // Only declared local relation cleanup is simulated; Workers themselves remain.
    for worker in value.workers.values_mut() {
        if let Some(groups) = worker["Groups"].as_array_mut() {
            groups.retain(|group| group["Type"] != "team" || group["Name"] != team);
        }
    }
}

pub(super) fn bound(value: &Instance) -> DomainResult<()> {
    if serde_json::to_vec(value)?.len() > 2 * 1024 * 1024 {
        return Err(DomainError::Validation("模拟实例记录超过2MiB，请使用独立测试实例".into()));
    }
    Ok(())
}
