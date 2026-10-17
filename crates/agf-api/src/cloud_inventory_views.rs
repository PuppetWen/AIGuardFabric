//! 云快照只投影展示所需字段，不向只读用户返回原始 Worker 配置或凭据。
use crate::{
    cloud_inventory::{self, Snapshot},
    cloud_store,
    state::AppState,
};
use agf_alicloud::agentteams::relations;
use agf_core::{
    error::DomainResult,
    ids::{TenantId, deterministic_id},
};
use serde_json::{Value, json};

pub async fn mocked(state: &AppState, tenant: TenantId) -> DomainResult<bool> {
    Ok(state.config.mock_mode
        || cloud_store::load(state, tenant, cloud_inventory::NAME).await?.is_some_and(|row| row.mock))
}
pub fn teams(tenant: TenantId, snapshot: &Snapshot) -> Vec<Value> {
    let relationships = relations::parse_inventory(&snapshot.instance_id, &snapshot.teams, &snapshot.workers).ok();
    snapshot
        .teams
        .iter()
        .map(|team| {
            let name = team["Name"].as_str().unwrap_or_default();
            let relationship = relationships.as_ref().and_then(|relations| relations.teams.get(name));
            let workers = relationship.and_then(|relationship| relationship.workers.as_ref());
            let members = workers
                .into_iter()
                .flat_map(|workers| workers.iter())
                .map(|(name, role)| member(snapshot, name, role.as_deref()))
                .collect::<Vec<_>>();
            let humans = relationship.and_then(|relationship| relationship.humans.as_ref());
            let people = humans
                .into_iter()
                .flat_map(|people| people.iter())
                .map(|name| json!({"name": name}))
                .collect::<Vec<_>>();
            let identity = format!("{tenant}:{}:{}:{name}", snapshot.region, snapshot.instance_id);
            let evidence = relationship.map_or("unverified", |relationship| relationship.evidence.as_str());
            let tasks = snapshot.tasks.get(name).into_iter().flatten().map(task).collect::<Vec<_>>();
            json!({
                "id": deterministic_id("agf.cloud.team", &identity),
                "workspaceId": snapshot.instance_id,
                "name": name,
                "region": snapshot.region,
                "memberCount": workers.map(std::collections::BTreeMap::len),
                "members": members,
                "relationshipAvailable": workers.is_some(),
                "relationshipEvidence": evidence,
                "humanMembers": people,
                "humanMembersAvailable": humans.is_some(),
                "humanMemberCount": humans.map(std::collections::BTreeSet::len),
                "adminName": team["AdminName"].as_str(),
                "leaderName": team["LeaderName"].as_str(),
                "dag": [],
                "dagAvailable": false,
                "dagEvidence": "not-provided",
                "riskScore": 0,
                "riskAvailable": false,
                "crossTeamCalls24h": 0,
                "metricsAvailable": false,
                "mocked": snapshot.mocked,
                "createdAt": team["CreatedAt"].as_str(),
                "syncedAt": snapshot.checked_at,
                "tasks": tasks
            })
        })
        .collect()
}

fn member(snapshot: &Snapshot, name: &str, role: Option<&str>) -> Value {
    let worker = snapshot.workers.iter().find(|worker| worker["Name"].as_str() == Some(name));
    let raw_status = worker.and_then(|worker| worker["Status"].as_str()).unwrap_or("unknown");
    let status = match raw_status.to_ascii_lowercase().as_str() {
        "running" | "active" => "active",
        "stopped" | "failed" => "offline",
        _ => "idle",
    };
    json!({
        "id": name,
        "name": name,
        "role": role,
        "cloudRole": role,
        "model": worker.and_then(|worker| worker["Model"]["ModelName"].as_str()).unwrap_or(""),
        "status": status,
        "cloudStatus": raw_status,
        "assetId": snapshot.assets.get(name),
        "invocations24h": 0,
        "metricsAvailable": false
    })
}

fn task(task: &Value) -> Value {
    json!({
        "taskId": task["TaskId"].as_str(),
        "taskTitle": task["TaskTitle"].as_str(),
        "assignedTo": task["AssignedTo"].as_str(),
        "status": task["Status"].as_str(),
        "createdAt": task["CreatedAt"].as_str()
    })
}
