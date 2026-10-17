//! AgentTeams 2026-06-05 的资源接口；不把人类 TeamMembers 当成 Worker。
use super::relations::{self, ResourceKind};
use super::*;
use crate::openapi::contract;
use serde_json::{Value, json};
use std::collections::BTreeSet;

impl AgentTeamsAdapter {
    pub(super) async fn call(&self, action: &str, mut input: Value) -> DomainResult<Value> {
        if self.instance_id.trim().is_empty() {
            return Err(DomainError::Config("AgentTeams 需要 settings.instance_id".into()));
        }
        input["InstanceId"] = json!(self.instance_id);
        let response = contract(AliCloudService::AgentTeams, action)?.call(self.live_client()?, &input).await?;
        Ok(response.body)
    }

    async fn pages(&self, action: &str, mut input: Value) -> DomainResult<Vec<Value>> {
        input["MaxResults"] = json!(100);
        let mut result = Vec::new();
        let mut tokens = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut total = None;
        for _ in 0..20 {
            let body = self.call(action, input.clone()).await?;
            let items = body["Items"].as_array().ok_or_else(|| invalid("列表缺少 Items"))?;
            if let Some(value) = body.get("TotalCount").filter(|value| !value.is_null()) {
                let count = value.as_u64().ok_or_else(|| invalid("TotalCount 无效"))?;
                if total.is_some_and(|previous| previous != count) {
                    return Err(invalid("分页 TotalCount 不一致"));
                }
                total = Some(count);
            }
            for item in items {
                if !names.insert(required(item, "Name")?.to_owned()) {
                    return Err(invalid("资源列表返回重复 Name"));
                }
                result.push(item.clone());
            }
            if result.len() > 200 {
                return Err(DomainError::Validation("单次盘点最多 200 个资源，请按实例拆分".into()));
            }
            if total.is_some_and(|count| count < result.len() as u64) {
                return Err(invalid("资源数超过 TotalCount"));
            }
            let next = match body.get("NextToken").filter(|value| !value.is_null()) {
                None => "",
                Some(value) => value.as_str().ok_or_else(|| invalid("NextToken 无效"))?,
            };
            if next.is_empty() {
                if total.is_some_and(|count| count != result.len() as u64) {
                    return Err(invalid("资源列表提前结束"));
                }
                return Ok(result);
            }
            if !tokens.insert(next.to_owned()) {
                return Err(invalid("资源列表返回重复 NextToken"));
            }
            input["NextToken"] = json!(next);
        }
        Err(DomainError::Validation("AgentTeams 单次盘点超过 20 页，结果未发布".into()))
    }

    pub(super) async fn live_teams(&self) -> DomainResult<Vec<AgentTeam>> {
        let listed_teams = self.pages("ListTeams", json!({})).await?;
        let listed_workers = self.pages("ListWorkers", json!({})).await?;
        let mut teams = Vec::new();
        for team in &listed_teams {
            teams.push(self.detail(team, "GetTeam", ResourceKind::Team).await?);
        }
        let mut workers = BTreeMap::new();
        for worker in &listed_workers {
            let name = required(worker, "Name")?;
            workers.insert(name.to_owned(), self.detail(worker, "GetWorker", ResourceKind::Worker).await?);
        }
        let worker_details = workers.values().cloned().collect::<Vec<_>>();
        let relationships = relations::parse_inventory(&self.instance_id, &teams, &worker_details)?;
        relations::verify_list_references(&listed_teams, &listed_workers, &relationships)?;
        relationships.require_complete()?;
        let mut result = Vec::new();
        for item in teams {
            let name = required(&item, "Name")?;
            let mut agents = Vec::new();
            let mut roles = BTreeMap::new();
            let team = relationships.teams.get(name).ok_or_else(|| invalid("团队详情缺失"))?;
            let worker_names = team.workers.as_ref().ok_or_else(|| invalid("团队关系未验证"))?;
            for (worker_name, role) in worker_names {
                let worker = workers.get(worker_name).ok_or_else(|| invalid("成员缺少完整 Worker 详情"))?;
                let role_names = role.clone().into_iter().collect();
                if let Some(role) = role {
                    roles.entry(role.to_owned()).or_insert(AgentTeamRole {
                        name: role.to_owned(),
                        description: "云团队角色；平台权限须显式映射".into(),
                        allowed_tools: vec![],
                        mapped_platform_role: None,
                    });
                }
                agents.push(AgentTeamMember {
                    cloud_agent_id: worker_name.into(),
                    name: worker_name.into(),
                    models: worker["Model"]["ModelName"].as_str().map(str::to_owned).into_iter().collect(),
                    tools: worker["McpServers"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|mcp| mcp["Name"].as_str().map(|v| format!("mcp:{v}")))
                        .collect(),
                    role_names,
                    asset_id: None,
                    status: worker["Status"].as_str().unwrap_or("unknown").into(),
                });
            }
            let scope = format!(
                "{}:{}:{}:{}:{name}",
                self.core.tenant_id, self.core.account_id, self.core.region, self.instance_id
            );
            result.push(AgentTeam {
                id: deterministic_id(NS_TEAM, &scope),
                tenant_id: self.core.tenant_id,
                cloud_team_id: name.into(),
                name: name.into(),
                description: item["Description"].as_str().unwrap_or_default().into(),
                agents,
                roles: roles.into_values().collect(),
                orchestration: vec![],
                onboarding: OnboardingMode::ObserveOnly,
                synced: false,
                cloud_updated_at: item["UpdatedAt"].as_str().and_then(|s| Timestamp::parse_rfc3339(s).ok()),
                created_at: Timestamp::now(),
                updated_at: Timestamp::now(),
            });
        }
        Ok(result)
    }

    async fn detail(&self, listed: &Value, action: &str, kind: ResourceKind) -> DomainResult<Value> {
        let name = required(listed, "Name")?;
        let body = self.call(action, json!({"Name":name})).await?;
        let data = &body["Data"];
        relations::verify_detail(listed, data, &self.instance_id, kind)?;
        Ok(data.clone())
    }
}

fn invalid(note: &str) -> DomainError {
    DomainError::Parse(format!("AgentTeams {note}"))
}
fn required<'a>(value: &'a Value, key: &str) -> DomainResult<&'a str> {
    super::relations_fields::text(&value[key], key)
}
pub(super) fn checked_data<'a>(body: &'a Value, name: &str, instance: &str) -> DomainResult<&'a Value> {
    let data = &body["Data"];
    if !data.is_object() || data["Name"] != name || data["InstanceId"] != instance {
        return Err(invalid("响应资源身份与请求不一致"));
    }
    Ok(data)
}
