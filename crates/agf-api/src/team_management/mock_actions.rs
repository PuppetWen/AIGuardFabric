use super::mock_store::{Deletion, Instance, Token};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};
use serde_json::{Value, json};

pub(super) fn envelope(fields: Value) -> Value {
    let mut result = json!({"RequestId":Id::new().to_string(),"HttpStatusCode":200,"Code":"SUCCESS","Success":true});
    if let (Some(target), Some(fields)) = (result.as_object_mut(), fields.as_object()) {
        target.extend(fields.clone());
    }
    result
}
pub(super) fn absent() -> Value {
    json!({"__agfMockFault":true,"Code":"Resource.NotFound","RequestId":Id::new().to_string(),
        "Success":false,"HttpStatusCode":404})
}

pub(super) fn write(value: &mut Instance, action: &str, input: &Value, instance: &str) -> DomainResult<Value> {
    let team_name = input["Name"].as_str().ok_or_else(|| DomainError::Validation("缺少团队名".into()))?;
    super::validation::name(team_name)?;
    let token = input.get("ClientToken").and_then(Value::as_str);
    let hash = super::validation::hash(&(action, input))?;
    if let Some(prior) = token.and_then(|token| value.tokens.get(token)) {
        return if prior.hash == hash { Ok(prior.response.clone()) } else { Err(super::stale()) };
    }
    if value.deletions.get(team_name).is_some_and(|deletion| !deletion.absent) {
        return Err(DomainError::PreconditionFailed("模拟团队正在异步清理，只允许观察".into()));
    }
    if let Some(members) = input.get("TeamMembers") {
        let members = members.as_array().ok_or_else(|| DomainError::Validation("TeamMembers须为数组".into()))?;
        for member in members {
            let name = member["Name"].as_str().ok_or_else(|| DomainError::Validation("人员身份无效".into()))?;
            if !value.users.contains_key(name) {
                return Err(DomainError::PreconditionFailed("模拟目标人员不存在于此实例".into()));
            }
        }
    }
    if input.get("AdminName").is_some_and(|name| name.as_str().is_none_or(|name| !value.users.contains_key(name))) {
        return Err(DomainError::PreconditionFailed("模拟管理员身份不存在；本地存在性不证明真实云管理员资格".into()));
    }
    let result = match action {
        "CreateTeam" => {
            if value.teams.contains_key(team_name) {
                return Err(super::stale());
            }
            if value.teams.len() >= 200 {
                return Err(DomainError::Validation("模拟团队最多200个".into()));
            }
            let mut team = json!({"Name":team_name,"InstanceId":instance,"WorkerNames":[],"Rooms":[],
                "TeamMembers":[],"Status":"Running","CreatedAt":Timestamp::now()});
            for field in ["Description", "TeamMembers", "AdminName"] {
                if let Some(field_value) = input.get(field) {
                    team[field] = field_value.clone();
                }
            }
            value.teams.insert(team_name.into(), team.clone());
            value.tasks.insert(team_name.into(), Vec::new());
            value.deletions.remove(team_name);
            envelope(json!({"Data":team}))
        }
        "UpdateTeam" => {
            let Some(team) = value.teams.get_mut(team_name) else { return Ok(absent()) };
            for field in ["Description", "TeamMembers"] {
                if let Some(field_value) = input.get(field) {
                    team[field] = field_value.clone();
                }
            }
            team["UpdatedAt"] = json!(Timestamp::now());
            envelope(json!({"Data":team}))
        }
        "DeleteTeam" => {
            let Some(team) = value.teams.get_mut(team_name) else { return Ok(absent()) };
            team["Status"] = json!("Deleting");
            value.deletions.insert(team_name.into(), Deletion { observations: 0, absent: false });
            envelope(json!({}))
        }
        _ => return Err(DomainError::Validation("本地模拟器不支持此团队写入".into())),
    };
    if let Some(token) = token {
        if value.tokens.len() >= 2000 {
            return Err(DomainError::Validation("模拟幂等账本已满，请更换独立测试实例".into()));
        }
        value.tokens.insert(token.into(), Token { hash, response: result.clone() });
    }
    Ok(result)
}

pub(super) fn page(items: Vec<Value>, input: &Value) -> DomainResult<Value> {
    let offset = match input.get("NextToken").filter(|value| !value.is_null()) {
        None => 0,
        Some(Value::String(token)) if token.is_empty() => 0,
        Some(Value::String(token)) => {
            token.parse::<usize>().map_err(|_| DomainError::Validation("模拟分页游标无效".into()))?
        }
        _ => return Err(DomainError::Validation("模拟分页游标必须是字符串".into())),
    };
    let count = match input.get("MaxResults") {
        None => 10,
        Some(count) => count
            .as_u64()
            .filter(|count| (1..=100).contains(count))
            .ok_or_else(|| DomainError::Validation("分页大小须为1至100".into()))? as usize,
    };
    if offset > items.len() {
        return Err(DomainError::Validation("模拟分页游标超出查询范围".into()));
    }
    let next = offset.saturating_add(count).min(items.len());
    Ok(envelope(json!({"Items":items[offset..next],"TotalCount":items.len(),"MaxResults":count,
        "NextToken":if next < items.len() {Some(next.to_string())}else{None}})))
}
