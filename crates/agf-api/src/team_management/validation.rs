use super::{
    contract::{Room, TeamObservation, UserOption},
    input::Change,
};
use agf_alicloud::agentteams::relations::{self, ResourceKind};
use agf_core::error::{DomainError, DomainResult};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn name(value: &str) -> DomainResult<()> {
    if value.is_empty() || value.len() > 256 || value.trim() != value || value.chars().any(char::is_control) {
        return Err(DomainError::Validation("名称须非空、不超过256字节且无首尾空格/控制字符".into()));
    }
    Ok(())
}

pub(super) fn change(change: &Change) -> DomainResult<()> {
    name(change.team())?;
    if change.description().is_some_and(|value| {
        value.len() > 8192 || value.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    }) {
        return Err(DomainError::Validation("描述最多8192字节且不能包含非文本控制字符".into()));
    }
    if let Some(names) = change.members() {
        if names.len() > 200 {
            return Err(DomainError::Validation("本次最多维护200名云人员".into()));
        }
        let mut unique = BTreeSet::new();
        for member in names {
            name(member)?;
            if !unique.insert(member) {
                return Err(DomainError::Validation("目标人员名单不能重复".into()));
            }
        }
    }
    if let Some(admin) = change.admin() {
        name(admin)?;
    }
    match change {
        Change::Update { description, members, .. } => {
            if description.is_none() && members.is_none() {
                return Err(DomainError::Validation("请明确修改描述或替换人员名单".into()));
            }
            if members.as_ref().is_some_and(|members| !members.confirmed) {
                return Err(DomainError::PreconditionFailed("请确认人员名单是整体替换".into()));
            }
        }
        Change::Delete { team_name, confirm_team_name, confirm_async_cleanup }
            if team_name != confirm_team_name || !confirm_async_cleanup =>
        {
            return Err(DomainError::PreconditionFailed("请输入准确团队名并确认异步关联资源清理".into()));
        }
        Change::Create { .. } | Change::Delete { .. } => {}
    }
    Ok(())
}

fn text(value: &Value, field: &str) -> DomainResult<Option<String>> {
    match value.get(field).filter(|value| !value.is_null()) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .filter(|value| {
                value.len() <= 8192
                    && !value
                        .chars()
                        .any(|c| c.is_control() && (field != "Description" || (c != '\n' && c != '\r' && c != '\t')))
            })
            .map(|value| Some(value.to_owned()))
            .ok_or_else(|| DomainError::Parse(format!("{field} 必须是有界字符串"))),
    }
}

fn names(value: &Value, field: &str, objects: bool) -> DomainResult<Option<Vec<String>>> {
    let Some(value) = value.get(field).filter(|value| !value.is_null()) else { return Ok(None) };
    let items = value.as_array().ok_or_else(|| DomainError::Parse(format!("{field} 必须是数组")))?;
    let mut result = BTreeSet::new();
    for item in items {
        let item = if objects { item.get("Name").unwrap_or(&Value::Null) } else { item };
        let value = item.as_str().ok_or_else(|| DomainError::Parse(format!("{field} 名称无效")))?;
        name(value)?;
        if !result.insert(value.to_owned()) {
            return Err(DomainError::Parse(format!("{field} 返回重复名称")));
        }
    }
    Ok(Some(result.into_iter().collect()))
}

pub(super) fn team(data: &Value, expected: &str, instance: &str) -> DomainResult<TeamObservation> {
    relations::verify_detail(&json!({"Name":expected,"InstanceId":instance}), data, instance, ResourceKind::Team)?;
    let rooms = match data.get("Rooms").filter(|value| !value.is_null()) {
        None => None,
        Some(value) => {
            let items = value.as_array().ok_or_else(|| DomainError::Parse("Rooms必须是数组".into()))?;
            let mut rooms = BTreeMap::new();
            for room in items {
                let room_type = room["Type"].as_str().ok_or_else(|| DomainError::Parse("Room.Type无效".into()))?;
                let room_id = room["RoomId"].as_str().ok_or_else(|| DomainError::Parse("Room.RoomId无效".into()))?;
                name(room_type)?;
                name(room_id)?;
                if rooms
                    .insert(
                        (room_type.to_owned(), room_id.to_owned()),
                        Room { room_type: room_type.into(), room_id: room_id.into() },
                    )
                    .is_some()
                {
                    return Err(DomainError::Parse("Rooms返回重复身份".into()));
                }
            }
            Some(rooms.into_values().collect())
        }
    };
    Ok(TeamObservation {
        presence: [
            "Description",
            "TeamMembers",
            "AdminName",
            "LeaderName",
            "WorkerNames",
            "Rooms",
            "Status",
            "CreatedAt",
        ]
        .into_iter()
        .map(|key| {
            (
                key.into(),
                match data.get(key) {
                    None => "missing",
                    Some(Value::Null) => "null",
                    Some(_) => "value",
                }
                .into(),
            )
        })
        .collect(),
        name: expected.into(),
        instance_id: instance.into(),
        description: text(data, "Description")?,
        member_names: names(data, "TeamMembers", true)?,
        admin_name: text(data, "AdminName")?,
        leader_name: text(data, "LeaderName")?,
        worker_names: names(data, "WorkerNames", false)?,
        rooms,
        status: text(data, "Status")?,
        created_at: text(data, "CreatedAt")?,
    })
}

pub(super) fn user(data: &Value, instance: &str, expected: Option<&str>) -> DomainResult<UserOption> {
    let user = data["Name"].as_str().ok_or_else(|| DomainError::Parse("User.Name无效".into()))?;
    name(user)?;
    if expected.is_some_and(|expected| expected != user)
        || data.get("InstanceId").filter(|value| !value.is_null()).is_some_and(|value| value != instance)
        || (expected.is_some() && data["InstanceId"] != instance)
    {
        return Err(DomainError::Parse("用户响应身份与当前实例请求不一致".into()));
    }
    Ok(UserOption {
        name: user.into(),
        display_name: text(data, "DisplayName")?,
        status: text(data, "Status")?,
        existence_verified: expected.is_some(),
        admin_eligibility: None,
    })
}

pub(super) fn hash<T: serde::Serialize>(value: &T) -> DomainResult<String> {
    use sha2::{Digest, Sha256};
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

pub(super) fn matches(change: &Change, observation: Option<&TeamObservation>) -> bool {
    if matches!(change, Change::Delete { .. }) {
        return observation.is_none();
    }
    let Some(observed) = observation else { return false };
    if change.description().is_some_and(|expected| observed.description.as_deref() != Some(expected))
        || change.admin().is_some_and(|expected| observed.admin_name.as_deref() != Some(expected))
    {
        return false;
    }
    if let Some(expected) = change.members() {
        let mut names = expected.to_vec();
        names.sort();
        if observed.member_names.as_ref() != Some(&names) {
            return false;
        }
    }
    true
}
