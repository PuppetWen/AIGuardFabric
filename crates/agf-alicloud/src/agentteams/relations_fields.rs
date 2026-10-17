//! Strict field parsing shared by inventory comparison and relationship projection.
use agf_core::error::{DomainError, DomainResult};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) type Groups = BTreeMap<(String, String), Option<String>>;

pub(super) fn invalid(note: &str) -> DomainError {
    DomainError::Parse(format!("AgentTeams {note}"))
}

pub(super) fn text<'a>(value: &'a Value, field: &str) -> DomainResult<&'a str> {
    value.as_str().filter(|text| valid_text(text)).ok_or_else(|| invalid(&format!("{field} 必须为非空有效字符串")))
}

fn valid_text(text: &str) -> bool {
    !text.is_empty() && text.len() <= 256 && text.trim() == text && !text.chars().any(char::is_control)
}

pub(super) fn optional_text(value: &Value, field: &str) -> DomainResult<Option<String>> {
    match value.get(field).filter(|value| !value.is_null()) {
        None => Ok(None),
        Some(value) => text(value, field).map(|value| Some(value.to_owned())),
    }
}

pub(super) fn array<'a>(value: &'a Value, field: &str) -> DomainResult<Option<&'a Vec<Value>>> {
    match value.get(field).filter(|value| !value.is_null()) {
        None => Ok(None),
        Some(value) => value.as_array().map(Some).ok_or_else(|| invalid(&format!("{field} 必须为数组"))),
    }
}

pub(super) fn names(value: &Value, field: &str, objects: bool) -> DomainResult<Option<BTreeSet<String>>> {
    let Some(items) = array(value, field)? else { return Ok(None) };
    let mut names = BTreeSet::new();
    for item in items {
        if objects && !item.is_object() {
            return Err(invalid(&format!("{field} 成员必须为对象")));
        }
        let name = text(if objects { &item["Name"] } else { item }, field)?;
        names.insert(name.to_owned());
    }
    Ok(Some(names))
}

pub(super) fn groups(value: &Value) -> DomainResult<Option<Groups>> {
    let Some(items) = array(value, "Groups")? else { return Ok(None) };
    let mut result: Groups = BTreeMap::new();
    for group in items {
        if !group.is_object() {
            return Err(invalid("Groups 成员必须为对象"));
        }
        let key = (text(&group["Type"], "Groups.Type")?.to_owned(), text(&group["Name"], "Groups.Name")?.to_owned());
        let role = optional_text(group, "Role")?;
        if let Some(previous) = result.get(&key) {
            if previous.as_ref().zip(role.as_ref()).is_some_and(|(a, b)| a != b) {
                return Err(invalid("同一 Worker/Group 返回矛盾的 Role"));
            }
            if previous.is_some() {
                continue;
            }
        }
        result.insert(key, role);
    }
    Ok(Some(result))
}

pub(super) fn identity<'a>(value: &'a Value, instance: &str, listed: bool) -> DomainResult<&'a str> {
    if !value.is_object() {
        return Err(invalid("资源必须为对象"));
    }
    let name = text(&value["Name"], "Name")?;
    let id = value.get("InstanceId").filter(|value| !value.is_null());
    if listed && id.is_none_or(|value| value.as_str() == Some("")) {
        return Ok(name);
    }
    if id.map(|value| text(value, "InstanceId")).transpose()? != Some(instance) {
        return Err(invalid("响应 InstanceId 与请求不一致"));
    }
    Ok(name)
}
