//! Stored safe observations are bounded and revalidated; decryption alone does not confer trust.
use super::{scope::SourceTarget, util};
use agf_core::error::DomainResult;
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub(super) struct SafeSnapshot {
    value: Value,
}
impl SafeSnapshot {
    pub(super) fn parse(target: &SourceTarget, value: Value) -> DomainResult<Self> {
        util::bound(&value, super::MAX_BODY_BYTES)?;
        keys(&value, &["scope", "app", "jobs", "pagination", "fingerprint"])?;
        keys(&value["scope"], &["clusterId", "appName"])?;
        if value["scope"]["clusterId"] != target.cluster_id || value["scope"]["appName"] != target.app_name {
            return Err(util::corrupt());
        }
        let app = &value["app"];
        keys(app, &["id", "name", "title", "kind"])?;
        required_id(&app["id"])?;
        if app["name"] != target.app_name {
            return Err(util::corrupt());
        }
        optional_text(&app["title"], 512)?;
        optional_i32(&app["kind"], false)?;
        let jobs = value["jobs"].as_array().ok_or_else(util::corrupt)?;
        if jobs.len() > 2000 {
            return Err(util::corrupt());
        }
        let mut identifiers = BTreeSet::new();
        let mut previous = None;
        for row in jobs {
            job(row, app["id"].as_str().ok_or_else(util::corrupt)?, &target.app_name)?;
            let id = row["id"].as_str().ok_or_else(util::corrupt)?;
            if !identifiers.insert(id) || previous.is_some_and(|prior| prior >= id) {
                return Err(util::corrupt());
            }
            previous = Some(id);
        }
        let paging = &value["pagination"];
        keys(paging, &["total", "listingComplete", "strongSnapshot", "pages"])?;
        let total = paging["total"].as_u64().ok_or_else(util::corrupt)?;
        if total != jobs.len() as u64 || paging["listingComplete"] != true || paging["strongSnapshot"] != false {
            return Err(util::corrupt());
        }
        let pages = paging["pages"].as_array().ok_or_else(util::corrupt)?;
        let count = jobs.len().div_ceil(100).max(1);
        if pages.len() != count || pages.len() > 20 {
            return Err(util::corrupt());
        }
        let mut observed = 0;
        for (offset, page) in pages.iter().enumerate() {
            keys(page, &["number", "size", "records", "requestId"])?;
            let records = (jobs.len() - observed).min(100);
            if page["number"].as_u64() != Some((offset + 1) as u64)
                || page["size"] != 100
                || page["records"].as_u64() != Some(records as u64)
            {
                return Err(util::corrupt());
            }
            let receipt = page["requestId"].as_str().filter(|text| util::text(text, 256)).ok_or_else(util::corrupt)?;
            if receipt.is_empty() {
                return Err(util::corrupt());
            }
            observed += records;
        }
        let hash = util::canonical_hash(&json!({"scope":value["scope"],"app":app,"jobs":jobs,"total":total}))?;
        if value["fingerprint"] != hash {
            return Err(util::corrupt());
        }
        Ok(Self { value })
    }
    pub(super) fn value(&self) -> &Value {
        &self.value
    }
    pub(super) fn app_id(&self) -> &str {
        self.value["app"]["id"].as_str().unwrap_or_default()
    }
    pub(super) fn fingerprint(&self) -> &str {
        self.value["fingerprint"].as_str().unwrap_or_default()
    }
    pub(super) fn jobs(&self) -> &[Value] {
        self.value["jobs"].as_array().map(Vec::as_slice).unwrap_or_default()
    }
    pub(super) fn total(&self) -> u32 {
        self.jobs().len() as u32
    }
}
fn keys(value: &Value, expected: &[&str]) -> DomainResult<()> {
    let object = value.as_object().ok_or_else(util::corrupt)?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(util::corrupt());
    }
    Ok(())
}
fn required_id(value: &Value) -> DomainResult<()> {
    if value.as_str().is_none_or(|id| !util::positive_id(id)) {
        return Err(util::corrupt());
    }
    Ok(())
}
fn optional_text(value: &Value, max: usize) -> DomainResult<()> {
    if !value.is_null() && value.as_str().is_none_or(|text| text.len() > max || text.chars().any(char::is_control)) {
        return Err(util::corrupt());
    }
    Ok(())
}
fn optional_i32(value: &Value, nonnegative: bool) -> DomainResult<()> {
    if !value.is_null() && value.as_i64().is_none_or(|n| i32::try_from(n).is_err() || (nonnegative && n < 0)) {
        return Err(util::corrupt());
    }
    Ok(())
}
fn job(value: &Value, app: &str, name: &str) -> DomainResult<()> {
    keys(
        value,
        &[
            "id",
            "appName",
            "appId",
            "name",
            "kind",
            "httpJob",
            "status",
            "enabled",
            "schedule",
            "maxAttempt",
            "attemptInterval",
            "routeStrategy",
            "shardCount",
            "updateTimeNative",
            "http",
        ],
    )?;
    required_id(&value["id"])?;
    if value["appName"] != name || (!value["appId"].is_null() && value["appId"] != app) {
        return Err(util::corrupt());
    }
    let label = value["name"].as_str().ok_or_else(util::corrupt)?;
    if label.trim().is_empty() || label.len() > 512 || label.chars().any(char::is_control) {
        return Err(util::corrupt());
    }
    optional_text(&value["kind"], 64)?;
    if value["httpJob"].as_bool() != Some(value["kind"].as_str() == Some("http")) {
        return Err(util::corrupt());
    }
    let expected_enabled = match value["status"].as_i64() {
        Some(0) => Value::Bool(false),
        Some(1) => Value::Bool(true),
        None if value["status"].is_null() => Value::Null,
        _ => return Err(util::corrupt()),
    };
    if value["enabled"] != expected_enabled || !value["shardCount"].is_null() {
        return Err(util::corrupt());
    }
    for key in ["maxAttempt", "attemptInterval", "routeStrategy"] {
        optional_i32(&value[key], true)?;
    }
    let update = &value["updateTimeNative"];
    if !update.is_null()
        && update.as_str().is_none_or(|text| {
            text.parse::<i64>().is_err() || text.parse::<i64>().is_ok_and(|n| n < 0 || n.to_string() != text)
        })
    {
        return Err(util::corrupt());
    }
    let schedule = &value["schedule"];
    keys(schedule, &["kind", "expression", "calendar", "zone", "utc"])?;
    optional_i32(&schedule["kind"], false)?;
    for key in ["expression", "calendar"] {
        optional_text(&schedule[key], 256)?;
    }
    optional_text(&schedule["zone"], 64)?;
    let utc = schedule["zone"].as_str().map_or(Value::Null, |zone| Value::Bool(zone == "UTC"));
    if schedule["utc"] != utc {
        return Err(util::corrupt());
    }
    let http = &value["http"];
    keys(http, &["verified", "parameters", "handler", "attributes", "script", "fingerprint"])?;
    if http["verified"] != false || http["fingerprint"].as_str().is_none_or(|hash| !util::digest(hash)) {
        return Err(util::corrupt());
    }
    for key in ["parameters", "handler", "attributes", "script"] {
        if http[key].as_str().is_none_or(|text| !["missing", "null", "empty", "present"].contains(&text)) {
            return Err(util::corrupt());
        }
    }
    Ok(())
}
