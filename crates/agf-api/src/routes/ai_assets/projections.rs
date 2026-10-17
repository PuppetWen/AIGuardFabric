//! 台账 `Asset` → 各视图的投影，以及属性读取与视图检索小工具。

use super::*;
use crate::store::asset_facets;

// ===========================================================================
// 视图投影
// ===========================================================================

/// 台账 Agent → [`AgentView`]。
pub(super) fn agent_view(asset: &Asset) -> AgentView {
    let endpoints = endpoint_parts(asset);
    let now = Timestamp::now();
    let interval = attr_i64(asset, "heartbeat_interval_secs").filter(|v| *v > 0);
    AgentView {
        id: asset.id.to_string(),
        name: asset.name.clone(),
        flavor: asset_facets::flavor(asset),
        version: asset.version.clone().unwrap_or_default(),
        host: endpoints.host,
        ip: endpoints.ip,
        management: asset_facets::management(asset),
        online: asset_facets::online(asset, now),
        last_heartbeat_at: asset.last_seen_at,
        heartbeat_interval_sec: interval,
        department: asset.department.clone().unwrap_or_default(),
        owner: asset.owner.clone().unwrap_or_default(),
        active_sessions: attr_u64(asset, "active_sessions"),
        tool_count: attr_u64(asset, "tool_count"),
        risk_score: risk_score(asset),
    }
}

/// 台账 MCP → [`McpServerView`]。
pub(super) fn mcp_view(asset: &Asset) -> McpServerView {
    let now = Timestamp::now();
    McpServerView {
        id: asset.id.to_string(),
        name: asset.name.clone(),
        transport: asset_facets::transport(asset),
        endpoint: asset.endpoint.clone().unwrap_or_default(),
        tool_count: attr_u64(asset, "tool_count"),
        shadow: asset_facets::shadow(asset),
        plaintext_credential: plaintext_credential(asset),
        owner: asset.owner.clone().unwrap_or_default(),
        department: asset.department.clone().unwrap_or_default(),
        online: asset_facets::online(asset, now),
        registered_at: asset.created_at,
        last_seen_at: asset.last_seen_at,
        risk_score: risk_score(asset),
    }
}

/// 台账 Skill → [`SkillView`]。
pub(crate) fn skill_view(asset: &Asset) -> SkillView {
    SkillView {
        id: asset.id.to_string(),
        name: asset.name.clone(),
        version: asset.version.clone().unwrap_or_default(),
        publisher: asset.vendor.clone().unwrap_or_default(),
        status: skill_status(asset.lifecycle).to_string(),
        requested_by: asset.owner.clone().unwrap_or_default(),
        requested_at: asset.created_at,
        decided_at: review_decision(asset)
            .and_then(|review| review.get("at"))
            .and_then(|value| serde_json::from_value(value.clone()).ok()),
        decided_by: review_decision(asset)
            .and_then(|review| review.get("actor"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        review: SkillReviewView {
            lifecycle: asset.lifecycle.as_str().into(),
            allowed_next: asset.lifecycle.allowed_next().iter().map(|state| state.as_str().into()).collect(),
            updated_at: asset.updated_at,
            owner: asset.owner.clone().unwrap_or_default(),
            department: asset.department.clone().unwrap_or_default(),
            data_class: asset.data_class.as_str().into(),
        },
        risk_score: risk_score(asset),
        capabilities: capabilities(asset),
        whitelist: whitelist(asset),
        attached_agents: attr_u64(asset, "attached_agents"),
    }
}

/// 台账模型端点 → [`ModelEndpointView`]。
pub(super) fn model_endpoint_view(asset: &Asset) -> ModelEndpointView {
    ModelEndpointView {
        id: asset.id.to_string(),
        vendor: model_vendor(asset),
        model: attr_str(asset, "model").or_else(|| asset.version.clone()).unwrap_or_else(|| asset.name.clone()),
        endpoint: attr_str(asset, "base_url").or_else(|| asset.endpoint.clone()).unwrap_or_default(),
        local: attr_bool(asset, "local_deployment"),
        mock_mode: attr_bool(asset, "mock_mode"),
        input_price_per_k_tok: attr_f64(asset, "input_price_per_ktok").filter(|v| v.is_finite() && *v >= 0.0),
        output_price_per_k_tok: attr_f64(asset, "output_price_per_ktok").filter(|v| v.is_finite() && *v >= 0.0),
        priority: attr_u64(asset, "priority").and_then(|v| u32::try_from(v).ok()),
        fallback: attr_bool(asset, "fallback"),
        latency_p95_ms: attr_u64(asset, "latency_p95_ms"),
        health: attr_str(asset, "health")
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| MODEL_HEALTHS.contains(&h.as_str()))
            .unwrap_or_else(|| "unknown".to_string()),
    }
}

/// 端点拆解结果（宿主与 IP）。
#[derive(Debug, Clone, Default)]
struct EndpointParts {
    host: String,
    ip: String,
}

/// 从 `endpoint` / `attributes.host` 拆出宿主与 IP。
///
/// 台账 `endpoint` 可能是 `host:port`、URL 或 `stdio:<命令>`；无法判定时只回填名称。
fn endpoint_parts(asset: &Asset) -> EndpointParts {
    let raw = attr_str(asset, "host").or_else(|| asset.endpoint.clone()).unwrap_or_else(|| asset.name.clone());
    if raw.starts_with("stdio:") {
        return EndpointParts { host: raw, ip: String::new() };
    }
    let without_scheme = raw.split_once("://").map_or(raw.as_str(), |(_, rest)| rest);
    let host_port = without_scheme.split(['/', '?', '#']).next().unwrap_or(without_scheme);
    let host = host_port.split('@').next_back().unwrap_or(host_port);
    let host_only = host.rsplit_once(':').map_or(host, |(h, _)| h);
    let ip = if host_only.parse::<std::net::IpAddr>().is_ok() { host_only.to_string() } else { String::new() };
    EndpointParts { host: raw, ip }
}

/// 生命周期 → Skill 审批状态（前端 `SkillStatus`）。
pub(crate) const fn skill_status(lifecycle: LifecycleState) -> &'static str {
    match lifecycle {
        LifecycleState::Requested | LifecycleState::UnderReview | LifecycleState::Trial | LifecycleState::Changing => {
            "pending"
        }
        LifecycleState::Production => "approved",
        LifecycleState::Archived => "revoked",
        LifecycleState::Rejected => "rejected",
    }
}

/// Skill 能力标签：`attributes.capabilities` 优先，其次台账 `tags`，只保留前端枚举内的取值。
pub(super) fn capabilities(asset: &Asset) -> Vec<String> {
    let from_attr = value_string_list(asset.attributes.get("capabilities"));
    let source = if from_attr.is_empty() { asset.tags.clone() } else { from_attr };
    source
        .into_iter()
        .map(|c| c.trim().to_ascii_lowercase().replace('_', "-"))
        .filter(|c| TOOL_CAPABILITIES.contains(&c.as_str()))
        .collect()
}

/// Skill 白名单：`attributes.whitelist.{domains,paths}`，缺省为空。
pub(super) fn whitelist(asset: &Asset) -> SkillWhitelistView {
    let value = asset.attributes.get("whitelist");
    SkillWhitelistView {
        domains: value.and_then(|v| v.get("domains")).map(|v| value_string_list(Some(v))).unwrap_or_default(),
        paths: value.and_then(|v| v.get("paths")).map(|v| value_string_list(Some(v))).unwrap_or_default(),
    }
}

/// 模型厂商：`vendor`（命中前端枚举）→ `custom`。
fn model_vendor(asset: &Asset) -> String {
    attr_str(asset, "vendor")
        .or_else(|| asset.vendor.clone())
        .map(|v| v.trim().to_ascii_lowercase().replace('_', "-"))
        .filter(|v| MODEL_VENDORS.contains(&v.as_str()))
        .unwrap_or_else(|| "custom".to_string())
}

/// Only a saved risk assessment is a risk score.
pub(super) fn risk_score(asset: &Asset) -> Option<u8> {
    asset.risk_score
}

/// 明文凭据标记（与 `InventoryStats` 同口径：两种键名都认）。
pub(super) fn plaintext_credential(asset: &Asset) -> bool {
    asset_facets::plaintext(asset)
}

// ===========================================================================
// 属性读取与视图检索小工具
// ===========================================================================

/// 读字符串属性。
fn attr_str(asset: &Asset, key: &str) -> Option<String> {
    asset.attributes.get(key).and_then(|v| v.as_str()).map(ToString::to_string)
}

/// 读整数属性。
fn attr_i64(asset: &Asset, key: &str) -> Option<i64> {
    asset.attributes.get(key).and_then(serde_json::Value::as_i64)
}

/// 读无符号整数属性。
fn attr_u64(asset: &Asset, key: &str) -> Option<u64> {
    asset.attributes.get(key).and_then(serde_json::Value::as_u64)
}

/// 读浮点属性。
fn attr_f64(asset: &Asset, key: &str) -> Option<f64> {
    asset.attributes.get(key).and_then(serde_json::Value::as_f64)
}

/// 读布尔属性。
fn attr_bool(asset: &Asset, key: &str) -> Option<bool> {
    asset.attributes.get(key).and_then(serde_json::Value::as_bool)
}

/// 读字符串数组属性。
pub(super) fn value_string_list(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|items| items.iter().filter_map(|v| v.as_str().map(ToString::to_string)).collect())
        .unwrap_or_default()
}

// Only a server-recorded decision for the current terminal/production state is approval evidence.
fn review_decision(asset: &Asset) -> Option<&serde_json::Value> {
    if !matches!(asset.lifecycle, LifecycleState::Production | LifecycleState::Rejected | LifecycleState::Archived) {
        return None;
    }
    asset
        .attributes
        .get("agf_governance")
        .filter(|row| row.get("lifecycle").and_then(serde_json::Value::as_str) == Some(asset.lifecycle.as_str()))
}
