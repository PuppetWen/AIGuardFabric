//! 前端枚举与资产字段的映射、取值小工具（视图构造共用）。

use super::*;

// ===========================================================================
// 映射与取值小工具
// ===========================================================================

/// 前端 `RiskDomain` 的 5 个取值（顺序与 demo 的 `DOMAINS` 一致）。
pub(super) const FRONTEND_DOMAINS: [&str; 5] = ["asset", "data", "identity", "runtime", "compliance"];

/// 后端 `RiskDomain`（提示词攻击/凭证泄露/RAG 投毒/工具滥用/模型与数据）→ 前端 `RiskDomain`
/// （资产/数据/身份/运行时/合规）。
///
/// 两套词表不同名：`PromptAttack`/`ToolAbuse` 都归 `runtime`（运行时域），
/// `RagPoison`/`ModelData` 都归 `data`（数据域），`CredentialLeak` 归 `identity`。
pub(super) fn risk_domain_frontend(domain: RiskDomain) -> &'static str {
    match domain {
        RiskDomain::PromptAttack | RiskDomain::ToolAbuse => "runtime",
        RiskDomain::CredentialLeak => "identity",
        RiskDomain::RagPoison | RiskDomain::ModelData => "data",
    }
}

/// 资产类型 → 前端 `RiskDomain`（与 demo 的 `domainOfAsset` 同口径）。
pub(super) fn asset_domain_of_kind(kind: AssetKind) -> &'static str {
    match kind {
        AssetKind::DataSource | AssetKind::RagKb | AssetKind::VectorStore => "data",
        AssetKind::Credential => "identity",
        AssetKind::Skill | AssetKind::PromptTemplate => "compliance",
        AssetKind::Agent | AssetKind::McpServer | AssetKind::McpClient => "runtime",
        // 模型端点/算力节点/IDE 插件/采集器/其他：demo 归 `asset`（资产域）。
        _ => "asset",
    }
}

/// 资产类型 → 前端 `AssetKind`。
pub(super) fn asset_kind_frontend(kind: AssetKind) -> &'static str {
    match kind {
        AssetKind::Agent => "agent",
        AssetKind::McpServer | AssetKind::McpClient => "mcp",
        AssetKind::Skill | AssetKind::PromptTemplate => "skill",
        AssetKind::ModelEndpoint => "model",
        AssetKind::DataSource | AssetKind::RagKb | AssetKind::VectorStore => "datasource",
        AssetKind::Credential => "credential",
        _ => "endpoint",
    }
}

/// 生命周期 → 前端 `LifecycleState`。
const fn lifecycle_frontend(state: LifecycleState) -> &'static str {
    match state {
        LifecycleState::Requested => "planned",
        LifecycleState::UnderReview | LifecycleState::Trial => "onboarding",
        LifecycleState::Production | LifecycleState::Changing => "active",
        LifecycleState::Archived => "deprecated",
        LifecycleState::Rejected => "retired",
    }
}

/// 发现来源 → 前端 `DiscoverySource`。
const fn discovery_source_frontend(source: DiscoverySource) -> &'static str {
    match source {
        DiscoverySource::AgentReport | DiscoverySource::NetworkScan | DiscoverySource::GitScan => "agent-scan",
        DiscoverySource::CloudApi => "cloud-api",
        DiscoverySource::PassiveTraffic => "gateway-mirror",
        DiscoverySource::Collector => "ingest-log",
        DiscoverySource::Manual | DiscoverySource::Sidecar | DiscoverySource::Import => "manual",
    }
}

/// The latest saved risk assessment; absence is not a measured zero.
pub(super) fn asset_risk_score(asset: &Asset) -> Option<u8> {
    asset.risk_score
}

/// 台账资产 → 前端 `Asset` 视图。
pub(super) fn asset_view(asset: &Asset, open_findings: Option<i64>) -> AssetView {
    let mut description = format!("{} · {}", asset.kind.as_str(), asset.name);
    if let Some(vendor) = &asset.vendor {
        description.push_str(&format!(" · {vendor}"));
    }
    if let Some(version) = &asset.version {
        description.push_str(&format!(" {version}"));
    }
    if let Some(endpoint) = &asset.endpoint {
        description.push_str(&format!(" · {endpoint}"));
    }
    AssetView {
        id: asset.id.to_string(),
        tenant_id: asset.tenant_id.to_string(),
        name: asset.name.clone(),
        kind: asset_kind_frontend(asset.kind).to_string(),
        owner: asset.owner.clone().unwrap_or_default(),
        department: asset.department.clone().unwrap_or_default(),
        classification: asset.data_class.as_str().to_string(),
        lifecycle: lifecycle_frontend(asset.lifecycle).to_string(),
        exposure: crate::store::asset_exposure(asset).to_string(),
        risk_score: asset_risk_score(asset),
        open_findings,
        sources: vec![discovery_source_frontend(asset.discovery_source).to_string()],
        tags: asset.tags.clone(),
        first_seen_at: asset.created_at.to_rfc3339(),
        last_seen_at: asset.last_seen_at.map(|value| value.to_rfc3339()).unwrap_or_default(),
        description,
    }
}

/// 发现是否已关闭（误报 / 已修复）。
pub(super) fn is_closed_finding(state: FindingState) -> bool {
    matches!(state, FindingState::FalsePositive | FindingState::Fixed)
}

/// 告警状态 → 前端 `AlertStatus`（`escalated`→`in-progress`、`closed`→`resolved`）。
pub(super) const fn alert_state_frontend(state: AlertState) -> &'static str {
    match state {
        AlertState::Open => "open",
        AlertState::Acknowledged => "acknowledged",
        AlertState::Suppressed => "suppressed",
        AlertState::Escalated => "in-progress",
        AlertState::Closed => "resolved",
    }
}

/// 后端策略动作（10 个）→ 前端 `PolicyAction`（7 个）。映射是**有损**的：
/// `audit`→`alert`（只记录）、`redact`→`mask`、`quota`/`throttle`→`throttle`、
/// `degrade`→`redirect`、`circuit-break`/`isolate`/`approval`→`quarantine`。
pub(super) const fn policy_action_frontend(action: PolicyAction) -> &'static str {
    match action {
        PolicyAction::Allow => "allow",
        PolicyAction::Deny => "deny",
        PolicyAction::Audit => "alert",
        PolicyAction::Redact => "mask",
        PolicyAction::Quota | PolicyAction::Throttle => "throttle",
        PolicyAction::Degrade => "redirect",
        PolicyAction::CircuitBreak | PolicyAction::Isolate | PolicyAction::Approval => "quarantine",
    }
}

/// 读无符号整数属性。
pub(super) fn attribute_u64(asset: &Asset, key: &str) -> Option<u64> {
    asset.attributes.get(key).and_then(serde_json::Value::as_u64)
}

/// 读布尔属性。
pub(super) fn attribute_bool(asset: &Asset, key: &str) -> Option<bool> {
    asset.attributes.get(key).and_then(serde_json::Value::as_bool)
}
