//! 资产模型（§4.1）：台账、画像、快照、差异漂移、暴露面评分。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::enums::{AssetKind, DataClass, DiscoverySource, LifecycleState, Protocol, RiskDomain, Severity};
use crate::ids::{Id, TenantId, TenantScoped};
use crate::time::Timestamp;

/// 资产主体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 资产类型。
    pub kind: AssetKind,
    /// 名称（上报值，可能重名）。
    pub name: String,
    /// 资产指纹（`deterministic_id` 的输入键，用于去重）。
    pub fingerprint: String,
    /// 厂商。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// 版本。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// 通信协议。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    /// 监听地址（`host:port` 或命令，如 `stdio:claude`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// 归属人。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// 归属部门。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// 数据分级。
    pub data_class: DataClass,
    /// 生命周期状态。
    pub lifecycle: LifecycleState,
    /// 发现来源。
    pub discovery_source: DiscoverySource,
    /// 暴露面评分（0-100，越高越危险）。
    pub exposure_score: u8,
    /// 运行环境（`windows` / `linux` / `macos` / `k8s` / `saas`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// 网络位置（`endpoint` 内网 / `dmz` / `public`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_zone: Option<String>,
    /// 关联云资源 id（ECS/ACK/函数计算等）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_resource_id: Option<String>,
    /// 标签。
    #[serde(default)]
    pub tags: Vec<String>,
    /// 扩展属性（厂商特有字段，保真存储）。
    #[serde(default)]
    pub attributes: BTreeMap<String, serde_json::Value>,
    /// 依赖（下游资产 id：Agent → MCP Server → Tool → 数据源 → 模型）。
    #[serde(default)]
    pub dependencies: Vec<Id>,
    /// 最近一次风险评分（0-100）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<u8>,
    /// 最近活跃时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<Timestamp>,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
    /// 软删除。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<Timestamp>,
}

impl TenantScoped for Asset {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl Asset {
    /// 新建资产（默认值 + 指纹长度校验）。
    #[must_use]
    pub fn new(tenant_id: TenantId, kind: AssetKind, name: impl Into<String>, fingerprint: impl Into<String>) -> Self {
        let now = Timestamp::now();
        let name = name.into();
        Self {
            id: Id::new(),
            tenant_id,
            kind,
            name,
            fingerprint: fingerprint.into(),
            vendor: None,
            version: None,
            protocol: None,
            endpoint: None,
            owner: None,
            department: None,
            data_class: DataClass::Internal,
            lifecycle: LifecycleState::Trial,
            discovery_source: DiscoverySource::Manual,
            exposure_score: 0,
            runtime: None,
            network_zone: None,
            cloud_resource_id: None,
            tags: Vec::new(),
            attributes: BTreeMap::new(),
            dependencies: Vec::new(),
            risk_score: None,
            last_seen_at: Some(now),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    /// 是否可对外暴露（生命周期判定）。
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.deleted_at.is_none() && matches!(self.lifecycle, LifecycleState::Production | LifecycleState::Trial)
    }

    /// 暴露面分级。
    #[must_use]
    pub const fn exposure_level(&self) -> Severity {
        match self.exposure_score {
            0..=24 => Severity::Info,
            25..=49 => Severity::Low,
            50..=69 => Severity::Medium,
            70..=84 => Severity::High,
            _ => Severity::Critical,
        }
    }
}

/// 暴露面评分输入。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExposureInput {
    /// 是否监听 `0.0.0.0` 或公网可达。
    pub publicly_reachable: bool,
    /// 是否无认证。
    pub unauthenticated: bool,
    /// 是否明文传输（无 TLS）。
    pub plaintext: bool,
    /// 是否可写（工具具备写/执行能力）。
    pub write_capable: bool,
    /// 是否接触受限数据。
    pub touches_restricted_data: bool,
    /// 关联高危发现数量。
    pub critical_findings: u32,
    /// 关联高风险发现数量。
    pub high_findings: u32,
    /// 版本是否已知存在未修复漏洞。
    pub known_vulnerable_version: bool,
    /// 是否已过生命周期评审（未评审上线 = 加风险）。
    pub unreviewed: bool,
}

/// 计算暴露面评分（0-100）。
///
/// 规则公开可解释（控制台展示扣分项），避免"黑盒评分"：
/// 公网可达 +25、无认证 +20、明文 +10、可写 +10、接触受限数据 +10、
/// 严重发现每个 +6（上限 18）、高危发现每个 +3（上限 9）、
/// 已知漏洞版本 +8、未评审上线 +5。总分明文截断到 100。
#[must_use]
pub fn score_exposure(input: &ExposureInput) -> (u8, Vec<(&'static str, u8)>) {
    let mut items: Vec<(&'static str, u8)> = Vec::new();
    if input.publicly_reachable {
        items.push(("publicly_reachable", 25));
    }
    if input.unauthenticated {
        items.push(("unauthenticated", 20));
    }
    if input.plaintext {
        items.push(("plaintext_transport", 10));
    }
    if input.write_capable {
        items.push(("write_capable_tool", 10));
    }
    if input.touches_restricted_data {
        items.push(("restricted_data", 10));
    }
    if input.critical_findings > 0 {
        items.push(("critical_findings", (input.critical_findings * 6).min(18) as u8));
    }
    if input.high_findings > 0 {
        items.push(("high_findings", (input.high_findings * 3).min(9) as u8));
    }
    if input.known_vulnerable_version {
        items.push(("known_vulnerable_version", 8));
    }
    if input.unreviewed {
        items.push(("unreviewed_rollout", 5));
    }
    let total: u32 = items.iter().map(|(_, v)| u32::from(*v)).sum();
    (u8::try_from(total.min(100)).unwrap_or(100), items)
}

/// 资产快照（基线，用于每日 diff）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSnapshot {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 快照日期（`YYYY-MM-DD`，UTC）。
    pub snapshot_date: String,
    /// 资产 id。
    pub asset_id: Id,
    /// 资产类型（便于跨类型聚合）。
    pub kind: AssetKind,
    /// 序列化后的资产画像（JSON）。
    pub payload: serde_json::Value,
    /// 内容哈希（SHA-256 hex），用于快速判定"是否变化"。
    pub content_hash: String,
    /// 创建时间。
    pub created_at: Timestamp,
}

/// 差异类型（§4.1 差异漂移）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeKind {
    /// 新增资产（可能为未授权 MCP/Skill）。
    Added,
    /// 资产消失。
    Removed,
    /// 属性变更。
    Modified,
}

impl ChangeKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Modified => "modified",
        }
    }
}

/// 资产变更记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetChange {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 资产 id。
    pub asset_id: Id,
    /// 资产类型。
    pub kind: AssetKind,
    /// 变更类型。
    pub change_kind: ChangeKind,
    /// 变更字段路径（如 `endpoint`），新增/删除时为 `None`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// 旧值。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_value: Option<serde_json::Value>,
    /// 新值。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_value: Option<serde_json::Value>,
    /// 是否被判定为高风险漂移（未授权资产 / 端点替换）。
    pub risky: bool,
    /// 风险说明。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_note: Option<String>,
    /// 关联安全域。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<RiskDomain>,
    /// 检出时间。
    pub detected_at: Timestamp,
}

/// 比较两份资产画像，产出差异列表（纯函数，便于属性测试）。
///
/// 只比较"安全相关"字段集合，避免展示名等无关变更造成噪声。
#[must_use]
pub fn diff_assets(before: &Asset, after: &Asset) -> Vec<AssetChange> {
    let mut changes = Vec::new();
    let now = Timestamp::now();
    let mut push = |field: &str, old: serde_json::Value, new: serde_json::Value| {
        let risky = matches!(field, "endpoint" | "protocol" | "version" | "vendor");
        changes.push(AssetChange {
            id: Id::new(),
            tenant_id: after.tenant_id,
            asset_id: after.id,
            kind: after.kind,
            change_kind: ChangeKind::Modified,
            field: Some(field.to_string()),
            old_value: Some(old),
            new_value: Some(new),
            risky,
            risk_note: risky.then(|| format!("安全相关字段 {field} 发生变更，需确认是否授权")),
            domain: risky.then_some(RiskDomain::ToolAbuse),
            detected_at: now,
        });
    };

    if before.endpoint != after.endpoint {
        push(
            "endpoint",
            serde_json::Value::from(before.endpoint.clone()),
            serde_json::Value::from(after.endpoint.clone()),
        );
    }
    if before.protocol != after.protocol {
        push(
            "protocol",
            serde_json::to_value(before.protocol).unwrap_or(serde_json::Value::Null),
            serde_json::to_value(after.protocol).unwrap_or(serde_json::Value::Null),
        );
    }
    if before.version != after.version {
        push(
            "version",
            serde_json::Value::from(before.version.clone()),
            serde_json::Value::from(after.version.clone()),
        );
    }
    if before.vendor != after.vendor {
        push("vendor", serde_json::Value::from(before.vendor.clone()), serde_json::Value::from(after.vendor.clone()));
    }
    if before.data_class != after.data_class {
        push(
            "data_class",
            serde_json::Value::from(before.data_class.as_str()),
            serde_json::Value::from(after.data_class.as_str()),
        );
    }
    if before.lifecycle != after.lifecycle {
        push(
            "lifecycle",
            serde_json::Value::from(before.lifecycle.as_str()),
            serde_json::Value::from(after.lifecycle.as_str()),
        );
    }
    if before.dependencies != after.dependencies {
        push(
            "dependencies",
            serde_json::to_value(&before.dependencies).unwrap_or(serde_json::Value::Null),
            serde_json::to_value(&after.dependencies).unwrap_or(serde_json::Value::Null),
        );
    }
    changes
}

/// 资产上线申请（生命周期入口）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetOnboarding {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 资产类型。
    pub kind: AssetKind,
    /// 申请名称。
    pub name: String,
    /// 申请人。
    pub requester: String,
    /// 部门。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// 用途说明。
    pub purpose: String,
    /// 数据分级。
    pub data_class: DataClass,
    /// 状态。
    pub state: LifecycleState,
    /// 评审人。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<String>,
    /// 评审意见。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_note: Option<String>,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 决策时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<Timestamp>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposure_score_is_bounded_and_explainable() {
        let input = ExposureInput {
            publicly_reachable: true,
            unauthenticated: true,
            plaintext: true,
            write_capable: true,
            touches_restricted_data: true,
            critical_findings: 100,
            high_findings: 100,
            known_vulnerable_version: true,
            unreviewed: true,
        };
        let (score, items) = score_exposure(&input);
        assert_eq!(score, 100);
        assert!(items.len() >= 9);
        assert!(items.iter().any(|(k, _)| *k == "publicly_reachable"));
    }

    #[test]
    fn exposure_score_zero_when_clean() {
        let (score, items) = score_exposure(&ExposureInput::default());
        assert_eq!(score, 0);
        assert!(items.is_empty());
    }

    #[test]
    fn exposure_level_boundaries() {
        let mut a = Asset::new(TenantId::default_tenant(), AssetKind::McpServer, "m", "fp");
        a.exposure_score = 0;
        assert_eq!(a.exposure_level(), Severity::Info);
        a.exposure_score = 30;
        assert_eq!(a.exposure_level(), Severity::Low);
        a.exposure_score = 60;
        assert_eq!(a.exposure_level(), Severity::Medium);
        a.exposure_score = 80;
        assert_eq!(a.exposure_level(), Severity::High);
        a.exposure_score = 95;
        assert_eq!(a.exposure_level(), Severity::Critical);
    }

    #[test]
    fn diff_detects_endpoint_change_as_risky() {
        let mut before = Asset::new(TenantId::default_tenant(), AssetKind::McpServer, "m", "fp");
        before.endpoint = Some("http://10.0.0.1:8080".into());
        let mut after = before.clone();
        after.endpoint = Some("http://evil.example.com:8080".into());
        let changes = diff_assets(&before, &after);
        assert_eq!(changes.len(), 1);
        assert!(changes[0].risky);
        assert_eq!(changes[0].field.as_deref(), Some("endpoint"));
    }

    #[test]
    fn diff_detects_data_class_change() {
        let before = Asset::new(TenantId::default_tenant(), AssetKind::RagKb, "kb", "fp");
        let mut after = before.clone();
        after.data_class = DataClass::Restricted;
        let changes = diff_assets(&before, &after);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field.as_deref(), Some("data_class"));
        assert!(!changes[0].risky);
    }

    #[test]
    fn diff_empty_when_identical() {
        let a = Asset::new(TenantId::default_tenant(), AssetKind::Agent, "a", "fp");
        assert!(diff_assets(&a, &a).is_empty());
    }

    #[test]
    fn live_asset_requires_active_lifecycle() {
        let mut a = Asset::new(TenantId::default_tenant(), AssetKind::Agent, "a", "fp");
        assert!(a.is_live());
        a.lifecycle = LifecycleState::Archived;
        assert!(!a.is_live());
        a.lifecycle = LifecycleState::Production;
        a.deleted_at = Some(Timestamp::now());
        assert!(!a.is_live());
    }
}
