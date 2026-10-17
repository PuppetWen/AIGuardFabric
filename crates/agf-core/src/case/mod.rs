//! 案件闭环模型（§4.6 告警 → 案件 → 证据 → 处置 → 复盘）。

use serde::{Deserialize, Serialize};

use crate::enums::{CaseState, Severity};

use crate::ids::{Id, TenantId};

use crate::time::Timestamp;

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 案件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 案件编号（人类可读，形如 `CASE-2026-0001`）。
    pub code: String,
    /// 标题。
    pub title: String,
    /// 摘要。
    #[serde(default)]
    pub summary: String,
    /// 严重等级。
    pub severity: Severity,
    /// 状态。
    pub state: CaseState,
    /// 来源告警 id 列表。
    #[serde(default)]
    pub alert_ids: Vec<Id>,
    /// 关联 finding id 列表。
    #[serde(default)]
    pub finding_ids: Vec<Id>,
    /// 受影响资产 id 列表。
    #[serde(default)]
    pub asset_ids: Vec<Id>,
    /// 负责人。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// 协作人。
    #[serde(default)]
    pub collaborators: Vec<String>,
    /// 是否升级为安全事件（对外通报）。
    #[serde(default)]
    pub security_incident: bool,
    /// 处置结论。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
    /// 根因分析。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_cause: Option<String>,
    /// 复盘要点。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lessons: Option<String>,
    /// 证据包对象存储 key（导出 zip）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_bundle_ref: Option<String>,
    /// SLA 截止。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sla_due_at: Option<Timestamp>,
    /// 是否已超 SLA。
    #[serde(default)]
    pub sla_breached: bool,
    /// 标签。
    #[serde(default)]
    pub tags: Vec<String>,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 关闭时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<Timestamp>,
    /// 更新时间。
    pub updated_at: Timestamp,
}

/// 案件时间线事件类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseEventKind {
    /// 创建案件。
    Created,
    /// 状态变更。
    StateChanged,
    /// 指派。
    Assigned,
    /// 添加证据。
    EvidenceAdded,
    /// 添加评论。
    Comment,
    /// 执行处置动作。
    Containment,
    /// 执行隔离。
    Isolation,
    /// 吊销凭据。
    CredentialRevoked,
    /// 封禁域名/IP。
    Blocklisted,
    /// 升级。
    Escalated,
    /// 关闭。
    Closed,
    /// 自动化剧本执行。
    PlaybookRun,
}

/// 案件时间线条目。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseEvent {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 案件 id。
    pub case_id: Id,
    /// 类型。
    pub kind: CaseEventKind,
    /// 操作者（用户或系统）。
    pub actor: String,
    /// 说明。
    pub note: String,
    /// 结构化详情。
    #[serde(default)]
    pub detail: serde_json::Value,
    /// 是否为自动化动作（SOAR 剧本）。
    #[serde(default)]
    pub automated: bool,
    /// 发生时间。
    pub at: Timestamp,
}

/// 处置动作（SOAR-lite 可执行动作集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContainmentAction {
    /// 隔离 Agent（断开其 MCP/模型出口）。
    IsolateAgent,
    /// 通过已配置的 EDR 隔离案件关联主机。
    IsolateHost,
    /// 通过已配置的 SCIM 身份平台停用案件关联身份。
    DeactivateExternalUser,
    /// 吊销凭据。
    RevokeCredential,
    /// 封禁域名。
    BlockDomain,
    /// 封禁 IP。
    BlockIp,
    /// 禁用 MCP Server。
    DisableMcpServer,
    /// 撤销 Skill 授权。
    RevokeSkill,
    /// 强制下线会话。
    KillSession,
    /// 降级到本地模型。
    ForceLocalModel,
    /// 通知责任人。
    NotifyOwner,
    /// 打标并归档。
    Archive,
}

/// SOAR-lite 剧本（YAML 声明式，§4.6）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    /// 稳定键。
    pub key: String,
    /// 名称。
    pub name: String,
    /// 描述。
    #[serde(default)]
    pub description: String,
    /// 触发条件。
    pub trigger: PlaybookTrigger,
    /// 执行步骤。
    pub steps: Vec<PlaybookStep>,
    /// 是否启用。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 是否需人工审批后执行。
    #[serde(default)]
    pub require_approval: bool,
    /// 最大执行时长（秒），超时中止。
    #[serde(default = "default_timeout")]
    pub timeout_secs: i64,
    /// 版本。
    #[serde(default = "default_version")]
    pub version: u32,
}

const fn default_true() -> bool {
    true
}

const fn default_timeout() -> i64 {
    300
}

const fn default_version() -> u32 {
    1
}

/// 剧本触发条件。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlaybookTrigger {
    /// 触发的安全域。
    #[serde(default)]
    pub domains: Vec<crate::enums::RiskDomain>,
    /// 最低严重等级。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<Severity>,
    /// 命中的规则键（空 = 不限）。
    #[serde(default)]
    pub rule_keys: Vec<String>,
    /// 资产类型过滤。
    #[serde(default)]
    pub asset_kinds: Vec<crate::enums::AssetKind>,
    /// 附加 CEL 条件表达式。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
}

/// 剧本步骤。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    /// 步骤名。
    pub name: String,
    /// 执行动作（处置类）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<ContainmentAction>,
    /// 通知渠道键（通知类步骤）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify_channel: Option<String>,
    /// 动作参数。
    #[serde(default)]
    pub params: serde_json::Value,
    /// 失败是否继续后续步骤。
    #[serde(default)]
    pub continue_on_error: bool,
    /// 该步超时。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<i64>,
}

mod impl_case;
#[cfg(test)]
mod tests;
