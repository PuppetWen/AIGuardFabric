//! 审计日志模型（§4.7 哈希链防篡改审计）。
//!
//! 防篡改设计：
//! - 每条记录计算 `entry_hash = SHA256(prev_hash ‖ 规范化载荷)`；
//! - `prev_hash` 指向同租户上一条记录，形成链；
//! - 定期生成链锚点（[`AuditChainAnchor`]）并对锚点做 HMAC 签名，
//!   即使攻击者改库并重算链路，也无法伪造锚点签名。

use serde::{Deserialize, Serialize};

use crate::ids::{Id, TenantId};

use crate::time::Timestamp;

#[allow(unused_imports)]
pub use impl_audit_action::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 审计动作类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditAction {
    /// 登录/登出。
    Login,
    /// 登出。
    Logout,
    /// 创建。
    Create,
    /// 读取（敏感数据访问）。
    Read,
    /// 更新。
    Update,
    /// 删除。
    Delete,
    /// 导出（数据外带重点审计）。
    Export,
    /// 执行（扫描/红队/剧本）。
    Execute,
    /// 配置变更（策略/规则/集成）。
    Configure,
    /// 授权变更（角色/权限/API Key）。
    Grant,
    /// 审批。
    Approve,
    /// 处置动作（隔离/封禁/吊销）。
    Contain,
    /// 系统事件（迁移/备份/自检）。
    System,
}

/// 审计结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    /// 成功。
    Success,
    /// 失败。
    Failure,
    /// 被拒绝（权限/策略）。
    Denied,
}

/// 审计目标。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTarget {
    /// 资源类型（`asset` / `policy` / `user` …）。
    pub kind: String,
    /// 资源 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// 资源名（删除后仍可读）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// 审计操作者。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditActor {
    /// 主体 id（用户/API Key/Agent/服务）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Id>,
    /// 主体类型。
    pub kind: String,
    /// 名称（用户名/Key 名/服务名）。
    pub name: String,
    /// 来源 IP。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// User-Agent。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// 会话 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

/// 审计记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 链内序号（单调递增，从 1 开始）。
    pub sequence: i64,
    /// 动作。
    pub action: AuditAction,
    /// 结果。
    pub outcome: AuditOutcome,
    /// 操作者。
    pub actor: AuditActor,
    /// 目标。
    pub target: AuditTarget,
    /// 变更前快照（敏感值已脱敏）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    /// 变更后快照。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
    /// 变更字段列表。
    #[serde(default)]
    pub changed_fields: Vec<String>,
    /// 请求 id（关联 trace）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// 失败原因。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// 备注。
    #[serde(default)]
    pub note: String,
    /// 上一条哈希（创世为 64 个 0）。
    pub prev_hash: String,
    /// 本条哈希。
    pub entry_hash: String,
    /// 发生时间。
    pub at: Timestamp,
}

/// 创世哈希（链起点）。
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// 链校验报告的单项问题。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainViolation {
    /// 出问题的记录 id。
    pub entry_id: Id,
    /// 序号。
    pub sequence: i64,
    /// 问题类型（`hash_mismatch` / `prev_gap` / `sequence_gap`）。
    pub kind: String,
    /// 说明。
    pub detail: String,
}

/// 链校验结果。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChainVerification {
    /// 校验记录数。
    pub checked: usize,
    /// 是否通过。
    pub passed: bool,
    /// 问题列表。
    #[serde(default)]
    pub violations: Vec<ChainViolation>,
    /// 链首序号。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_sequence: Option<i64>,
    /// 链尾序号。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sequence: Option<i64>,
    /// 校验时间。
    pub verified_at: Option<Timestamp>,
}

/// 链锚点（定期生成并签名，防止整链重算）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChainAnchor {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 锚定的最大序号。
    pub up_to_sequence: i64,
    /// 锚定时的链尾哈希。
    pub tail_hash: String,
    /// 记录数。
    pub entry_count: i64,
    /// 生成时间。
    pub created_at: Timestamp,
    /// HMAC 签名（平台主密钥，hex）。
    pub signature: String,
}

/// 审计查询过滤条件。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditQuery {
    /// 动作过滤。
    #[serde(default)]
    pub actions: Vec<AuditAction>,
    /// 结果过滤。
    #[serde(default)]
    pub outcomes: Vec<AuditOutcome>,
    /// 操作者名模糊匹配。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// 目标类型。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<String>,
    /// 起始时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Timestamp>,
    /// 结束时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Timestamp>,
    /// 是否只看高敏感动作。
    #[serde(default)]
    pub sensitive_only: bool,
}

mod impl_audit_action;
#[cfg(test)]
mod tests;

mod anchor;
pub use anchor::{
    AgentAuditAcknowledgement, AgentAuditBatch, AuditChainKind, SignedAuditAnchor, valid_hash, verify_agent_segment,
};
