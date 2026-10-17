//! 运行时策略模型（§4.3）。
//!
//! 策略用 Rego（regorus）或 CEL 表达，动作集见 [`crate::enums::PolicyAction`]。
//! 策略**必须签名**：`signature` 由平台主密钥对策略内容做 HMAC，
//! 运行时校验签名，防止被管 Agent 篡改本地策略缓存绕过管控。

use serde::{Deserialize, Serialize};

use crate::enums::{InterceptPoint, PolicyAction, Severity};

use crate::ids::{Id, TenantId};

use crate::time::Timestamp;

#[allow(unused_imports)]
pub use impl_policy_language::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 策略语言。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyLanguage {
    /// Rego（Open Policy Agent 语法，regorus 执行）。
    Rego,
    /// CEL（Common Expression Language）。
    Cel,
    /// 结构化内置规则（无需写代码，UI 双模编辑器的表单模式）。
    Structured,
}

/// 结构化策略条件（表单模式，避免客户手写 Rego）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StructuredCondition {
    /// 命令黑名单模式（正则或子串，如 `rm -rf`、`curl | sh`）。
    #[serde(default)]
    pub command_deny: Vec<String>,
    /// 允许调用的工具白名单（空 = 不限制）。
    #[serde(default)]
    pub tool_allowlist: Vec<String>,
    /// 禁止调用的工具黑名单。
    #[serde(default)]
    pub tool_denylist: Vec<String>,
    /// 允许出网的域名（支持 `*.example.com` 通配）。
    #[serde(default)]
    pub domain_allowlist: Vec<String>,
    /// 禁止出网的域名（优先级高于白名单）。
    #[serde(default)]
    pub domain_denylist: Vec<String>,
    /// 允许访问的文件路径前缀。
    #[serde(default)]
    pub path_allowlist: Vec<String>,
    /// 禁止访问的文件路径前缀（如 `/etc/shadow`、`%USERPROFILE%\.ssh`）。
    #[serde(default)]
    pub path_denylist: Vec<String>,
    /// 触发策略的规则域（空 = 全部）。
    #[serde(default)]
    pub domains: Vec<crate::enums::RiskDomain>,
    /// 触发策略的最低严重等级。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<Severity>,
    /// 请求体大小上限（字节）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_payload_bytes: Option<u64>,
    /// 要求人工审批。
    #[serde(default)]
    pub require_approval: bool,
}

/// 策略定义。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 名称。
    pub name: String,
    /// 描述。
    #[serde(default)]
    pub description: String,
    /// 语言。
    pub language: PolicyLanguage,
    /// 源码（Rego/CEL）。
    #[serde(default)]
    pub source: String,
    /// 结构化条件（表单模式）。
    #[serde(default)]
    pub structured: StructuredCondition,
    /// 动作。
    pub action: PolicyAction,
    /// 优先级（数值小者先匹配并短路；deny 类建议高优先级）。
    pub priority: u32,
    /// 生效的拦截点。
    #[serde(default)]
    pub intercept_points: Vec<InterceptPoint>,
    /// 作用域：限定的 Agent 资产 id（空 = 全租户）。
    #[serde(default)]
    pub scope_agent_ids: Vec<Id>,
    /// 作用域：限定的部门。
    #[serde(default)]
    pub scope_departments: Vec<String>,
    /// 是否启用。
    pub enabled: bool,
    /// 是否处于模拟（dry-run）模式：只记录不拦截。
    #[serde(default)]
    pub dry_run: bool,
    /// 配额档位（`action=quota` 时引用）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_id: Option<Id>,
    /// 重定向到本地模型的端点 id（`action=degrade` 时引用）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degrade_endpoint_id: Option<Id>,
    /// 内容哈希。
    pub content_hash: String,
    /// 签名（HMAC-SHA256(主密钥, content_hash)，hex）。
    pub signature: String,
    /// 版本号。
    pub version: u32,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
    /// 软删除。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<Timestamp>,
}

/// 策略版本（回滚与审计）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersion {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 策略 id。
    pub policy_id: Id,
    /// 版本号。
    pub version: u32,
    /// 快照。
    pub snapshot: Policy,
    /// 变更人。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed_by: Option<Id>,
    /// 变更说明。
    #[serde(default)]
    pub change_note: String,
    /// 创建时间。
    pub created_at: Timestamp,
}

/// 策略命中记录（运行时审计）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyHit {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 策略 id。
    pub policy_id: Id,
    /// 策略名。
    pub policy_name: String,
    /// 动作。
    pub action: PolicyAction,
    /// 拦截点。
    pub intercept_point: InterceptPoint,
    /// 会话 id。
    pub session_id: String,
    /// Agent 资产 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<Id>,
    /// 请求摘要（脱敏）。
    pub request_excerpt: String,
    /// 是否实际执行了动作（dry-run 为 false）。
    pub enforced: bool,
    /// 是否被人工审批覆盖。
    #[serde(default)]
    pub overridden_by_approval: bool,
    /// 审批单 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<Id>,
    /// 发生时间。
    pub at: Timestamp,
}

/// 策略评估输入（运行时统一上下文）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    /// 租户。
    pub tenant_id: TenantId,
    /// 会话 id。
    pub session_id: String,
    /// Agent 资产 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<Id>,
    /// 部门。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// 拦截点。
    pub intercept_point: InterceptPoint,
    /// 目标工具名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// 目标路径。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// 目标域名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// 命令文本。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// 原始载荷（已做必要脱敏）。
    #[serde(default)]
    pub payload: serde_json::Value,
    /// 载荷字节数。
    pub payload_bytes: u64,
    /// 命中的风险域。
    #[serde(default)]
    pub risk_domains: Vec<crate::enums::RiskDomain>,
    /// 命中的最高严重等级。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_severity: Option<Severity>,
    /// 数据分级。
    pub data_class: crate::enums::DataClass,
    /// 当前时间。
    pub now: Timestamp,
}

/// 策略评估结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// 最终动作。
    pub action: PolicyAction,
    /// 决定该动作的策略 id（`None` = 默认放行）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<Id>,
    /// 策略名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    /// 原因说明（会展示在拦截提示与审计里）。
    pub reason: String,
    /// 是否需要脱敏处理。
    pub redact: bool,
    /// 是否仅审计（不拦截）。
    pub dry_run: bool,
    /// 引用的配额 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_id: Option<Id>,
    /// 降级目标端点。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degrade_endpoint_id: Option<Id>,
    /// 评估耗时（微秒）。
    pub eval_micros: u64,
}

mod impl_policy_language;
#[cfg(test)]
mod tests;
