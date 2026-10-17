//! RBAC + ABAC 权限模型（§4.7）。
//!
//! 权限点命名规范：`<资源组>:<动作>`，例如 `assets:read`、`policies:write`、`redteam:run`。
//! 角色是权限点的集合；`role_bindings` 把角色绑定到主体并可携带 ABAC 条件
//! （部门、数据分级、时间窗），实现"同一角色不同数据可见范围"。

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::enums::DataClass;

use crate::ids::{Id, TenantId};

use crate::time::Timestamp;

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 内置角色标识。
pub mod builtin {
    /// 平台超级管理员（跨租户，仅平台运维）。
    pub const SUPERADMIN: &str = "superadmin";
    /// 租户管理员。
    pub const TENANT_ADMIN: &str = "tenant-admin";
    /// 安全运营（告警/案件处置）。
    pub const SOC_ANALYST: &str = "soc-analyst";
    /// 红队工程师。
    pub const REDTEAM_ENGINEER: &str = "redteam-engineer";
    /// 审计员（只读 + 审计导出）。
    pub const AUDITOR: &str = "auditor";
    /// 只读观察者。
    pub const VIEWER: &str = "viewer";
    /// 资产负责人（仅本部门资产）。
    pub const ASSET_OWNER: &str = "asset-owner";
}

/// 权限点。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Permission(String);

/// 资源组（§8 API 资源组，权限点前缀与此一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceGroup {
    /// 资产台账。
    Assets,
    /// Agent。
    Agents,
    /// MCP。
    Mcps,
    /// Skill。
    Skills,
    /// 模型端点。
    Models,
    /// 风险发现。
    Findings,
    /// 检测规则。
    Rules,
    /// 扫描任务。
    Scans,
    /// 红队。
    Redteam,
    /// 策略。
    Policies,
    /// 配额。
    Quotas,
    /// 告警。
    Alerts,
    /// 案件。
    Cases,
    /// 日志接入源。
    Sources,
    /// 解析器。
    Parsers,
    /// 集成/适配器。
    Integrations,
    /// 阿里云。
    Alicloud,
    /// 审计。
    Audit,
    /// 报表。
    Reports,
    /// 设置。
    Settings,
    /// 平台管理（租户/用户/角色）。
    Platform,
}

/// 动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// 读。
    Read,
    /// 写（创建/更新）。
    Write,
    /// 删除。
    Delete,
    /// 执行（扫描、红队、剧本）。
    Execute,
    /// 审批。
    Approve,
    /// 导出。
    Export,
    /// 管理（成员/角色/配额）。
    Admin,
}

/// 角色。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// 主键。
    pub id: Id,
    /// 租户（内置角色属于默认租户，可被各租户引用）。
    pub tenant_id: TenantId,
    /// 角色标识（租户内唯一）。
    pub name: String,
    /// 显示名。
    pub display_name: String,
    /// 描述。
    pub description: String,
    /// 权限点集合。
    pub permissions: Vec<Permission>,
    /// 是否内置（内置角色不可删除，仅可复制后修改）。
    pub builtin: bool,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
}

/// ABAC 条件（角色绑定上的附加约束）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AbacCondition {
    /// 仅限指定部门（空 = 不限）。
    #[serde(default)]
    pub departments: Vec<String>,
    /// 仅限这些数据分级（空 = 不限）。
    #[serde(default)]
    pub data_classes: Vec<DataClass>,
    /// 生效时间窗（如仅工作时间可写）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_window: Option<String>,
    /// 仅限指定来源 IP 段（CIDR）。
    #[serde(default)]
    pub source_cidrs: Vec<String>,
}

/// 角色绑定（主体 ← 角色 + ABAC 条件）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleBinding {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 主体：用户 id、API Key id、或 Agent id（Agent 也需最小权限）。
    pub subject_id: Id,
    /// 主体类型。
    pub subject_kind: SubjectKind,
    /// 角色 id。
    pub role_id: Id,
    /// ABAC 条件。
    #[serde(default)]
    pub condition: AbacCondition,
    /// 生效时间。
    pub granted_at: Timestamp,
    /// 过期时间（临时授权）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// 授权人。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted_by: Option<Id>,
}

/// 主体类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubjectKind {
    /// 用户。
    User,
    /// API Key。
    ApiKey,
    /// Agent（Agent 调用平台 API 时）。
    Agent,
    /// 服务账号（内建组件）。
    Service,
}

/// API Key（`X-AGF-Key` 认证）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 名称。
    pub name: String,
    /// 前缀（明文可见部分，形如 `agf_live_3f2a`，用于定位）。
    pub prefix: String,
    /// 密钥指纹（SHA-256 hex，不存明文）。
    pub key_fingerprint: String,
    /// 直接授予的权限点（与角色绑定叠加）。
    #[serde(default)]
    pub scopes: Vec<Permission>,
    /// 绑定的 Agent（Agent 上报专用 Key）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_agent_id: Option<Id>,
    /// 过期时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// 最后使用时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<Timestamp>,
    /// 来源 IP 白名单。
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
    /// 是否吊销。
    pub revoked: bool,
    /// 创建时间。
    pub created_at: Timestamp,
}

/// 权限判定请求。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequest {
    /// 需要的权限点。
    pub permission: Permission,
    /// 目标资源的租户。
    pub resource_tenant: TenantId,
    /// 目标资源的数据分级。
    pub data_class: Option<DataClass>,
    /// 目标资源所属部门。
    pub department: Option<String>,
    /// 来源 IP。
    pub source_ip: Option<String>,
}

/// 主体有效权限集合（合并多个角色 + ABAC 过滤后的结果）。
#[derive(Debug, Clone, Default)]
pub struct EffectivePermissions {
    /// 权限点集合。
    pub permissions: BTreeSet<Permission>,
    /// 是否超级管理员。
    pub superadmin: bool,
    /// 是否只读（用于前端 UI 裁剪）。
    pub read_only: bool,
}

mod impl_permission;
#[cfg(test)]
mod tests;
