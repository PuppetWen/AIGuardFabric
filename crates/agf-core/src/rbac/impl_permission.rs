//! 由 `rbac.rs` 拆分：`AbacCondition`/`Action`/`ApiKey`/`EffectivePermissions`/`Permission`/`ResourceGroup`/`Role`/`RoleBinding`/`SubjectKind` 的实现（纯搬移，逻辑不变）。
use super::*;

use crate::ids::{TenantId, TenantScoped};

impl Permission {
    /// 由 `组:动作` 构造。
    #[must_use]
    pub fn new(group: &str, action: &str) -> Self {
        Self(format!("{group}:{action}"))
    }

    /// 由完整字符串构造（不做合法性校验，加载期校验）。
    #[must_use]
    pub fn from_raw(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 完整字符串。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 通配匹配：支持 `assets:*` 与 `*`。
    #[must_use]
    pub fn matches(&self, required: &Self) -> bool {
        if self.0 == "*" || self.0 == required.0 {
            return true;
        }
        match (self.0.split_once(':'), required.0.split_once(':')) {
            (Some((g1, "*")), Some(_)) => required.0.starts_with(&format!("{g1}:")),
            _ => false,
        }
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl ResourceGroup {
    /// 文本形式（权限点前缀）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Assets => "assets",
            Self::Agents => "agents",
            Self::Mcps => "mcps",
            Self::Skills => "skills",
            Self::Models => "models",
            Self::Findings => "findings",
            Self::Rules => "rules",
            Self::Scans => "scans",
            Self::Redteam => "redteam",
            Self::Policies => "policies",
            Self::Quotas => "quotas",
            Self::Alerts => "alerts",
            Self::Cases => "cases",
            Self::Sources => "sources",
            Self::Parsers => "parsers",
            Self::Integrations => "integrations",
            Self::Alicloud => "alicloud",
            Self::Audit => "audit",
            Self::Reports => "reports",
            Self::Settings => "settings",
            Self::Platform => "platform",
        }
    }

    /// 全部资源组。
    #[must_use]
    pub const fn all() -> [Self; 21] {
        [
            Self::Assets,
            Self::Agents,
            Self::Mcps,
            Self::Skills,
            Self::Models,
            Self::Findings,
            Self::Rules,
            Self::Scans,
            Self::Redteam,
            Self::Policies,
            Self::Quotas,
            Self::Alerts,
            Self::Cases,
            Self::Sources,
            Self::Parsers,
            Self::Integrations,
            Self::Alicloud,
            Self::Audit,
            Self::Reports,
            Self::Settings,
            Self::Platform,
        ]
    }
}

impl Action {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::Execute => "execute",
            Self::Approve => "approve",
            Self::Export => "export",
            Self::Admin => "admin",
        }
    }

    /// 全部动作。
    #[must_use]
    pub const fn all() -> [Self; 7] {
        [Self::Read, Self::Write, Self::Delete, Self::Execute, Self::Approve, Self::Export, Self::Admin]
    }
}

impl TenantScoped for Role {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl Role {
    /// 是否拥有某权限（支持通配）。
    #[must_use]
    pub fn allows(&self, required: &Permission) -> bool {
        self.permissions.iter().any(|p| p.matches(required))
    }

    /// 内置角色定义表（首次启动 migrate 时写入）。
    #[must_use]
    pub fn builtin_definitions() -> Vec<(&'static str, &'static str, &'static str, &'static [&'static str])> {
        vec![
            (builtin::SUPERADMIN, "平台超级管理员", "跨租户平台运维", &["*"]),
            (
                builtin::TENANT_ADMIN,
                "租户管理员",
                "本租户内全部管理权限",
                &[
                    "assets:*",
                    "agents:*",
                    "mcps:*",
                    "skills:*",
                    "models:*",
                    "findings:*",
                    "rules:*",
                    "scans:*",
                    "redteam:*",
                    "policies:*",
                    "quotas:*",
                    "alerts:*",
                    "cases:*",
                    "sources:*",
                    "parsers:*",
                    "integrations:*",
                    "alicloud:*",
                    "audit:read",
                    "audit:export",
                    "reports:*",
                    "settings:*",
                    "platform:admin",
                ],
            ),
            (
                builtin::SOC_ANALYST,
                "安全运营",
                "告警研判与案件处置",
                &[
                    "assets:read",
                    "findings:read",
                    "alerts:read",
                    "alerts:write",
                    "cases:read",
                    "cases:write",
                    "reports:read",
                    "reports:write",
                    "scans:read",
                    "redteam:read",
                ],
            ),
            (
                builtin::REDTEAM_ENGINEER,
                "红队工程师",
                "红队用例编排与执行",
                &[
                    "assets:read",
                    "findings:read",
                    "findings:write",
                    "redteam:*",
                    "scans:read",
                    "scans:execute",
                    "rules:read",
                    "reports:read",
                ],
            ),
            (
                builtin::AUDITOR,
                "审计员",
                "只读与审计导出",
                &["audit:read", "audit:export", "reports:read", "assets:read", "findings:read", "cases:read"],
            ),
            (
                builtin::VIEWER,
                "只读观察者",
                "控制台只读",
                &["assets:read", "findings:read", "alerts:read", "cases:read", "reports:read"],
            ),
            (
                builtin::ASSET_OWNER,
                "资产负责人",
                "仅本部门资产（ABAC 生效）",
                &["assets:read", "assets:write", "agents:read", "mcps:read", "findings:read"],
            ),
        ]
    }
}

impl AbacCondition {
    /// 是否为空条件（等价于无条件放行）。
    #[must_use]
    pub fn is_unconstrained(&self) -> bool {
        self.departments.is_empty()
            && self.data_classes.is_empty()
            && self.active_window.is_none()
            && self.source_cidrs.is_empty()
    }
}

impl TenantScoped for RoleBinding {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl RoleBinding {
    /// 当前是否有效。
    #[must_use]
    pub fn is_effective(&self) -> bool {
        self.expires_at.is_none_or(|e| e.as_datetime() > chrono::Utc::now())
    }
}

impl SubjectKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::ApiKey => "api-key",
            Self::Agent => "agent",
            Self::Service => "service",
        }
    }
}

impl TenantScoped for ApiKey {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl EffectivePermissions {
    /// 判定是否允许。
    #[must_use]
    pub fn allows(&self, required: &Permission) -> bool {
        self.superadmin || self.permissions.iter().any(|p| p.matches(required))
    }
}
