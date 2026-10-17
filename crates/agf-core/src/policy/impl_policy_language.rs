//! 由 `policy.rs` 拆分：`impl_PolicyLanguage`/`impl_Policy` 等 8 项（纯搬移，逻辑不变）。
use super::*;

use crate::enums::{InterceptPoint, PolicyAction};
use crate::ids::{Id, TenantId, TenantScoped};

impl PolicyLanguage {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Rego => "rego",
            Self::Cel => "cel",
            Self::Structured => "structured",
        }
    }

    /// 解析文本。
    ///
    /// # Errors
    /// 未知语言返回错误。
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "rego" | "opa" => Ok(Self::Rego),
            "cel" => Ok(Self::Cel),
            "structured" | "form" => Ok(Self::Structured),
            other => Err(format!("未知策略语言: {other}")),
        }
    }
}

impl TenantScoped for Policy {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl Policy {
    /// 计算策略内容哈希（用于签名与变更检测）。
    #[must_use]
    pub fn compute_hash(&self) -> String {
        let canonical = serde_json::json!({
            "id": self.id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "description": self.description,
            "deleted_at": self.deleted_at,
            "language": self.language.as_str(),
            "source": self.source,
            "structured": self.structured,
            "action": self.action.as_str(),
            "priority": self.priority,
            "enabled": self.enabled,
            "dry_run": self.dry_run,
            "scope_agent_ids": self.scope_agent_ids,
            "scope_departments": self.scope_departments,
            "quota_id": self.quota_id,
            "degrade_endpoint_id": self.degrade_endpoint_id,
            "intercept_points": self.intercept_points.iter().map(InterceptPoint::as_str).collect::<Vec<_>>(),
            "version": self.version,
        });
        crate::secret::content_hash(&serde_json::to_string(&canonical).unwrap_or_default())
    }

    /// 对所有拦截点是否生效（用于 UI 与自检提示）。
    #[must_use]
    pub fn covers_all_points(&self) -> bool {
        self.intercept_points.len() >= 3
    }

    /// 是否适用于指定资产（作用域判定）。
    #[must_use]
    pub fn applies_to(&self, agent_id: Option<&Id>, department: Option<&str>) -> bool {
        if !self.enabled {
            return false;
        }
        let agent_ok =
            self.scope_agent_ids.is_empty() || agent_id.is_some_and(|id| self.scope_agent_ids.iter().any(|s| s == id));
        let dept_ok = self.scope_departments.is_empty()
            || department.is_some_and(|d| self.scope_departments.iter().any(|s| s == d));
        agent_ok && dept_ok
    }
}

impl TenantScoped for PolicyVersion {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl PolicyDecision {
    /// 默认放行决策。
    #[must_use]
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            action: PolicyAction::Allow,
            policy_id: None,
            policy_name: None,
            reason: reason.into(),
            redact: false,
            dry_run: false,
            quota_id: None,
            degrade_endpoint_id: None,
            eval_micros: 0,
        }
    }

    /// 是否阻断请求。
    #[must_use]
    pub const fn is_blocking(&self) -> bool {
        matches!(self.action, PolicyAction::Deny | PolicyAction::Isolate | PolicyAction::CircuitBreak) && !self.dry_run
    }

    /// 是否需要改写载荷。
    #[must_use]
    pub const fn needs_redaction(&self) -> bool {
        !self.dry_run && (self.redact || matches!(self.action, PolicyAction::Redact))
    }

    /// 是否要求人工审批后放行。
    #[must_use]
    pub const fn needs_approval(&self) -> bool {
        !self.dry_run && matches!(self.action, PolicyAction::Approval)
    }
}

/// 域名匹配：支持精确、后缀通配（`*.example.com`）与全局通配（`*`）。
#[must_use]
pub fn domain_matches(pattern: &str, domain: &str) -> bool {
    let p = pattern.trim().to_ascii_lowercase();
    let d = domain.trim().to_ascii_lowercase();
    if p == "*" {
        return true;
    }
    if let Some(suffix) = p.strip_prefix("*.") {
        return d == suffix || d.ends_with(&format!(".{suffix}"));
    }
    if let Some(suffix) = p.strip_prefix('.') {
        return d == suffix || d.ends_with(&format!(".{suffix}"));
    }
    p == d
}

/// 路径前缀匹配（Windows 反斜杠归一化 + 大小写不敏感）。
#[must_use]
pub fn path_matches_prefix(pattern: &str, path: &str) -> bool {
    let norm = |s: &str| s.replace('\\', "/").to_ascii_lowercase();
    let p = norm(pattern);
    let v = norm(path);
    if p == "*" {
        return true;
    }
    v == p || v.starts_with(&format!("{}/", p.trim_end_matches('/')))
}

/// 命令黑名单匹配（子串或正则；正则以 `re:` 前缀声明）。
///
/// # Errors
/// 当以 `re:` 声明但正则非法时返回错误描述。
pub fn command_matches_deny(pattern: &str, command: &str) -> Result<bool, String> {
    if let Some(re_src) = pattern.strip_prefix("re:") {
        let re = regex::Regex::new(re_src).map_err(|e| format!("命令黑名单正则非法 {re_src}: {e}"))?;
        return Ok(re.is_match(command));
    }
    Ok(command.to_ascii_lowercase().contains(&pattern.to_ascii_lowercase()))
}
