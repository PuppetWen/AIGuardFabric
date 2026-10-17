//! 由 `policy.rs` 拆分：`pattern_matches` 等 2 个函数（纯搬移，逻辑不变）。
use super::*;

/// 工具/命令类模式的匹配（`re:` 前缀为正则，否则大小写不敏感子串）。
pub(crate) fn pattern_matches(pattern: &str, text: &str) -> bool {
    command_matches_deny(pattern, text).unwrap_or(false)
}

/// 便捷：构造一个作用域为全租户的结构化策略（测试与内置策略使用）。
#[must_use]
pub fn structured_policy(
    tenant_id: TenantId,
    name: impl Into<String>,
    structured: StructuredCondition,
    action: PolicyAction,
    priority: u32,
) -> Policy {
    let now = agf_core::time::Timestamp::now();
    Policy {
        id: Id::new(),
        tenant_id,
        name: name.into(),
        description: String::new(),
        language: PolicyLanguage::Structured,
        source: String::new(),
        structured,
        action,
        priority,
        intercept_points: vec![],
        scope_agent_ids: vec![],
        scope_departments: vec![],
        enabled: true,
        dry_run: false,
        quota_id: None,
        degrade_endpoint_id: None,
        content_hash: String::new(),
        signature: String::new(),
        version: 1,
        created_at: now,
        updated_at: now,
        deleted_at: None,
    }
}
