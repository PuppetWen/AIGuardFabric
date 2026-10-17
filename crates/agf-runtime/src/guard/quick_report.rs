//! 由 `guard.rs` 拆分：`quick_report` 等 3 个函数（纯搬移，逻辑不变）。
use super::*;

/// 便捷：对引擎做一次快速自检（离线演示入口）。
///
/// # Errors
/// 永不返回错误；保留 `Result` 以匹配 [`crate::engine::RuntimeEngine::guard_report`] 的签名风格。
pub fn quick_report<'a>(
    engine: &'a PolicyEngine,
    blocklist: &'a Blocklist,
    audit: &'a InterceptionAuditLog,
    config: &'a EngineConfig,
) -> GuardReport {
    SelfCheck::new(engine, blocklist, audit, config, TenantId::default_tenant()).run()
}

/// 便捷：端点 id 生成（`kind:name`）。
#[must_use]
pub fn endpoint_id(kind: &str, name: &str) -> String {
    format!("{kind}:{name}")
}

/// 便捷：由资产 id 生成端点 id。
#[must_use]
pub fn endpoint_id_of(kind: &str, id: Id) -> String {
    format!("{kind}:{id}")
}
