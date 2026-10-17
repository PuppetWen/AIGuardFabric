//! 由 `quota.rs` 拆分：`window_secs` 等 2 个函数（纯搬移，逻辑不变）。
use super::*;

/// 窗口长度（秒）；`Session`/`Total` 返回 `0`（不设 TTL）。
pub(crate) fn window_secs(quota: &Quota) -> i64 {
    quota.window.seconds().unwrap_or(0)
}

/// 构造"因存储不可达而拒绝"的结论。
pub(crate) fn hard_fail(quota: &Quota, mode: FailMode, reason: String, degraded: &mut bool) -> QuotaCheckOutcome {
    *degraded = true;
    QuotaCheckOutcome {
        check: QuotaCheck {
            allowed: false,
            exceeded_quota_id: Some(quota.id),
            dimension: Some(quota.dimension),
            scope: Some(quota.scope),
            used: -1,
            limit: quota.limit,
            soft_breached: Vec::new(),
            action: if matches!(quota.on_exceed, PolicyAction::Allow) { PolicyAction::Deny } else { quota.on_exceed },
            retry_after_secs: quota.window.seconds(),
        },
        degraded: true,
        reason: Some(format!("{}（失败方向 {}）", reason, mode.as_str())),
    }
}
