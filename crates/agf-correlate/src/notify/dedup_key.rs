//! 由 `notify.rs` 拆分：`dedup_key` 等 2 个函数（纯搬移，逻辑不变）。
use super::*;

/// 去重键：`租户|对象类型|对象 id|渠道 id`。
///
/// 语义：**同一案件在同一渠道只发一次**（§4.6 通知去重要求）。若需要"同一案件多次提醒"，
/// 应由上层的提醒轮次把轮次并入 `subject_kind`（如 `case-reminder-2`），而不是放开去重。
#[must_use]
pub fn dedup_key(tenant_id: TenantId, subject_kind: &str, subject_id: Id, channel_id: Id) -> String {
    format!("{tenant_id}|{subject_kind}|{subject_id}|{channel_id}")
}

/// 便捷：投递结论是否成功。
#[must_use]
pub fn is_delivered(delivery: &ChannelDelivery) -> bool {
    delivery.outcome == DeliveryOutcome::Delivered
}
