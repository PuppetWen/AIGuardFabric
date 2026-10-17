//! 由 `deadletter.rs` 拆分：`record_push_failure` 等 2 个函数（纯搬移，逻辑不变）。
use super::*;

/// 便捷：把失败的操作入队并把错误回报给调用方（不改变主流程的返回语义）。
///
/// 用法：`let outcome = adapter.push(&p).await; if let Err(e) = &outcome { queue.record_push_failure(...)?; }`
///
/// # Errors
/// 锁中毒。
pub fn record_push_failure(
    queue: &OfflineQueue,
    tenant_id: TenantId,
    adapter: &str,
    payload: &PushPayload,
    error: &DomainError,
) -> DomainResult<usize> {
    queue.enqueue(OfflineOp::push(tenant_id, adapter, payload, &error.to_string()))
}

/// 便捷：记录一次失败的同步。
///
/// # Errors
/// 锁中毒。
pub fn record_sync_failure(
    queue: &OfflineQueue,
    tenant_id: TenantId,
    adapter: &str,
    direction: SyncDirection,
    request: &PullRequest,
    error: &DomainError,
) -> DomainResult<usize> {
    queue.enqueue(OfflineOp::sync(tenant_id, adapter, direction, request, &error.to_string()))
}
