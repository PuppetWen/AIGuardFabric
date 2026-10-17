//! 由 `aggregate.rs` 拆分：`reduce_once` 等 2 个函数（纯搬移，逻辑不变）。
use super::*;

/// 便捷入口：一次性聚合一批告警（无抑制规则），返回报告。
///
/// 适合"批量回放/离线分析"；在线流式场景请直接用 [`AlertAggregator`] 的
/// `ingest` + `flush` 两段式。
///
/// # Errors
/// 配置非法或存在跨租户输入时返回错误。
pub fn reduce_once(
    tenant: TenantId,
    inputs: &[AlertInput],
    config: AggregationConfig,
    now: Timestamp,
) -> Result<ReduceReport, AggregateError> {
    let mut aggregator = AlertAggregator::new(config, Vec::new())?;
    aggregator.ingest_many(inputs)?;
    aggregator.flush(now);
    aggregator.report(tenant, now)
}

/// 某个 [`Alert`] 是否属于给定租户（便捷守卫）。
#[must_use]
pub fn alert_belongs_to(alert: &Alert, tenant: TenantId) -> bool {
    TenantScoped::tenant_id(alert) == tenant
}
