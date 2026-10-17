//! 计量与预算守卫：token 会计、成本（微元）、用量记录、按租户/Agent/会话累计。
//!
//! ## 计费口径
//!
//! - 单位：**微元**（1e-6 元），全整数运算，避免浮点误差；
//! - 单价来自 [`agf_core::model::ModelPricing`]（每 1K token）；
//! - 命中厂商侧 prompt cache 的 token 按 `cached_prompt_micro_per_1k` 计价，
//!   该字段为 0 时退回常规单价（与 [`crate::cache::cost_micro`] 同一口径）；
//! - Anthropic 缓存写入按常规输入单价的 5 分钟 1.25 倍、1 小时 2 倍计价；
//! - Mock / 本地免费模型（`pricing.is_free()`）计费为 0，但仍**记录用量**
//!   （否则离线演示看不到 token 消耗）。
//!
//! ## 为什么记账与实际收费分离
//!
//! [`Meter`] 是**内存事实来源**：网关不依赖数据库即可工作（§12.4 降级要求）。
//! 落库由上层（`agf-storage`）消费 [`UsageRecord`] 完成，网关不阻塞在写库上。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Arc;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::enums::LlmProvider;
pub(crate) use agf_core::model::ModelEndpoint;
pub(crate) use agf_core::model::UsageRecord;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use parking_lot::Mutex;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use crate::wire::Usage;

#[cfg(test)]
pub(crate) use agf_core::enums::DataClass;

#[cfg(test)]
pub(crate) use agf_core::model::Modality;
#[cfg(test)]
pub(crate) use agf_core::model::ModelPricing;

#[cfg(test)]
pub(crate) use pretty_assertions::assert_eq as eq;

#[allow(unused_imports)]
pub use impl_cost_breakdown::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 成本明细（微元）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostBreakdown {
    /// 常规输入 token 费用。
    pub prompt_micro: u64,
    /// 命中 prompt cache 的输入 token 费用。
    pub cached_prompt_micro: u64,
    /// Provider prompt-cache write charge (including Anthropic TTL premium).
    #[serde(default)]
    pub cache_write_prompt_micro: u64,
    /// 输出 token 费用。
    pub completion_micro: u64,
    /// 合计。
    pub total_micro: u64,
}

/// 计量键（三级：租户 / Agent / 会话）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MeterKey {
    /// 租户级。
    Tenant(TenantId),
    /// Agent 级。
    Agent(TenantId, Id),
    /// 会话级。
    Session(TenantId, String),
}

/// 单个键的累计值。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeterTotals {
    /// 调用次数。
    pub calls: u64,
    /// 缓存命中次数（不计上游费用）。
    pub cache_hits: u64,
    /// Mock 调用次数。
    pub mocked_calls: u64,
    /// 输入 token。
    pub prompt_tokens: u64,
    /// 输出 token。
    pub completion_tokens: u64,
    /// 缓存读取 token。
    pub cached_tokens: u64,
    /// Provider prompt-cache writes.
    #[serde(default)]
    pub cache_write_tokens: u64,
    /// One-hour subset of provider prompt-cache writes.
    #[serde(default)]
    pub cache_write_1h_tokens: u64,
    /// 费用（微元）。
    pub cost_micro: u64,
    /// 累计上游耗时（毫秒）。
    pub latency_ms: u64,
}

/// 计量快照（控制台"成本计量"页直接展示）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MeterSnapshot {
    /// A bounded committed projection refused an update; durable Usage/checkpoints remain authoritative.
    #[serde(default)]
    pub committed_projection_incomplete: bool,
    /// Fine-grained committed groups merged into the explicit other group; totals stay exact.
    #[serde(default)]
    pub committed_groups_merged: bool,
    /// 全局合计。
    pub total: MeterTotals,
    /// 按租户。
    pub by_tenant: BTreeMap<String, MeterTotals>,
    /// 按 Agent。
    pub by_agent: BTreeMap<String, MeterTotals>,
    /// 按会话（仅保留最近写入的键，由上层裁剪）。
    pub by_session: BTreeMap<String, MeterTotals>,
    /// 按厂商。
    pub by_provider: BTreeMap<String, MeterTotals>,
    /// 按模型。
    pub by_model: BTreeMap<String, MeterTotals>,
    /// 快照时间。
    pub generated_at: Option<Timestamp>,
}

/// 内存计量器。
#[derive(Debug, Clone, Default)]
pub struct Meter {
    inner: Arc<Mutex<MeterInner>>,
}

#[derive(Debug, Default)]
struct MeterInner {
    total: MeterTotals,
    by_tenant: BTreeMap<String, MeterTotals>,
    by_agent: BTreeMap<String, MeterTotals>,
    by_session: BTreeMap<String, MeterTotals>,
    by_provider: BTreeMap<String, MeterTotals>,
    by_model: BTreeMap<String, MeterTotals>,
    /// 最近若干条用量记录（环形裁剪，上限 [`Meter::MAX_RECENT`]）。
    recent: Vec<UsageRecord>,
    seen: BTreeMap<(TenantId, Id), String>,
    committed: BTreeMap<TenantId, CommittedMeterProjection>,
    committed_projection_incomplete: bool,
}

/// 预算守卫：调用**之前**判断预估费用是否超限。
///
/// 与配额（`agf-core::quota`，按周期计量）不同，预算守卫是"单次/累计上限"的
/// 前置短路：宁可少调一次，也不产生不可控的上游费用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetGuard {
    /// 单次调用费用上限（微元，0 = 不限）。
    pub max_single_micro: u64,
    /// 累计费用上限（微元，0 = 不限）。
    pub max_total_micro: u64,
}

mod committed;
mod projection;
pub use projection::CommittedMeterProjection;
mod impl_cost_breakdown;
pub use committed::UsageInput;
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests;

#[cfg(test)]
mod tests_committed;
