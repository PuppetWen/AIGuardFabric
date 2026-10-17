//! 多模型路由：按策略选端点、执行"数据不出域"门禁、产出有序降级链。
//!
//! ## 硬性过滤（先于排序）
//!
//! 1. **启用**：`enabled == false` 一律排除；
//! 2. **租户**：只保留 `tenant_id == ctx.tenant` 或"全局端点"（`TenantId::default_tenant()`）；
//! 3. **数据分级**：`accepts_data_class(ctx.data_class)`——`DataClass::Restricted`
//!    只可能落在 `local_deployment == true` 的端点上（数据不出域）；
//! 4. **能力**：`require_streaming` → `supports_streaming`；`require_tools` → `supports_tools`；
//!    `require_vision` → `modalities` 含 [`Modality::Vision`]；
//! 5. **锁定模型**：`ctx.pinned_model` 非空时，只保留 id 或 model 名匹配的端点。
//!
//! ## 排序策略（全部确定性，无随机数）
//!
//! | 策略 | 排序键（依次比较） | 适用场景 |
//! |---|---|---|
//! | [`RoutingStrategy::CostFirst`] | 估算总费用 ↑ → priority ↑ → id ↑ | 默认；成本敏感 |
//! | [`RoutingStrategy::LatencyFirst`] | priority ↑ → 上下文窗口 ↓ → id ↑ | 交互式会话（priority 由运维按实测延迟标定） |
//! | [`RoutingStrategy::QualityFirst`] | 上下文窗口 ↓ → priority ↑ → id ↑ | 研判/报告等质量优先任务 |
//! | [`RoutingStrategy::LocalFirst`] | `local_deployment` ↓ → priority ↑ → id ↑ | 数据合规优先 |
//! | [`RoutingStrategy::RoundRobin`] | 以原子计数器轮转（请求间轮换，进程内确定） | 多端点负载分摊 |
//!
//! 所有排序都以 `id` 作为最后的 tie-breaker，保证**同一输入必定得到同一顺序**（可测）。

pub(crate) use std::sync::atomic::AtomicUsize;
pub(crate) use std::sync::atomic::Ordering;

pub(crate) use agf_core::enums::DataClass;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::model::Modality;
pub(crate) use agf_core::model::ModelEndpoint;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use crate::wire::ChatRequest;

#[cfg(test)]
pub(crate) use agf_core::enums::LlmProvider;

#[cfg(test)]
pub(crate) use agf_core::ids::Id;

#[cfg(test)]
pub(crate) use agf_core::model::ModelPricing;

#[cfg(test)]
pub(crate) use agf_core::time::Timestamp;

#[cfg(test)]
pub(crate) use pretty_assertions::assert_eq as eq;

#[allow(unused_imports)]
pub use cost_key::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 路由策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoutingStrategy {
    /// 成本优先。
    CostFirst,
    /// 延迟优先。
    LatencyFirst,
    /// 质量优先。
    QualityFirst,
    /// 本地优先（数据合规）。
    LocalFirst,
    /// 轮询（多端点分摊）。
    RoundRobin,
}

/// 路由上下文。
#[derive(Debug, Clone)]
pub struct RoutingContext {
    /// 租户。
    pub tenant: TenantId,
    /// 数据分级（决定"数据不出域"）。
    pub data_class: DataClass,
    /// 锁定的模型（端点 id 或 model 名；`None` = 不锁定）。
    pub pinned_model: Option<String>,
    /// 策略。
    pub strategy: RoutingStrategy,
    /// 是否必须支持流式。
    pub require_streaming: bool,
    /// 是否必须支持工具调用。
    pub require_tools: bool,
    /// 是否必须支持视觉（请求里含图片）。
    pub require_vision: bool,
    /// 是否允许降级（false 时链路只保留第一个候选）。
    pub allow_fallback: bool,
}

/// 端点被排除的原因（控制台排障 + 覆盖终态回写）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exclusion {
    /// 端点显示名。
    pub endpoint: String,
    /// 原因。
    pub reason: String,
}

/// 一次路由的决策记录（审计与排障）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingDecision {
    /// 策略。
    pub strategy: RoutingStrategy,
    /// 数据分级。
    pub data_class: DataClass,
    /// 候选端点（有序降级链）。
    pub chain: Vec<String>,
    /// 被排除的端点及原因。
    pub excluded: Vec<Exclusion>,
}

/// 模型路由器。
#[derive(Debug)]
pub struct ModelRouter {
    endpoints: Vec<ModelEndpoint>,
    round_robin: AtomicUsize,
}

mod cost_key;
mod impl_routing_strategy;
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests;
