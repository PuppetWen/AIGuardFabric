//! [`AiGateway`]：统一网关编排器。
//!
//! ## 一次调用的完整链路（每一步都有测试覆盖）
//!
//! ```text
//! chat(ctx, req)
//!   │
//!   ├─ 0 写入周期幂等检查（预算守卫投影）
//!   ├─ 1 内容安全预筛  screen_request
//!   │      └─ Block → Err(PolicyDenied)【零成本拦截，不触达厂商】
//!   │      └─ Redact → 用改写后的请求继续（缓存/上游都只看改写结果）
//!   ├─ 2 路由          router.select(ctx, &req) → 有序降级链
//!   │      └─ 空链 → Err(Config)
//!   ├─ 3 缓存查询      is_cacheable ? cache.get : skip
//!   │      └─ 命中 → 当前后筛与输出上限 → 返回（cached=true，cost_micro=0）
//!   ├─ 4 逐端点调用    熔断门禁 + 超时 + 重试（provider 内部）
//!   │      ├─ 缺凭据 / 失败 → 记录后沿链降级（fallback_used=true）
//!   │      └─ 成功 → 继续
//!   ├─ 5 后置过滤      screen_response（脱敏/判定泄露）
//!   ├─ 6 计量          meter.record(...) → UsageRecord
//!   └─ 7 缓存写入      should_write_cache ?
//! ```
//!
//! ## 与 Mock 的关系
//!
//! `provider_for` 在以下任一条件下返回 [`MockProvider`]：
//! 1. `self.mock_mode`（`AGF_MOCK_MODE=1`）；
//! 2. 端点 `provider == LlmProvider::Mock`；
//! 3. 端点**没有任何凭据引用**（`credential_ref.is_none()`）。
//!
//! 第 3 条是"平台永远可启动"的关键：真实厂商端点缺凭据时不报错，
//! 而是改用 Mock 合成回复，并把 `GatewayResponse.mocked` 置为 `true`。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Arc;

pub(crate) use std::time::Instant;

pub(crate) use agf_core::enums::DataClass;
pub(crate) use agf_core::enums::LlmProvider;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::model::ModelEndpoint;
pub(crate) use agf_core::model::UsageRecord;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use futures::future::Either;

pub(crate) use futures::StreamExt as _;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use tracing::debug;
pub(crate) use tracing::info;
pub(crate) use tracing::warn;

pub(crate) use crate::cache::CacheStats;
pub(crate) use crate::cache::CachedResponse;
pub(crate) use crate::cache::ExactCache;
pub(crate) use crate::cache::SemanticCache;
pub(crate) use crate::cache::is_cacheable;
pub(crate) use crate::cache::should_write_cache;

pub(crate) use crate::meter::BudgetGuard;
pub(crate) use crate::meter::CostBreakdown;
pub(crate) use crate::meter::Meter;
pub(crate) use crate::meter::breakdown;

pub(crate) use crate::mock::MockProvider;

pub(crate) use crate::provider::AnthropicProvider;
pub(crate) use crate::provider::BedrockProvider;
pub(crate) use crate::provider::CredentialResolver;
pub(crate) use crate::provider::EnvCredentialResolver;
pub(crate) use crate::provider::GeminiProvider;
pub(crate) use crate::provider::OpenAiCompatProvider;
pub(crate) use crate::provider::ProviderAdapter;
pub(crate) use crate::provider::ProviderDescriptor;
pub(crate) use crate::provider::ProviderStream;

pub(crate) use crate::router::ModelRouter;
pub(crate) use crate::router::RoutingContext;
pub(crate) use crate::router::RoutingStrategy;

pub(crate) use crate::screen::ContentScreen;
pub(crate) use crate::screen::NoopScreen;
pub(crate) use crate::screen::ScreenOutcome;
pub(crate) use crate::screen::ScreenVerdict;

pub(crate) use crate::wire::ChatRequest;
pub(crate) use crate::wire::ChatResponse;
pub(crate) use crate::wire::MessageContent;
pub(crate) use crate::wire::Role;
pub(crate) use crate::wire::StreamAccumulator;
pub(crate) use crate::wire::StreamChunk;
pub(crate) use crate::wire::Usage;

#[cfg(test)]
pub(crate) use crate::cache::InMemorySemanticCache;

#[cfg(test)]
pub(crate) use crate::provider::StaticCredentialResolver;

#[cfg(test)]
pub(crate) use crate::screen::KeywordScreen;

#[cfg(test)]
pub(crate) use crate::wire::ChatMessage;

#[cfg(test)]
pub(crate) use agf_core::model::Modality;
#[cfg(test)]
pub(crate) use agf_core::model::ModelPricing;

#[cfg(test)]
pub(crate) use pretty_assertions::assert_eq as eq;

#[allow(unused_imports)]
pub use impl_ai_gateway_2::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests_2::*;

/// 一次调用的上下文（租户/会话/Agent 身份 + 数据分级 + 缓存与预算开关）。
#[derive(Debug, Clone)]
pub struct CallContext {
    /// 租户。
    pub tenant: TenantId,
    /// 会话 id（缺省自动生成，用于会话级计量与缓存隔离）。
    pub session_id: String,
    /// Agent 资产 id（可选）。
    pub agent_id: Option<Id>,
    /// 数据分级（决定"数据不出域"约束）。
    pub data_class: DataClass,
    /// 显式允许缓存（可豁免温度检查，但**不能**豁免数据分级与副作用检查）。
    pub allow_cache: bool,
    /// 禁止本次请求读取或写入缓存，优先于确定性采样及 allow_cache。
    pub disable_cache: bool,
    /// 路由策略。
    pub strategy: RoutingStrategy,
    /// 预算守卫。
    pub budget: BudgetGuard,
    /// 本次调用超时（秒），`None` 用 [`crate::DEFAULT_TIMEOUT_SECS`]。
    pub timeout_secs: Option<u64>,
    /// 是否允许降级（false 时只用链上第一个端点）。
    pub allow_fallback: bool,
}

/// 端点展示视图（控制台"接入管理"页）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointView {
    /// 端点 id。
    pub id: Id,
    /// 显示名。
    pub name: String,
    /// 厂商。
    pub provider: LlmProvider,
    /// 模型。
    pub model: String,
    /// 协议族。
    pub protocol: String,
    /// 适配器注册名。
    pub adapter: String,
    /// 是否启用。
    pub enabled: bool,
    /// 是否本地部署（可承接受限数据）。
    pub local_deployment: bool,
    /// 数据分级上限。
    pub max_data_class: DataClass,
    /// 单价（微元/1K token）。
    pub pricing: agf_core::model::ModelPricing,
    /// 是否具备凭据（false 时**运行时会自动走 Mock**）。
    pub credential_configured: bool,
    /// 是否 Mock 模式。
    pub mocked: bool,
    /// 是否当前可用（启用 + 凭据/ Mock）。
    pub usable: bool,
    /// 不可用原因。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// 网关响应。
#[derive(Debug, Clone)]
pub struct GatewayResponse {
    /// 模型回复。
    pub response: ChatResponse,
    /// 实际使用的端点 id。
    pub endpoint_id: Id,
    /// 实际使用的厂商。
    pub provider: LlmProvider,
    /// 实际使用的模型。
    pub model: String,
    /// token 用量。
    pub usage: Usage,
    /// 本次费用（微元；缓存命中为 0）。
    pub cost_micro: u64,
    /// 费用明细。
    pub cost: CostBreakdown,
    /// 是否命中语义缓存。
    pub cached: bool,
    /// 是否走的是 Mock 模型。
    pub mocked: bool,
    /// 是否发生了降级（首个候选端点失败后切到后续端点）。
    pub fallback_used: bool,
    /// 总耗时（毫秒，含降级重试）。
    pub latency_ms: u64,
    /// 内容安全裁决摘要。
    pub screening: ScreeningSummary,
    /// 计量记录（已计入 [`Meter`]）。
    pub usage_record: UsageRecord,
}

/// 内容安全裁决摘要（审计用；**不含原文**）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScreeningSummary {
    /// 前置过滤命中的规则 id。
    pub request_rules: Vec<String>,
    /// 后置过滤命中的规则 id。
    pub response_rules: Vec<String>,
    /// Actual response Block verdict; redaction alone never sets this flag.
    #[serde(default)]
    pub response_blocked: bool,
    /// 前置脱敏条目数。
    pub request_redactions: usize,
    /// 后置脱敏条目数。
    pub response_redactions: usize,
    /// 是否被过滤改写过。
    pub mutated: bool,
}

/// 统一网关。
pub struct AiGateway {
    router: Arc<ModelRouter>,
    credentials: Arc<dyn CredentialResolver>,
    cache: Arc<ExactCache>,
    meter: Arc<Meter>,
    screen: Arc<dyn ContentScreen>,
    /// 覆盖 `AGF_MOCK_MODE` 的显式开关（`None` = 跟随环境变量）。
    mock_mode_override: Option<bool>,
    /// 已构造的提供商实例（按端点缓存，保留熔断状态）。
    providers: parking_lot::Mutex<BTreeMap<String, Arc<dyn ProviderAdapter>>>,
    /// Prompt 模板（名称 → 内容），供 [`AiGateway::analyze`] 使用。
    prompts: BTreeMap<String, String>,
    /// 分析用模型名（缺省用路由链第一个端点）。
    analysis_model: Option<String>,
    /// 会话→端点映射，保证多轮会话尽量落在同一端点（KV 缓存友好）。
    session_affinity: parking_lot::Mutex<BTreeMap<String, Id>>,
}

/// 预筛结果：改写后的请求 + 裁决摘要。
pub(crate) struct Prepared {
    /// 预筛（可能脱敏）后的请求。
    request: ChatRequest,
    /// 内容安全裁决摘要（会随响应回传审计）。
    screening: ScreeningSummary,
}

mod deferred;
pub use deferred::{DeferredCall, SettlementGuard};
mod deferred_components;
#[cfg(test)]
mod deferred_components_tests;
pub use deferred_components::{
    DeferredComponentAnchor, DeferredComponentOutcome, DeferredEvidence, MAX_CHAT_COMPONENTS,
};
mod anthropic_native;
mod streaming;
pub(crate) use anthropic_native::{native_response_view, native_stream_view};
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod cache_response_tests;
mod impl_ai_gateway;
mod impl_ai_gateway_2;
mod impl_call_context;
mod response;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod security_tests;
#[cfg(test)]
mod settlement_screen_tests;
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests;
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests_2;

/// 流式调用选中端点和一次性计量结果；只有完整读取流才会收到回执。
#[derive(Debug)]
pub struct StreamMetadata {
    /// 实际选中端点。
    pub endpoint_id: Id,
    /// 实际上游模型名。
    pub model: String,
    /// 本次是否为模拟调用。
    pub mocked: bool,
    /// 该请求的最终计量记录，与会话内的其他并发请求隔离。
    pub usage: tokio::sync::oneshot::Receiver<UsageRecord>,
}
