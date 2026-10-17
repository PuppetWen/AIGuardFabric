#![forbid(unsafe_code)]
//! # agf-aigw — AIGuardFabric 大模型统一网关
//!
//! 本 crate 实现产品规格 §4.4「大模型统一网关」：多厂商适配、统一协议转换、
//! 流式转发、多模型路由与自动降级、语义缓存、Prompt 模板渲染、成本计量、
//! 内容安全前置过滤，以及**无 Key 时的 Mock 降级**。
//!
//! ## 模块地图
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`wire`] | 统一协议（canonical wire format）：请求/响应/流式分片，纯 serde |
//! | [`convert`] | canonical ↔ 厂商格式转换 + SSE 增量解析器（纯函数） |
//! | [`provider`] | [`provider::ProviderAdapter`] 契约 + OpenAI 兼容 / Anthropic / Gemini / Bedrock 实现 |
//! | [`router`] | [`router::ModelRouter`]：按策略选端点、数据分级门禁、降级链 |
//! | [`cache`] | [`cache::SemanticCache`]：精确指纹缓存（内存 / Redis）与可缓存性判定 |
//! | [`meter`] | token/成本计量、[`meter::Meter`] 汇总、[`meter::BudgetGuard`] 预算守卫 |
//! | [`screen`] | [`screen::ContentScreen`] 内容安全前置/后置过滤 |
//! | [`gateway`] | [`gateway::AiGateway`] 编排器：预筛→路由→缓存→熔断重试→降级→计量→回写 |
//! | [`mock`] | [`mock::MockProvider`] 离线 Mock 模型与录制响应 fixtures |
//!
//! ## 降级行为（§12.4 强制要求）
//!
//! | 依赖/条件 | 网关行为 | 用户可见结果 |
//! |---|---|---|
//! | 无任何模型端点（`enabled = false` 或未登记） | 返回 `DomainError::Config`，提示"无可用模型端点" | 控制台"接入管理"页显示端点为空；**不 panic** |
//! | 端点缺凭据（`credential_ref` 为空或解析失败） | **自动降级到 Mock**：[`mock::MockProvider`] 合成确定性回复 | `GatewayResponse.mocked = true`，响应/审计标注 Mock |
//! | `AGF_MOCK_MODE=1` | **全部请求走 Mock**，一行真实 HTTP 都不发 | `mocked = true`；适配器 health = `Degraded` |
//! | 首个端点失败/超时 | 熔断计数 + 重试，随后沿降级链切下一个端点 | `fallback_used = true`，`endpoint_id` 为实际端点 |
//! | 全部端点失败 | 返回最后一次错误（`DependencyUnavailable`/`Timeout`） | 调用方按 RFC 9457 处理；**不返回半截响应** |
//! | Redis 不可用 | 语义缓存自动降级为纯内存实现 | 功能不中断；日志告警；`cached=false` |
//! | 数据库不可用 | 计量记录留在内存（[`meter::Meter`]），由上层决定是否补写 | 网关本身不依赖数据库即可工作 |
//! | 内容安全预筛命中 | `ScreenVerdict::Block` → 直接返回 `PolicyDenied`，**不触达任何厂商** | 审计事件记录规则名 |
//! | 预算超限 | [`meter::BudgetGuard::ensure_within_budget`] 返回 `QuotaExceeded` | 调用前拒绝，不产生上游费用 |
//! | Bedrock SigV4 签名 | **真实实现**（本 crate 自行签 [`provider::BedrockProvider`]），无桩降级 | 见该模块文档"局限"一节 |
//!
//! ## Mock 实现位置（§12.4 要求逐适配器写明）
//!
//! | 适配器 | 真实实现 | Mock 实现位置 |
//! |---|---|---|
//! | OpenAI 兼容（OpenAI/Azure/百炼/方舟/混元/文心/Kimi/DeepSeek/GLM/MiniMax/Ollama/vLLM/自定义） | [`provider::OpenAiCompatProvider`] | [`mock::MockProvider`]（`src/mock.rs`），由 [`gateway::AiGateway`] 在缺凭据时自动接管 |
//! | Anthropic | [`provider::AnthropicProvider`] | 同上 |
//! | Gemini | [`provider::GeminiProvider`] | 同上 |
//! | Bedrock | [`provider::BedrockProvider`]（自签 SigV4） | 同上 |
//! | `LlmProvider::Mock` | — | [`mock::MockProvider`] |
//!
//! ## 为什么"无 Key 也不报错"
//!
//! 网关在**发出任何网络请求之前**做三层判断
//! （[`provider::ProviderAdapter`] 实现内的 `api_key()` 门禁 +
//! [`gateway::AiGateway::chat`] 的 Mock 接管 + [`provider`] 的 `Client` 注入）：
//!
//! 1. `AGF_MOCK_MODE=1` → 直接构造 [`mock::MockProvider`]；
//! 2. 端点凭据缺失（[`provider::CredentialResolver`] 返回 `None`）→ Mock 接管；
//! 3. 端点 `provider == LlmProvider::Mock` → 直接 Mock。
//!
//! 因此 §11 阶段一验收准则 5「无 Key 时平台自动降级不报错」可离线演示。

pub mod cache;
pub mod convert;
pub mod gateway;
pub mod meter;
pub mod mock;
pub mod provider;
pub mod router;
pub mod screen;
pub mod semantic;
pub mod wire;

pub use cache::{
    CacheStats, CachedResponse, ExactCache, InMemorySemanticCache, RedisSemanticCache, SemanticCache, exact_cache_key,
    is_cacheable,
};
pub use convert::{
    SseDecoder, SseEvent, from_anthropic_response, from_gemini_response, from_openai_response, to_anthropic_body,
    to_gemini_body, to_openai_body,
};
pub use gateway::{AiGateway, CallContext, EndpointView, GatewayResponse, ScreeningSummary};
pub use meter::{BudgetGuard, CostBreakdown, Meter, MeterSnapshot, MeterTotals};
pub use mock::{MockIntent, MockProvider, RecordedFixture};
pub use provider::{
    AnthropicProvider, AwsCredentials, BedrockProvider, CredentialResolver, EnvCredentialResolver, GeminiProvider,
    MockCredentialResolver, OpenAiCompatProvider, ProviderAdapter, ProviderDescriptor, ProviderStream,
    StaticCredentialResolver, default_base_url, sign_sigv4,
};
pub use router::{ModelRouter, RoutingContext, RoutingDecision, RoutingStrategy};
pub use screen::{
    CompositeScreen, ContentScreen, KeywordAction, KeywordCategory, KeywordScreen, NoopScreen, ScreenOutcome,
    ScreenRule, ScreenVerdict,
};
pub use wire::{
    ChatDelta, ChatMessage, ChatRequest, ChatResponse, ContentPart, FinishReason, MessageContent, ResponseFormat, Role,
    StreamAccumulator, StreamChunk, ToolCall, ToolDefinition, Usage,
};

/// 平台版本。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 网关默认请求超时（秒）。
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Mock 模式环境变量名。
pub const ENV_MOCK_MODE: &str = "AGF_MOCK_MODE";

/// 判断是否处于 Mock 模式（`AGF_MOCK_MODE=1`）。
///
/// 该判断是"平台永远可启动、离线可演示"的第一道开关：为真时网关
/// **不会发出任何真实 HTTP 请求**。
#[must_use]
pub fn mock_mode_enabled() -> bool {
    std::env::var(ENV_MOCK_MODE).is_ok_and(|v| {
        let v = v.trim();
        v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn version_is_exposed() {
        assert!(!VERSION.is_empty());
        assert!(!ENV_MOCK_MODE.is_empty());
        assert_eq!(DEFAULT_TIMEOUT_SECS, 60);
    }

    #[test]
    fn mock_mode_flag_parsing() {
        // 环境变量是进程级共享状态，这里只验证"未设置"的稳定分支；
        // 真值分支由显式传参路径（`AiGateway::mock_mode`）覆盖。
        let before = std::env::var(ENV_MOCK_MODE).ok();
        if before.is_none() {
            assert!(!mock_mode_enabled());
        }
    }
}
