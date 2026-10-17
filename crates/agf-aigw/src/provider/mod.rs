//! 厂商适配器：统一 [`ProviderAdapter`] 契约 + OpenAI 兼容 / Anthropic / Gemini / Bedrock 实现。
//!
//! ## 网络调用的铁律
//!
//! **所有 `reqwest` 调用都在"凭据 + Mock 开关"双门禁之后**：
//!
//! ```text
//! complete()/stream()
//!   ├─ mock_mode_enabled() 或 provider == Mock  → 绝不进这里（由 gateway 层截住）
//!   ├─ api_key() == None（未配置 / 解密失败）    → Err(NotImplemented) 【不联网】
//!   └─ 已配置                                    → 真实 HTTP
//! ```
//!
//! 因此："无 Key 时平台自动降级不报错"是由"网关在缺凭据时用 [`crate::mock::MockProvider`]
//! 接管"实现的，而适配器自身在缺凭据时返回的是**可降级错误**
//! （`DomainError::NotImplemented` 的 `is_degradable() == true`），
//! 不会把不可恢复的错误抛给调用方。
//!
//! ## 四大适配器的差异落点
//!
//! | 适配器 | 请求路径 | 鉴权 | 请求体构造 | 响应解析 |
//! |---|---|---|---|---|
//! | [`OpenAiCompatProvider`] | `{base_url}/chat/completions` | `Authorization: Bearer`（Azure 用 `api-key`） | [`crate::convert::to_openai_body`] | [`crate::convert::from_openai_response`] |
//! | [`AnthropicProvider`] | `{base_url}/messages` | `x-api-key` + `anthropic-version` | [`crate::convert::to_anthropic_body`] | [`crate::convert::from_anthropic_response`] |
//! | [`GeminiProvider`] | `{base_url}/models/{model}:streamGenerateContent?alt=sse` | `x-goog-api-key` | [`crate::convert::to_gemini_body`] | [`crate::convert::from_gemini_response`] |
//! | [`BedrockProvider`] | `https://bedrock-runtime.{region}.amazonaws.com/model/{model}/converse[-stream]` | 自签 AWS SigV4 | [`to_bedrock_converse_body`] | [`from_bedrock_converse_response`] |
//!
//! ## Bedrock 的"真实实现"与局限
//!
//! Bedrock **不使用官方 `aws-sdk-bedrockruntime`**（那会把 SDK 版本、重试策略、
//! 凭据链一次性绑进本 crate），而是按 AWS 官方文档自行构造并**签名**请求：
//!
//! - 签名算法：`AWS4-HMAC-SHA256`，签名头 `host;x-amz-content-sha256;x-amz-date[;x-amz-security-token]`；
//! - 规范请求 = `POST\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}`；
//! - 派生密钥 = `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")`。
//!
//! 局限（已登记 TODO 锚点，属"需要真实凭据/外网"的验证项）：
//! 1. 只实现 `converse` / `converse-stream` 两个动作，未覆盖 `invokeModel` 的
//!    厂商私有请求体（Anthropic on Bedrock 的 `anthropic_version` 差异）；
//! 2. 凭据只支持"显式 AK/SK（含 STS token）+ 环境变量"，未接入 EC2/ECS/SSO 凭据链；
//! 3. Bedrock 的 `converse-stream` 使用 AWS Event Stream 二进制帧而非 SSE，
//!    这里实现的是帧解析器，**未经真实端点验证**（不校验帧 CRC）。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::pin::Pin;

pub(crate) use std::sync::Arc;

pub(crate) use std::time::Duration;

pub(crate) use agf_core::adapter::Adapter;
pub(crate) use agf_core::adapter::AdapterCapability;
pub(crate) use agf_core::adapter::AdapterConfig;
pub(crate) use agf_core::adapter::AdapterDescriptor;
pub(crate) use agf_core::adapter::AdapterHealth;
pub(crate) use agf_core::adapter::CircuitSnapshot;
pub(crate) use agf_core::adapter::PullRequest;
pub(crate) use agf_core::adapter::PullResponse;
pub(crate) use agf_core::adapter::PushPayload;
pub(crate) use agf_core::adapter::SyncDirection;
pub(crate) use agf_core::adapter::SyncOutcome;

pub(crate) use agf_core::enums::DataClass;
pub(crate) use agf_core::enums::HealthState;
pub(crate) use agf_core::enums::LlmProvider;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;

pub(crate) use agf_core::model::ModelEndpoint;

pub(crate) use agf_core::secret::mask_default;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use async_trait::async_trait;

use base64::Engine as _;

pub(crate) use base64::engine::general_purpose::STANDARD as B64;

pub(crate) use futures::Stream;

pub(crate) use serde_json::Map;
pub(crate) use serde_json::Value;
pub(crate) use serde_json::json;

pub(crate) use sha2::Digest;
pub(crate) use sha2::Sha256;

pub(crate) use tracing::debug;
pub(crate) use tracing::warn;

pub(crate) use crate::convert::SseDecoder;
pub(crate) use crate::convert::from_anthropic_event;
pub(crate) use crate::convert::from_anthropic_response;
pub(crate) use crate::convert::from_gemini_chunk;
pub(crate) use crate::convert::from_gemini_response;
pub(crate) use crate::convert::from_openai_chunk;
pub(crate) use crate::convert::from_openai_response;
pub(crate) use crate::convert::to_anthropic_body;
pub(crate) use crate::convert::to_gemini_body;
pub(crate) use crate::convert::to_openai_body;

pub(crate) use crate::wire::ChatMessage;
pub(crate) use crate::wire::ChatRequest;
pub(crate) use crate::wire::ChatResponse;
pub(crate) use crate::wire::FinishReason;
pub(crate) use crate::wire::StreamChunk;
pub(crate) use crate::wire::ToolCall;
pub(crate) use crate::wire::Usage;

pub(crate) use crate::DEFAULT_TIMEOUT_SECS;
pub(crate) use crate::mock_mode_enabled;

#[cfg(test)]
pub(crate) use agf_core::adapter::CircuitBreakerConfig;
#[cfg(test)]
pub(crate) use agf_core::adapter::CircuitState;
#[cfg(test)]
pub(crate) use agf_core::adapter::RetryConfig;

#[cfg(test)]
pub(crate) use agf_core::ids::TenantId;

#[cfg(test)]
pub(crate) use agf_core::model::Modality;

#[cfg(test)]
pub(crate) use pretty_assertions::assert_eq as eq;

#[cfg(test)]
pub(crate) use crate::convert::ANTHROPIC_DEFAULT_MAX_TOKENS;

#[allow(unused_imports)]
pub use impl_gemini_provider::*;
#[allow(unused_imports)]
pub use impl_open_ai_compat_provider::*;
#[allow(unused_imports)]
pub(crate) use impl_static_credential_resolver::*;
#[allow(unused_imports)]
pub use parse_bedrock_event::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests_2::*;
#[allow(unused_imports)]
pub use types::*;

/// 适配器能力（真实 HTTP 提供商的固定能力集合）。
pub const LLM_CAPABILITIES: [AdapterCapability; 2] = [AdapterCapability::PushMetrics, AdapterCapability::SelfCheck];

/// 流式分片流。
pub type ProviderStream = Pin<Box<dyn Stream<Item = DomainResult<StreamChunk>> + Send>>;

/// 凭据解析器：把端点的 `credential_ref` 解成明文 API Key。
///
/// 由 `agf-storage::FieldCipher` 驱动的实现放在上层（API/运行时）crate，
/// 本 crate 只依赖这个窄接口——这样网关可以完全离线单测（用
/// [`StaticCredentialResolver`] / [`MockCredentialResolver`]）。
pub trait CredentialResolver: Send + Sync + std::fmt::Debug {
    /// 解析 API Key。返回 `None` 表示"未配置"，调用方应降级到 Mock。
    fn resolve_api_key(&self, credential_ref: &Id) -> Option<String>;

    /// 解析 Bedrock 的 `(access_key_id, secret_access_key, session_token)`。
    ///
    /// 默认实现返回 `None`（用环境变量或显式配置兜底）。
    fn resolve_aws_credentials(&self, _credential_ref: &Id) -> Option<AwsCredentials> {
        None
    }
}

/// AWS 显式凭据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsCredentials {
    /// Access Key ID。
    pub access_key_id: String,
    /// Secret Access Key。
    pub secret_access_key: String,
    /// STS 会话令牌（临时凭据时必填）。
    pub session_token: Option<String>,
}

/// 静态凭据解析器（测试 / 单机部署 / 从配置文件读取）。
#[derive(Debug, Clone, Default)]
pub struct StaticCredentialResolver {
    keys: BTreeMap<String, String>,
    aws: BTreeMap<String, AwsCredentials>,
}

/// 从不返回凭据的解析器（默认值）：网关据此判定"全部端点未配置"→ 全面 Mock。
#[derive(Debug, Clone, Copy, Default)]
pub struct MockCredentialResolver;

/// 从环境变量读取凭据（`AGF_LLM_KEY_<id>`，或 [`EnvCredentialResolver::with_env`] 指定的名字）。
///
/// 环境变量缺失时返回 `None`（**不报错**），网关随后降级到 Mock。
#[derive(Debug, Clone, Default)]
pub struct EnvCredentialResolver {
    overrides: BTreeMap<String, String>,
}

/// 提供商元信息（接入管理页 `AdapterDescriptor` + 端点展示）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProviderDescriptor {
    /// 适配器元信息（复用 `agf_core::adapter::AdapterDescriptor` 的字段语义）。
    pub adapter: AdapterDescriptor,
    /// 该适配器覆盖的厂商。
    pub providers: Vec<LlmProvider>,
    /// 协议族（`openai-compat` / `anthropic` / `gemini` / `bedrock`）。
    pub protocol: String,
    /// 是否为真实 HTTP 实现。
    pub real_implementation: bool,
}

/// 运行态共享字段（熔断快照）——各适配器内嵌它，避免重复实现。
#[derive(Debug, Clone, Default)]
pub struct ProviderState {
    circuit: Arc<parking_lot::Mutex<CircuitSnapshot>>,
}

/// 轻量状态门禁：流式路径与 [`ProviderState`] 共享同一份熔断状态。
#[derive(Debug, Clone, Default)]
struct StateGate {
    state: ProviderState,
}

/// OpenAI 兼容适配器注册名（`&'static str`，避免流式返回类型借用 `&self`）。
const OPENAI_ADAPTER: &str = "llm-openai-compat";

/// Anthropic 适配器注册名。
const ANTHROPIC_ADAPTER: &str = "llm-anthropic";

/// Gemini 适配器注册名。
const GEMINI_ADAPTER: &str = "llm-gemini";

/// Bedrock 适配器注册名。
const BEDROCK_ADAPTER: &str = "llm-bedrock";

/// SSE 分片解析函数指针（每家一个）。
type SseParser = fn(&Value) -> StreamChunk;

// ---------------------------------------------------------------------------
// 各适配器的公共实现（宏避免四份样板）
// ---------------------------------------------------------------------------

/// 为 HTTP 提供商生成 [`ProviderAdapter`] 与 [`Adapter`] 的样板实现。
///
/// 生成内容：
/// - `ProviderAdapter::name/descriptor/health/circuit/record_*`；
/// - `Adapter::name/descriptor/init/health/sync/push/pull/shutdown`；
/// - 底层 HTTP 客户端的只读访问器。
macro_rules! http_provider_boilerplate {
    ($ty:ty, $name:literal, $display:literal, $protocol:literal, $providers:expr, $secrets:expr, $client_field:ident, $complete:path, $stream:path) => {
        #[async_trait]
        impl ProviderAdapter for $ty {
            fn adapter_name(&self) -> &'static str {
                $name
            }

            fn provider_descriptor(&self) -> ProviderDescriptor {
                ProviderDescriptor::new($name, $display, $protocol, $providers, $secrets, true)
            }

            async fn complete(&self, req: &ChatRequest) -> DomainResult<ChatResponse> {
                $complete(self, req).await
            }

            async fn stream(&self, req: &ChatRequest) -> DomainResult<ProviderStream> {
                $stream(self, req).await
            }

            async fn health(&self) -> DomainResult<AdapterHealth> {
                Ok(self.report_health())
            }

            fn circuit(&self) -> CircuitSnapshot {
                self.state.snapshot()
            }

            fn record_failure(&self, error: &str) {
                self.state.failure(error);
            }

            fn record_success(&self) {
                self.state.success();
            }
        }

        impl $ty {
            /// 生成健康报告（供 `ProviderAdapter::health` 与 `Adapter::health` 共用）。
            #[must_use]
            pub fn report_health(&self) -> AdapterHealth {
                let circuit = self.state.snapshot();
                if self.api_key_missing() {
                    return self
                        .provider_descriptor()
                        .unconfigured_health("未配置 API Key：网关将自动切换到 MockProvider，不发起上游请求", circuit);
                }
                let mut h = AdapterHealth {
                    adapter: $name.to_string(),
                    state: HealthState::Healthy,
                    configured: true,
                    mocked: false,
                    latency_ms: None,
                    circuit,
                    capabilities: $crate::provider::LLM_CAPABILITIES.to_vec(),
                    message: Some(format!("已配置；base_url={}", self.base_url)),
                    checked_at: Timestamp::now(),
                };
                if mock_mode_enabled() {
                    h.mocked = true;
                    h.state = HealthState::Degraded;
                    h.message = Some("AGF_MOCK_MODE=1：不触达真实厂商".to_string());
                }
                h
            }
        }

        #[async_trait]
        impl Adapter for $ty {
            fn name(&self) -> &str {
                $name
            }

            fn descriptor(&self) -> AdapterDescriptor {
                ProviderAdapter::provider_descriptor(self).adapter
            }

            async fn init(&mut self, _config: &AdapterConfig) -> DomainResult<()> {
                // 未配置凭据不是错误：由 `health()` 返回 `Unconfigured` 让上层降级
                Ok(())
            }

            async fn health(&self) -> DomainResult<AdapterHealth> {
                ProviderAdapter::health(self).await
            }

            async fn sync(&self, _direction: SyncDirection, _req: &PullRequest) -> DomainResult<SyncOutcome> {
                let mut outcome = SyncOutcome::default();
                outcome.warnings.push("LLM 提供商适配器不参与台账同步（模型端点由 agf-asset 登记）".to_string());
                outcome.finished_at = Some(Timestamp::now());
                Ok(outcome)
            }

            async fn push(&self, _payload: &PushPayload) -> DomainResult<()> {
                Err(DomainError::NotImplemented(format!("{} 不支持向远端推送实体", $name)))
            }

            async fn pull(&self, _req: &PullRequest) -> DomainResult<PullResponse> {
                Ok(PullResponse {
                    items: Vec::new(),
                    next_cursor: None,
                    mocked: mock_mode_enabled(),
                    origin: format!("{}#pull-not-applicable", $name),
                })
            }

            async fn shutdown(&mut self) -> DomainResult<()> {
                // 幂等：无长连接需要释放
                Ok(())
            }
        }

        impl $ty {
            /// 底层 HTTP 客户端（供扩展与测试探针使用）。
            #[must_use]
            pub const fn client(&self) -> &reqwest::Client {
                &self.$client_field
            }
        }
    };
}

// ---------------------------------------------------------------------------
// OpenAI 兼容
// ---------------------------------------------------------------------------

/// OpenAI 兼容适配器。
///
/// 覆盖：OpenAI、Azure OpenAI、阿里云百炼/通义(DashScope)、火山方舟/豆包(Ark)、
/// 腾讯混元、百度文心(Qianfan)、Kimi(Moonshot)、DeepSeek、智谱 GLM、MiniMax、
/// Ollama、vLLM，以及任意 OpenAI 兼容自定义 Endpoint。
#[derive(Debug)]
pub struct OpenAiCompatProvider {
    /// 厂商（用于选默认 `base_url` 与鉴权头风格）。
    pub provider: LlmProvider,
    /// 端点模型名。
    pub model: String,
    /// Base URL。
    pub base_url: String,
    /// 明文凭据（`None` = 未配置）。
    pub credential: Option<String>,
    /// 附加请求头（Azure 的 `api-version` 等）。
    pub extra_headers: BTreeMap<String, String>,
    state: ProviderState,
    client: reqwest::Client,
}

http_provider_boilerplate!(
    OpenAiCompatProvider,
    "llm-openai-compat",
    "OpenAI 兼容大模型（OpenAI/Azure/百炼/方舟/混元/文心/Kimi/DeepSeek/GLM/MiniMax/Ollama/vLLM/自定义）",
    "openai-compat",
    LlmProvider::all().iter().copied().filter(LlmProvider::is_openai_compatible).collect(),
    vec!["api_key".to_string()],
    client,
    openai_complete,
    openai_stream
);

http_provider_boilerplate!(
    AnthropicProvider,
    "llm-anthropic",
    "Anthropic Claude Messages API",
    "anthropic",
    vec![LlmProvider::Anthropic],
    vec!["api_key".to_string()],
    client,
    anthropic_complete,
    anthropic_stream
);

// ---------------------------------------------------------------------------
// Gemini
// ---------------------------------------------------------------------------

/// Google Gemini 适配器。
#[derive(Debug)]
pub struct GeminiProvider {
    /// 端点模型名（`gemini-1.5-pro`）。
    pub model: String,
    /// Base URL。
    pub base_url: String,
    /// 明文凭据。
    pub credential: Option<String>,
    state: ProviderState,
    client: reqwest::Client,
}

http_provider_boilerplate!(
    GeminiProvider,
    "llm-gemini",
    "Google Gemini generateContent",
    "gemini",
    vec![LlmProvider::Gemini],
    vec!["api_key".to_string()],
    client,
    gemini_complete,
    gemini_stream
);

http_provider_boilerplate!(
    BedrockProvider,
    "llm-bedrock",
    "AWS Bedrock Converse API（自签 SigV4）",
    "bedrock",
    vec![LlmProvider::Bedrock],
    vec!["aws_access_key_id".to_string(), "aws_secret_access_key".to_string()],
    client,
    bedrock_complete,
    bedrock_stream
);

mod deferred_http;
pub mod embedding;
pub(crate) use deferred_http::single_dispatch;
mod impl_gemini_provider;
mod impl_open_ai_compat_provider;
mod impl_static_credential_resolver;
mod parse_bedrock_event;
#[cfg(test)]
mod stream_completion_tests;
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests;
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests_2;
mod types;
