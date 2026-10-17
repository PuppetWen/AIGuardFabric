//! 由 `provider.rs` 拆分：`ProviderAdapter`/`SigV4Input` 等 4 项（纯搬移，逻辑不变）。
use super::*;

/// 统一提供商契约。
///
/// 实现者必须保证：**未配置凭据时不发起任何网络请求**，而是返回
/// `DomainError::NotImplemented`（可降级），由网关切换到 Mock。
#[async_trait]
pub trait ProviderAdapter: Send + Sync + std::fmt::Debug {
    /// 适配器注册名（如 `llm-openai-compat`）。
    fn adapter_name(&self) -> &str;

    /// 提供商描述（接入管理页展示 + 降级说明 + Mock 位置）。
    fn provider_descriptor(&self) -> ProviderDescriptor;

    /// 单次（非流式）补全。
    ///
    /// # Errors
    /// 未配置凭据（可降级）、上游 HTTP 错误、响应解析失败。
    async fn complete(&self, req: &ChatRequest) -> DomainResult<ChatResponse>;

    /// 流式补全。
    ///
    /// # Errors
    /// 未配置凭据（可降级）或建立连接失败。**注意**：流一旦返回，
    /// 后续分片错误通过 `Item` 传递，不再返回 `Err`。
    async fn stream(&self, req: &ChatRequest) -> DomainResult<ProviderStream>;

    /// 适配器健康（含熔断快照）。
    ///
    /// # Errors
    /// 仅在"配置存在但损坏"时返回错误；未配置一律返回 `HealthState::Unconfigured`。
    async fn health(&self) -> DomainResult<AdapterHealth>;

    /// 熔断快照（只读）。
    fn circuit(&self) -> CircuitSnapshot;

    /// 记录一次外部可见的失败。
    fn record_failure(&self, error: &str);

    /// 记录一次成功。
    fn record_success(&self);
}

// ---------------------------------------------------------------------------
// AWS SigV4
// ---------------------------------------------------------------------------

/// SigV4 签名输入。
#[derive(Debug)]
pub struct SigV4Input<'a> {
    /// HTTP 方法（`POST`）。
    pub method: &'a str,
    /// 完整 URL。
    pub url: &'a str,
    /// 请求体字节。
    pub body: &'a [u8],
    /// 区域。
    pub region: &'a str,
    /// 服务名（`bedrock`）。
    pub service: &'a str,
    /// 凭据。
    pub credentials: &'a AwsCredentials,
    /// 签名时刻。
    pub now: Timestamp,
}

// ---------------------------------------------------------------------------
// Anthropic
// ---------------------------------------------------------------------------

/// Anthropic Messages API 适配器。
#[derive(Debug)]
pub struct AnthropicProvider {
    /// 端点模型名（`claude-3-5-sonnet-20241022` 等）。
    pub model: String,
    /// Base URL。
    pub base_url: String,
    /// 明文凭据。
    pub credential: Option<String>,
    /// API 版本头（`anthropic-version`）。
    pub api_version: String,
    pub(crate) state: ProviderState,
    pub(crate) client: reqwest::Client,
}

// ---------------------------------------------------------------------------
// AWS Bedrock（自签 SigV4）
// ---------------------------------------------------------------------------

/// AWS Bedrock 适配器（自行构造并签名 SigV4 请求，不依赖官方 SDK）。
#[derive(Debug)]
pub struct BedrockProvider {
    /// 端点模型名（`anthropic.claude-3-5-sonnet-20241022-v2:0`）。
    pub model: String,
    /// 区域（`us-east-1`）。
    pub region: String,
    /// 运行时端点 Base URL（留空则按区域推导）。
    pub base_url: String,
    /// AWS 凭据（`None` = 未配置 → 可降级）。
    pub credentials: Option<AwsCredentials>,
    pub(crate) state: ProviderState,
    pub(crate) client: reqwest::Client,
}
