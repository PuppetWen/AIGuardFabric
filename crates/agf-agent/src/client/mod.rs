//! 上报客户端：注册 / 心跳 / 快照 / 增量 + 断线重试退避 + 本地队列积压。
//!
//! ## 三种运行模式（在发出任何请求**之前**判定）
//!
//! | 模式 | 触发条件 | 行为 |
//! |---|---|---|
//! | [`ClientMode::Mock`] | `AGF_MOCK_MODE=1` / `config.mock = true` | **不发任何网络请求**：只把投递记录进内存（[`AgentClient::recorded_deliveries`]），返回 `mocked = true` |
//! | [`ClientMode::Live`] | 配置了 `server_url` 且非 Mock | 经 [`AgentTransport`] 上行；`http(s)://` 走 [`TlsTransport`]（**mTLS 已实现**，见 [`tls`]），配置错误时**明确报错**并计入健康画像 |
//! | [`ClientMode::Unconfigured`] | 未配置 `server_url` | 不假装成功：入本地队列等待补传，回执 `queued = true` 且 `note` 说明原因 |
//!
//! ## TLS / mTLS（`https://`）
//!
//! | 配置 | 模式 | 行为 |
//! |---|---|---|
//! | `AGF_AGENT_TLS_CERT` + `AGF_AGENT_TLS_KEY` 成对 | [`TlsMode::Mutual`] | 双向认证：客户端证书即主体身份（服务端按 subject/SAN 识别） |
//! | 只给其中一个 | — | **明确报错**（[`DomainError::Config`]）：不会被静默忽略或降级为单向上行 |
//! | 未配置客户端证书 | [`TlsMode::ServerAuth`] | 校验服务端（`AGF_AGENT_TLS_CA` 或内置公共根），不出示客户端身份 |
//! | `AGF_AGENT_TLS_INSECURE_SKIP_VERIFY=1` 且（`AGF_ENV=dev` 或 `AGF_AGENT_TLS_ALLOW_INSECURE=1`） | 任意 | 跳过服务端证书链校验，**必然 `warn!`** 并写入健康画像 |
//! | `..._SKIP_VERIFY=1` 但未获授权 | — | **明确报错**（不静默忽略） |
//! | `http://` + 客户端证书 | — | **明确报错**：拒绝把证书用于明文上行 |
//!
//! ## 失败处理与"绝不丢数据"
//!
//! - 可重试错误（`DependencyUnavailable` / `Config` / `NotImplemented` / 超时）→ 指数退避重试
//!   `retry.max_attempts` 次 → 仍失败则入本地队列（上限与淘汰策略见 [`crate::queue`]）；
//! - **不可重试错误**（`Validation` / `Parse`，即载荷本身非法）→ 直接返回错误，**不入队**
//!   （入队只会无限重放一个永远失败的载荷）；
//! - 严格入口 [`AgentClient::deliver_strict`] 不入队，只返回明确错误（供"必须确认送达"的场景使用）。
//!
//! ## 降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | `AGF_MOCK_MODE=1` | 零网络、零 socket；回执 `mocked=true` |
//! | 未配置 `server_url` | 入队 + `queued=true` + `note`；**不回执成功** |
//! | mTLS 配置错误（证书/私钥缺失、未授权的跳过校验） | 传输层为 `http-not-implemented`（携带**原始配置错误**），失败入队 + `/health` 如实标注 |
//! | 队列落盘失败 | 内存队列仍可用；`save_queue` 返回错误由上层记 warning |
//! | `AGF_AGENT_TOKEN` 未配置 | 不发送鉴权头（由服务端按 mTLS/网络策略决定是否接受） |

pub(crate) use std::fmt;

pub(crate) use std::sync::Arc;

pub(crate) use std::time::Instant;

pub(crate) use agf_core::adapter::RetryConfig;

pub(crate) use agf_core::agent::AgentReport;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use secrecy::ExposeSecret;
pub(crate) use secrecy::SecretString;

pub(crate) use crate::identity::AgentIdentity;

pub(crate) use crate::payload::CollectionExtras;
pub(crate) use crate::payload::DiffPayload;
pub(crate) use crate::payload::Envelope;
pub(crate) use crate::payload::HeartbeatPayload;
pub(crate) use crate::payload::PayloadKind;
pub(crate) use crate::payload::SnapshotPayload;
pub(crate) use crate::payload::compute_diff;

pub(crate) use crate::queue::FlushStats;
pub(crate) use crate::queue::LocalQueue;
pub(crate) use crate::queue::QueueConfig;
pub(crate) use crate::queue::QueueStats;

#[cfg(test)]
pub(crate) use crate::payload::CollectorStatus;

#[cfg(test)]
pub(crate) use agf_core::enums::Severity;

#[cfg(test)]
pub(crate) use std::sync::Mutex;

#[cfg(test)]
pub(crate) use std::sync::atomic::AtomicU32;
#[cfg(test)]
pub(crate) use std::sync::atomic::Ordering;

#[allow(unused_imports)]
pub use impl_endpoint_paths::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
pub use tls::*;
#[allow(unused_imports)]
pub use tls_rustls::*;
#[allow(unused_imports)]
pub use tls_transport::*;

/// 服务端地址环境变量。
pub const ENV_SERVER_URL: &str = "AGF_AGENT_SERVER_URL";

/// 上行令牌环境变量（Bearer）。
pub const ENV_TOKEN: &str = "AGF_AGENT_TOKEN";

/// 心跳间隔环境变量（秒）。
pub const ENV_HEARTBEAT_SECS: &str = "AGF_AGENT_HEARTBEAT_SECS";

/// 真实 HTTP 上行的 TODO 锚点。
pub const TODO_ANCHOR: &str = "agent-http";

/// 默认心跳间隔（秒）。
pub const DEFAULT_HEARTBEAT_SECS: u64 = 60;

/// 上行路径集合。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EndpointPaths {
    /// 注册。
    pub register: String,
    /// 心跳。
    pub heartbeat: String,
    /// 快照 / 增量。
    pub report: String,
}

/// 上行传输（阶段一只有 Mock 与"未实现"两种实现）。
pub trait AgentTransport: Send + Sync + fmt::Debug {
    /// 传输名（健康/排障用）。
    fn name(&self) -> &'static str;

    /// 是否需要网络。
    fn requires_network(&self) -> bool;

    /// 发送一次（同步；真实实现应为阻塞 HTTP 客户端）。
    ///
    /// # Errors
    /// 网络/协议失败；占位实现恒为 `NotImplemented`。
    fn send(&self, endpoint: &str, body: &str) -> DomainResult<()>;

    /// 最近一次真实上行响应（默认 `None`：Mock 与占位传输没有响应可报）。
    fn last_response(&self) -> Option<TlsResponse> {
        None
    }
}

/// Mock 传输：**绝不发起任何网络请求**（`AGF_MOCK_MODE=1` 时使用）。
#[derive(Debug, Default, Clone, Copy)]
pub struct MockTransport;

/// 真实 HTTP 传输占位：**明确失败，不假装成功**。
///
/// 只在两种情况下启用：① 未配置 `server_url`（无从连接）；② TLS/mTLS 配置非法
/// （此时 `cause` 携带**原始配置错误文本**，绝不静默降级为明文或单向上行）。
#[derive(Debug, Default, Clone)]
pub struct HttpTransportNotImplemented {
    /// 装配失败的原因（`None` = 未配置服务端）。
    pub cause: Option<String>,
}

impl HttpTransportNotImplemented {
    /// 带原因的占位传输。
    #[must_use]
    pub fn with_cause(cause: impl Into<String>) -> Self {
        Self { cause: Some(cause.into()) }
    }
}

/// 客户端运行模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientMode {
    /// Mock（零网络）。
    Mock,
    /// 真实上行。
    Live,
    /// 未配置（入队等待补传）。
    Unconfigured,
}

/// 客户端配置。
#[derive(Clone)]
pub struct ClientConfig {
    /// 服务端基址（`https://agf.example.com`）。
    pub server_url: Option<String>,
    /// 上行令牌（`Debug` 掩码）。
    pub token: Option<SecretString>,
    /// 是否 Mock。
    pub mock: bool,
    /// 心跳间隔（秒）。
    pub heartbeat_interval_secs: u64,
    /// 重试参数。
    pub retry: RetryConfig,
    /// 队列参数。
    pub queue: QueueConfig,
    /// 上行路径。
    pub paths: EndpointPaths,
    /// mTLS / TLS 配置（客户端证书、信任锚、跳过校验门禁）。
    pub tls: tls::TlsConfig,
}

/// 投递回执。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeliveryOutcome {
    /// 载荷种类。
    pub kind: PayloadKind,
    /// 是否 Mock（未触达服务端）。
    pub mocked: bool,
    /// 是否已入本地队列（等待补传）。
    pub queued: bool,
    /// 尝试次数（含首次）。
    pub attempts: u32,
    /// 耗时（毫秒）。
    pub latency_ms: u64,
    /// 目标地址（已脱敏）。
    pub endpoint: String,
    /// 说明（未配置/未实现等原因）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Mock 模式下的一条投递记录。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecordedDelivery {
    /// 载荷种类。
    pub kind: PayloadKind,
    /// 目标地址。
    pub endpoint: String,
    /// 字节数。
    pub bytes: usize,
    /// 幂等键。
    pub idempotency_key: String,
    /// 记录时间（Unix 秒）。
    pub at_unix_secs: i64,
}

/// 上报客户端。
pub struct AgentClient {
    identity: AgentIdentity,
    config: ClientConfig,
    transport: Arc<dyn AgentTransport>,
    /// 传输装配失败的原因（**明确报错，不静默降级**）：`None` = 未发生配置错误。
    transport_config_error: Option<DomainError>,
    queue: LocalQueue,
    recorded: Vec<RecordedDelivery>,
    registered: bool,
    last_snapshot: Option<AgentReport>,
    started_at: Instant,
}

mod impl_agent_client;
mod impl_endpoint_paths;
#[cfg(test)]
mod tests;
mod tls;
mod tls_rustls;
mod tls_transport;
