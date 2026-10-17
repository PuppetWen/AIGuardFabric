//! 阿里云 RPC 客户端：构建请求 → 签名 → 发送 → 解析 → 错误映射。
//!
//! ## 最重要的不变量：Mock / 缺凭据时**绝不发请求**
//!
//! 所有真实调用都必须先拿到一个 [`RpcClient`]，而 [`RpcClient::live`] 是唯一的构造入口：
//! - [`AdapterMode::Mocked`] → `Err`；
//! - 没有凭据 → `Err`。
//!
//! 也就是说"忘了判断 mock 就打网络"在类型层面不成立：Mock 模式的适配器根本拿不到 `RpcClient`。
//!
//! ## 两条发送通道
//!
//! | 通道 | 载体 | 用途 | 约束 |
//! |---|---|---|---|
//! | 同步 [`RpcClient::call`] | [`Transport`] 替身 | **测试**：断言请求构造与响应解析 | 真实客户端设了异步通道后会被拒绝执行 |
//! | 异步 [`RpcClient::call_async`] | [`ReqwestTransport`] | 生产 | 需显式注入，未注入即明确失败 |
//!
//! 之所以要"两条通道"：`reqwest` 的阻塞 API 在 tokio 运行时里会 panic。
//! 与其在适配器里小心翼翼，不如把它做成编译期/运行期都不通的路径。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Arc;
pub(crate) use std::sync::Mutex;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use crate::AdapterMode;

pub(crate) use crate::credential::CloudCredential;

pub(crate) use crate::endpoint::ResolvedEndpoint;

pub(crate) use crate::signer::RpcSignInput;
pub(crate) use crate::signer::V3SignInput;
pub(crate) use crate::signer::canonicalized_query;
pub(crate) use crate::signer::sign_rpc;
pub(crate) use crate::signer::sign_v3;

#[cfg(test)]
pub(crate) use crate::endpoint::EndpointStyle;
#[cfg(test)]
pub(crate) use crate::endpoint::resolve;

#[cfg(test)]
pub(crate) use agf_core::enums::AliCloudService;

#[allow(unused_imports)]
pub use check_response::*;
#[allow(unused_imports)]
pub use error_chain::*;
#[allow(unused_imports)]
pub use impl_sign_style::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 请求签名风格。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignStyle {
    /// RPC 风格（HMAC-SHA1，`?Action=Xxx`）——本 crate 默认。
    Rpc,
    /// V3 风格（ACS3-HMAC-SHA256）。
    V3,
}

/// 一次待发送的 RPC 调用。
#[derive(Clone)]
pub struct RpcRequest {
    /// HTTP 方法。
    pub method: String,
    /// 完整 URL（不含查询串）。
    pub url: String,
    /// 签名风格。
    pub style: SignStyle,
    /// 最终查询串（RPC 风格含 `Signature`；V3 风格为规范化查询串）。
    pub query: String,
    /// 头部（V3 风格含 `Authorization`；RPC 风格为空）。
    pub headers: BTreeMap<String, String>,
    /// 请求体（JSON 字符串；无体时为空串）。
    pub body: String,
}

/// HTTP 响应（已解析为 JSON 值）。
#[derive(Clone)]
pub struct RpcResponse {
    /// HTTP 状态码。
    pub status: u16,
    /// 解析后的 JSON。
    pub body: serde_json::Value,
    /// 原始文本（截断）。
    pub raw: String,
}

/// HTTP 发送口（测试替身接口）。
pub trait Transport: Send + Sync {
    /// 发送请求。
    ///
    /// # Errors
    /// 网络失败 / 响应非法。
    fn send(&self, request: &RpcRequest) -> DomainResult<RpcResponse>;
}

/// 请求录制器 + 固定响应（测试用，**绝不触网**）。
#[derive(Debug)]
pub struct RecordingTransport {
    /// 已发送请求。
    pub requests: Mutex<Vec<RpcRequest>>,
    /// 固定响应体。
    pub response: Mutex<serde_json::Value>,
    /// 固定状态码。
    pub status: Mutex<u16>,
    /// 模拟网络故障的原因。
    pub fail_with: Mutex<Option<String>>,
}

/// 真实 HTTP 发送口（reqwest + rustls）。
///
/// ## TLS 校验策略（**生产默认最严**）
///
/// 默认使用 rustls 编译内置的信任锚（webpki 根证书）—— 自签证书/内部 CA 一律拒绝。
/// 只有在**显式**给出 `ca_pem`（信任指定 CA）或 `allow_insecure_tls`（跳过校验）时才放松，
/// 且两者都**只应在 `AGF_ENV=dev`（或显式开关）下生效**（判定见 [`tls_override_allowed`]）；
/// 一旦生效会 `warn!` 并记录到 [`ReqwestTransport::tls_policy`]，供自检/`/readyz` 如实标注。
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
    timeout: std::time::Duration,
    tls_policy: TlsPolicy,
}

/// 实际生效的 TLS 策略（自检与 `/readyz` notes 的输入）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsPolicy {
    /// 默认：校验系统/内置根证书链，**关闭**不安全开关。
    VerifyChain,
    /// 追加信任指定的 CA（PEM）。
    CustomCa,
    /// 跳过证书校验（**危险**，仅 dev/联调）。
    Insecure,
}

/// 签名与发送配置。
#[derive(Debug, Clone)]
pub struct RpcClientConfig {
    /// 适配器名（错误信息与日志用）。
    pub adapter: String,
    /// 地域。
    pub region: String,
    /// 账号 id。
    pub account_id: String,
    /// 签名风格。
    pub style: SignStyle,
    /// 超时（秒）。
    pub timeout_secs: u64,
}

/// RPC 客户端。
pub struct RpcClient {
    config: RpcClientConfig,
    credential: CloudCredential,
    endpoint: ResolvedEndpoint,
    sync_transport: Arc<dyn Transport>,
    async_transport: Option<Arc<ReqwestTransport>>,
    nonce_override: Option<String>,
    timestamp_override: Option<Timestamp>,
}

mod form;
mod roa;
pub use roa::RoaCall;

mod check_response;
mod error_chain;
mod impl_sign_style;
#[cfg(test)]
mod tests;
