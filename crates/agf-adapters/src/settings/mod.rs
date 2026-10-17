//! 适配器配置：非敏感设置 + 凭据引用 + 超时/重试/熔断参数。
//!
//! ## 凭据获取优先级（`docs/adapter-spec.md` §3）
//!
//! ```text
//! ① 注入的 SecretLookup（生产：credentials 表解密后的内存凭据）
//!         ↓ 不可用时
//! ② 环境变量 `AGF_ADAPTER_<适配器名>_<凭据键>`（运维兜底，便于容器化部署）
//!         ↓ 不可用时
//! ③ 未配置 → 降级为 Unconfigured（**不报错、不假装成功**）
//! ```
//!
//! **明文绝不出现在 `Debug` 输出、日志与序列化中**：凭据以 [`secrecy::SecretString`]
//! 封装（`Debug` 为 `[REDACTED]`），本模块的 [`std::fmt::Debug`] 实现只打印**键名**。
//!
//! ## 降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 必需凭据缺失 | 模式为 `Unconfigured`；`send/sync/pull` 返回明确错误，不触达外部系统 |
//! | 配置存在但非法（URL/超时/重试越界） | `prepare()` 返回 `DomainError::Config`，**已有配置保持不变** |
//! | 环境变量未设置 | `lookup` 返回 `None`（不 panic、不落默认凭据——**禁止硬编码凭据**） |

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::fmt;

pub(crate) use agf_core::adapter::AdapterConfig;
pub(crate) use agf_core::adapter::CircuitBreakerConfig;
pub(crate) use agf_core::adapter::RetryConfig;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use secrecy::ExposeSecret;
pub(crate) use secrecy::SecretString;

pub(crate) use url::Url;

pub(crate) use crate::contract::AdapterMetadata;

#[cfg(test)]
pub(crate) use agf_core::adapter::AdapterCapability;

#[allow(unused_imports)]
pub use impl_adapter_mode::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
pub use validate_endpoint::*;

/// 超时下限（秒）。
pub const MIN_TIMEOUT_SECS: u64 = 1;

/// 超时上限（秒）。
pub const MAX_TIMEOUT_SECS: u64 = 600;

/// 重试次数上限。
pub const MAX_ATTEMPTS: u32 = 10;

/// 允许的 endpoint scheme（覆盖 HTTP 通道与 SMTP/Syslog 等非 HTTP 通道）。
pub const ALLOWED_SCHEMES: [&str; 7] = ["http", "https", "smtp", "smtps", "syslog", "tcp", "udp"];

/// 适配器运行模式（与 `agf-alicloud::AdapterMode` 同构）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdapterMode {
    /// 未配置（缺必需凭据 / 必需设置）。
    Unconfigured,
    /// Mock（确定性回执，**绝不发起真实请求**）。
    Mocked,
    /// 真实模式（配置齐全且未开 Mock：所有内置适配器都已实现真实传输，会真实发包）。
    Live,
}

/// 凭据解析口（生产实现读 `credentials` 表密文，测试实现内存注入）。
pub trait SecretLookup: Send + Sync {
    /// 按 `(适配器名, 凭据键)` 取明文；未配置返回 `None`。
    fn lookup(&self, adapter: &str, key: &str) -> Option<SecretString>;
}

/// 永不返回凭据的实现（测试/离线默认值）。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSecrets;

/// 内存注入的凭据（**测试专用**，不读磁盘、不读环境）。
#[derive(Debug, Default, Clone)]
pub struct StaticSecrets {
    values: BTreeMap<String, String>,
}

/// 环境变量凭据解析口：`AGF_ADAPTER_<ADAPTER>_<KEY>`。
#[derive(Debug, Clone)]
pub struct EnvSecrets {
    prefix: String,
}

/// 适配器配置（运行时形态；由 [`AdapterSettings::from_config`] 从 DB 实体构造）。
#[derive(Clone)]
pub struct AdapterSettings {
    /// 适配器注册名。
    pub adapter: String,
    /// 显示名。
    pub display_name: String,
    /// 租户。
    pub tenant_id: TenantId,
    /// 是否启用。
    pub enabled: bool,
    /// 是否强制 Mock。
    pub mock: bool,
    /// 超时（秒）。
    pub timeout_secs: u64,
    /// 熔断参数。
    pub circuit: CircuitBreakerConfig,
    /// 重试参数。
    pub retry: RetryConfig,
    /// endpoint（非敏感设置；Webhook 类适配器为 `None`，其 URL 是凭据）。
    pub endpoint: Option<String>,
    /// 非敏感设置（原样保留，供厂商读取自有键）。
    pub settings: BTreeMap<String, serde_json::Value>,
    /// 凭据引用（键 → `credentials` 表主键）。
    pub secret_refs: BTreeMap<String, Id>,
    /// 已解析的明文凭据（键 → `SecretString`，`Debug` 为 `[REDACTED]`）。
    pub secrets: BTreeMap<String, SecretString>,
    /// 必需凭据键（来自元信息）。
    pub required_secrets: Vec<String>,
    /// 必需设置键（来自元信息，用于 `is_configured` 判定）。
    pub required_settings: Vec<String>,
    /// endpoint 设置键（来自元信息）。
    pub endpoint_key: Option<String>,
}

mod impl_adapter_mode;
#[cfg(test)]
mod tests;
mod validate_endpoint;
