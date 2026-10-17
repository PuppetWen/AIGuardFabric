//! 运行时配置（§0 铁律 4：路径与凭据一律从环境注入，禁止硬编码）。
//!
//! 本模块只做**解析与校验**，不做 I/O：`.env` 的加载由各二进制入口用 `dotenvy` 完成，
//! 这样配置逻辑可被单元测试完整覆盖（通过注入 `BTreeMap<String, String>`）。
//!
//! 安全约定：`Debug` 实现会**自动打码**所有密钥字段，因此 `tracing::info!(?config)` 是安全的。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[allow(unused_imports)]
pub use impl_run_env::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 平台运行配置（聚合所有子配置）。
#[derive(Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// 运行环境。
    pub env: RunEnv,
    /// Mock 模式（离线可演示，§11 阶段一默认开启）。
    pub mock_mode: bool,
    /// 缺失外部依赖时降级而非报错。
    pub degrade_on_missing: bool,
    /// 日志级别。
    pub log_level: String,
    /// 日志格式。
    pub log_format: LogFormat,
    /// 项目根（唯一写入区）。
    pub project_root: String,
    /// 数据卷目录。
    pub data_dir: String,
    /// 服务监听。
    pub server: ServerConfig,
    /// 数据库。
    pub database: DatabaseConfig,
    /// Redis。
    pub redis: RedisConfig,
    /// NATS。
    pub nats: NatsConfig,
    /// ClickHouse（可选）。
    pub clickhouse: ClickHouseConfig,
    /// 对象存储。
    pub s3: S3Config,
    /// 安全配置。
    pub security: SecurityConfig,
    /// 配额默认值。
    pub quota: QuotaDefaults,
    /// 可观测性。
    pub observability: ObservabilityConfig,
    /// 告警设备开关（键 = 适配器名，值 = 是否启用）。
    pub device_adapters: BTreeMap<String, bool>,
}

/// 运行环境。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunEnv {
    /// 开发。
    Dev,
    /// 测试。
    Test,
    /// 生产。
    Prod,
}

/// 日志格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// 人类可读。
    Pretty,
    /// 结构化 JSON。
    Json,
}

/// 服务监听配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// API 主机。
    pub host: String,
    /// API 端口。
    pub port: u16,
    /// 接入服务端口。
    pub ingest_port: u16,
    /// Syslog TCP 端口。
    pub syslog_tcp_port: u16,
    /// Syslog UDP 端口。
    pub syslog_udp_port: u16,
    /// MCP 代理端口。
    pub mcp_proxy_port: u16,
    /// 指标端口。
    pub metrics_port: u16,
    /// API 前缀。
    pub api_prefix: String,
    /// 请求体上限（字节）。
    pub max_body_bytes: usize,
}

/// 数据库配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// 主机。
    pub host: String,
    /// 端口。
    pub port: u16,
    /// 库名。
    pub database: String,
    /// 用户。
    pub user: String,
    /// 口令（Debug 打码）。
    pub password: String,
    /// 连接池上限。
    pub pool_max: u32,
    /// 连接池下限。
    pub pool_min: u32,
    /// 连接超时（秒）。
    pub connect_timeout_secs: u64,
}

/// Redis 配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    /// 连接 URL（Debug 打码）。
    pub url: String,
    /// 键前缀（多租户共用实例时隔离）。
    pub key_prefix: String,
}

/// NATS 配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsConfig {
    /// 是否启用（关闭则使用进程内广播）。
    pub enabled: bool,
    /// 连接 URL。
    pub url: String,
    /// JetStream 流名。
    pub stream: String,
}

/// ClickHouse 配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickHouseConfig {
    /// 是否启用。
    pub enabled: bool,
    /// HTTP 端点。
    pub url: String,
    /// 库名。
    pub database: String,
    /// 用户。
    pub user: String,
    /// 口令。
    pub password: String,
}

/// 对象存储配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    /// 端点。
    pub endpoint: String,
    /// 区域。
    pub region: String,
    /// 桶名。
    pub bucket: String,
    /// Access Key。
    pub access_key: String,
    /// Secret Key。
    pub secret_key: String,
    /// 是否强制 path-style（MinIO 需要）。
    pub force_path_style: bool,
}

/// 安全配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// JWT 签名密钥。
    pub jwt_secret: String,
    /// 访问令牌有效期（秒）。
    pub jwt_access_ttl_secs: i64,
    /// 刷新令牌有效期（秒）。
    pub jwt_refresh_ttl_secs: i64,
    /// 签发者。
    pub jwt_issuer: String,
    /// 主密钥（base64，32 字节）。
    pub master_key_b64: String,
    /// 指纹盐（用于不可逆凭据指纹）。
    pub fingerprint_salt: String,
    /// KMS 后端。
    pub kms_backend: String,
    /// 引导管理员用户名。
    pub bootstrap_admin_user: String,
    /// 引导管理员邮箱。
    pub bootstrap_admin_email: String,
    /// 引导管理员初始口令（空 = 首启随机生成并写文件）。
    pub bootstrap_admin_password: String,
    /// 强制首登改密。
    pub force_password_change: bool,
    /// 口令最小长度。
    pub password_min_length: usize,
    /// 登录失败锁定阈值。
    pub login_max_failures: u32,
    /// 锁定持续（秒）。
    pub login_lockout_secs: i64,
    /// 租户级每 5 分钟请求数上限。
    pub tenant_rate_per_5min: u32,
}

/// 配额默认值。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaDefaults {
    /// 租户每日 token。
    pub tenant_tokens_per_day: i64,
    /// Agent 每日 token。
    pub agent_tokens_per_day: i64,
    /// 会话 token。
    pub session_tokens: i64,
    /// 租户每分钟请求数。
    pub tenant_req_per_min: i64,
}

/// 可观测性配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// 是否启用 OTLP。
    pub otel_enabled: bool,
    /// OTLP 端点。
    pub otel_endpoint: String,
    /// 服务名。
    pub otel_service_name: String,
    /// 是否启用 Prometheus。
    pub prometheus_enabled: bool,
}

mod impl_app_config;
mod impl_run_env;
#[cfg(test)]
mod tests;
