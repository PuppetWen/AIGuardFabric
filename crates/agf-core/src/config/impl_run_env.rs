//! 由 `config.rs` 拆分：`impl_RunEnv`/`impl_LogFormat` 等 16 项（纯搬移，逻辑不变）。
use super::*;

use crate::error::{DomainError, DomainResult};
use crate::secret::mask_default;
use std::collections::BTreeMap;

impl RunEnv {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Test => "test",
            Self::Prod => "prod",
        }
    }

    /// 是否生产环境（生产下更严格的安全校验）。
    #[must_use]
    pub const fn is_prod(&self) -> bool {
        matches!(self, Self::Prod)
    }

    /// 解析。
    ///
    /// # Errors
    /// 未知环境名返回错误。
    pub fn parse(value: &str) -> DomainResult<Self> {
        match value.to_ascii_lowercase().as_str() {
            "dev" | "development" => Ok(Self::Dev),
            "test" | "testing" | "ci" => Ok(Self::Test),
            "prod" | "production" => Ok(Self::Prod),
            other => Err(DomainError::Config(format!("未知 AGF_ENV: {other}"))),
        }
    }
}

impl LogFormat {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pretty => "pretty",
            Self::Json => "json",
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            ingest_port: 8090,
            syslog_tcp_port: 5514,
            syslog_udp_port: 5514,
            mcp_proxy_port: 8091,
            metrics_port: 9100,
            api_prefix: crate::constants::API_PREFIX.to_string(),
            max_body_bytes: 16 * 1024 * 1024,
        }
    }
}

impl ServerConfig {
    /// 绑定地址字符串。
    #[must_use]
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 5432,
            database: "aiguardfabric".to_string(),
            user: "agf".to_string(),
            password: String::new(),
            pool_max: 20,
            pool_min: 2,
            connect_timeout_secs: 10,
        }
    }
}

impl DatabaseConfig {
    /// 构造 DSN（口令会出现在字符串里，**禁止直接写入日志**）。
    #[must_use]
    pub fn dsn(&self) -> String {
        format!("postgres://{}:{}@{}:{}/{}", self.user, self.password, self.host, self.port, self.database)
    }

    /// 脱敏后的 DSN（可安全打印）。
    #[must_use]
    pub fn masked_dsn(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.user,
            mask_default(&self.password),
            self.host,
            self.port,
            self.database
        )
    }

    /// 是否使用了明显的弱口令/占位口令（安全基线检查）。
    #[must_use]
    pub fn uses_placeholder_password(&self) -> bool {
        let p = self.password.to_lowercase();
        p.is_empty() || p.contains("change_me") || p.contains("changeme") || p.contains("password") || p.len() < 12
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self { url: "redis://127.0.0.1:6379/0".to_string(), key_prefix: "agf".to_string() }
    }
}

impl RedisConfig {
    /// 脱敏 URL。
    #[must_use]
    pub fn masked_url(&self) -> String {
        // redis://[:password@]host:port/db
        match self.url.split_once('@') {
            Some((scheme_and_auth, rest)) => match scheme_and_auth.split_once("://") {
                Some((scheme, auth)) => {
                    let masked = auth.split_once(':').map_or_else(|| "***".to_string(), |(u, _)| format!("{u}:***"));
                    format!("{scheme}://{masked}@{rest}")
                }
                None => format!("***@{rest}"),
            },
            None => self.url.clone(),
        }
    }
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self { enabled: true, url: "nats://127.0.0.1:4222".to_string(), stream: "AGF_EVENTS".to_string() }
    }
}

impl Default for ClickHouseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: "http://127.0.0.1:8123".to_string(),
            database: "agf".to_string(),
            user: "default".to_string(),
            password: String::new(),
        }
    }
}

impl S3Config {
    /// 是否为非默认占位值（用于降级判断）。
    #[must_use]
    pub fn is_configured(&self) -> bool {
        !self.endpoint.is_empty() && !self.access_key.is_empty() && !self.secret_key.is_empty()
    }
}

impl SecurityConfig {
    /// JWT 密钥是否达到最小强度（32 字节）。
    #[must_use]
    pub fn jwt_secret_strong_enough(&self) -> bool {
        self.jwt_secret.len() >= 32 && !self.jwt_secret.to_lowercase().contains("change_me")
    }

    /// 主密钥是否为占位值。
    #[must_use]
    pub fn master_key_is_placeholder(&self) -> bool {
        let k = self.master_key_b64.to_lowercase();
        k.is_empty() || k.contains("change_me")
    }

    /// 主密钥解码后的字节数（非法 base64 返回 0）。
    #[must_use]
    pub fn master_key_len(&self) -> usize {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(self.master_key_b64.trim()).map_or(0, |v| v.len())
    }
}

impl Default for QuotaDefaults {
    fn default() -> Self {
        Self {
            tenant_tokens_per_day: 5_000_000,
            agent_tokens_per_day: 500_000,
            session_tokens: 100_000,
            tenant_req_per_min: 6_000,
        }
    }
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            otel_enabled: false,
            otel_endpoint: "http://127.0.0.1:4318".to_string(),
            otel_service_name: "agf-server".to_string(),
            prometheus_enabled: true,
        }
    }
}

/// 从"环境变量表"解析配置（纯函数，便于测试）。
///
/// # Errors
/// 必填项缺失/非法时返回 [`DomainError::Config`]。
pub fn from_env_map(env: &BTreeMap<String, String>) -> DomainResult<AppConfig> {
    let get = |k: &str| env.get(k).map(String::as_str).unwrap_or("");
    let get_or = |k: &str, d: &str| {
        let v = get(k);
        if v.is_empty() { d.to_string() } else { v.to_string() }
    };
    let parse_u16 = |k: &str, d: u16| -> DomainResult<u16> {
        let raw = get(k);
        if raw.is_empty() {
            return Ok(d);
        }
        raw.parse::<u16>().map_err(|e| DomainError::Config(format!("{k} 必须是端口号: {e}")))
    };
    let parse_i64 = |k: &str, d: i64| -> DomainResult<i64> {
        let raw = get(k);
        if raw.is_empty() {
            return Ok(d);
        }
        raw.parse::<i64>().map_err(|e| DomainError::Config(format!("{k} 必须是整数: {e}")))
    };
    let parse_u32 = |k: &str, d: u32| -> DomainResult<u32> {
        let raw = get(k);
        if raw.is_empty() {
            return Ok(d);
        }
        raw.parse::<u32>().map_err(|e| DomainError::Config(format!("{k} 必须是正整数: {e}")))
    };
    let parse_bool = |k: &str, d: bool| -> DomainResult<bool> {
        let raw = get(k);
        if raw.is_empty() {
            return Ok(d);
        }
        match raw.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(DomainError::Config(format!("{k} 必须是布尔值: {other}"))),
        }
    };

    let env_kind = RunEnv::parse(&get_or("AGF_ENV", "dev"))?;
    let log_format = match get_or("AGF_LOG_FORMAT", "pretty").to_ascii_lowercase().as_str() {
        "json" => LogFormat::Json,
        "pretty" | "text" => LogFormat::Pretty,
        other => return Err(DomainError::Config(format!("未知 AGF_LOG_FORMAT: {other}"))),
    };

    let server = ServerConfig {
        host: get_or("AGF_SERVER_HOST", "0.0.0.0"),
        port: parse_u16("AGF_SERVER_PORT", 8080)?,
        ingest_port: parse_u16("AGF_INGEST_PORT", 8090)?,
        syslog_tcp_port: parse_u16("AGF_SYSLOG_TCP_PORT", 5514)?,
        syslog_udp_port: parse_u16("AGF_SYSLOG_UDP_PORT", 5514)?,
        mcp_proxy_port: parse_u16("AGF_MCP_PROXY_PORT", 8091)?,
        metrics_port: parse_u16("AGF_METRICS_PORT", 9100)?,
        api_prefix: get_or("AGF_API_PREFIX", crate::constants::API_PREFIX),
        max_body_bytes: usize::try_from(parse_i64("AGF_MAX_BODY_BYTES", 16 * 1024 * 1024)?).unwrap_or(16 * 1024 * 1024),
    };

    let database = DatabaseConfig {
        host: get_or("AGF_PG_HOST", "127.0.0.1"),
        port: parse_u16("AGF_PG_PORT", 5432)?,
        database: get_or("AGF_PG_DB", "aiguardfabric"),
        user: get_or("AGF_PG_USER", "agf"),
        password: get("AGF_PG_PASSWORD").to_string(),
        pool_max: parse_u32("AGF_PG_POOL_MAX", 20)?,
        pool_min: parse_u32("AGF_PG_POOL_MIN", 2)?,
        connect_timeout_secs: u64::try_from(parse_i64("AGF_PG_CONNECT_TIMEOUT_SECS", 10)?).unwrap_or(10),
    };

    let redis = RedisConfig {
        url: get_or("AGF_REDIS_URL", "redis://127.0.0.1:6379/0"),
        key_prefix: get_or("AGF_REDIS_PREFIX", "agf"),
    };

    let nats = NatsConfig {
        enabled: parse_bool("AGF_NATS_ENABLED", true)?,
        url: get_or("AGF_NATS_URL", "nats://127.0.0.1:4222"),
        stream: get_or("AGF_NATS_STREAM", "AGF_EVENTS"),
    };

    let clickhouse = ClickHouseConfig {
        enabled: parse_bool("AGF_CLICKHOUSE_ENABLED", false)?,
        url: get_or("AGF_CLICKHOUSE_URL", "http://127.0.0.1:8123"),
        database: get_or("AGF_CLICKHOUSE_DB", "agf"),
        user: get_or("AGF_CLICKHOUSE_USER", "default"),
        password: get("AGF_CLICKHOUSE_PASSWORD").to_string(),
    };

    let s3 = S3Config {
        endpoint: get("AGF_S3_ENDPOINT").to_string(),
        region: get_or("AGF_S3_REGION", "us-east-1"),
        bucket: get_or("AGF_S3_BUCKET", "agf-evidence"),
        access_key: get("AGF_S3_ACCESS_KEY").to_string(),
        secret_key: get("AGF_S3_SECRET_KEY").to_string(),
        force_path_style: parse_bool("AGF_S3_FORCE_PATH_STYLE", true)?,
    };

    let security = SecurityConfig {
        jwt_secret: get("AGF_JWT_SECRET").to_string(),
        jwt_access_ttl_secs: parse_i64("AGF_JWT_ACCESS_TTL_SECS", 3_600)?,
        jwt_refresh_ttl_secs: parse_i64("AGF_JWT_REFRESH_TTL_SECS", 259_200)?,
        jwt_issuer: get_or("AGF_JWT_ISSUER", crate::constants::JWT_ISSUER),
        master_key_b64: get("AGF_MASTER_KEY_BASE64").to_string(),
        fingerprint_salt: get_or("AGF_FINGERPRINT_SALT", "aiguardfabric-default-salt-change-in-prod"),
        kms_backend: get_or("AGF_KMS_BACKEND", "local-file"),
        bootstrap_admin_user: get_or("AGF_BOOTSTRAP_ADMIN_USER", crate::constants::BOOTSTRAP_ADMIN_USER),
        bootstrap_admin_email: get_or("AGF_BOOTSTRAP_ADMIN_EMAIL", "admin@aiguardfabric.local"),
        bootstrap_admin_password: get("AGF_BOOTSTRAP_ADMIN_PASSWORD").to_string(),
        force_password_change: parse_bool("AGF_FORCE_PASSWORD_CHANGE", true)?,
        password_min_length: usize::try_from(parse_i64("AGF_PASSWORD_MIN_LENGTH", 12)?).unwrap_or(12),
        login_max_failures: parse_u32("AGF_LOGIN_MAX_FAILURES", 5)?,
        login_lockout_secs: parse_i64("AGF_LOGIN_LOCKOUT_SECS", 900)?,
        tenant_rate_per_5min: parse_u32("AGF_QUOTA_TENANT_REQ_PER_MIN", 6_000)?,
    };

    let quota = QuotaDefaults {
        tenant_tokens_per_day: parse_i64("AGF_QUOTA_TENANT_TOKENS_PER_DAY", 5_000_000)?,
        agent_tokens_per_day: parse_i64("AGF_QUOTA_AGENT_TOKENS_PER_DAY", 500_000)?,
        session_tokens: parse_i64("AGF_QUOTA_SESSION_TOKENS", 100_000)?,
        tenant_req_per_min: parse_i64("AGF_QUOTA_TENANT_REQ_PER_MIN", 6_000)?,
    };

    let observability = ObservabilityConfig {
        otel_enabled: parse_bool("AGF_OTEL_ENABLED", false)?,
        otel_endpoint: get_or("AGF_OTEL_ENDPOINT", "http://127.0.0.1:4318"),
        otel_service_name: get_or("AGF_OTEL_SERVICE_NAME", "agf-server"),
        prometheus_enabled: parse_bool("AGF_PROMETHEUS_ENABLED", true)?,
    };

    let mut device_adapters: BTreeMap<String, bool> = BTreeMap::new();
    for name in [
        "qingteng",
        "alicloud-waf",
        "huawei-waf",
        "huawei-hss",
        "tencent",
        "sangfor",
        "qianxin",
        "nsfocus",
        "topsec",
        "fortinet",
        "paloalto",
        "crowdstrike",
        "wazuh",
    ] {
        let key = format!("AGF_{}_ENABLED", name.replace('-', "_").to_uppercase());
        device_adapters.insert(name.to_string(), parse_bool(&key, false)?);
    }

    Ok(AppConfig {
        env: env_kind,
        mock_mode: parse_bool(crate::constants::ENV_MOCK_MODE, true)?,
        degrade_on_missing: parse_bool("AGF_DEGRADE_ON_MISSING", true)?,
        log_level: get_or("AGF_LOG_LEVEL", "info"),
        log_format,
        project_root: get_or("AGF_PROJECT_ROOT", "."),
        data_dir: get_or("AGF_DATA_DIR", "./data"),
        server,
        database,
        redis,
        nats,
        clickhouse,
        s3,
        security,
        quota,
        observability,
        device_adapters,
    })
}

/// 从进程环境解析配置。
///
/// # Errors
/// 同 [`from_env_map`]。
pub fn from_process_env() -> DomainResult<AppConfig> {
    let map: BTreeMap<String, String> = std::env::vars().collect();
    from_env_map(&map)
}
