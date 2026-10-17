//! 由 `settings.rs` 拆分：`impl_AdapterMode`/`impl_NoSecrets` 等 10 项（纯搬移，逻辑不变）。
use super::*;

impl AdapterMode {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unconfigured => "unconfigured",
            Self::Mocked => "mocked",
            Self::Live => "live",
        }
    }

    /// 是否 Mock。
    #[must_use]
    pub const fn is_mock(&self) -> bool {
        matches!(self, Self::Mocked)
    }

    /// 是否可发起真实调用（阶段一未实现真实传输的适配器调用会返回 `NotImplemented`）。
    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Live)
    }
}

impl SecretLookup for NoSecrets {
    fn lookup(&self, _adapter: &str, _key: &str) -> Option<SecretString> {
        None
    }
}

impl StaticSecrets {
    /// 空集合。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 注入一条凭据（链式）。
    #[must_use]
    pub fn with(mut self, key: &str, value: &str) -> Self {
        self.values.insert(key.to_string(), value.to_string());
        self
    }

    /// 读取注入值（排障用；返回明文，勿写日志）。
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
}

impl SecretLookup for StaticSecrets {
    /// 先查 `<适配器名>:<键>`（多适配器隔离），再回退到裸 `<键>`（单适配器便捷写法）。
    fn lookup(&self, adapter: &str, key: &str) -> Option<SecretString> {
        self.values.get(&format!("{adapter}:{key}")).or_else(|| self.values.get(key)).cloned().map(SecretString::from)
    }
}

impl EnvSecrets {
    /// 指定前缀（如 `AGF_ADAPTER`）。
    #[must_use]
    pub fn new(prefix: impl Into<String>) -> Self {
        Self { prefix: prefix.into() }
    }

    /// 平台默认前缀的实现。
    #[must_use]
    pub fn platform_default() -> Self {
        Self::new("AGF_ADAPTER")
    }

    /// 前缀。
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }
}

impl Default for EnvSecrets {
    fn default() -> Self {
        Self::platform_default()
    }
}

impl SecretLookup for EnvSecrets {
    fn lookup(&self, adapter: &str, key: &str) -> Option<SecretString> {
        let name = env_key_for(&self.prefix, adapter, key);
        std::env::var(name).ok().filter(|v| !v.trim().is_empty()).map(SecretString::from)
    }
}

/// 组装环境变量名：全大写，非字母数字一律归一为 `_`（与 `agf-core::config` 的取名口径一致）。
#[must_use]
pub fn env_key_for(prefix: &str, adapter: &str, key: &str) -> String {
    let sanitize = |s: &str| -> String {
        s.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' }).collect()
    };
    format!("{}_{}_{}", sanitize(prefix), sanitize(adapter), sanitize(key))
}

impl fmt::Debug for AdapterSettings {
    /// **只打印键名与脱敏 endpoint**，绝不打印凭据明文。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdapterSettings")
            .field("adapter", &self.adapter)
            .field("display_name", &self.display_name)
            .field("tenant_id", &self.tenant_id)
            .field("enabled", &self.enabled)
            .field("mock", &self.mock)
            .field("timeout_secs", &self.timeout_secs)
            .field("endpoint", &self.endpoint.as_deref().map(crate::transport::redact_url))
            .field("setting_keys", &self.settings.keys().collect::<Vec<_>>())
            .field("secret_ref_keys", &self.secret_refs.keys().collect::<Vec<_>>())
            .field("secret_keys", &self.secrets.keys().collect::<Vec<_>>())
            .field("required_secrets", &self.required_secrets)
            .field("required_settings", &self.required_settings)
            .finish_non_exhaustive()
    }
}

impl AdapterSettings {
    /// 由元信息构造"未配置"默认值（不发网络、不含凭据）。
    #[must_use]
    pub fn defaults(meta: &AdapterMetadata) -> Self {
        Self {
            adapter: meta.name.clone(),
            display_name: meta.display_name.clone(),
            tenant_id: TenantId::default_tenant(),
            enabled: true,
            mock: false,
            timeout_secs: 30,
            circuit: CircuitBreakerConfig::default(),
            retry: RetryConfig::default(),
            endpoint: None,
            settings: BTreeMap::new(),
            secret_refs: BTreeMap::new(),
            secrets: BTreeMap::new(),
            required_secrets: meta.required_secrets.clone(),
            required_settings: Vec::new(),
            endpoint_key: meta.endpoint_key.clone(),
        }
    }

    /// 由 DB 实体构造（含凭据解析与配置校验）。
    ///
    /// # Errors
    /// 配置存在但非法（超时越界、URL 非法、重试参数非法）时返回 `DomainError::Config`。
    pub fn from_config(
        meta: &AdapterMetadata,
        config: &AdapterConfig,
        lookup: &dyn SecretLookup,
    ) -> DomainResult<Self> {
        let mut settings = Self::defaults(meta);
        if !config.display_name.trim().is_empty() {
            settings.display_name.clone_from(&config.display_name);
        }
        settings.tenant_id = config.tenant_id;
        settings.enabled = config.enabled;
        settings.mock = config.mock;
        settings.timeout_secs = config.timeout_secs;
        settings.circuit = config.circuit_breaker;
        settings.retry = config.retry;
        settings.settings.clone_from(&config.settings);
        settings.secret_refs.clone_from(&config.secret_refs);
        settings.endpoint = meta.endpoint_key.as_ref().and_then(|key| config.get_str(key)).map(ToString::to_string);
        for key in meta.required_secrets.iter().chain(meta.optional_secrets.iter()) {
            if let Some(value) = lookup.lookup(&meta.name, key) {
                settings.secrets.insert(key.clone(), value);
            }
        }
        settings.validate()?;
        Ok(settings)
    }

    /// 配置校验（纯函数，不触网）。
    ///
    /// # Errors
    /// 任一参数越界或 endpoint 非法时返回 `DomainError::Config`。
    pub fn validate(&self) -> DomainResult<()> {
        if self.adapter.trim().is_empty() || self.adapter.chars().any(char::is_whitespace) {
            return Err(DomainError::Config(format!("适配器名非法: {:?}", self.adapter)));
        }
        if !(MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&self.timeout_secs) {
            return Err(DomainError::Config(format!(
                "适配器 {} 超时越界: {}s（允许 {MIN_TIMEOUT_SECS}..={MAX_TIMEOUT_SECS}）",
                self.adapter, self.timeout_secs
            )));
        }
        if self.retry.max_attempts == 0 || self.retry.max_attempts > MAX_ATTEMPTS {
            return Err(DomainError::Config(format!(
                "适配器 {} 重试次数越界: {}（允许 1..={MAX_ATTEMPTS}）",
                self.adapter, self.retry.max_attempts
            )));
        }
        if self.retry.multiplier < 1.0 {
            return Err(DomainError::Config(format!(
                "适配器 {} 退避倍数非法: {}（必须 >= 1.0）",
                self.adapter, self.retry.multiplier
            )));
        }
        if self.retry.initial_backoff_ms > self.retry.max_backoff_ms {
            return Err(DomainError::Config(format!(
                "适配器 {} 初始退避 {}ms 大于上限 {}ms",
                self.adapter, self.retry.initial_backoff_ms, self.retry.max_backoff_ms
            )));
        }
        if self.circuit.failure_threshold == 0 {
            return Err(DomainError::Config(format!("适配器 {} 熔断阈值不能为 0", self.adapter)));
        }
        if self.circuit.open_secs <= 0 {
            return Err(DomainError::Config(format!("适配器 {} 熔断开路时长必须为正", self.adapter)));
        }
        if self.circuit.half_open_probes == 0 {
            return Err(DomainError::Config(format!("适配器 {} 半开探测额度必须为正", self.adapter)));
        }
        if let Some(endpoint) = &self.endpoint {
            validate_endpoint(endpoint)?;
        }
        // `sync` 的冲突策略：存在但无法识别即配置错误（**不静默回退**，避免"配了却没生效"）
        if let Some(policy) = self.get_str(crate::contract::SETTING_CONFLICT_POLICY) {
            if crate::contract::ConflictPolicy::parse(policy).is_none() {
                return Err(DomainError::Config(format!(
                    "适配器 {} 的 {} 非法: {policy:?}（允许 external-wins / local-wins / 外部优先 / 本地优先）",
                    self.adapter,
                    crate::contract::SETTING_CONFLICT_POLICY
                )));
            }
        }
        Ok(())
    }

    /// 读取非敏感字符串设置。
    #[must_use]
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.settings.get(key).and_then(serde_json::Value::as_str)
    }

    /// 读取布尔设置（可给缺省值）。
    #[must_use]
    pub fn get_bool(&self, key: &str, default: bool) -> bool {
        self.settings.get(key).and_then(serde_json::Value::as_bool).unwrap_or(default)
    }

    /// 读取凭据封装。
    #[must_use]
    pub fn secret(&self, key: &str) -> Option<&SecretString> {
        self.secrets.get(key)
    }

    /// 读取凭据明文（**仅用于构造请求，勿写日志**）。
    #[must_use]
    pub fn secret_raw(&self, key: &str) -> Option<&str> {
        self.secrets.get(key).map(ExposeSecret::expose_secret)
    }

    /// 是否持有某凭据。
    #[must_use]
    pub fn has_secret(&self, key: &str) -> bool {
        self.secrets.contains_key(key)
    }

    /// 已解析凭据键清单。
    #[must_use]
    pub fn present_secret_keys(&self) -> Vec<String> {
        self.secrets.keys().cloned().collect()
    }

    /// 必需凭据缺项。
    #[must_use]
    pub fn missing_secrets(&self) -> Vec<&str> {
        self.required_secrets.iter().filter(|k| !self.secrets.contains_key(*k)).map(String::as_str).collect()
    }

    /// 必需**设置**缺项（缺键即缺项；数字/布尔设置同样算"已提供"）。
    #[must_use]
    pub fn missing_settings(&self) -> Vec<&str> {
        self.required_settings.iter().filter(|k| !self.settings.contains_key(*k)).map(String::as_str).collect()
    }

    /// 配置是否齐全（凭据 + 必需设置）。
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.missing_secrets().is_empty() && self.missing_settings().is_empty()
    }

    /// 解析 endpoint：优先非敏感设置，其次指定凭据键（Webhook 类 URL 本身是凭据）。
    ///
    /// # Errors
    /// 两处都缺时返回 `DomainError::Config`（错误信息只含键名，不含凭据值）。
    pub fn resolve_endpoint(&self, secret_key: Option<&str>) -> DomainResult<String> {
        if let Some(endpoint) = &self.endpoint {
            return Ok(endpoint.clone());
        }
        if let Some(key) = secret_key {
            if let Some(value) = self.secret_raw(key) {
                return Ok(value.to_string());
            }
            return Err(DomainError::Config(format!(
                "适配器 {} 缺少 endpoint：设置项 {:?} 与凭据 {key} 都未配置",
                self.adapter, self.endpoint_key
            )));
        }
        Err(DomainError::Config(format!("适配器 {} 缺少 endpoint 设置项 {:?}", self.adapter, self.endpoint_key)))
    }

    /// 与元信息合并后的候选配置（用于注册表热替换；不改动原对象）。
    #[must_use]
    pub fn with_required_settings(mut self, keys: &[&str]) -> Self {
        self.required_settings = keys.iter().map(|k| (*k).to_string()).collect();
        self
    }
}
