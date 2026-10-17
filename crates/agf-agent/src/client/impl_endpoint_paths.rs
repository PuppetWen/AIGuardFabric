//! 由 `client.rs` 拆分：`impl_EndpointPaths`/`impl_EndpointPaths` 等 11 项（纯搬移，逻辑不变）。
use super::*;

impl Default for EndpointPaths {
    fn default() -> Self {
        Self {
            register: PayloadKind::Register.default_path().to_string(),
            heartbeat: PayloadKind::Heartbeat.default_path().to_string(),
            report: PayloadKind::Snapshot.default_path().to_string(),
        }
    }
}

impl EndpointPaths {
    /// 按载荷种类取路径。
    #[must_use]
    pub fn for_kind(&self, kind: PayloadKind) -> &str {
        match kind {
            PayloadKind::Register => &self.register,
            PayloadKind::Heartbeat => &self.heartbeat,
            PayloadKind::Snapshot | PayloadKind::Diff => &self.report,
        }
    }
}

impl AgentTransport for MockTransport {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn requires_network(&self) -> bool {
        false
    }

    fn send(&self, _endpoint: &str, _body: &str) -> DomainResult<()> {
        Ok(())
    }
}

impl AgentTransport for HttpTransportNotImplemented {
    fn name(&self) -> &'static str {
        "http-not-implemented"
    }

    fn requires_network(&self) -> bool {
        true
    }

    fn send(&self, endpoint: &str, _body: &str) -> DomainResult<()> {
        match &self.cause {
            Some(cause) => Err(DomainError::Config(format!(
                "上行未建立（{cause}）：目标 {endpoint}；mTLS 已实现（锚点 {TLS_IMPLEMENTED_ANCHOR}），\
                 但配置非法时必须明确报错而不是静默降级"
            ))),
            None => Err(DomainError::NotImplemented(format!(
                "Agent 上行 HTTP 尚未接通（TODO({TODO_ANCHOR})）：目标 {endpoint}；\
                 未配置服务端地址与 TLS 材料"
            ))),
        }
    }
}

/// 上行目标脱敏：掩码查询串取值与长路径段，避免把令牌写进日志。
#[must_use]
pub fn redact_endpoint(url: &str) -> String {
    let (base, query) = url.split_once('?').map_or((url, None), |(b, q)| (b, Some(q)));
    let mut out = base.to_string();
    if let Some(query) = query {
        out.push('?');
        let masked: Vec<String> = query
            .split('&')
            .map(|pair| match pair.split_once('=') {
                Some((k, v)) if !v.is_empty() => format!("{k}={}", agf_core::secret::mask_default(v)),
                _ => pair.to_string(),
            })
            .collect();
        out.push_str(&masked.join("&"));
    }
    out
}

impl ClientMode {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Live => "live",
            Self::Unconfigured => "unconfigured",
        }
    }
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("server_url", &self.server_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("mock", &self.mock)
            .field("heartbeat_interval_secs", &self.heartbeat_interval_secs)
            .field("retry", &self.retry)
            .field("paths", &self.paths)
            // TLS 只暴露模式与"配了什么"，**不打印证书/私钥内容**（路径本身不是秘密）
            .field("tls_mode", &self.tls_mode())
            .field("tls_client_cert", &self.tls.client_cert_pem)
            .field("tls_client_key", &self.tls.client_key_pem)
            .field("tls_ca", &self.tls.ca_pem)
            .finish_non_exhaustive()
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_url: None,
            token: None,
            mock: false,
            heartbeat_interval_secs: DEFAULT_HEARTBEAT_SECS,
            retry: RetryConfig {
                max_attempts: 3,
                initial_backoff_ms: 200,
                multiplier: 2.0,
                max_backoff_ms: 5_000,
                jitter: false,
            },
            queue: QueueConfig::default(),
            paths: EndpointPaths::default(),
            tls: TlsConfig::default(),
        }
    }
}

impl ClientConfig {
    /// Mock 模式配置（零网络）。
    #[must_use]
    pub fn mock() -> Self {
        Self { mock: true, server_url: Some("mock://agf".to_string()), ..Self::default() }
    }

    /// 指定服务端（链式）。
    #[must_use]
    pub fn with_server_url(mut self, url: impl Into<String>) -> Self {
        self.server_url = Some(url.into());
        self
    }

    /// 指定令牌（链式）。
    #[must_use]
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(SecretString::from(token.into()));
        self
    }

    /// 指定队列（链式）。
    #[must_use]
    pub fn with_queue(mut self, queue: QueueConfig) -> Self {
        self.queue = queue;
        self
    }

    /// 指定重试（链式）。
    #[must_use]
    pub fn with_retry(mut self, retry: RetryConfig) -> Self {
        self.retry = retry;
        self
    }

    /// 从环境变量装配（`AGF_AGENT_SERVER_URL` / `AGF_AGENT_TOKEN` / `AGF_MOCK_MODE` / `AGF_AGENT_TLS_*`）。
    #[must_use]
    pub fn from_env() -> Self {
        let mut config = Self { mock: crate::mock_mode_from_env(), tls: TlsConfig::from_env(), ..Self::default() };
        if let Ok(url) = std::env::var(ENV_SERVER_URL) {
            let trimmed = url.trim();
            if !trimmed.is_empty() {
                config.server_url = Some(trimmed.to_string());
            }
        }
        if let Ok(token) = std::env::var(ENV_TOKEN) {
            let trimmed = token.trim();
            if !trimmed.is_empty() {
                config.token = Some(SecretString::from(trimmed.to_string()));
            }
        }
        if let Ok(secs) = std::env::var(ENV_HEARTBEAT_SECS) {
            if let Ok(parsed) = secs.trim().parse::<u64>() {
                if parsed > 0 {
                    config.heartbeat_interval_secs = parsed;
                }
            }
        }
        config
    }

    /// 是否配置了可用服务端。
    #[must_use]
    pub fn has_server(&self) -> bool {
        self.server_url.as_deref().is_some_and(|u| !u.trim().is_empty())
    }
}

impl DeliveryOutcome {
    /// 是否真正送达服务端（Mock 也算"已处理"，但不代表触达）。
    #[must_use]
    pub const fn is_delivered(&self) -> bool {
        !self.queued && !self.mocked
    }
}

impl fmt::Debug for AgentClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentClient")
            .field("identity", &self.identity)
            .field("config", &self.config)
            .field("transport", &self.transport.name())
            .field("queue_depth", &self.queue.len())
            .field("registered", &self.registered)
            .field("recorded", &self.recorded.len())
            .finish_non_exhaustive()
    }
}
