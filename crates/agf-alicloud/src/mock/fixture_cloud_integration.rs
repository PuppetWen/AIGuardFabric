//! 由 `mock.rs` 拆分：`fixture_cloud_integration`/`null_transport` 等 4 项（纯搬移，逻辑不变）。
use super::*;

/// 构造确定性的 fixture 集成（Mock 模式或无云凭据时使用）。
#[must_use]
pub fn fixture_cloud_integration() -> CloudIntegration {
    let now = Timestamp::now();
    CloudIntegration {
        id: deterministic_id("aiguardfabric.alicloud", "mock-integration"),
        tenant_id: TenantId::default_tenant(),
        provider: CloudProvider::AliCloud,
        name: FIXTURE_INTEGRATION_NAME.to_string(),
        account_id: FIXTURE_ACCOUNT_ID.to_string(),
        region_id: FIXTURE_REGION.to_string(),
        credential_kind: agf_core::cloud::CloudCredentialKind::LongTermAk,
        credential_ref: None,
        assume_role_arn: None,
        role_session_name: None,
        sts_expires_at: None,
        endpoints: BTreeMap::new(),
        enabled: true,
        health: HealthState::Unconfigured,
        last_sync_at: None,
        last_error: None,
        permission_checks: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

/// 共享的 Mock 传输替身（Mock 模式适配器持有它以满足结构一致性，但永不使用）。
#[must_use]
pub fn null_transport() -> Arc<RecordingTransport> {
    Arc::new(RecordingTransport::with_body(serde_json::json!({ "mock": true })))
}

impl std::fmt::Debug for AdapterCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterCore")
            .field("service", &self.service.as_str())
            .field("mode", &self.mode)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint.as_ref().map(|e| e.host.clone()))
            .field("account_id", &self.account_id)
            .field("tenant_id", &self.tenant_id)
            .field("style", &self.style)
            .field("sign_style", &self.sign_style)
            .field("timeout_secs", &self.timeout_secs)
            .field("unconfigured_reason", &self.unconfigured_reason)
            .field("endpoint_overrides", &self.endpoint_overrides)
            // TLS 放松开关：只打印"是否配置/长度"，不打印 CA PEM 内容
            .field("tls_ca_pem_bytes", &self.tls_ca_pem.as_ref().map(String::len))
            .field("tls_allow_insecure", &self.tls_allow_insecure)
            .field("circuit_config", &self.circuit_config)
            .field("retry_config", &self.retry_config)
            .field("credential", &self.credential)
            .field("credential_warnings", &self.credential_warnings.len())
            .field("circuit", &self.circuit)
            .field("config_id", &self.config_id)
            .finish()
    }
}

impl AdapterCore {
    /// 新内核（未配置态）。
    #[must_use]
    pub fn new(service: AliCloudService) -> Self {
        Self {
            service,
            mode: AdapterMode::Unconfigured,
            unconfigured_reason: Some("尚未调用 init（无配置）".to_string()),
            region: FIXTURE_REGION.to_string(),
            account_id: String::new(),
            tenant_id: TenantId::default_tenant(),
            style: EndpointStyle::Public,
            sign_style: SignStyle::Rpc,
            timeout_secs: 30,
            endpoint_overrides: BTreeMap::new(),
            tls_ca_pem: None,
            tls_allow_insecure: false,
            endpoint: None,
            credential: None,
            credential_warnings: Vec::new(),
            circuit_config: CircuitBreakerConfig::default(),
            retry_config: RetryConfig::default(),
            circuit: CircuitSnapshot::default(),
            config_id: None,
        }
    }

    /// 当前模式。
    #[must_use]
    pub const fn mode(&self) -> AdapterMode {
        self.mode
    }

    /// 是否 Mock。
    #[must_use]
    pub const fn is_mock(&self) -> bool {
        self.mode.is_mock()
    }

    /// 是否真实模式。
    #[must_use]
    pub const fn is_live(&self) -> bool {
        self.mode.is_live()
    }

    /// endpoint 主机。
    #[must_use]
    pub fn endpoint_host(&self) -> Option<String> {
        self.endpoint.as_ref().map(|e| e.host.clone())
    }

    /// 设置凭据。
    pub fn set_credential(&mut self, credential: Option<CloudCredential>) {
        self.credential = credential;
    }

    /// 应用一次凭据解析结果（含风险告警）。
    pub fn apply_outcome(&mut self, outcome: &CredentialOutcome) {
        self.credential = Some(outcome.credential.clone());
        self.credential_warnings = outcome.warnings.clone();
    }

    /// 装载配置（不解析凭据、不建连接）。
    ///
    /// 模式判定优先级：
    /// 1. 环境变量 `AGF_MOCK_MODE`；
    /// 2. `AdapterConfig::mock`；
    /// 3. 缺少必需凭据 → [`AdapterMode::Unconfigured`]（**降级而非失败**）。
    ///
    /// # Errors
    /// 地域非法时返回 [`DomainError::Config`]。
    pub fn load_from_config(&mut self, config: &AdapterConfig) -> DomainResult<()> {
        self.config_id = Some(config.id);
        self.tenant_id = config.tenant_id;
        self.circuit_config = config.circuit_breaker;
        self.retry_config = config.retry;
        self.timeout_secs = config.timeout_secs.max(1);
        self.region = config.get_str("region_id").map_or_else(|| FIXTURE_REGION.to_string(), ToString::to_string);
        self.account_id = config.get_str("account_id").unwrap_or_default().to_string();
        self.style = match config.get_str("endpoint_style").unwrap_or("public") {
            "private" | "privatelink" | "vpc" => EndpointStyle::Private,
            _ => EndpointStyle::Public,
        };
        self.sign_style = match config.get_str("sign_style").unwrap_or("rpc") {
            "v3" | "acs3" => SignStyle::V3,
            _ => SignStyle::Rpc,
        };
        self.endpoint_overrides = config
            .settings
            .iter()
            .filter(|(k, _)| {
                !matches!(
                    k.as_str(),
                    // endpoint 覆盖的内建键 + TLS 开关（TLS 开关不是 endpoint，单独取值）
                    "region_id" | "account_id" | "endpoint_style" | "sign_style" | "ca_pem" | "insecure_tls"
                )
            })
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();
        // TLS 放松开关：**仅 dev / 显式开关生效**（见 `http::tls_override_allowed`），
        // 生产下即使配了也忽略（`with_tls_options` 会 warn）。
        self.tls_ca_pem = config
            .settings
            .get("ca_pem")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);
        self.tls_allow_insecure =
            config.settings.get("insecure_tls").and_then(serde_json::Value::as_bool).unwrap_or(false);
        // endpoint 解析放在这里：地域非法必须在 init 阶段暴露（配置存在但非法 = 错误）
        self.endpoint = Some(resolve(self.service, &self.region, self.style, &self.endpoint_overrides)?);

        if config.mock || crate::mock_mode_from_env() {
            self.mode = AdapterMode::Mocked;
            self.unconfigured_reason = None;
            // Mock 也给一份"自洽凭据"，让签名路径可被测试完整走通（fixtures 专用，非真实 AK）
            self.credential = Some(CloudCredential::long_term(FIXTURE_ACCESS_KEY_ID, FIXTURE_ACCESS_KEY_SECRET));
        } else if config.has_secrets(&["access_key_id", "access_key_secret"])
            || config.get_str("credential_source").is_some_and(|s| s.starts_with("env"))
        {
            self.mode = AdapterMode::Live;
            self.unconfigured_reason = None;
            self.resolve_credentials();
        } else {
            self.mode = AdapterMode::Unconfigured;
            self.unconfigured_reason = Some(
                "缺少 access_key_id / access_key_secret 凭据引用，且未启用 Mock（AGF_MOCK_MODE=1）：已降级为不触达云 API"
                    .to_string(),
            );
            self.credential = None;
        }
        Ok(())
    }

    /// 解析凭据（真实模式）；失败时保持 Live 但 `credential = None`，
    /// 业务方法会因此明确报 `DependencyUnavailable`（**不假装成功**）。
    pub(crate) fn resolve_credentials(&mut self) {
        let resolver = self.resolver_chain();
        let ctx = CredentialContext::new(MapSecretStore::shared(&[]), false);
        let integration = self.synthetic_integration();
        match resolver.resolve(&integration, &ctx) {
            Ok(outcome) => self.apply_outcome(&outcome),
            Err(_) => {
                self.credential = None;
                self.credential_warnings.clear();
            }
        }
    }

    /// 依据账号配置组装解析器链。
    ///
    /// `TODO(pending-verification):` 真实 STS / 跨账号 AssumeRole 调用尚未实现，
    /// 因此 Live 模式的解析器链会明确返回 `DependencyUnavailable`/`NotImplemented`，
    /// 由 `agf-runtime` 的接入引导流程注入已就绪凭据。见 `docs/pending-verification.md`。
    pub(crate) fn resolver_chain(&self) -> Arc<dyn CredentialResolver> {
        if self.account_id.is_empty() {
            Arc::new(EnvResolver::new())
        } else {
            let source = Arc::new(StaticResolver::new(CloudCredential::long_term(
                FIXTURE_ACCESS_KEY_ID,
                FIXTURE_ACCESS_KEY_SECRET,
            )));
            Arc::new(AssumeRoleResolver::new(source))
        }
    }

    /// 用当前内核状态重建一个用于凭据解析的集成描述。
    pub(crate) fn synthetic_integration(&self) -> CloudIntegration {
        let mut integration = fixture_cloud_integration();
        if !self.account_id.is_empty() {
            integration.account_id = self.account_id.clone();
        }
        integration.region_id = self.region.clone();
        integration.endpoints = self.endpoint_overrides.clone();
        integration
    }

    /// 实际生效的 TLS 策略（自检报告与 `/readyz` notes 的数据源）。
    ///
    /// 未配置 `ca_pem`/`insecure_tls`，或不在 dev/显式开关下 ⇒ 一律 [`TlsPolicy::VerifyChain`]。
    #[must_use]
    pub fn tls_policy(&self) -> TlsPolicy {
        if !crate::http::tls_override_allowed() {
            return TlsPolicy::VerifyChain;
        }
        if self.tls_allow_insecure {
            TlsPolicy::Insecure
        } else if self.tls_ca_pem.is_some() {
            TlsPolicy::CustomCa
        } else {
            TlsPolicy::VerifyChain
        }
    }

    /// 真实模式且凭据就绪时构造 [`RpcClient`]（绑定 reqwest 异步通道）；否则 `None`。
    #[must_use]
    pub fn build_live_client(&self) -> Option<Arc<RpcClient>> {
        if !self.mode.is_live() {
            return None;
        }
        let credential = self.credential.clone()?;
        let endpoint = self.endpoint.clone()?;
        // reqwest 客户端（连接池）建成 `Arc` 后同时作为同步占位与异步通道：真实模式下
        // `RpcClient::execute` 会因存在异步通道而拒绝，因此不会有阻塞调用漏网。
        // TLS 选项来自 settings.ca_pem / settings.insecure_tls（仅 dev/显式开关生效）。
        let transport = Arc::new(
            ReqwestTransport::with_tls_options(
                self.timeout_secs,
                self.tls_ca_pem.clone().map(String::into_bytes),
                self.tls_allow_insecure,
            )
            .ok()?,
        );
        let config = RpcClientConfig {
            adapter: self.service.as_str().to_string(),
            region: self.region.clone(),
            account_id: self.account_id.clone(),
            style: self.sign_style,
            timeout_secs: self.timeout_secs,
        };
        RpcClient::live(self.mode, config, Some(credential), endpoint, transport.clone())
            .ok()
            .map(|client| Arc::new(client.with_async_transport(transport)))
    }

    /// 用测试替身构造真实模式客户端（**不触网**，用于断言请求构造）。
    ///
    /// # Errors
    /// 缺少凭据或 endpoint 未解析。
    pub fn build_test_client(&self, transport: Arc<dyn crate::http::Transport>) -> DomainResult<Arc<RpcClient>> {
        let credential = self
            .credential
            .clone()
            .ok_or_else(|| unavailable(self.service, "无法构造测试客户端：缺少凭据（未配置或未初始化）"))?;
        let endpoint = self
            .endpoint
            .clone()
            .ok_or_else(|| unavailable(self.service, "无法构造测试客户端：endpoint 未解析（未调用 init）"))?;
        let config = RpcClientConfig {
            adapter: self.service.as_str().to_string(),
            region: self.region.clone(),
            account_id: self.account_id.clone(),
            style: self.sign_style,
            timeout_secs: self.timeout_secs,
        };
        RpcClient::live(AdapterMode::Live, config, Some(credential), endpoint, transport).map(Arc::new)
    }

    /// 凭据是否临近过期。
    #[must_use]
    pub fn credential_expiring_soon(&self, now: Timestamp) -> bool {
        self.credential
            .as_ref()
            .is_some_and(|c| c.expires_at.is_some_and(|e| e.since_secs(&now) < REFRESH_THRESHOLD_SECS))
    }

    /// 健康报告。
    #[must_use]
    pub fn health_of(&self) -> AdapterHealth {
        let capabilities = capabilities_of(self.service);
        match self.mode {
            AdapterMode::Unconfigured => {
                let reason = self.unconfigured_reason.clone().unwrap_or_else(|| "未配置".to_string());
                let mut health = AdapterHealth::unconfigured(self.service.as_str(), &reason);
                health.capabilities = capabilities;
                health.circuit = self.circuit.clone();
                health
            }
            AdapterMode::Mocked => {
                let mut health = AdapterHealth::mocked(self.service.as_str());
                health.capabilities = capabilities;
                health.circuit = self.circuit.clone();
                health.message = Some(format!(
                    "{}：使用 {} 的确定性 fixtures，未触达真实阿里云",
                    health.message.unwrap_or_default(),
                    mock_location(self.service)
                ));
                health
            }
            AdapterMode::Live => {
                let credentials_ok = self.credential.is_some() && self.credential_warnings.is_empty();
                let mut health = AdapterHealth {
                    adapter: self.service.as_str().to_string(),
                    state: if credentials_ok { HealthState::Healthy } else { HealthState::Degraded },
                    configured: true,
                    mocked: false,
                    latency_ms: None,
                    circuit: self.circuit.clone(),
                    capabilities,
                    message: Some(if credentials_ok {
                        format!(
                            "真实模式：{} @ {}，凭据 {}",
                            self.service.as_str(),
                            self.endpoint_host().unwrap_or_default(),
                            self.credential.as_ref().map_or("未知", |c| c.kind.as_str())
                        )
                    } else {
                        "真实模式但凭据未就绪（需要 STS / AssumeRole 或显式注入凭据）".to_string()
                    }),
                    checked_at: Timestamp::now(),
                };
                if self.circuit.state == CircuitState::Open {
                    health.state = HealthState::CircuitOpen;
                }
                health
            }
        }
    }

    /// 关闭：清空连接与凭据，回到未配置态（幂等）。
    pub fn shutdown_common(&mut self) {
        self.credential = None;
        self.endpoint = None;
        self.mode = AdapterMode::Unconfigured;
        self.unconfigured_reason = Some("已 shutdown".to_string());
    }
}
