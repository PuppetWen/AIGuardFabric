//! 由 `apig.rs` 拆分：`ApigAdapter`/`ApigPolicy`/`ApigPolicyKind` 的实现（纯搬移，逻辑不变）。
use super::*;

impl ApigPolicyKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RateLimit => "rate-limit",
            Self::TokenQuota => "token-quota",
            Self::ContentSafety => "content-safety",
            Self::ModelRouting => "model-routing",
        }
    }

    /// 对应的 APIG 插件类型（下发给云侧的 `PluginType`）。
    #[must_use]
    pub const fn plugin_type(&self) -> &'static str {
        match self {
            Self::RateLimit => "ai-rate-limit",
            Self::TokenQuota => "ai-token-quota",
            Self::ContentSafety => "ai-content-safety",
            Self::ModelRouting => "ai-model-router",
        }
    }

    /// 解析文本。
    ///
    /// # Errors
    /// 未知类型返回错误描述。
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().replace('_', "-").as_str() {
            "rate-limit" | "ratelimit" | "throttle" => Ok(Self::RateLimit),
            "token-quota" | "quota" => Ok(Self::TokenQuota),
            "content-safety" | "safety" => Ok(Self::ContentSafety),
            "model-routing" | "routing" => Ok(Self::ModelRouting),
            other => Err(format!("未知 APIG 策略类型: {other}")),
        }
    }
}

impl ApigPolicy {
    /// 限流策略。
    #[must_use]
    pub fn rate_limit(name: impl Into<String>, qps: u32) -> Self {
        Self {
            name: name.into(),
            kind: ApigPolicyKind::RateLimit,
            route_ids: Vec::new(),
            enabled: true,
            config: serde_json::json!({ "qps": qps, "burst": qps.saturating_mul(2) }),
        }
    }

    /// Token 配额策略。
    #[must_use]
    pub fn token_quota(name: impl Into<String>, tokens: i64, window: &str) -> Self {
        Self {
            name: name.into(),
            kind: ApigPolicyKind::TokenQuota,
            route_ids: Vec::new(),
            enabled: true,
            config: serde_json::json!({ "limit": tokens, "window": window }),
        }
    }

    /// 内容安全策略（命中即阻断并回传平台）。
    #[must_use]
    pub fn content_safety(name: impl Into<String>, categories: &[&str]) -> Self {
        Self {
            name: name.into(),
            kind: ApigPolicyKind::ContentSafety,
            route_ids: Vec::new(),
            enabled: true,
            config: serde_json::json!({ "action": "block", "report_to": "agf-ingest", "categories": categories }),
        }
    }

    /// 模型路由策略。
    #[must_use]
    pub fn model_routing(name: impl Into<String>, model: &str, upstream: &str) -> Self {
        Self {
            name: name.into(),
            kind: ApigPolicyKind::ModelRouting,
            route_ids: Vec::new(),
            enabled: true,
            config: serde_json::json!({ "model": model, "upstream": upstream }),
        }
    }

    /// 组装下发参数（`CreatePlugin` / `UpdatePlugin` 的公共部分）。
    #[must_use]
    pub fn params(&self, gateway_id: &str) -> Vec<(String, String)> {
        vec![
            ("GatewayId".to_string(), gateway_id.to_string()),
            ("PluginName".to_string(), self.name.clone()),
            ("PluginType".to_string(), self.kind.plugin_type().to_string()),
            ("Enabled".to_string(), self.enabled.to_string()),
            ("PluginConfig".to_string(), self.config.to_string()),
            ("RouteIds".to_string(), self.route_ids.join(",")),
        ]
    }
}

impl std::fmt::Debug for ApigAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApigAdapter")
            .field("core", &self.core)
            .field("has_client", &self.client.is_some())
            .field("transport", &"<transport-double>")
            .finish()
    }
}

impl Default for ApigAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ApigAdapter {
    /// 未配置态构造。
    #[must_use]
    pub fn new() -> Self {
        Self { core: AdapterCore::new(AliCloudService::Apig), client: None, transport: null_transport() }
    }

    /// Mock 模式构造。
    #[must_use]
    pub fn mocked() -> Self {
        let mut adapter = Self::new();
        adapter.core.mode = AdapterMode::Mocked;
        adapter.core.unconfigured_reason = None;
        adapter
    }

    /// 注入录制替身并重建真实调用通道（测试用）。
    ///
    /// # Errors
    /// 缺少凭据或未初始化。
    pub fn with_recording_transport(&mut self, transport: Arc<dyn crate::http::Transport>) -> DomainResult<()> {
        self.client = Some(self.core.build_test_client(transport)?);
        Ok(())
    }

    /// 当前模式。
    #[must_use]
    pub const fn mode(&self) -> AdapterMode {
        self.core.mode()
    }

    /// 只读核心。
    #[must_use]
    pub const fn core(&self) -> &AdapterCore {
        &self.core
    }

    /// 可变核心。
    pub const fn core_mut(&mut self) -> &mut AdapterCore {
        &mut self.core
    }

    /// 传输替身句柄（Mock 模式下恒不被调用；测试用它断言"零网络"）。
    #[must_use]
    pub fn transport(&self) -> Arc<crate::http::RecordingTransport> {
        self.transport.clone()
    }

    pub(crate) fn live_client(&self) -> DomainResult<&RpcClient> {
        if self.core.is_mock() {
            return Err(mock::mock_blocked(AliCloudService::Apig));
        }
        self.client
            .as_deref()
            .ok_or_else(|| mock::unavailable(AliCloudService::Apig, "适配器未初始化或凭据未就绪（无真实调用通道）"))
    }

    /// 平台策略 → APIG 策略集合（默认四类，供 `sync(Push)` 使用）。
    #[must_use]
    pub fn default_policy_set(rate_limit_qps: u32, token_limit: i64) -> Vec<ApigPolicy> {
        vec![
            ApigPolicy::rate_limit("agf-rate-limit", rate_limit_qps),
            ApigPolicy::token_quota("agf-token-quota", token_limit, "day"),
            ApigPolicy::content_safety(
                "agf-content-safety",
                &["prompt_attack", "credential_leak", "data_exfiltration"],
            ),
            ApigPolicy::model_routing("agf-model-routing", "qwen-max", "dashscope.aliyuncs.com"),
        ]
    }
}

#[async_trait]
impl Adapter for ApigAdapter {
    fn name(&self) -> &str {
        AliCloudService::Apig.as_str()
    }

    fn descriptor(&self) -> AdapterDescriptor {
        mock::descriptor_of(AliCloudService::Apig)
    }

    async fn init(&mut self, config: &AdapterConfig) -> DomainResult<()> {
        self.core.load_from_config(config)?;
        self.client = self.core.build_live_client();
        mock::log_init(AliCloudService::Apig, self.core.mode());
        Ok(())
    }

    async fn health(&self) -> DomainResult<AdapterHealth> {
        Ok(self.core.health_of())
    }

    async fn sync(&self, direction: SyncDirection, req: &PullRequest) -> DomainResult<SyncOutcome> {
        let started = std::time::Instant::now();
        let mut outcome = SyncOutcome {
            mocked: self.core.is_mock(),
            degraded: !self.core.is_live(),
            finished_at: Some(Timestamp::now()),
            ..SyncOutcome::default()
        };
        if direction.includes_pull() {
            let gateways = self.pull_gateways().await?;
            let routes = self.pull_routes(None).await?;
            let plugins = self.pull_plugins().await?;
            outcome.pulled = gateways.len() + routes.len() + plugins.len();
            outcome.changes.insert("gateway".to_string(), gateways.len());
            outcome.changes.insert("route".to_string(), routes.len());
            outcome.changes.insert("plugin".to_string(), plugins.len());
        }
        if direction.includes_push() {
            if !self.core.is_mock() {
                return Err(DomainError::Validation(
                    "真实策略发布必须显式提供目标网关和插件配置，禁止自动下发演示策略".into(),
                ));
            }
            // 平台 → 云：按默认四类策略下发到每个网关
            let gateways = self.pull_gateways().await?;
            let policies = Self::default_policy_set(200, 1_000_000);
            let mut pushed = 0_usize;
            let mut failed = 0_usize;
            for gateway in &gateways {
                for policy in &policies {
                    match self.push_policy(&gateway.gateway_id, policy).await {
                        Ok(_) => pushed += 1,
                        Err(_) => failed += 1,
                    }
                }
            }
            outcome.pushed = pushed;
            outcome.failed = failed;
            outcome.changes.insert("policy".to_string(), pushed);
            if failed > 0 {
                outcome.warnings.push(format!("{failed} 条策略下发失败，未自动重试，请核对回执"));
            }
        }
        if self.core.is_mock() {
            outcome.warnings.push("Mock 模式：返回确定性 fixtures，未触达真实 AI 网关（AGF_MOCK_MODE）".to_string());
        }
        if !req.resource.is_empty() {
            outcome.changes.insert("requested_resource".to_string(), 1);
        }
        outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(outcome)
    }

    async fn push(&self, payload: &PushPayload) -> DomainResult<()> {
        match payload.entity.as_str() {
            "policy" => {
                let gateway_id = payload
                    .body
                    .get("gateway_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("gw-mock-001")
                    .to_string();
                let policy: ApigPolicy = serde_json::from_value(payload.body.clone())?;
                self.push_policy(&gateway_id, &policy).await?;
                Ok(())
            }
            other => Err(DomainError::Validation(format!("APIG 适配器只接受 policy 载荷，收到 {other}"))),
        }
    }

    async fn pull(&self, req: &PullRequest) -> DomainResult<PullResponse> {
        let resource = if req.resource.is_empty() { "gateways".to_string() } else { req.resource.clone() };
        let (items, origin_kind) = match resource.as_str() {
            "gateways" => (
                self.pull_gateways()
                    .await?
                    .into_iter()
                    .map(|g| serde_json::to_value(g).unwrap_or(serde_json::Value::Null))
                    .collect::<Vec<_>>(),
                "gateways",
            ),
            "routes" => {
                let gateway_id = req.filter.get("gateway_id").map(String::as_str);
                (
                    self.pull_routes(gateway_id)
                        .await?
                        .into_iter()
                        .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
                        .collect::<Vec<_>>(),
                    "routes",
                )
            }
            "plugins" => (
                self.pull_plugins()
                    .await?
                    .into_iter()
                    .map(|p| serde_json::to_value(p).unwrap_or(serde_json::Value::Null))
                    .collect::<Vec<_>>(),
                "plugins",
            ),
            "access-logs" | "logs" => (self.pull_access_logs(req).await?, "access-logs"),
            other => return Err(DomainError::Validation(format!("APIG 不支持拉取资源类型 {other}"))),
        };
        Ok(PullResponse {
            items,
            next_cursor: None,
            mocked: self.core.is_mock(),
            origin: self.origin_label(origin_kind),
        })
    }

    async fn self_check(&self) -> DomainResult<AdapterHealth> {
        let mut health = self.core.health_of();
        let checks = crate::selfcheck::service_checks(AliCloudService::Apig, &self.core, None);
        health.message = Some(crate::selfcheck::summarize_checks(&checks, self.core.mode()));
        Ok(health)
    }

    async fn shutdown(&mut self) -> DomainResult<()> {
        self.core.shutdown_common();
        self.client = None;
        Ok(())
    }
}

impl ApigAdapter {
    pub(crate) fn origin_label(&self, resource: &str) -> String {
        if self.core.is_mock() {
            format!("fixture:crates/agf-alicloud/src/mock.rs#{resource}")
        } else {
            format!("https://{}", self.core.endpoint_host().unwrap_or_default())
        }
    }
}
