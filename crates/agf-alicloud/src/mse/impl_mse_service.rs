//! 由 `mse.rs` 拆分：`MseAdapter`/`MseConfig`/`MseService` 的实现（纯搬移，逻辑不变）。
use super::*;

impl MseService {
    /// 元数据字符串取值。
    #[must_use]
    pub fn meta_str(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).and_then(serde_json::Value::as_str)
    }

    /// 服务唯一键（`namespace/group/service`）。
    #[must_use]
    pub fn unique_key(&self) -> String {
        format!("{}/{}/{}", self.namespace, self.group_name, self.service_name)
    }

    /// 是否健康（全部实例健康才算健康）。
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.instance_count > 0 && self.healthy_count == self.instance_count
    }

    /// 推断资产类型。
    #[must_use]
    pub fn asset_kind(&self) -> AssetKind {
        match self.meta_str("kind").unwrap_or("other") {
            "mcp-server" => AssetKind::McpServer,
            "mcp-client" => AssetKind::McpClient,
            "agent" => AssetKind::Agent,
            "model-endpoint" => AssetKind::ModelEndpoint,
            "skill" | "tool" => AssetKind::Skill,
            "rag-kb" => AssetKind::RagKb,
            "vector-store" => AssetKind::VectorStore,
            "prompt-template" => AssetKind::PromptTemplate,
            "credential" => AssetKind::Credential,
            "collector" => AssetKind::Collector,
            "data-source" => AssetKind::DataSource,
            _ => AssetKind::Other,
        }
    }

    /// 推断协议。
    #[must_use]
    pub fn protocol(&self) -> Option<Protocol> {
        match self.meta_str("protocol")? {
            "mcp-stdio" => Some(Protocol::McpStdio),
            "mcp-sse" => Some(Protocol::McpSse),
            "mcp-http" => Some(Protocol::McpHttp),
            "openai-compat" => Some(Protocol::OpenAiCompat),
            "anthropic" => Some(Protocol::Anthropic),
            "gemini" => Some(Protocol::Gemini),
            "a2a" => Some(Protocol::A2a),
            "grpc" => Some(Protocol::Grpc),
            "http" => Some(Protocol::Http),
            "websocket" => Some(Protocol::WebSocket),
            _ => Some(Protocol::Other),
        }
    }

    /// 数据分级（缺省内部）。
    #[must_use]
    pub fn data_class(&self) -> DataClass {
        match self.meta_str("data_class") {
            Some("public") => DataClass::Public,
            Some("confidential") => DataClass::Confidential,
            Some("restricted") => DataClass::Restricted,
            _ => DataClass::Internal,
        }
    }

    /// 资产指纹输入键。
    #[must_use]
    pub fn fingerprint(&self) -> String {
        format!("mse://{}/{}", self.cluster_id, self.unique_key())
    }
}

impl MseConfig {
    /// 组装下发参数。
    #[must_use]
    pub fn params(&self) -> Vec<(String, String)> {
        vec![
            ("DataId".to_string(), self.data_id.clone()),
            ("Group".to_string(), self.group_name.clone()),
            ("NamespaceId".to_string(), self.namespace.clone()),
            ("Content".to_string(), self.content.clone()),
        ]
    }
}

impl std::fmt::Debug for MseAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MseAdapter")
            .field("core", &self.core)
            .field("has_client", &self.client.is_some())
            // stale_marks 是内部对账状态，不逐条打印
            .finish_non_exhaustive()
    }
}

impl Default for MseAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl MseAdapter {
    /// 未配置态构造。
    #[must_use]
    pub fn new() -> Self {
        Self {
            core: AdapterCore::new(AliCloudService::Mse),
            instance_id: None,
            namespace: String::new(),
            client: None,
            transport: null_transport(),
            stale_marks: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Mock 模式构造。
    #[must_use]
    pub fn mocked() -> Self {
        let mut adapter = Self::new();
        adapter.core.mode = AdapterMode::Mocked;
        adapter.core.unconfigured_reason = None;
        adapter
    }

    /// 注入录制替身（测试用）。
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

    /// 当前被标记为 `stale` 的资源 id（云侧已消失）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn stale_marks(&self) -> DomainResult<Vec<String>> {
        self.stale_marks.lock().map(|v| v.clone()).map_err(|_| DomainError::Internal("stale 标记锁中毒".to_string()))
    }

    pub(crate) fn live_client(&self) -> DomainResult<&RpcClient> {
        if self.core.is_mock() {
            return Err(mock::mock_blocked(AliCloudService::Mse));
        }
        self.client
            .as_deref()
            .ok_or_else(|| mock::unavailable(AliCloudService::Mse, "适配器未初始化或凭据未就绪（无真实调用通道）"))
    }
}

#[async_trait]
impl Adapter for MseAdapter {
    fn name(&self) -> &str {
        AliCloudService::Mse.as_str()
    }

    fn descriptor(&self) -> AdapterDescriptor {
        mock::descriptor_of(AliCloudService::Mse)
    }

    async fn init(&mut self, config: &AdapterConfig) -> DomainResult<()> {
        self.core.load_from_config(config)?;
        self.instance_id = config.get_str("instance_id").map(str::to_owned);
        self.namespace = config.get_str("namespace_id").unwrap_or_default().into();
        self.client = self.core.build_live_client();
        mock::log_init(AliCloudService::Mse, self.core.mode());
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
            let clusters = self.pull_clusters().await?;
            let services = self.pull_services().await?;
            outcome.pulled = clusters.len() + services.len();
            outcome.changes.insert("mse_cluster".to_string(), clusters.len());
            outcome.changes.insert("nacos_service".to_string(), services.len());
            outcome
                .changes
                .insert("unhealthy_service".to_string(), services.iter().filter(|s| !s.is_healthy()).count());
            // 云侧服务清单是资产发现的权威来源：把不在清单里的资源登记为 stale（不删除）
            let live_keys: Vec<String> = services.iter().map(MseService::unique_key).collect();
            if let Ok(mut marks) = self.stale_marks.lock() {
                marks.retain(|k| live_keys.contains(k));
            }
            let stale = services.iter().filter(|s| !s.is_healthy()).map(MseService::unique_key).collect::<Vec<_>>();
            if let Ok(mut marks) = self.stale_marks.lock() {
                for key in stale {
                    if !marks.contains(&key) {
                        marks.push(key);
                    }
                }
            }
        }
        if direction.includes_push() {
            if !self.core.is_mock() {
                return Err(DomainError::Validation(
                    "真实配置发布必须调用 push 并提供实际配置；禁止自动下发演示策略".into(),
                ));
            }
            // 平台 → Nacos：把平台策略/配额配置热更新下发
            let configs = crate::mse::platform_default_configs();
            let mut pushed = 0_usize;
            for config in &configs {
                if self.push_config(config).await.is_ok() {
                    pushed += 1;
                } else {
                    outcome.failed += 1;
                }
            }
            outcome.pushed = pushed;
            outcome.changes.insert("nacos_config".to_string(), pushed);
        }
        if self.core.is_mock() {
            outcome.warnings.push("Mock 模式：返回确定性 fixtures，未触达真实 MSE（AGF_MOCK_MODE）".to_string());
        }
        if !req.resource.is_empty() {
            outcome.changes.insert("requested_resource".to_string(), 1);
        }
        outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(outcome)
    }

    async fn push(&self, payload: &PushPayload) -> DomainResult<()> {
        match payload.entity.as_str() {
            "config" | "nacos-config" => {
                let config: MseConfig = serde_json::from_value(payload.body.clone())?;
                self.push_config(&config).await?;
                Ok(())
            }
            other => Err(DomainError::Validation(format!("MSE 适配器只接受 config / nacos-config 载荷，收到 {other}"))),
        }
    }

    async fn pull(&self, req: &PullRequest) -> DomainResult<PullResponse> {
        let resource = if req.resource.is_empty() { "services".to_string() } else { req.resource.clone() };
        let items = match resource.as_str() {
            "services" | "nacos-services" => self
                .pull_services()
                .await?
                .into_iter()
                .map(|s| serde_json::to_value(s).unwrap_or(serde_json::Value::Null))
                .collect(),
            "clusters" => self
                .pull_clusters()
                .await?
                .into_iter()
                .map(|c| serde_json::to_value(c).unwrap_or(serde_json::Value::Null))
                .collect(),
            "configs" => self
                .pull_configs()
                .await?
                .into_iter()
                .map(|c| serde_json::to_value(c).unwrap_or(serde_json::Value::Null))
                .collect(),
            "gateways" => self
                .pull_gateways()
                .await?
                .into_iter()
                .map(|g| serde_json::to_value(g).unwrap_or(serde_json::Value::Null))
                .collect(),
            other => return Err(DomainError::Validation(format!("MSE 不支持拉取资源类型 {other}"))),
        };
        Ok(PullResponse {
            items,
            next_cursor: None,
            mocked: self.core.is_mock(),
            origin: if self.core.is_mock() {
                format!("fixture:crates/agf-alicloud/src/mock.rs#{resource}")
            } else {
                format!("https://{}", self.core.endpoint_host().unwrap_or_default())
            },
        })
    }

    async fn self_check(&self) -> DomainResult<AdapterHealth> {
        let mut health = self.core.health_of();
        let checks = crate::selfcheck::service_checks(AliCloudService::Mse, &self.core, None);
        health.message = Some(crate::selfcheck::summarize_checks(&checks, self.core.mode()));
        Ok(health)
    }

    async fn shutdown(&mut self) -> DomainResult<()> {
        self.core.shutdown_common();
        self.client = None;
        Ok(())
    }
}
