//! 由 `vendor.rs` 拆分：`VendorAdapterImpl` 的实现（纯搬移，逻辑不变）。
use super::*;

impl<V: VendorSpec> Default for VendorAdapterImpl<V> {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<V: VendorSpec> VendorAdapter for VendorAdapterImpl<V> {
    fn name(&self) -> &str {
        V::NAME
    }

    fn metadata(&self) -> AdapterMetadata {
        V::metadata()
    }

    fn descriptor(&self) -> AdapterDescriptor {
        V::metadata().to_descriptor()
    }

    fn mode(&self) -> AdapterMode {
        self.core.mode
    }

    fn prepare(&self, config: &AdapterConfig, lookup: &dyn SecretLookup) -> DomainResult<AdapterSettings> {
        self.prepare_settings(config, lookup)
    }

    fn commit(&mut self, settings: AdapterSettings) {
        self.commit_settings(settings);
    }

    fn force_mock(&mut self) {
        let mut settings = self.core.settings.clone();
        settings.mock = true;
        self.core.mock_env = true;
        self.commit_settings(settings);
    }

    async fn init_with(
        &mut self,
        config: &AdapterConfig,
        lookup: &dyn SecretLookup,
        mock_env: bool,
    ) -> DomainResult<()> {
        // 两段式：prepare 失败则**不留任何副作用**（旧配置保持有效）
        let settings = self.prepare_settings(config, lookup)?;
        self.core.mock_env = mock_env;
        self.commit_settings(settings);
        Ok(())
    }

    async fn health_check(&self) -> DomainResult<AdapterHealthRecord> {
        Ok(self.build_record())
    }

    async fn send(&mut self, msg: &AdapterMessage) -> DomainResult<AdapterReceipt> {
        self.ensure_open()?;
        if !V::subscribes(msg) {
            return Err(DomainError::Validation(format!("适配器 {} 不订阅事件类型 {}", V::NAME, msg.event_type)));
        }
        match self.core.mode {
            AdapterMode::Mocked => {
                // Mock 模式**不依赖真实 endpoint / 凭据**（零配置可用）：
                // 编码因"未配置"失败属计划内降级（忽略）；载荷本身缺字段（Validation）
                // 仍必须暴露——否则 Mock 会把真实问题掩盖掉。
                if let Err(error) = V::encode(msg, &self.core.settings) {
                    if !matches!(error, DomainError::Config(_)) {
                        self.note_failure(&error, 1, 0);
                        return Err(error);
                    }
                }
                self.note_success(1, 0);
                Ok(Self::mock_receipt(msg, 1))
            }
            AdapterMode::Unconfigured => {
                let error = self.unconfigured_error();
                self.note_failure(&error, 0, 0);
                Err(error)
            }
            AdapterMode::Live => self.send_live(msg).await,
        }
    }

    async fn push(&self, payload: &PushPayload) -> DomainResult<PushOutcome> {
        self.push_semantic(payload).await
    }

    async fn pull(&self, req: &PullRequest) -> DomainResult<PullResponse> {
        self.pull_semantic(req).await
    }

    async fn sync(&self, req: &SyncRequest) -> DomainResult<SyncOutcome> {
        self.sync_semantic(req).await
    }

    fn semantics(&self) -> SemanticProfile {
        V::semantics()
    }

    async fn close(&mut self) -> DomainResult<()> {
        // 幂等：重复调用恒 Ok
        self.core.closed = true;
        self.core.last = Mutex::new(super::LastCall::default());
        Ok(())
    }

    fn subscribes(&self, msg: &AdapterMessage) -> bool {
        V::subscribes(msg)
    }

    fn encode(&self, msg: &AdapterMessage) -> DomainResult<crate::transport::VendorRequest> {
        V::encode(msg, &self.core.settings)
    }
}

#[async_trait]
impl<V: VendorSpec> CoreAdapter for VendorAdapterImpl<V> {
    fn name(&self) -> &str {
        V::NAME
    }

    fn descriptor(&self) -> AdapterDescriptor {
        V::metadata().to_descriptor()
    }

    async fn init(&mut self, config: &AdapterConfig) -> DomainResult<()> {
        let mock_env = crate::mock_mode::mock_mode_from_env();
        self.init_with(config, &EnvSecrets::platform_default(), mock_env).await
    }

    async fn health(&self) -> DomainResult<AdapterHealth> {
        Ok(self.build_record().to_core_health(V::metadata()))
    }

    async fn sync(&self, direction: SyncDirection, req: &PullRequest) -> DomainResult<SyncOutcome> {
        // 桥接：`PullRequest::filter` 里 `local.<远端id>` 条目 = 本地案件快照（见 contract::sync_types）
        let sync_request = SyncRequest::from_pull_request(req)?;
        self.sync_direction(direction, &sync_request).await
    }

    async fn push(&self, payload: &PushPayload) -> DomainResult<()> {
        self.push_semantic(payload).await.map(|_| ())
    }

    async fn pull(&self, req: &PullRequest) -> DomainResult<PullResponse> {
        self.pull_semantic(req).await
    }

    async fn shutdown(&mut self) -> DomainResult<()> {
        self.close().await
    }
}
