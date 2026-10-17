//! 由 `mock.rs` 拆分：`impl_MockProvider`/`impl_MockProvider` 等 7 项（纯搬移，逻辑不变）。
use super::*;

impl MockProvider {
    /// 构造 Mock 端点的健康报告。
    #[must_use]
    pub fn health_report(&self) -> AdapterHealth {
        AdapterHealth {
            adapter: "llm-mock".to_string(),
            state: HealthState::Degraded,
            configured: true,
            mocked: true,
            latency_ms: Some(0),
            circuit: CircuitSnapshot::default(),
            capabilities: LLM_CAPABILITIES.to_vec(),
            message: Some(format!(
                "离线 Mock 模型（{}）：返回确定性合成回复，fixtures={} 条，未触达真实外部系统",
                self.model,
                self.fixture_count()
            )),
            checked_at: Timestamp::now(),
        }
    }

    /// 为"未配置凭据"的真实端点构造一个 Mock 端点（网关降级用）。
    #[must_use]
    pub fn endpoint_for_fallback(tenant: agf_core::ids::TenantId, model: impl Into<String>) -> ModelEndpoint {
        let now = Timestamp::now();
        ModelEndpoint {
            id: agf_core::ids::deterministic_id("aiguardfabric.aigw.mock", &model.into()),
            tenant_id: tenant,
            asset_id: agf_core::ids::Id::nil(),
            name: "Mock 离线模型".to_string(),
            provider: LlmProvider::Mock,
            base_url: "mock://local".to_string(),
            model: MOCK_MODEL.to_string(),
            modalities: vec![agf_core::model::Modality::Text],
            context_window: Some(32_768),
            max_output_tokens: Some(4096),
            supports_streaming: true,
            supports_tools: true,
            credential_ref: None,
            local_deployment: true,
            max_data_class: agf_core::enums::DataClass::Restricted,
            pricing: agf_core::model::ModelPricing::default(),
            enabled: true,
            fallback: true,
            priority: u32::MAX,
            extra_headers: BTreeMap::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

#[async_trait]
impl ProviderAdapter for MockProvider {
    fn adapter_name(&self) -> &'static str {
        "llm-mock"
    }

    fn provider_descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor::new(
            "llm-mock",
            "离线 Mock 模型（无 Key 降级 / 离线演示）",
            "mock",
            vec![LlmProvider::Mock],
            Vec::new(),
            true,
        )
    }

    async fn complete(&self, req: &ChatRequest) -> DomainResult<ChatResponse> {
        if self.synthetic_latency_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.synthetic_latency_ms)).await;
        }
        Ok(self.synthesize(req))
    }

    async fn stream(&self, req: &ChatRequest) -> DomainResult<ProviderStream> {
        let chunks = self.synthesize_stream(req);
        let stream = futures::stream::iter(chunks.into_iter().map(Ok));
        Ok(Box::pin(stream))
    }

    async fn health(&self) -> DomainResult<AdapterHealth> {
        Ok(self.health_report())
    }

    fn circuit(&self) -> CircuitSnapshot {
        CircuitSnapshot::default()
    }

    fn record_failure(&self, _error: &str) {
        // Mock 永不失败，熔断器无需计数
    }

    fn record_success(&self) {
        // 同上
    }
}

#[async_trait]
impl Adapter for MockProvider {
    fn name(&self) -> &'static str {
        "llm-mock"
    }

    fn descriptor(&self) -> AdapterDescriptor {
        ProviderAdapter::provider_descriptor(self).adapter
    }

    async fn init(&mut self, _config: &AdapterConfig) -> DomainResult<()> {
        Ok(())
    }

    async fn health(&self) -> DomainResult<AdapterHealth> {
        Ok(self.health_report())
    }

    async fn sync(&self, _direction: SyncDirection, _req: &PullRequest) -> DomainResult<SyncOutcome> {
        let mut outcome = SyncOutcome::mock(0, 0);
        outcome.warnings.push("Mock 适配器不参与台账同步".to_string());
        outcome.changes.insert("mock_responses".to_string(), self.fixture_count());
        Ok(outcome)
    }

    async fn push(&self, _payload: &PushPayload) -> DomainResult<()> {
        Ok(())
    }

    async fn pull(&self, _req: &PullRequest) -> DomainResult<PullResponse> {
        Ok(PullResponse {
            items: Vec::new(),
            next_cursor: None,
            mocked: true,
            origin: "crates/agf-aigw/src/mock.rs#MockProvider".to_string(),
        })
    }

    async fn shutdown(&mut self) -> DomainResult<()> {
        Ok(())
    }
}

/// 判断某个响应是否来自 Mock（审计与前端标注用）。
#[must_use]
pub fn is_mock_response(response: &ChatResponse) -> bool {
    response.raw.as_ref().and_then(|r| r.get("mock")).and_then(Value::as_bool).unwrap_or(false)
}

/// 提取 Mock 响应中的意图标签（非 Mock 返回 `None`）。
#[must_use]
pub fn mock_intent_of(response: &ChatResponse) -> Option<String> {
    response.raw.as_ref().and_then(|r| r.get("intent")).and_then(Value::as_str).map(ToString::to_string)
}

/// 快速构造一段 Mock 文本（供提示词模板渲染失败的兜底展示）。
#[must_use]
pub fn mock_placeholder_text(topic: &str) -> String {
    format!("【Mock】{topic}：未接入真实模型，此处为离线占位输出（平台不因缺 Key 而失败）。")
}

/// 判断消息内容是否为空（Mock 回显时会引用）。
#[must_use]
pub fn content_is_empty(content: &MessageContent) -> bool {
    content.is_empty()
}
