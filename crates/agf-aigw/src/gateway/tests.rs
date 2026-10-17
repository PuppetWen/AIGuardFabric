//! 由 `gateway.rs` 拆分：`endpoint`/`FakeProvider` 等 23 项（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn endpoint(
    id_name: &str,
    provider: LlmProvider,
    local: bool,
    enabled: bool,
    cred: Option<Id>,
) -> ModelEndpoint {
    let now = Timestamp::now();
    ModelEndpoint {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        asset_id: Id::new(),
        name: id_name.to_string(),
        provider,
        base_url: "https://example.invalid/v1".into(),
        model: format!("{id_name}-model"),
        modalities: vec![Modality::Text],
        context_window: Some(32_000),
        max_output_tokens: Some(4096),
        supports_streaming: true,
        supports_tools: true,
        credential_ref: cred,
        local_deployment: local,
        max_data_class: if local { DataClass::Restricted } else { DataClass::Confidential },
        pricing: ModelPricing {
            prompt_micro_per_1k: 2_000,
            completion_micro_per_1k: 8_000,
            cached_prompt_micro_per_1k: 500,
        },
        enabled,
        fallback: true,
        priority: 1,
        extra_headers: BTreeMap::new(),
        created_at: now,
        updated_at: now,
    }
}

/// 假提供商：可控成功/失败、可控用量与回复内容（**无网络**）。
#[derive(Debug)]
pub(crate) struct FakeProvider {
    pub(crate) label: &'static str,
    pub(crate) fail: bool,
    pub(crate) reply: String,
    pub(crate) usage: Usage,
}

impl FakeProvider {
    pub(crate) fn ok(label: &'static str, reply: &str) -> Self {
        Self { label, fail: false, reply: reply.to_string(), usage: Usage::new(100, 20, 0) }
    }

    pub(crate) fn failing(label: &'static str) -> Self {
        Self { label, fail: true, reply: String::new(), usage: Usage::default() }
    }
}

#[async_trait::async_trait]
impl ProviderAdapter for FakeProvider {
    fn adapter_name(&self) -> &'static str {
        self.label
    }

    fn provider_descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor::new(self.label, self.label, "fake", vec![LlmProvider::OpenAi], vec![], true)
    }

    async fn complete(&self, req: &ChatRequest) -> DomainResult<ChatResponse> {
        if self.fail {
            return Err(DomainError::DependencyUnavailable {
                dependency: self.label.to_string(),
                cause: "假提供商固定失败".to_string(),
            });
        }
        let mut r = ChatResponse::text(req.model.clone(), self.reply.clone(), self.usage);
        r.raw = Some(serde_json::json!({"fake": self.label}));
        Ok(r)
    }

    async fn stream(&self, req: &ChatRequest) -> DomainResult<ProviderStream> {
        if self.fail {
            return Err(DomainError::DependencyUnavailable {
                dependency: self.label.to_string(),
                cause: "假提供商固定失败".to_string(),
            });
        }
        let chunks = vec![
            Ok(StreamChunk::text("假")),
            Ok(StreamChunk::text("回复")),
            Ok(StreamChunk::finished(crate::wire::FinishReason::Stop, Some(self.usage))),
        ];
        let _ = req;
        Ok(Box::pin(futures::stream::iter(chunks)))
    }

    async fn health(&self) -> DomainResult<agf_core::adapter::AdapterHealth> {
        Ok(agf_core::adapter::AdapterHealth::unconfigured(self.label, "fake"))
    }

    fn circuit(&self) -> agf_core::adapter::CircuitSnapshot {
        agf_core::adapter::CircuitSnapshot::default()
    }

    fn record_failure(&self, _error: &str) {}

    fn record_success(&self) {}
}

/// 造一个"所有端点都指向 FakeProvider"的网关。
///
/// **显式关掉 Mock 模式**：Mock 开关会读环境变量 `AGF_MOCK_MODE`，而本仓库为"离线演示"
/// 默认在 `.env` 里把它设为 1 —— 测试若跟随环境变量，就会在开发机上"意外全绿/意外全红"。
/// 单元测试必须自洽：要测 Mock 的用例自己 `with_mock_mode(true)`。
pub(crate) fn gateway_with_fakes(endpoints: Vec<ModelEndpoint>, fakes: Vec<Arc<dyn ProviderAdapter>>) -> AiGateway {
    // 为每个带 `credential_ref` 的端点预置一条"看起来已配置"的密钥：否则
    // `endpoint_is_mock()` 会因"无凭据"把端点判成 Mock，用例测到的就不是真实适配器路径。
    let mut creds = StaticCredentialResolver::new();
    for ep in &endpoints {
        if let Some(reference) = ep.credential_ref {
            creds = creds.with_key(reference, "test-key-0123456789abcdef");
        }
    }
    let gw = AiGateway::new(endpoints).with_credentials(Arc::new(creds)).with_mock_mode(false);
    let mut guard = gw.providers.lock();
    for (endpoint, fake) in gw.router.endpoints().iter().zip(fakes) {
        guard.insert(endpoint.id.to_string(), fake);
    }
    drop(guard);
    gw
}

pub(crate) fn cred_ref() -> Id {
    Id::new()
}

#[tokio::test]
pub(crate) async fn chat_happy_path_uses_provider_and_records_usage() {
    let ep = endpoint("ep-a", LlmProvider::OpenAi, false, true, Some(cred_ref()));
    let gw = gateway_with_fakes(vec![ep.clone()], vec![Arc::new(FakeProvider::ok("fake-a", "结论：恶意"))]);
    let ctx = CallContext::new(TenantId::default_tenant());
    let resp =
        gw.chat(ctx, ChatRequest::simple(ep.model.clone(), "研判这条告警")).await.unwrap_or_else(|e| panic!("{e}"));

    eq!(resp.response.text_content(), "结论：恶意");
    eq!(resp.endpoint_id, ep.id);
    assert!(!resp.cached);
    assert!(!resp.mocked);
    assert!(!resp.fallback_used);
    eq!(resp.usage, Usage::new(100, 20, 0));
    // 100*2000/1000 + 20*8000/1000 = 200 + 160 = 360
    eq!(resp.cost_micro, 360);
    assert!(resp.cost.is_consistent());
    assert!(resp.summary().contains("cost=360微元"));
    // 计量已写入
    eq!(gw.meter().snapshot().total.calls, 1);
    eq!(gw.recent_usage(1).len(), 1);
    eq!(resp.usage_record.prompt_tokens, 100);
    eq!(resp.billed_tokens(), 120);
}

#[tokio::test]
pub(crate) async fn second_identical_call_hits_cache_and_costs_zero() {
    let ep = endpoint("ep-a", LlmProvider::OpenAi, false, true, Some(cred_ref()));
    let gw = gateway_with_fakes(vec![ep.clone()], vec![Arc::new(FakeProvider::ok("fake-a", "结论：恶意"))]);
    let ctx = CallContext::new(TenantId::default_tenant());
    let req = ChatRequest::simple(ep.model.clone(), "研判这条告警");

    let first = gw.chat(ctx.clone(), req.clone()).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(!first.cached);
    eq!(first.cost_micro, 360);

    let second = gw.chat(ctx, req).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(second.cached, "第二次相同请求必须命中语义缓存");
    eq!(second.response.text_content(), "结论：恶意");
    eq!(second.cost_micro, 0, "缓存命中不产生费用");
    eq!(second.billed_tokens(), 0);
    assert!(second.usage_record.cache_hit);

    let stats = gw.cache_stats();
    eq!(stats.hits, 1);
    eq!(stats.saved_tokens, 100);
    eq!(stats.saved_micro, 360);
    // 计量两条（一次真实 + 一次缓存）
    eq!(gw.meter().snapshot().total.calls, 2);
    eq!(gw.meter().snapshot().total.cache_hits, 1);
}

#[tokio::test]
pub(crate) async fn endpoint_configuration_change_invalidates_cached_response() {
    let ep = endpoint("ep-a", LlmProvider::OpenAi, false, true, Some(cred_ref()));
    let cache = Arc::new(ExactCache::memory());
    let first = gateway_with_fakes(vec![ep.clone()], vec![Arc::new(FakeProvider::ok("old", "旧回复"))])
        .with_cache(cache.clone());
    let req = ChatRequest::simple(ep.model.clone(), "研判");
    let ctx = CallContext::new(TenantId::default_tenant());
    first.chat(ctx.clone(), req.clone()).await.unwrap_or_else(|e| panic!("{e}"));

    let mut changed = ep;
    changed.base_url = "https://new-endpoint.invalid/v1".into();
    let second = gateway_with_fakes(vec![changed], vec![Arc::new(FakeProvider::ok("new", "新回复"))]).with_cache(cache);
    let response = second.chat(ctx, req).await.unwrap_or_else(|e| panic!("{e}"));
    eq!(response.response.text_content(), "新回复");
    assert!(!response.cached, "端点配置改变后不能复用旧回复");
}

#[tokio::test]
pub(crate) async fn data_classification_separates_cached_responses() {
    let ep = endpoint("ep-local", LlmProvider::Ollama, true, true, Some(cred_ref()));
    let gw = gateway_with_fakes(vec![ep.clone()], vec![Arc::new(FakeProvider::ok("local", "回复"))]);
    let req = ChatRequest::simple(ep.model, "相同问题");
    let internal = CallContext::new(TenantId::default_tenant());
    gw.chat(internal, req.clone()).await.unwrap_or_else(|e| panic!("{e}"));
    let restricted = CallContext::new(TenantId::default_tenant()).with_data_class(DataClass::Restricted);
    let response = gw.chat(restricted, req).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(!response.cached, "受限数据不能复用普通数据分级的缓存条目");
}

#[tokio::test]
pub(crate) async fn temperature_positive_disables_cache() {
    let ep = endpoint("ep-a", LlmProvider::OpenAi, false, true, Some(cred_ref()));
    // 用两个假提供商轮换（同一实例会被复用，但缓存是否命中的判据是可缓存性）
    let gw = gateway_with_fakes(vec![ep.clone()], vec![Arc::new(FakeProvider::ok("fake-a", "回复"))]);
    let ctx = CallContext::new(TenantId::default_tenant());
    let mut req = ChatRequest::simple(ep.model.clone(), "写一首诗");
    req.temperature = Some(0.9);
    let _ = gw.chat(ctx.clone(), req.clone()).await.unwrap_or_else(|e| panic!("{e}"));
    let second = gw.chat(ctx, req).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(!second.cached, "温度 > 0 不得命中缓存");
    eq!(gw.cache_stats().hits, 0);
}

#[tokio::test]
pub(crate) async fn stream_flag_requests_are_never_cached() {
    let ep = endpoint("ep-a", LlmProvider::OpenAi, false, true, Some(cred_ref()));
    let gw = gateway_with_fakes(vec![ep.clone()], vec![Arc::new(FakeProvider::ok("fake-a", "回复"))]);
    let ctx = CallContext::new(TenantId::default_tenant());
    let mut req = ChatRequest::simple(ep.model.clone(), "问答");
    req.stream = true;
    let _ = gw.chat(ctx.clone(), req.clone()).await.unwrap_or_else(|e| panic!("{e}"));
    let second = gw.chat(ctx, req).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(!second.cached);
}

#[tokio::test]
pub(crate) async fn fallback_when_first_endpoint_fails() {
    // 同一模型名下的两个端点（真实场景：同一模型的多条接入通道，一条挂了切另一条）
    let good = endpoint("ep-good", LlmProvider::DeepSeek, false, true, Some(cred_ref()));
    let mut bad = endpoint("ep-bad", LlmProvider::OpenAi, false, true, Some(cred_ref()));
    bad.model = good.model.clone();
    // 让坏端点优先（priority 更小）
    let mut bad_first = bad.clone();
    bad_first.priority = 0;
    let mut good_second = good.clone();
    good_second.priority = 10;
    let bad_model = bad_first.model.clone();

    let gw = gateway_with_fakes(
        vec![bad_first, good_second],
        vec![Arc::new(FakeProvider::failing("fake-bad")), Arc::new(FakeProvider::ok("fake-good", "降级成功"))],
    );
    let ctx = CallContext::new(TenantId::default_tenant()).with_strategy(RoutingStrategy::QualityFirst);
    let req = ChatRequest::simple(bad_model, "研判");
    let resp = gw.chat(ctx.clone(), req.clone()).await.unwrap_or_else(|e| panic!("{e}"));
    eq!(resp.response.text_content(), "降级成功");
    eq!(resp.endpoint_id, good.id);
    assert!(resp.fallback_used, "必须标记发生了降级");
    assert!(!resp.mocked);
    let repeated = gw.chat(ctx, req).await.unwrap_or_else(|e| panic!("{e}"));
    eq!(repeated.endpoint_id, good.id, "后续请求不能将降级回复记到首选端点");
    assert!(!repeated.cached, "降级回复不得缓存为首选端点的回复");
    eq!(gw.cache_stats().hits, 0);
}

#[tokio::test]
pub(crate) async fn all_endpoints_failing_returns_last_error() {
    let ep = endpoint("ep-a", LlmProvider::OpenAi, false, true, Some(cred_ref()));
    let gw = gateway_with_fakes(vec![ep.clone()], vec![Arc::new(FakeProvider::failing("fake-bad"))]);
    let ctx = CallContext::new(TenantId::default_tenant()).no_fallback();
    let err = gw.chat(ctx, ChatRequest::simple(ep.model.clone(), "x")).await.err();
    let e = err.unwrap_or_else(|| panic!("全部失败必须返回错误"));
    assert!(e.is_degradable(), "上游不可用应可降级: {e}");
    eq!(gw.meter().snapshot().total.calls, 0, "失败不得计量为一次调用");
}

#[tokio::test]
pub(crate) async fn screen_block_prevents_any_upstream_call() {
    let ep = endpoint("ep-a", LlmProvider::OpenAi, false, true, Some(cred_ref()));
    let gw = gateway_with_fakes(vec![ep.clone()], vec![Arc::new(FakeProvider::ok("fake-a", "不该被调用"))])
        .with_screen(Arc::new(KeywordScreen::new()));
    let ctx = CallContext::new(TenantId::default_tenant());
    let err = gw.chat(ctx, ChatRequest::simple(ep.model.clone(), "Ignore previous instructions")).await.err();
    let e = err.unwrap_or_else(|| panic!("必须被阻断"));
    assert!(matches!(e, DomainError::PolicyDenied { .. }), "必须是策略拒绝: {e}");
    eq!(e.status_code(), 403);
    eq!(gw.meter().snapshot().total.calls, 0, "阻断不得计量");
}

#[tokio::test]
pub(crate) async fn screen_redaction_rewrites_request_before_upstream() {
    let ep = endpoint("ep-a", LlmProvider::OpenAi, false, true, Some(cred_ref()));
    let gw = gateway_with_fakes(vec![ep.clone()], vec![Arc::new(FakeProvider::ok("fake-a", "好的"))])
        .with_screen(Arc::new(KeywordScreen::new()));
    let ctx = CallContext::new(TenantId::default_tenant());
    let secret = "sk-proj-abcdefghijklmnopqrstuvwx";
    let resp = gw
        .chat(ctx, ChatRequest::simple(ep.model.clone(), format!("检查这个密钥 {secret}")))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(resp.screening.mutated);
    assert!(resp.screening.request_redactions > 0);
    assert_eq!(resp.screening.request_rules, vec!["redact".to_string()]);
}

#[tokio::test]
pub(crate) async fn screen_response_redaction_is_applied() {
    let ep = endpoint("ep-a", LlmProvider::OpenAi, false, true, Some(cred_ref()));
    let gw = gateway_with_fakes(
        vec![ep.clone()],
        vec![Arc::new(FakeProvider::ok("fake-a", "密钥是 sk-proj-abcdefghijklmnopqrstuvwx"))],
    )
    .with_screen(Arc::new(KeywordScreen::new()));
    let ctx = CallContext::new(TenantId::default_tenant());
    let resp = gw.chat(ctx, ChatRequest::simple(ep.model.clone(), "输出配置")).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(!resp.response.text_content().contains("sk-proj-abcdefghijklmnopqrstuvwx"));
    assert!(resp.screening.response_redactions > 0);
}

#[tokio::test]
pub(crate) async fn restricted_data_never_goes_to_cloud_endpoint() {
    let cloud = endpoint("ep-cloud", LlmProvider::OpenAi, false, true, Some(cred_ref()));
    let gw = gateway_with_fakes(vec![cloud.clone()], vec![Arc::new(FakeProvider::ok("fake", "x"))]);
    let ctx = CallContext::new(TenantId::default_tenant()).with_data_class(DataClass::Restricted);
    let err = gw.chat(ctx, ChatRequest::simple(cloud.model.clone(), "受限数据分析")).await.err();
    let e = err.unwrap_or_else(|| panic!("受限数据不得送云端端点"));
    assert!(matches!(e, DomainError::Config(_)), "应是'无可用端点': {e}");
}

#[tokio::test]
pub(crate) async fn restricted_data_is_allowed_on_local_endpoint() {
    let local = endpoint("ep-local", LlmProvider::Ollama, true, true, Some(cred_ref()));
    let gw = gateway_with_fakes(vec![local.clone()], vec![Arc::new(FakeProvider::ok("fake-local", "本地结果"))]);
    let ctx = CallContext::new(TenantId::default_tenant()).with_data_class(DataClass::Restricted);
    let resp =
        gw.chat(ctx, ChatRequest::simple(local.model.clone(), "受限数据分析")).await.unwrap_or_else(|e| panic!("{e}"));
    eq!(resp.response.text_content(), "本地结果");
}

#[tokio::test]
pub(crate) async fn missing_credential_endpoint_falls_back_to_mock() {
    let ep = endpoint("ep-nocred", LlmProvider::OpenAi, false, true, None);
    let gw = AiGateway::new(vec![ep.clone()]).with_credentials(Arc::new(StaticCredentialResolver::new()));
    let ctx = CallContext::new(TenantId::default_tenant());
    let resp = gw
        .chat(ctx, ChatRequest::simple(ep.model.clone(), "研判这条告警：暴力破解"))
        .await
        .unwrap_or_else(|e| panic!("无 Key 不得报错: {e}"));
    assert!(resp.mocked, "必须标记为 Mock");
    eq!(resp.cost_micro, 0, "Mock 不计费");
    assert!(resp.response.text_content().contains("verdict"), "Mock 应给出结构化研判");
    eq!(gw.meter().snapshot().total.mocked_calls, 1);
}

#[tokio::test]
pub(crate) async fn mock_mode_flag_forces_mock_even_with_credential() {
    let ep = endpoint("ep-openai", LlmProvider::OpenAi, false, true, Some(cred_ref()));
    let gw = AiGateway::new(vec![ep.clone()]).with_mock_mode(true);
    assert!(gw.mock_mode());
    let ctx = CallContext::new(TenantId::default_tenant());
    let resp = gw.chat(ctx, ChatRequest::simple(ep.model.clone(), "生成报告")).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(resp.mocked);
    assert!(resp.response.text_content().contains("## 摘要"));
}

#[tokio::test]
pub(crate) async fn no_endpoints_is_a_config_error_not_panic() {
    let gw = AiGateway::new(vec![]);
    let ctx = CallContext::new(TenantId::default_tenant());
    let err = gw.chat(ctx, ChatRequest::simple("m", "x")).await.err();
    let e = err.unwrap_or_else(|| panic!("必须报 Config"));
    assert!(matches!(e, DomainError::Config(_)));
    assert_eq!(e.status_code(), 500);
}

#[tokio::test]
pub(crate) async fn disabled_endpoint_is_not_selected() {
    let ep = endpoint("ep-off", LlmProvider::OpenAi, false, false, Some(cred_ref()));
    let gw = gateway_with_fakes(vec![ep.clone()], vec![Arc::new(FakeProvider::ok("fake", "x"))]);
    let ctx = CallContext::new(TenantId::default_tenant());
    assert!(gw.chat(ctx, ChatRequest::simple(ep.model.clone(), "x")).await.is_err());
}

#[tokio::test]
pub(crate) async fn budget_guard_refuses_before_calling_upstream() {
    let ep = endpoint("ep-a", LlmProvider::OpenAi, false, true, Some(cred_ref()));
    let gw = gateway_with_fakes(vec![ep.clone()], vec![Arc::new(FakeProvider::ok("fake-a", "不该被调用"))]);
    let ctx = CallContext::new(TenantId::default_tenant()).with_budget(BudgetGuard::single(1));
    let err = gw.chat(ctx, ChatRequest::simple(ep.model.clone(), "很长的提示词")).await.err();
    let e = err.unwrap_or_else(|| panic!("预算必须拦下"));
    assert!(matches!(e, DomainError::QuotaExceeded { .. }));
    eq!(gw.meter().snapshot().total.calls, 0);
}

#[tokio::test]
pub(crate) async fn chat_stream_yields_chunks_then_usage() {
    let ep = endpoint("ep-a", LlmProvider::OpenAi, false, true, Some(cred_ref()));
    let gw = gateway_with_fakes(vec![ep.clone()], vec![Arc::new(FakeProvider::ok("fake-a", "ignored"))]);
    let ctx = CallContext::new(TenantId::default_tenant());
    let mut req = ChatRequest::simple(ep.model.clone(), "流式测试");
    req.stream = true;
    let stream = gw.chat_stream(ctx, req).await.unwrap_or_else(|e| panic!("{e}"));
    let chunks: Vec<_> = stream.collect().await;
    assert!(chunks.len() >= 2, "至少内容分片 + 结束分片");
    let mut acc = StreamAccumulator::new();
    for c in &chunks {
        acc.push(c.as_ref().unwrap_or_else(|e| panic!("{e}")));
    }
    eq!(acc.content(), "假回复");
    eq!(acc.usage(), Usage::new(100, 20, 0));
    eq!(gw.meter().snapshot().total.calls, 1, "流式也必须计量");
}
