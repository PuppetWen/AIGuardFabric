//! 由 `provider.rs` 拆分：`endpoint` 等 30 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn endpoint(provider: LlmProvider, credential_ref: Option<Id>) -> ModelEndpoint {
    let now = Timestamp::now();
    ModelEndpoint {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        asset_id: Id::new(),
        name: "ep".into(),
        provider,
        base_url: String::new(),
        model: "gpt-4o".into(),
        modalities: vec![Modality::Text],
        context_window: Some(128_000),
        max_output_tokens: Some(4096),
        supports_streaming: true,
        supports_tools: true,
        credential_ref,
        local_deployment: false,
        max_data_class: DataClass::Confidential,
        pricing: agf_core::model::ModelPricing::default(),
        enabled: true,
        fallback: false,
        priority: 1,
        extra_headers: BTreeMap::new(),
        created_at: now,
        updated_at: now,
    }
}

pub(crate) fn adapter_config() -> AdapterConfig {
    let now = Timestamp::now();
    AdapterConfig {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        adapter: "llm-gemini".into(),
        display_name: "Gemini".into(),
        enabled: true,
        settings: BTreeMap::new(),
        secret_refs: BTreeMap::new(),
        circuit_breaker: CircuitBreakerConfig::default(),
        retry: RetryConfig::default(),
        timeout_secs: 30,
        mock: false,
        is_default: true,
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
pub(crate) async fn openai_without_credential_never_errors_hard() {
    let ep = endpoint(LlmProvider::OpenAi, None);
    let p = OpenAiCompatProvider::from_endpoint(&ep, &MockCredentialResolver);
    let e = p
        .complete(&ChatRequest::simple("gpt-4o", "hi"))
        .await
        .err()
        .unwrap_or_else(|| panic!("缺凭据必须返回可降级错误"));
    assert!(e.is_degradable(), "缺凭据错误必须可降级: {e}");
    eq!(p.api_key(), None);
    assert!(p.api_key_missing());
}

#[tokio::test]
pub(crate) async fn all_http_providers_stream_without_credential_never_error_hard() {
    let ep = endpoint(LlmProvider::OpenAi, None);
    let resolver = MockCredentialResolver;
    let openai = OpenAiCompatProvider::from_endpoint(&ep, &resolver);
    assert!(openai.stream(&ChatRequest::simple("m", "hi")).await.is_err());
    let anthropic = AnthropicProvider::new("claude", "", None);
    assert!(anthropic.stream(&ChatRequest::simple("m", "hi")).await.is_err());
    let gemini = GeminiProvider::new("g", "", None);
    assert!(gemini.stream(&ChatRequest::simple("m", "hi")).await.is_err());
    let bedrock = BedrockProvider::new("m", "us-east-1", None);
    assert!(bedrock.stream(&ChatRequest::simple("m", "hi")).await.is_err());
}

#[tokio::test]
pub(crate) async fn all_http_providers_report_unconfigured_not_err() {
    let ep = endpoint(LlmProvider::OpenAi, None);
    let resolver = MockCredentialResolver;

    let openai = OpenAiCompatProvider::from_endpoint(&ep, &resolver);
    let h = ProviderAdapter::health(&openai).await.unwrap_or_else(|e| panic!("{e}"));
    eq!(h.state, HealthState::Unconfigured);
    assert!(!h.configured);
    assert!(!h.mocked, "未配置不等于 Mock 模式");

    let anthropic = AnthropicProvider::new("claude", "", None);
    let h = ProviderAdapter::health(&anthropic).await.unwrap_or_else(|e| panic!("{e}"));
    eq!(h.state, HealthState::Unconfigured);

    let gemini = GeminiProvider::new("gemini-1.5-pro", "", None);
    let h = ProviderAdapter::health(&gemini).await.unwrap_or_else(|e| panic!("{e}"));
    eq!(h.state, HealthState::Unconfigured);

    let bedrock = BedrockProvider::new("m", "us-east-1", None);
    let h = ProviderAdapter::health(&bedrock).await.unwrap_or_else(|e| panic!("{e}"));
    eq!(h.state, HealthState::Unconfigured);
    assert!(h.message.unwrap_or_default().contains("Mock"));
}

#[tokio::test]
pub(crate) async fn configured_provider_reports_healthy() {
    let p = OpenAiCompatProvider::new(LlmProvider::DeepSeek, "deepseek-chat", "", Some("sk-test-key".into()));
    let h = ProviderAdapter::health(&p).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(h.configured);
    eq!(h.adapter, "llm-openai-compat");
    assert!(h.capabilities.contains(&AdapterCapability::SelfCheck));
    eq!(p.chat_url(), "https://api.deepseek.com/v1/chat/completions");
    assert!(!p.api_key_missing());
}

#[test]
pub(crate) fn default_base_urls_are_official() {
    eq!(default_base_url(LlmProvider::OpenAi), "https://api.openai.com/v1");
    eq!(default_base_url(LlmProvider::DashScope), "https://dashscope.aliyuncs.com/compatible-mode/v1");
    assert!(default_base_url(LlmProvider::Ark).contains("volces.com"));
    assert!(default_base_url(LlmProvider::Vllm).contains("8000"));
    assert!(default_base_url(LlmProvider::Ollama).contains("11434"));
    for p in LlmProvider::all() {
        assert!(!default_base_url(p).is_empty(), "{p:?} 缺默认 base_url");
    }
}

#[test]
pub(crate) fn endpoint_with_empty_base_url_falls_back_to_vendor_default() {
    let ep = endpoint(LlmProvider::Moonshot, None);
    let p = OpenAiCompatProvider::from_endpoint(&ep, &MockCredentialResolver);
    eq!(p.base_url, "https://api.moonshot.cn/v1");
}

#[test]
pub(crate) fn azure_uses_api_key_header() {
    let azure = OpenAiCompatProvider::new(LlmProvider::AzureOpenAi, "gpt-4o", "https://r.openai.azure.com", None);
    assert!(azure.uses_azure_auth());
    let openai = OpenAiCompatProvider::new(LlmProvider::OpenAi, "gpt-4o", "", None);
    assert!(!openai.uses_azure_auth());
}

#[test]
pub(crate) fn azure_urls_support_v1_and_deployment_api_versions() {
    let root = OpenAiCompatProvider::new(LlmProvider::AzureOpenAi, "model", "https://r.openai.azure.com", None);
    eq!(root.chat_url(), "https://r.openai.azure.com/openai/v1/chat/completions");
    let mut legacy = OpenAiCompatProvider::new(
        LlmProvider::AzureOpenAi,
        "model",
        "https://r.openai.azure.com/openai/deployments/team/",
        None,
    );
    eq!(
        legacy.chat_url(),
        "https://r.openai.azure.com/openai/deployments/team/chat/completions?api-version=2024-10-21"
    );
    legacy.extra_headers.insert("api-version".into(), "2025-04-01-preview".into());
    assert!(legacy.chat_url().ends_with("?api-version=2025-04-01-preview"));
    legacy.base_url =
        "https://r.openai.azure.com/openai/deployments/team/chat/completions?api-version=2024-06-01".into();
    eq!(legacy.chat_url(), legacy.base_url);
    let req = legacy.attach_headers(legacy.client.post(legacy.chat_url()), "local-test-key").build().unwrap();
    assert!(!req.headers().contains_key("api-version"));
    eq!(req.headers()["api-key"], "local-test-key");
}

#[test]
pub(crate) fn joiner_tolerates_trailing_slash() {
    eq!(join_url("https://a/v1/", "/chat"), "https://a/v1/chat");
    eq!(join_url("https://a/v1", "chat"), "https://a/v1/chat");
}

#[test]
pub(crate) fn descriptors_declare_degradation_and_mock_location() {
    let p = AnthropicProvider::new("claude", "", None);
    let d = p.provider_descriptor();
    assert!(!d.adapter.degradation.is_empty(), "必须写明降级行为");
    assert!(d.adapter.mock_location.contains("mock.rs"), "必须写明 Mock 位置");
    assert!(d.real_implementation);
    eq!(d.protocol, "anthropic");
    eq!(d.providers, vec![LlmProvider::Anthropic]);
}

#[test]
pub(crate) fn openai_compat_descriptor_covers_all_compatible_vendors() {
    let p = OpenAiCompatProvider::new(LlmProvider::OpenAi, "gpt-4o", "", None);
    let d = p.provider_descriptor();
    for v in LlmProvider::all() {
        if v.is_openai_compatible() {
            assert!(d.providers.contains(&v), "{v:?} 应被 OpenAI 兼容适配器覆盖");
        }
    }
}

#[tokio::test]
pub(crate) async fn adapter_trait_impl_degrades_instead_of_failing() {
    let mut p = GeminiProvider::new("gemini-1.5-pro", "", None);
    let cfg = adapter_config();
    assert!(Adapter::init(&mut p, &cfg).await.is_ok());
    let h = Adapter::health(&p).await.unwrap_or_else(|e| panic!("{e}"));
    eq!(h.state, HealthState::Unconfigured);
    eq!(Adapter::name(&p), "llm-gemini");

    let outcome =
        Adapter::sync(&p, SyncDirection::Pull, &PullRequest::default()).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(!outcome.warnings.is_empty());
    assert!(outcome.finished_at.is_some());

    let pull = Adapter::pull(&p, &PullRequest::default()).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(pull.items.is_empty());
    assert!(pull.origin.contains("not-applicable"));

    let payload = PushPayload { entity: "x".into(), entity_id: "1".into(), body: Value::Null, idempotency_key: None };
    assert!(Adapter::push(&p, &payload).await.is_err());
    assert!(Adapter::shutdown(&mut p).await.is_ok());
    assert!(Adapter::shutdown(&mut p).await.is_ok(), "shutdown 必须幂等");

    let desc = Adapter::descriptor(&p);
    eq!(desc.category, "llm");
    assert!(desc.real_implementation);
}

#[tokio::test]
pub(crate) async fn every_provider_exposes_adapter_descriptor() {
    let providers: Vec<Box<dyn ProviderAdapter>> = vec![
        Box::new(OpenAiCompatProvider::new(LlmProvider::OpenAi, "gpt-4o", "", None)),
        Box::new(AnthropicProvider::new("claude", "", None)),
        Box::new(GeminiProvider::new("gemini", "", None)),
        Box::new(BedrockProvider::new("bedrock-model", "us-east-1", None)),
    ];
    for p in &providers {
        let d = p.provider_descriptor();
        eq!(d.adapter.category, "llm");
        assert!(d.adapter.real_implementation);
        assert!(!d.adapter.name.is_empty());
        assert!(d.adapter.required_secrets.iter().all(|s| !s.is_empty()));
        let h = p.as_ref().health().await.unwrap_or_else(|e| panic!("{e}"));
        eq!(h.state, HealthState::Unconfigured);
        eq!(p.circuit().state, CircuitState::Closed);
    }
}

#[test]
pub(crate) fn static_resolver_returns_injected_key() {
    let id = Id::new();
    let r = StaticCredentialResolver::new().with_key(id, "sk-abc");
    eq!(r.resolve_api_key(&id).as_deref(), Some("sk-abc"));
    eq!(r.resolve_api_key(&Id::new()), None);
    assert!(r.resolve_aws_credentials(&id).is_none());
}

#[test]
pub(crate) fn static_resolver_returns_injected_aws_credentials() {
    let id = Id::new();
    let creds = AwsCredentials { access_key_id: "AK".into(), secret_access_key: "SK".into(), session_token: None };
    let r = StaticCredentialResolver::new().with_aws(id, creds.clone());
    eq!(r.resolve_aws_credentials(&id), Some(creds));
}

#[test]
pub(crate) fn env_resolver_only_reads_explicit_or_conventional_names() {
    let id = Id::new();
    let r = EnvCredentialResolver::new().with_env(id, "AGF_TEST_DEFINITELY_UNSET_VAR");
    eq!(r.resolve_api_key(&id), None, "未设置的环境变量必须返回 None（不报错）");
    let r2 = EnvCredentialResolver::new();
    eq!(r2.resolve_api_key(&id), None);
}

#[test]
pub(crate) fn mock_resolver_never_returns_credentials() {
    let r = MockCredentialResolver;
    assert!(r.resolve_api_key(&Id::new()).is_none());
    assert!(r.resolve_aws_credentials(&Id::new()).is_none());
}

#[test]
pub(crate) fn credential_masking_never_leaks_plaintext() {
    let m = masked_credential(Some("sk-proj-abcdefghijklmnop"));
    assert!(m.contains('*'));
    assert!(!m.contains("abcdefghij"));
    eq!(masked_credential(None), "<未配置>");
}

#[test]
pub(crate) fn provider_state_tracks_circuit() {
    let s = ProviderState::default();
    eq!(s.snapshot().state, CircuitState::Closed);
    for _ in 0..5 {
        s.failure("boom");
    }
    eq!(s.snapshot().state, CircuitState::Open);
    s.success();
    eq!(s.snapshot().state, CircuitState::Closed);
    eq!(s.snapshot().total_success, 1);
}

#[test]
pub(crate) fn state_gate_shares_state_with_provider() {
    let s = ProviderState::default();
    let gate = StateGate::new(&s);
    gate.failure("x");
    gate.success();
    eq!(s.snapshot().total_failure, 1);
    eq!(s.snapshot().total_success, 1);
}

#[test]
pub(crate) fn bedrock_body_hoists_system_and_tools() {
    let mut req = ChatRequest::simple("anthropic.claude-3-5-sonnet-v2:0", "研判这条告警");
    req.messages.insert(0, ChatMessage::system("你是安全分析师"));
    req.max_tokens = Some(512);
    req.tools.push(crate::wire::ToolDefinition::query("query_asset", "查询", json!({"type": "object"})));
    let body = to_bedrock_converse_body(&req);
    eq!(body["system"][0]["text"], json!("你是安全分析师"));
    eq!(body["messages"][0]["role"], json!("user"));
    eq!(body["inferenceConfig"]["maxTokens"], json!(512));
    eq!(body["toolConfig"]["tools"][0]["toolSpec"]["name"], json!("query_asset"));
}

#[test]
pub(crate) fn bedrock_body_forwards_sampling_and_stop_sequences() {
    let mut request = ChatRequest::simple("bedrock-test", "hello");
    request.top_p = Some(0.7);
    request.stop = vec!["END".into(), "STOP".into()];
    let body = to_bedrock_converse_body(&request);
    assert!((body["inferenceConfig"]["topP"].as_f64().unwrap_or_default() - 0.7).abs() < 1e-6);
    eq!(body["inferenceConfig"]["stopSequences"], json!(["END", "STOP"]));
    request.top_p = None;
    request.stop.clear();
    let default = to_bedrock_converse_body(&request);
    assert!(default.get("inferenceConfig").is_none());
}

#[tokio::test]
pub(crate) async fn gemini_rejects_more_than_five_stops_before_network() {
    let provider = GeminiProvider::new("gemini-test", "http://127.0.0.1:1", Some("test-key".into()));
    let mut request = ChatRequest::simple("gemini-test", "hello");
    request.stop = (0..6).map(|index| format!("stop-{index}")).collect();
    assert!(matches!(provider.complete(&request).await, Err(DomainError::Validation(_))));
    assert!(matches!(provider.stream(&request).await.err(), Some(DomainError::Validation(_))));
}

#[test]
pub(crate) fn bedrock_body_tool_use_and_result() {
    let mut assistant = ChatMessage::assistant("");
    assistant.tool_calls.push(ToolCall::new("tu_1", "query_asset", json!({"id": "a"})));
    let req = ChatRequest {
        messages: vec![assistant, ChatMessage::tool_result("tu_1", "{\"ok\":1}")],
        ..ChatRequest::default()
    };
    let body = to_bedrock_converse_body(&req);
    eq!(body["messages"][0]["content"][0]["toolUse"]["toolUseId"], json!("tu_1"));
    eq!(body["messages"][1]["content"][0]["toolResult"]["toolUseId"], json!("tu_1"));
}

#[test]
pub(crate) fn bedrock_response_mapping() {
    let raw = json!({
        "output": {"message": {"role": "assistant", "content": [
            {"text": "判定为恶意"},
            {"toolUse": {"toolUseId": "tu", "name": "query_asset", "input": {"id": "a"}}}
        ]}},
        "stopReason": "tool_use",
        "usage": {"inputTokens": 30, "outputTokens": 9, "cacheReadInputTokens": 4},
        "modelId": "anthropic.claude-3-5-sonnet-v2:0"
    });
    let resp = from_bedrock_converse_response(&raw).unwrap_or_else(|e| panic!("{e}"));
    eq!(resp.text_content(), "判定为恶意");
    eq!(resp.finish_reason, FinishReason::ToolCalls);
    eq!(resp.usage, Usage::new(30, 9, 4));
    eq!(resp.tool_calls().len(), 1);
    eq!(resp.model, "anthropic.claude-3-5-sonnet-v2:0");
}

#[test]
pub(crate) fn bedrock_stop_reason_mapping() {
    let make = |reason: &str| {
        from_bedrock_converse_response(&json!({
            "output": {"message": {"content": [{"text": "x"}]}},
            "stopReason": reason
        }))
        .map(|r| r.finish_reason)
    };
    eq!(make("end_turn").ok(), Some(FinishReason::Stop));
    eq!(make("max_tokens").ok(), Some(FinishReason::Length));
    eq!(make("guardrail_intervened").ok(), Some(FinishReason::ContentFilter));
    eq!(make("weird").ok(), Some(FinishReason::Other));
}

#[test]
pub(crate) fn bedrock_response_rejects_malformed() {
    assert!(from_bedrock_converse_response(&json!({"stopReason": "end_turn"})).is_err());
}

#[test]
pub(crate) fn bedrock_event_payloads_parse() {
    let text = parse_bedrock_event(&json!({"contentBlockDelta": {"delta": {"text": "恶"}}}));
    eq!(text.map(|c| c.delta.content), Some("恶".to_string()));
    let stop = parse_bedrock_event(&json!({"messageStop": {"stopReason": "max_tokens"}}));
    eq!(stop.and_then(|c| c.finish_reason), Some(FinishReason::Length));
    let usage = parse_bedrock_event(&json!({"metadata": {"usage": {"inputTokens": 5, "outputTokens": 2}}}));
    eq!(usage.and_then(|c| c.usage), Some(Usage::new(5, 2, 0)));
    let start = parse_bedrock_event(&json!({
        "contentBlockStart": {"contentBlockIndex": 0, "start": {"toolUse": {"toolUseId": "tu", "name": "f"}}}
    }));
    eq!(start.and_then(|c| c.delta.tool_calls[0].id.clone()), Some("tu".to_string()));
    assert!(parse_bedrock_event(&json!({"unknown": 1})).is_none());
}

#[test]
pub(crate) fn bedrock_urls_are_correct() {
    let p = BedrockProvider::new("m-1", "us-east-1", None);
    eq!(p.converse_url(), "https://bedrock-runtime.us-east-1.amazonaws.com/model/m-1/converse");
    assert!(p.converse_stream_url().ends_with("/model/m-1/converse-stream"));
    assert!(!p.configured());
    assert!(p.api_key_missing());
}

#[test]
pub(crate) fn bedrock_from_endpoint_reads_region_header() {
    let mut ep = endpoint(LlmProvider::Bedrock, None);
    ep.model = "anthropic.claude-3-5-sonnet-v2:0".into();
    ep.extra_headers.insert("aws_region".into(), "cn-north-1".into());
    let p = BedrockProvider::from_endpoint(&ep, &MockCredentialResolver);
    eq!(p.region, "cn-north-1");
    assert!(p.base_url.contains("cn-north-1"));
    assert!(!p.configured(), "无凭据时必须未配置（后续由网关降级到 Mock）");
}

#[tokio::test]
pub(crate) async fn bedrock_without_credentials_is_degradable() {
    let p = BedrockProvider::new("m", "us-east-1", None);
    let e = p.complete(&ChatRequest::simple("m", "hi")).await.err().unwrap_or_else(|| panic!("应报错"));
    assert!(e.is_degradable());
    let d = p.provider_descriptor();
    assert!(d.adapter.required_secrets.contains(&"aws_access_key_id".to_string()));
}
