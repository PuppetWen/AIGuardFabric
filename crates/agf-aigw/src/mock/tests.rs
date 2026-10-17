//! 由 `mock.rs` 拆分：`triage_request` 等 21 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn triage_request() -> ChatRequest {
    ChatRequest::simple("mock-analyst-1", "请研判这条告警：SSH 暴力破解后出现 webshell 落地与横向移动")
}

#[test]
pub(crate) fn intent_detection_three_branches() {
    eq!(MockIntent::detect("请研判这条告警"), MockIntent::AlertTriage);
    eq!(MockIntent::detect("生成本次事件的报告"), MockIntent::Report);
    eq!(MockIntent::detect("总结一下攻击链路"), MockIntent::AttackChainSummary);
    eq!(MockIntent::detect("今天天气怎么样"), MockIntent::Echo);
    eq!(MockIntent::AlertTriage.as_str(), "alert-triage");
}

#[test]
pub(crate) fn triage_wins_over_report_when_both_present() {
    // 真实提示词常同时出现"研判"与"报告"，更具体的研判应胜出
    eq!(MockIntent::detect("研判该告警并生成报告"), MockIntent::AlertTriage);
}

#[test]
pub(crate) fn intent_detection_english_keywords() {
    eq!(MockIntent::detect("Please triage this alert"), MockIntent::AlertTriage);
    eq!(MockIntent::detect("generate a weekly report"), MockIntent::Report);
    eq!(MockIntent::detect("summarize the attack chain"), MockIntent::AttackChainSummary);
}

#[test]
pub(crate) fn triage_output_is_structured_json() {
    let p = MockProvider::new();
    let resp = p.synthesize(&triage_request());
    let text = resp.text_content();
    let value: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("研判输出必须是 JSON: {e}"));
    eq!(value["verdict"], json!("malicious"));
    assert!(value["confidence"].as_f64().unwrap_or(0.0) >= 0.7);
    assert!(!value["rationale"].as_str().unwrap_or_default().is_empty());
    assert!(value["cited_evidence"].as_array().is_some_and(|a| !a.is_empty()));
    eq!(mock_intent_of(&resp).as_deref(), Some("alert-triage"));
    assert!(is_mock_response(&resp));
}

#[test]
pub(crate) fn triage_verdict_branches() {
    let p = MockProvider::new();
    // 无高危/中危信号的"普通登录成功"→良性
    let benign = p.synthesize(&ChatRequest::simple("m", "这是普通登录成功日志，请判定"));
    let vb: Value = serde_json::from_str(&benign.text_content()).unwrap_or_default();
    eq!(vb["verdict"], json!("benign"));

    let suspicious = p.synthesize(&ChatRequest::simple("m", "请研判：出现多次异常登录与端口扫描"));
    let vs: Value = serde_json::from_str(&suspicious.text_content()).unwrap_or_default();
    eq!(vs["verdict"], json!("suspicious"));

    // 置信度随证据增多而提升
    let weak = vs["confidence"].as_f64().unwrap_or(0.0);
    let strong = {
        let r = p.synthesize(&triage_request());
        let v: Value = serde_json::from_str(&r.text_content()).unwrap_or_default();
        v["confidence"].as_f64().unwrap_or(0.0)
    };
    assert!(strong > weak, "高危信号更多时置信度必须更高: {strong} vs {weak}");
}

#[test]
pub(crate) fn report_output_has_required_sections() {
    let p = MockProvider::new();
    let text = p.synthesize(&ChatRequest::simple("m", "请生成本次安全事件报告")).text_content();
    for section in ["## 摘要", "## 关键发现", "## 影响", "## 处置建议"] {
        assert!(text.contains(section), "报告缺少小节: {section}");
    }
}

#[test]
pub(crate) fn attack_chain_output_lists_stages() {
    let p = MockProvider::new();
    let text = p.synthesize(&ChatRequest::simple("m", "总结攻击链路")).text_content();
    assert!(text.contains("初始访问"));
    assert!(text.contains("横向移动"));
    assert!(text.contains("数据外传"));
}

#[test]
pub(crate) fn echo_is_deterministic_and_never_panics() {
    let p = MockProvider::new();
    let req = ChatRequest::simple("m", "随便聊聊");
    let a = p.synthesize(&req);
    let b = p.synthesize(&req);
    eq!(a.text_content(), b.text_content(), "Mock 输出必须完全确定");
    eq!(a.id, b.id, "同指纹的 Mock 响应 id 必须一致");
    assert!(a.text_content().contains("Mock"));
}

#[test]
pub(crate) fn mock_is_deterministic_across_instances() {
    let a = MockProvider::new().synthesize(&triage_request());
    let b = MockProvider::new().synthesize(&triage_request());
    eq!(a.text_content(), b.text_content());
    eq!(a.usage, b.usage);
}

#[test]
pub(crate) fn fixtures_take_priority_over_synthesis() {
    let req = triage_request();
    let fixture = RecordedFixture::new(req.fingerprint(), "录制好的真实回复");
    let p = MockProvider::new().with_fixtures(vec![fixture]);
    eq!(p.fixture_count(), 1);
    let resp = p.synthesize(&req);
    eq!(resp.text_content(), "录制好的真实回复");
    eq!(resp.raw.as_ref().and_then(|r| r.get("source")).and_then(Value::as_str), Some("fixture"));
}

#[test]
pub(crate) fn fixture_parsing_is_fault_tolerant() {
    let good = serde_json::to_string(&vec![RecordedFixture::new("fp", "x")]).unwrap_or_default();
    eq!(RecordedFixture::parse_all(&good).len(), 1);
    assert!(RecordedFixture::parse_all("{ not json").is_empty(), "坏 fixtures 必须降级为空集");
    assert!(RecordedFixture::parse_all("[]").is_empty());
}

#[test]
pub(crate) fn missing_fixture_dir_is_not_an_error() {
    let dir = std::path::Path::new("definitely/not/here");
    assert!(MockProvider::load_fixtures_from_dir(dir).is_empty());
}

#[test]
pub(crate) fn usage_is_estimated_consistently() {
    let p = MockProvider::new();
    let req = triage_request();
    let expected_prompt = req.estimate_prompt_tokens();
    let resp = p.synthesize(&req);
    eq!(resp.usage.prompt_tokens, expected_prompt);
    assert!(resp.usage.completion_tokens > 0);
    eq!(resp.usage.cached_tokens, 0);
}

#[test]
pub(crate) fn mock_respects_requested_output_limit_in_both_modes() {
    let provider = MockProvider::new();
    let mut request = triage_request();
    request.max_tokens = Some(8);
    let response = provider.synthesize(&request);
    assert_eq!(response.finish_reason, FinishReason::Length);
    assert!(response.usage.completion_tokens <= 8);
    let chunks = provider.synthesize_stream(&request);
    assert_eq!(chunks.last().and_then(|chunk| chunk.finish_reason), Some(FinishReason::Length));
    assert!(chunks.last().and_then(|chunk| chunk.usage).is_some_and(|usage| usage.completion_tokens <= 8));
}

#[test]
pub(crate) fn streaming_yields_chunks_then_final_usage() {
    let p = MockProvider::new();
    let chunks = p.synthesize_stream(&triage_request());
    assert!(chunks.len() > 2, "至少要有角色分片 + 内容分片 + 结束分片");
    let last = chunks.last().cloned().unwrap_or_default();
    assert!(last.is_final());
    assert!(last.usage.is_some(), "结束分片必须带 usage");
    eq!(chunks[0].delta.role, Some(Role::Assistant));
    // 拼接后必须与一次性回复一致
    let mut acc = crate::wire::StreamAccumulator::new();
    for c in &chunks {
        acc.push(c);
    }
    let joined = acc.finish("mock-analyst-1");
    eq!(joined.text_content(), p.synthesize(&triage_request()).text_content());
}

#[tokio::test]
pub(crate) async fn provider_trait_complete_and_stream_work() {
    let p = MockProvider::new();
    let resp = p.complete(&triage_request()).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(!resp.text_content().is_empty());
    let mut stream = p.stream(&triage_request()).await.unwrap_or_else(|e| panic!("{e}"));
    use futures::StreamExt as _;
    let mut count = 0;
    while let Some(item) = stream.next().await {
        assert!(item.is_ok(), "Mock 流不允许出错");
        count += 1;
    }
    assert!(count > 1);
}

#[tokio::test]
pub(crate) async fn mock_health_is_degraded_but_never_error() {
    let p = MockProvider::new();
    let h = ProviderAdapter::health(&p).await.unwrap_or_else(|e| panic!("{e}"));
    eq!(h.state, HealthState::Degraded);
    assert!(h.mocked);
    assert!(h.configured);
    assert!(h.message.unwrap_or_default().contains("fixtures"));
    let d = p.provider_descriptor();
    eq!(d.protocol, "mock");
    eq!(d.providers, vec![LlmProvider::Mock]);
    assert!(d.adapter.required_secrets.is_empty(), "Mock 不需要凭据");
}

#[tokio::test]
pub(crate) async fn adapter_trait_impl_for_mock() {
    let mut p = MockProvider::new();
    let cfg = AdapterConfig {
        id: agf_core::ids::Id::new(),
        tenant_id: agf_core::ids::TenantId::default_tenant(),
        adapter: "llm-mock".into(),
        display_name: "Mock".into(),
        enabled: true,
        settings: BTreeMap::new(),
        secret_refs: BTreeMap::new(),
        circuit_breaker: agf_core::adapter::CircuitBreakerConfig::default(),
        retry: agf_core::adapter::RetryConfig::default(),
        timeout_secs: 30,
        mock: true,
        is_default: false,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    };
    assert!(Adapter::init(&mut p, &cfg).await.is_ok());
    let h = Adapter::health(&p).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(h.mocked);
    let outcome =
        Adapter::sync(&p, SyncDirection::Pull, &PullRequest::default()).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(outcome.mocked);
    let pull = Adapter::pull(&p, &PullRequest::default()).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(pull.mocked);
    assert!(Adapter::shutdown(&mut p).await.is_ok());
    assert!(Adapter::shutdown(&mut p).await.is_ok());
    // Mock 的 push 永远成功（不产生副作用）
    assert!(
        Adapter::push(
            &p,
            &PushPayload { entity: "x".into(), entity_id: "1".into(), body: Value::Null, idempotency_key: None }
        )
        .await
        .is_ok()
    );
}

#[test]
pub(crate) fn fallback_endpoint_is_local_and_restricted_capable() {
    let ep = MockProvider::endpoint_for_fallback(agf_core::ids::TenantId::default_tenant(), "mock-analyst-1");
    eq!(ep.provider, LlmProvider::Mock);
    assert!(ep.local_deployment, "Mock 是本地部署，可承接受限数据");
    assert!(ep.accepts_data_class(agf_core::enums::DataClass::Restricted));
    assert!(ep.pricing.is_free());
    assert!(ep.fallback);
    assert!(ep.enabled);
    eq!(ep.model, MOCK_MODEL);
}

#[test]
pub(crate) fn helper_texts() {
    assert!(mock_placeholder_text("攻击链路").contains("Mock"));
    assert!(content_is_empty(&MessageContent::text("")));
    assert!(!content_is_empty(&MessageContent::text("x")));
    assert!(!is_mock_response(&ChatResponse::text("m", "x", Usage::default())));
}

#[test]
pub(crate) fn synthetic_latency_is_configurable() {
    let mut p = MockProvider::new();
    p.synthetic_latency_ms = 0;
    eq!(p.synthetic_latency_ms, 0);
    eq!(MockProvider::default().fixture_count(), 0);
    eq!(MockProvider::new().with_model("mock-2").model, "mock-2");
}
