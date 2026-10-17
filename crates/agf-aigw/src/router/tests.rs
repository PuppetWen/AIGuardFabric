//! 由 `router.rs` 拆分：`endpoint` 等 32 个函数（纯搬移，逻辑不变）。
use super::*;

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
pub(crate) fn endpoint(
    name: &str,
    provider: LlmProvider,
    model: &str,
    local: bool,
    enabled: bool,
    priority: u32,
    context: u32,
    pricing: ModelPricing,
    max_class: DataClass,
    supports_tools: bool,
    supports_streaming: bool,
    modalities: Vec<Modality>,
) -> ModelEndpoint {
    let now = Timestamp::now();
    ModelEndpoint {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        asset_id: Id::new(),
        name: name.to_string(),
        provider,
        base_url: "https://example.invalid/v1".into(),
        model: model.to_string(),
        modalities,
        context_window: Some(context),
        max_output_tokens: Some(4096),
        supports_streaming,
        supports_tools,
        credential_ref: None,
        local_deployment: local,
        max_data_class: max_class,
        pricing,
        enabled,
        fallback: true,
        priority,
        extra_headers: std::collections::BTreeMap::default(),
        created_at: now,
        updated_at: now,
    }
}

pub(crate) fn text_only() -> Vec<Modality> {
    vec![Modality::Text]
}

pub(crate) fn cloud_cheap() -> ModelEndpoint {
    endpoint(
        "cloud-cheap",
        LlmProvider::DeepSeek,
        "deepseek-chat",
        false,
        true,
        5,
        64_000,
        ModelPricing { prompt_micro_per_1k: 1_000, completion_micro_per_1k: 2_000, cached_prompt_micro_per_1k: 0 },
        DataClass::Confidential,
        true,
        true,
        text_only(),
    )
}

pub(crate) fn cloud_premium() -> ModelEndpoint {
    endpoint(
        "cloud-premium",
        LlmProvider::OpenAi,
        "gpt-4o",
        false,
        true,
        1,
        128_000,
        ModelPricing { prompt_micro_per_1k: 5_000, completion_micro_per_1k: 15_000, cached_prompt_micro_per_1k: 0 },
        DataClass::Confidential,
        true,
        true,
        vec![Modality::Text, Modality::Vision],
    )
}

pub(crate) fn local_model() -> ModelEndpoint {
    endpoint(
        "local-ollama",
        LlmProvider::Ollama,
        "qwen2.5:14b",
        true,
        true,
        8,
        32_000,
        ModelPricing::default(),
        DataClass::Restricted,
        true,
        true,
        text_only(),
    )
}

pub(crate) fn req() -> ChatRequest {
    ChatRequest::simple("deepseek-chat", "研判这条告警")
}

#[test]
pub(crate) fn strategy_parse_roundtrip() {
    for s in RoutingStrategy::all() {
        eq!(RoutingStrategy::parse(s.as_str()), Ok(s));
        assert!(!s.display_zh().is_empty());
    }
    eq!(RoutingStrategy::parse("Cost_First"), Ok(RoutingStrategy::CostFirst));
    assert!(RoutingStrategy::parse("bogus").is_err());
    eq!(RoutingStrategy::default(), RoutingStrategy::CostFirst);
}

#[test]
pub(crate) fn cost_first_orders_by_price() {
    let router = ModelRouter::new(vec![cloud_premium(), cloud_cheap(), local_model()]);
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal);
    let chain = router.select(&ctx).unwrap_or_else(|e| panic!("{e}"));
    // 本地免费排最前，其次便宜
    eq!(chain[0].name, "local-ollama");
    eq!(chain[1].name, "cloud-cheap");
    eq!(chain[2].name, "cloud-premium");
}

#[test]
pub(crate) fn latency_first_orders_by_priority() {
    let router = ModelRouter::new(vec![cloud_cheap(), cloud_premium(), local_model()]);
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal)
        .with_strategy(RoutingStrategy::LatencyFirst);
    let chain = router.select(&ctx).unwrap_or_else(|e| panic!("{e}"));
    eq!(chain[0].name, "cloud-premium", "priority=1 应排最前");
    eq!(chain[1].name, "cloud-cheap");
    eq!(chain[2].name, "local-ollama");
}

#[test]
pub(crate) fn quality_first_prefers_largest_context() {
    let router = ModelRouter::new(vec![cloud_cheap(), local_model(), cloud_premium()]);
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal)
        .with_strategy(RoutingStrategy::QualityFirst);
    let chain = router.select(&ctx).unwrap_or_else(|e| panic!("{e}"));
    eq!(chain[0].name, "cloud-premium");
    eq!(chain[1].name, "cloud-cheap");
    eq!(chain[2].name, "local-ollama");
}

#[test]
pub(crate) fn local_first_prefers_local_deployment() {
    let router = ModelRouter::new(vec![cloud_cheap(), local_model()]);
    let ctx =
        RoutingContext::new(TenantId::default_tenant(), DataClass::Internal).with_strategy(RoutingStrategy::LocalFirst);
    let chain = router.select(&ctx).unwrap_or_else(|e| panic!("{e}"));
    eq!(chain[0].name, "local-ollama");
}

#[test]
pub(crate) fn round_robin_rotates_deterministically() {
    let router = ModelRouter::new(vec![cloud_cheap(), local_model(), cloud_premium()]);
    let ctx =
        RoutingContext::new(TenantId::default_tenant(), DataClass::Internal).with_strategy(RoutingStrategy::RoundRobin);
    let first = router.select(&ctx).unwrap_or_else(|e| panic!("{e}"));
    let second = router.select(&ctx).unwrap_or_else(|e| panic!("{e}"));
    let third = router.select(&ctx).unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(first[0].id, second[0].id, "轮询必须在请求间轮换");
    assert_ne!(second[0].id, third[0].id);
    eq!(router.round_robin_counter(), 3);
    // 每次链路都是同一集合（只是起点不同）
    let mut a: Vec<String> = first.iter().map(|e| e.name.clone()).collect();
    let mut b: Vec<String> = second.iter().map(|e| e.name.clone()).collect();
    a.sort();
    b.sort();
    eq!(a, b);
}

#[test]
pub(crate) fn restricted_data_excludes_cloud_endpoints() {
    let router = ModelRouter::new(vec![cloud_cheap(), cloud_premium(), local_model()]);
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Restricted);
    let (chain, decision) = router.select_with_decision(&ctx).unwrap_or_else(|e| panic!("{e}"));
    eq!(chain.len(), 1);
    eq!(chain[0].name, "local-ollama");
    eq!(decision.excluded.len(), 2);
    assert!(decision.excluded.iter().all(|e| e.reason.contains("数据不出域")));
    assert!(decision.summary().contains("分级=restricted"));
}

#[test]
pub(crate) fn data_class_ceiling_is_enforced() {
    let mut low = cloud_cheap();
    low.max_data_class = DataClass::Public;
    let router = ModelRouter::new(vec![low]);
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal);
    let err = router.select(&ctx).err().unwrap_or_else(|| panic!("应被排除"));
    assert!(err.to_string().contains("超过端点上限"), "{err}");
}

#[test]
pub(crate) fn disabled_endpoints_are_filtered() {
    let mut off = cloud_cheap();
    off.enabled = false;
    let router = ModelRouter::new(vec![off, cloud_premium()]);
    eq!(router.enabled_count(), 1);
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal);
    let chain = router.select(&ctx).unwrap_or_else(|e| panic!("{e}"));
    eq!(chain.len(), 1);
    eq!(chain[0].name, "cloud-premium");
}

#[test]
pub(crate) fn pinned_model_restricts_chain() {
    let router = ModelRouter::new(vec![cloud_cheap(), cloud_premium(), local_model()]);
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal).pinned("gpt-4o");
    let chain = router.select(&ctx).unwrap_or_else(|e| panic!("{e}"));
    eq!(chain.len(), 1);
    eq!(chain[0].name, "cloud-premium");
}

#[test]
pub(crate) fn pinned_by_endpoint_id_also_works() {
    let target = cloud_premium();
    let target_id = target.id;
    let router = ModelRouter::new(vec![cloud_cheap(), target]);
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal).pinned(target_id.to_string());
    let chain = router.select(&ctx).unwrap_or_else(|e| panic!("{e}"));
    eq!(chain.len(), 1);
    eq!(chain[0].id, target_id);
}

#[test]
pub(crate) fn pinned_model_not_registered_yields_error() {
    let router = ModelRouter::new(vec![cloud_cheap()]);
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal).pinned("no-such-model");
    let err = router.select(&ctx).err().unwrap_or_else(|| panic!("应报错"));
    assert!(err.to_string().contains("全部被排除"), "{err}");
}

#[test]
pub(crate) fn empty_candidate_list_is_a_config_error() {
    let router = ModelRouter::new(vec![]);
    assert!(router.is_empty());
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal);
    let err = router.select(&ctx).err().unwrap_or_else(|| panic!("必须报错"));
    assert!(matches!(err, DomainError::Config(_)));
}

#[test]
pub(crate) fn capability_gating_via_routing_context() {
    let mut no_tools = cloud_cheap();
    no_tools.supports_tools = false;
    let mut no_stream = cloud_premium();
    no_stream.supports_streaming = false;
    let router = ModelRouter::new(vec![no_tools, no_stream]);

    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal).requiring_tools();
    let chain = router.select(&ctx).unwrap_or_else(|e| panic!("{e}"));
    eq!(chain.len(), 1);
    eq!(chain[0].name, "cloud-premium");

    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal).requiring_stream();
    let chain = router.select(&ctx).unwrap_or_else(|e| panic!("{e}"));
    eq!(chain.len(), 1);
    eq!(chain[0].name, "cloud-cheap");
}

#[test]
pub(crate) fn vision_requirement_filters_text_only_endpoints() {
    let router = ModelRouter::new(vec![cloud_cheap(), cloud_premium()]);
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal).requiring_vision();
    let chain = router.select(&ctx).unwrap_or_else(|e| panic!("{e}"));
    eq!(chain.len(), 1);
    eq!(chain[0].name, "cloud-premium");
}

#[test]
pub(crate) fn tenant_isolation_is_enforced() {
    let mut foreign = cloud_cheap();
    foreign.tenant_id = TenantId::new();
    let router = ModelRouter::new(vec![foreign, cloud_premium()]);
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal);
    let (chain, decision) = router.select_with_decision(&ctx).unwrap_or_else(|e| panic!("{e}"));
    eq!(chain.len(), 1);
    assert!(decision.excluded.iter().any(|e| e.reason == "租户不匹配"));
}

#[test]
pub(crate) fn tenant_owned_endpoint_is_preferred_over_global() {
    let global = cloud_premium(); // default_tenant
    let mut owned = cloud_cheap();
    let tenant = TenantId::new();
    owned.tenant_id = tenant;
    let router = ModelRouter::new(vec![global, owned]);
    let ctx = RoutingContext::new(tenant, DataClass::Internal);
    let chain = router.select(&ctx).unwrap_or_else(|e| panic!("{e}"));
    // 全局端点作为兜底也在链上
    eq!(chain.len(), 2);
}

#[test]
pub(crate) fn without_fallback_truncates_to_one() {
    let router = ModelRouter::new(vec![cloud_cheap(), cloud_premium(), local_model()]);
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal).without_fallback();
    let chain = router.select(&ctx).unwrap_or_else(|e| panic!("{e}"));
    eq!(chain.len(), 1);
}

#[test]
pub(crate) fn selection_is_deterministic_for_same_input() {
    let router = ModelRouter::new(vec![cloud_cheap(), cloud_premium(), local_model()]);
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal);
    let a: Vec<String> = router.select(&ctx).unwrap_or_else(|e| panic!("{e}")).iter().map(|e| e.name.clone()).collect();
    let b: Vec<String> = router.select(&ctx).unwrap_or_else(|e| panic!("{e}")).iter().map(|e| e.name.clone()).collect();
    eq!(a, b);
}

#[test]
pub(crate) fn router_accessors() {
    let a = cloud_cheap();
    let id = a.id;
    let router = ModelRouter::new(vec![a, cloud_premium()]);
    eq!(router.len(), 2);
    eq!(router.enabled_count(), 2);
    assert!(!router.is_empty());
    assert!(router.get(id).is_some());
    assert!(router.get(Id::new()).is_none());
    eq!(router.by_model("gpt-4o").map(|e| e.name.clone()), Some("cloud-premium".to_string()));
    assert!(router.by_model("nope").is_none());
    eq!(router.endpoints().len(), 2);
}

#[test]
pub(crate) fn projected_cost_helper_matches_endpoint_pricing() {
    let ep = cloud_premium();
    let mut req = req();
    req.max_tokens = Some(1000);
    let prompt = req.estimate_prompt_tokens();
    let expected = ep.estimate_cost_micro(prompt, 1000);
    eq!(projected_cost_micro(&ep, &req), expected);
    assert!(projected_cost_micro(&ep, &req) > 0);
}

#[test]
pub(crate) fn free_endpoint_projected_cost_is_zero() {
    let ep = local_model();
    eq!(projected_cost_micro(&ep, &req()), 0);
}

#[test]
pub(crate) fn default_max_completion_is_used_when_unspecified() {
    let ep = cloud_premium();
    let req = req();
    assert!(req.max_tokens.is_none());
    let prompt = req.estimate_prompt_tokens();
    eq!(projected_cost_micro(&ep, &req), ep.estimate_cost_micro(prompt, 1024));
}

#[test]
pub(crate) fn routing_context_builders() {
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Confidential)
        .with_strategy(RoutingStrategy::LocalFirst)
        .pinned("m")
        .requiring_stream()
        .requiring_tools()
        .requiring_vision()
        .without_fallback();
    eq!(ctx.strategy, RoutingStrategy::LocalFirst);
    eq!(ctx.pinned_model.as_deref(), Some("m"));
    assert!(ctx.require_streaming && ctx.require_tools && ctx.require_vision);
    assert!(!ctx.allow_fallback);
}

#[test]
pub(crate) fn decision_summary_lists_chain() {
    let router = ModelRouter::new(vec![cloud_cheap(), cloud_premium()]);
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal);
    let (_, decision) = router.select_with_decision(&ctx).unwrap_or_else(|e| panic!("{e}"));
    let summary = decision.summary();
    assert!(summary.contains("策略=cost-first"));
    assert!(summary.contains("cloud-"));
}

#[test]
pub(crate) fn exclusion_reasons_are_actionable() {
    let mut off = cloud_cheap();
    off.enabled = false;
    let mut no_vision = cloud_premium();
    no_vision.modalities = text_only();
    let router = ModelRouter::new(vec![off, no_vision]);
    let ctx = RoutingContext::new(TenantId::default_tenant(), DataClass::Internal).requiring_vision();
    let err = router.select(&ctx).err().unwrap_or_else(|| panic!("应报错"));
    let text = err.to_string();
    assert!(text.contains("端点已禁用"), "{text}");
    assert!(text.contains("不支持视觉输入"), "{text}");
}
