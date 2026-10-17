//! 由 `cache.rs` 拆分：`endpoint` 等 33 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn endpoint(local: bool, max_class: DataClass, pricing: ModelPricing, enabled: bool) -> ModelEndpoint {
    let now = Timestamp::now();
    ModelEndpoint {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        asset_id: Id::new(),
        name: "ep".into(),
        provider: agf_core::enums::LlmProvider::OpenAi,
        base_url: "https://api.openai.com/v1".into(),
        model: "gpt-4o".into(),
        modalities: vec![Modality::Text],
        context_window: Some(128_000),
        max_output_tokens: Some(4096),
        supports_streaming: true,
        supports_tools: true,
        credential_ref: None,
        local_deployment: local,
        max_data_class: max_class,
        pricing,
        enabled,
        fallback: false,
        priority: 1,
        extra_headers: std::collections::BTreeMap::default(),
        created_at: now,
        updated_at: now,
    }
}

pub(crate) fn plain_request() -> ChatRequest {
    let mut r = ChatRequest::simple("gpt-4o", "总结今天的告警");
    r.temperature = Some(0.0);
    r
}

pub(crate) fn cached(ep: &ModelEndpoint, req: &ChatRequest) -> CachedResponse {
    let resp = ChatResponse::text("gpt-4o", "结论：恶意", Usage::new(100, 20, 0));
    CachedResponse::from_response(TenantId::default_tenant(), req.fingerprint(), ep, resp, DEFAULT_TTL_SECS)
}

// ---- 可缓存性（逐分支）--------------------------------------------

#[test]
pub(crate) fn cacheable_when_deterministic_and_unrestricted() {
    let ep = endpoint(false, DataClass::Confidential, ModelPricing::default(), true);
    assert!(is_cacheable(&plain_request(), &ep, false));
}

#[test]
pub(crate) fn not_cacheable_when_temperature_positive() {
    let ep = endpoint(false, DataClass::Confidential, ModelPricing::default(), true);
    let mut req = plain_request();
    req.temperature = Some(0.7);
    assert!(!is_cacheable(&req, &ep, false));
    // 显式 allow 可豁免温度检查
    assert!(is_cacheable(&req, &ep, true));
}

#[test]
pub(crate) fn not_cacheable_when_temperature_absent_is_allowed() {
    // 未显式设置温度视为确定性（厂商默认 1.0，但平台约定"未指定=确定性"以利缓存）
    let ep = endpoint(false, DataClass::Confidential, ModelPricing::default(), true);
    let req = ChatRequest::simple("gpt-4o", "x");
    assert!(req.temperature.is_none());
    assert!(is_cacheable(&req, &ep, false));
}

#[test]
pub(crate) fn not_cacheable_when_streaming() {
    let ep = endpoint(false, DataClass::Confidential, ModelPricing::default(), true);
    let mut req = plain_request();
    req.stream = true;
    assert!(!is_cacheable(&req, &ep, false));
    // 流式是硬性禁止，allow_cache 也不能豁免
    assert!(!is_cacheable(&req, &ep, true));
}

#[test]
pub(crate) fn not_cacheable_when_side_effecting_tools_present() {
    let ep = endpoint(false, DataClass::Confidential, ModelPricing::default(), true);
    let mut req = plain_request();
    req.tools.push(ToolDefinition::mutating("write_file", "写文件", json!({})));
    assert!(!is_cacheable(&req, &ep, false));
    assert!(!is_cacheable(&req, &ep, true), "副作用工具是安全底线，allow_cache 不得豁免");
}

#[test]
pub(crate) fn read_only_tools_are_still_cacheable() {
    let ep = endpoint(false, DataClass::Confidential, ModelPricing::default(), true);
    let mut req = plain_request();
    req.tools.push(ToolDefinition::query("query_asset", "查", json!({})));
    assert!(is_cacheable(&req, &ep, false));
}

#[test]
pub(crate) fn restricted_data_is_not_cacheable_on_cloud_endpoint() {
    let cloud = endpoint(false, DataClass::Restricted, ModelPricing::default(), true);
    let mut req = plain_request();
    req.metadata.insert("data_class".into(), "restricted".into());
    assert!(!is_cacheable(&req, &cloud, false));
    assert!(!is_cacheable(&req, &cloud, true), "数据不出域是安全底线");
}

#[test]
pub(crate) fn restricted_data_is_cacheable_on_local_endpoint() {
    let local = endpoint(true, DataClass::Restricted, ModelPricing::default(), true);
    let mut req = plain_request();
    req.metadata.insert("data_class".into(), "restricted".into());
    assert!(is_cacheable(&req, &local, false));
}

#[test]
pub(crate) fn data_class_ceiling_is_respected() {
    let ep = endpoint(true, DataClass::Internal, ModelPricing::default(), true);
    let mut req = plain_request();
    req.metadata.insert("data_class".into(), "confidential".into());
    assert!(!is_cacheable(&req, &ep, false), "超过端点分级上限不得缓存");
}

#[test]
pub(crate) fn should_write_cache_filters_unusable_responses() {
    let ep = endpoint(false, DataClass::Confidential, ModelPricing::default(), true);
    let req = plain_request();
    let good = ChatResponse::text("gpt-4o", "ok", Usage::new(10, 2, 0));
    assert!(should_write_cache(&req, &ep, false, &good));

    let mut filtered = ChatResponse::text("gpt-4o", "blocked", Usage::new(10, 2, 0));
    filtered.finish_reason = FinishReason::ContentFilter;
    assert!(!should_write_cache(&req, &ep, false, &filtered), "被安全拦截的回复不得进缓存");

    let empty = ChatResponse::text("gpt-4o", "", Usage::new(10, 2, 0));
    assert!(!should_write_cache(&req, &ep, false, &empty));

    let no_usage = ChatResponse::text("gpt-4o", "ok", Usage::default());
    assert!(!should_write_cache(&req, &ep, false, &no_usage));
}

// ---- 成本计算 ------------------------------------------------------

#[test]
pub(crate) fn cost_is_integer_and_cached_rate_applies() {
    let pricing =
        ModelPricing { prompt_micro_per_1k: 2_000, completion_micro_per_1k: 10_000, cached_prompt_micro_per_1k: 500 };
    let ep = endpoint(false, DataClass::Internal, pricing, true);
    // 1000 prompt（其中 400 cached）+ 100 completion
    // = 600*2000/1000 + 400*500/1000 + 100*10000/1000 = 1200 + 200 + 1000 = 2400
    eq!(cost_micro(&ep, &Usage::new(1000, 100, 400)), 2_400);
}

#[test]
pub(crate) fn cached_rate_falls_back_to_normal_rate_when_zero() {
    let pricing =
        ModelPricing { prompt_micro_per_1k: 1_000, completion_micro_per_1k: 0, cached_prompt_micro_per_1k: 0 };
    let ep = endpoint(false, DataClass::Internal, pricing, true);
    eq!(cost_micro(&ep, &Usage::new(1000, 0, 1000)), 1_000);
}

#[test]
pub(crate) fn free_endpoint_costs_zero() {
    let ep = endpoint(true, DataClass::Internal, ModelPricing::default(), true);
    eq!(cost_micro(&ep, &Usage::new(999_999, 999_999, 0)), 0);
    eq!(would_cost_micro(&ep, &Usage::new(10, 10, 0)), 0);
}

#[test]
pub(crate) fn cached_tokens_cannot_exceed_prompt_tokens() {
    let pricing =
        ModelPricing { prompt_micro_per_1k: 1_000, completion_micro_per_1k: 1_000, cached_prompt_micro_per_1k: 1_000 };
    let ep = endpoint(false, DataClass::Internal, pricing, true);
    // cached > prompt 时按 prompt 截断，不得出现负消费
    eq!(cost_micro(&ep, &Usage::new(10, 0, 999)), 10);
}

// ---- 内存实现 ------------------------------------------------------

#[tokio::test]
pub(crate) async fn memory_cache_hit_and_miss() {
    let cache = InMemorySemanticCache::new();
    let ep = endpoint(false, DataClass::Confidential, ModelPricing::default(), true);
    let req = plain_request();
    let fp = req.fingerprint();
    let tenant = TenantId::default_tenant();

    assert!(cache.get(tenant, &fp).await.unwrap_or_else(|e| panic!("{e}")).is_none());
    eq!(cache.misses(), 1);

    cache.put(cached(&ep, &req), DEFAULT_TTL_SECS).await.unwrap_or_else(|e| panic!("{e}"));
    eq!(cache.len(), Some(1));

    let hit = cache.get(tenant, &fp).await.unwrap_or_else(|e| panic!("{e}"));
    let entry = hit.unwrap_or_else(|| panic!("必须命中"));
    eq!(entry.response.text_content(), "结论：恶意");
    eq!(entry.hits, 1);
    eq!(cache.hits(), 1);
}

#[tokio::test]
pub(crate) async fn memory_cache_records_saved_tokens_and_cost() {
    let cache = InMemorySemanticCache::new();
    let pricing =
        ModelPricing { prompt_micro_per_1k: 2_000, completion_micro_per_1k: 10_000, cached_prompt_micro_per_1k: 0 };
    let ep = endpoint(false, DataClass::Confidential, pricing, true);
    let req = plain_request();
    let entry = cached(&ep, &req);
    let expected_tokens = entry.saved_prompt_tokens;
    let expected_micro = entry.saved_micro;
    assert_eq!(expected_tokens, 100);
    assert_eq!(expected_micro, 400); // 100*2000/1000 + 20*10000/1000 = 200 + 200

    cache.put(entry, DEFAULT_TTL_SECS).await.unwrap_or_else(|e| panic!("{e}"));
    let _ = cache.get(TenantId::default_tenant(), &req.fingerprint()).await;
    eq!(cache.saved_tokens(), expected_tokens);
    eq!(cache.saved_micro(), expected_micro);
    let stats = cache.stats();
    eq!(stats.hits, 1);
    eq!(stats.misses, 0);
    assert!((stats.hit_rate() - 1.0).abs() < f64::EPSILON);
}

#[tokio::test]
pub(crate) async fn memory_cache_expires_by_ttl() {
    let cache = InMemorySemanticCache::with_capacity(8, 0);
    let ep = endpoint(false, DataClass::Confidential, ModelPricing::default(), true);
    let req = plain_request();
    // ttl=0 → 立即过期
    cache.put(cached(&ep, &req), 0).await.unwrap_or_else(|e| panic!("{e}"));
    let hit = cache.get(TenantId::default_tenant(), &req.fingerprint()).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(hit.is_none(), "TTL=0 必须视为已过期");
    eq!(cache.len(), Some(0), "过期条目必须被清理");
}

#[tokio::test]
pub(crate) async fn memory_cache_evict_expired_reports_count() {
    let cache = InMemorySemanticCache::with_capacity(8, 10);
    let ep = endpoint(false, DataClass::Confidential, ModelPricing::default(), true);
    for i in 0..3 {
        let req = ChatRequest::simple("m", format!("问题 {i}"));
        cache.put(cached(&ep, &req), 1).await.unwrap_or_else(|e| panic!("{e}"));
    }
    eq!(cache.len(), Some(3));
    let future = Timestamp::now().unix_secs() + 10_000;
    eq!(cache.evict_expired(future), 3);
    eq!(cache.len(), Some(0));
}

#[tokio::test]
pub(crate) async fn memory_cache_evicts_lru_beyond_capacity() {
    // 通过内部容量常量间接验证：写入超过容量后条目数受控
    let cache = InMemorySemanticCache::with_capacity(DEFAULT_CAPACITY, DEFAULT_TTL_SECS);
    let ep = endpoint(false, DataClass::Confidential, ModelPricing::default(), true);
    for i in 0..(DEFAULT_CAPACITY + 20) {
        let req = ChatRequest::simple("m", format!("问题 {i}"));
        cache.put(cached(&ep, &req), DEFAULT_TTL_SECS).await.unwrap_or_else(|e| panic!("{e}"));
    }
    assert!(cache.len().unwrap_or(0) <= DEFAULT_CAPACITY, "必须做容量淘汰");
}

#[tokio::test]
pub(crate) async fn memory_cache_invalidate() {
    let cache = InMemorySemanticCache::new();
    let ep = endpoint(false, DataClass::Confidential, ModelPricing::default(), true);
    let req = plain_request();
    cache.put(cached(&ep, &req), DEFAULT_TTL_SECS).await.unwrap_or_else(|e| panic!("{e}"));
    cache.invalidate(TenantId::default_tenant(), &req.fingerprint()).await.unwrap_or_else(|e| panic!("{e}"));
    let hit = cache.get(TenantId::default_tenant(), &req.fingerprint()).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(hit.is_none());
    cache.clear();
    eq!(cache.len(), Some(0));
}

#[tokio::test]
pub(crate) async fn cache_is_tenant_scoped() {
    let cache = InMemorySemanticCache::new();
    let ep = endpoint(false, DataClass::Confidential, ModelPricing::default(), true);
    let req = plain_request();
    cache.put(cached(&ep, &req), DEFAULT_TTL_SECS).await.unwrap_or_else(|e| panic!("{e}"));
    let other = TenantId::new();
    let hit = cache.get(other, &req.fingerprint()).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(hit.is_none(), "跨租户必须不命中（缓存不得越权）");
}

#[test]
pub(crate) fn exact_cache_key_layout_is_stable() {
    let k = exact_cache_key(TenantId::default_tenant(), "abc");
    assert!(k.starts_with("aigw:cache:"));
    assert!(k.ends_with(":abc"));
}

#[test]
pub(crate) fn cached_response_expiry_helper() {
    let ep = endpoint(false, DataClass::Internal, ModelPricing::default(), true);
    let req = plain_request();
    let entry = cached(&ep, &req);
    assert!(!entry.is_expired_at(entry.created_at.unix_secs()));
    assert!(entry.is_expired_at(entry.expires_at_unix));
    assert!(entry.is_expired_at(entry.expires_at_unix + 1));
}

#[test]
pub(crate) fn hit_counter_saturates() {
    let ep = endpoint(false, DataClass::Internal, ModelPricing::default(), true);
    let req = plain_request();
    let mut entry = cached(&ep, &req);
    entry.hits = u64::MAX;
    entry.record_hit();
    eq!(entry.hits, u64::MAX);
}

#[test]
pub(crate) fn cache_stats_hit_rate_edge_cases() {
    eq!(CacheStats::default().hit_rate(), 0.0);
    let s = CacheStats { hits: 3, misses: 1, saved_tokens: 0, saved_micro: 0 };
    assert!((s.hit_rate() - 0.75).abs() < 1e-9);
}

// ---- ExactCache 组合层 ---------------------------------------------

#[tokio::test]
pub(crate) async fn exact_cache_memory_only_works_offline() {
    let cache = ExactCache::memory();
    assert!(!cache.has_redis());
    let ep = endpoint(false, DataClass::Internal, ModelPricing::default(), true);
    let req = plain_request();
    cache.put(cached(&ep, &req), DEFAULT_TTL_SECS).await.unwrap_or_else(|e| panic!("{e}"));
    let hit = cache.get(TenantId::default_tenant(), &req.fingerprint()).await.unwrap_or_else(|e| panic!("{e}"));
    assert!(hit.is_some());
    eq!(cache.hits(), 1);
    assert!(!cache.is_empty());
}

#[test]
pub(crate) fn ttl_duration_handles_non_positive() {
    eq!(ttl_duration(0), Duration::ZERO);
    eq!(ttl_duration(-5), Duration::ZERO);
    eq!(ttl_duration(30), Duration::from_secs(30));
}

#[test]
pub(crate) fn monotonic_clock_advances() {
    let c = MonotonicClock::start();
    assert!(c.elapsed_secs() < 60);
}

#[test]
pub(crate) fn data_class_of_defaults_to_internal() {
    let req = plain_request();
    eq!(data_class_of(&req), DataClass::Internal);
}

#[test]
pub(crate) fn message_role_import_is_used() {
    // 保持 `ChatMessage` 导入被使用（消息构造路径的健全性检查）
    let m = ChatMessage::user("x");
    assert!(!m.content.is_empty());
}
