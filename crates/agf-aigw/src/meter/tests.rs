//! 由 `meter.rs` 拆分：`endpoint` 等 22 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn endpoint(pricing: ModelPricing) -> ModelEndpoint {
    let now = Timestamp::now();
    ModelEndpoint {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        asset_id: Id::new(),
        name: "ep".into(),
        provider: LlmProvider::DeepSeek,
        base_url: "https://api.deepseek.com/v1".into(),
        model: "deepseek-chat".into(),
        modalities: vec![Modality::Text],
        context_window: Some(64_000),
        max_output_tokens: Some(4096),
        supports_streaming: true,
        supports_tools: true,
        credential_ref: None,
        local_deployment: false,
        max_data_class: DataClass::Confidential,
        pricing,
        enabled: true,
        fallback: false,
        priority: 1,
        extra_headers: std::collections::BTreeMap::default(),
        created_at: now,
        updated_at: now,
    }
}

pub(crate) fn paid_pricing() -> ModelPricing {
    ModelPricing { prompt_micro_per_1k: 2_000, completion_micro_per_1k: 8_000, cached_prompt_micro_per_1k: 500 }
}

#[test]
pub(crate) fn breakdown_matches_spec_arithmetic() {
    let ep = endpoint(paid_pricing());
    // 1000 prompt（其中 400 cached）+ 500 completion
    // = 600*2000/1000 + 400*500/1000 + 500*8000/1000 = 1200 + 200 + 4000 = 5400
    let b = breakdown(&ep, &Usage::new(1000, 500, 400));
    eq!(b.prompt_micro, 1_200);
    eq!(b.cached_prompt_micro, 200);
    eq!(b.completion_micro, 4_000);
    eq!(b.total_micro, 5_400);
    assert!(b.is_consistent());
}

#[test]
pub(crate) fn anthropic_cache_writes_use_their_ttl_multipliers() {
    let mut ep = endpoint(ModelPricing {
        prompt_micro_per_1k: 1_000,
        completion_micro_per_1k: 2_000,
        cached_prompt_micro_per_1k: 100,
    });
    ep.provider = LlmProvider::Anthropic;
    let usage = Usage {
        prompt_tokens: 4_000,
        completion_tokens: 100,
        cached_tokens: 1_000,
        cache_write_tokens: 2_000,
        cache_write_1h_tokens: 1_000,
    };
    let cost = breakdown(&ep, &usage);
    eq!(cost.prompt_micro, 1_000);
    eq!(cost.cached_prompt_micro, 100);
    eq!(cost.cache_write_prompt_micro, 3_250);
    eq!(cost.completion_micro, 200);
    eq!(cost.total_micro, 4_550);
    assert!(cost.is_consistent());
    eq!(crate::cache::cost_micro(&ep, &usage), cost.total_micro);
    let meter = Meter::new();
    let record = meter.record(TenantId::default_tenant(), "cached", None, &ep, usage, false, false, 1);
    eq!(record.cost_micro, 4_550);
    eq!(record.cache_write_tokens, 2_000);
    eq!(record.cache_write_1h_tokens, 1_000);
    eq!(meter.snapshot().total.cache_write_tokens, 2_000);
    ep.provider = LlmProvider::DeepSeek;
    eq!(breakdown(&ep, &usage).total_micro, 3_300);
}

#[test]
pub(crate) fn breakdown_uses_normal_rate_when_cached_rate_absent() {
    let ep = endpoint(ModelPricing {
        prompt_micro_per_1k: 1_000,
        completion_micro_per_1k: 2_000,
        cached_prompt_micro_per_1k: 0,
    });
    let b = breakdown(&ep, &Usage::new(1000, 100, 1000));
    eq!(b.prompt_micro, 0);
    eq!(b.cached_prompt_micro, 1_000);
    eq!(b.completion_micro, 200);
    eq!(b.total_micro, 1_200);
}

#[test]
pub(crate) fn breakdown_is_zero_for_free_endpoint() {
    let ep = endpoint(ModelPricing::default());
    let b = breakdown(&ep, &Usage::new(10_000, 10_000, 0));
    eq!(b.total_micro, 0);
    assert!(b.is_consistent());
    assert!((b.total_yuan() - 0.0).abs() < f64::EPSILON);
}

#[test]
pub(crate) fn breakdown_yuan_conversion() {
    let ep = endpoint(paid_pricing());
    let b = breakdown(&ep, &Usage::new(500, 0, 0));
    eq!(b.total_micro, 1_000);
    assert!((b.total_yuan() - 0.001).abs() < 1e-12);
}

#[test]
pub(crate) fn breakdown_handles_cached_exceeding_prompt() {
    let ep = endpoint(paid_pricing());
    let b = breakdown(&ep, &Usage::new(10, 0, 999));
    eq!(b.prompt_micro, 0);
    eq!(b.cached_prompt_micro, 5);
    assert!(b.is_consistent());
}

#[test]
pub(crate) fn meter_accumulates_globally_and_by_dimension() {
    let meter = Meter::new();
    let ep = endpoint(paid_pricing());
    let tenant = TenantId::default_tenant();
    let agent = Id::new();
    let r1 = meter.record(tenant, "s-1", Some(agent), &ep, Usage::new(1000, 500, 0), false, false, 120);
    let r2 = meter.record(tenant, "s-2", None, &ep, Usage::new(500, 100, 0), false, true, 5);

    eq!(r1.cost_micro, 6_000); // 1000*2000/1000 + 500*8000/1000 = 2000+4000
    assert_eq!(r2.cost_micro, 0, "Mock 保留逻辑用量，不计付费聊天成本");
    assert!(r2.mocked);
    assert_eq!(r1.provider, LlmProvider::DeepSeek);

    let snap = meter.snapshot();
    eq!(snap.total.calls, 2);
    eq!(snap.total.prompt_tokens, 1_500);
    eq!(snap.total.completion_tokens, 600);
    eq!(snap.total.cost_micro, 6_000);
    eq!(snap.total.mocked_calls, 1);
    eq!(snap.total.total_tokens(), 2_100);
    eq!(snap.total.avg_latency_ms(), 62);
    assert!(snap.generated_at.is_some());
    assert!((snap.cost_yuan() - 0.006).abs() < 1e-12);

    eq!(meter.tenant_totals(tenant).calls, 2);
    eq!(meter.agent_totals(agent).calls, 1);
    eq!(meter.session_totals("s-1").calls, 1);
    eq!(snap.by_provider.get("deepseek").map(|t| t.calls), Some(2));
    eq!(snap.by_model.get("deepseek-chat").map(|t| t.calls), Some(2));
}

#[test]
pub(crate) fn cache_hit_records_zero_cost_but_counts_tokens() {
    let meter = Meter::new();
    let ep = endpoint(paid_pricing());
    let record = meter.record(TenantId::default_tenant(), "s", None, &ep, Usage::new(1000, 500, 0), true, false, 3);
    eq!(record.cost_micro, 0, "缓存命中不得虚增成本");
    assert!(record.cache_hit);
    let snap = meter.snapshot();
    eq!(snap.total.cache_hits, 1);
    eq!(snap.total.calls, 1);
    eq!(snap.total.prompt_tokens, 1000, "token 用量仍需记录");
    eq!(snap.total.cost_micro, 0);
}

#[test]
pub(crate) fn meter_recent_records_are_capped_and_newest_first() {
    let meter = Meter::new();
    let ep = endpoint(paid_pricing());
    for i in 0..(Meter::MAX_RECENT + 10) {
        meter.record(TenantId::default_tenant(), &format!("s-{i}"), None, &ep, Usage::new(1, 1, 0), false, false, 1);
    }
    let recent = meter.recent(5);
    eq!(recent.len(), 5);
    assert_eq!(recent[0].session_id, format!("s-{}", Meter::MAX_RECENT + 9));
    eq!(meter.snapshot().total.calls, (Meter::MAX_RECENT + 10) as u64, "裁剪不得影响累计值");
}

#[test]
pub(crate) fn meter_reset_clears_state() {
    let meter = Meter::new();
    let ep = endpoint(paid_pricing());
    meter.record(TenantId::default_tenant(), "s", None, &ep, Usage::new(1, 1, 0), false, false, 1);
    meter.reset();
    eq!(meter.snapshot().total.calls, 0);
    assert!(meter.recent(10).is_empty());
}

#[test]
pub(crate) fn meter_absorb_external_record() {
    let meter = Meter::new();
    let ep = endpoint(paid_pricing());
    let record = UsageRecord {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        session_id: "external".into(),
        agent_id: Some(Id::new()),
        endpoint_id: ep.id,
        provider: LlmProvider::OpenAi,
        model: "gpt-4o".into(),
        prompt_tokens: 10,
        completion_tokens: 20,
        cached_tokens: 0,
        cache_write_tokens: 0,
        cache_write_1h_tokens: 0,
        cache_hit: false,
        cost_micro: 999,
        mocked: false,
        latency_ms: 50,
        at: Timestamp::now(),
    };
    meter.absorb(&record);
    let snap = meter.snapshot();
    eq!(snap.total.calls, 1);
    eq!(snap.total.cost_micro, 999);
    eq!(meter.session_totals("external").total_tokens(), 30);
}

#[test]
pub(crate) fn totals_accumulate_and_average() {
    let mut a = MeterTotals { calls: 2, latency_ms: 100, ..MeterTotals::default() };
    let b = MeterTotals { calls: 2, latency_ms: 200, prompt_tokens: 5, ..MeterTotals::default() };
    a.accumulate(&b);
    eq!(a.calls, 4);
    eq!(a.latency_ms, 300);
    eq!(a.avg_latency_ms(), 75);
    eq!(a.prompt_tokens, 5);
    eq!(MeterTotals::default().avg_latency_ms(), 0);
}

#[test]
pub(crate) fn meter_key_labels() {
    let t = TenantId::default_tenant();
    assert!(MeterKey::Tenant(t).label().starts_with("tenant:"));
    assert!(MeterKey::Agent(t, Id::new()).label().starts_with("agent:"));
    assert!(MeterKey::Session(t, "s".into()).label().starts_with("session:"));
}

// ---- 预算守卫 ------------------------------------------------------

#[test]
pub(crate) fn budget_guard_allows_within_single_cap() {
    let ep = endpoint(paid_pricing());
    let guard = BudgetGuard::single(10_000);
    // 1000 prompt + 1000 completion = 2000 + 8000 = 10000 → 恰好等于上限（放行）
    let projected = guard.ensure_within_budget("tenant", &ep, 1000, 1000, 0).unwrap_or_else(|e| panic!("{e}"));
    eq!(projected, 10_000);
}

#[test]
pub(crate) fn budget_guard_refuses_over_single_cap() {
    let ep = endpoint(paid_pricing());
    let guard = BudgetGuard::single(9_999);
    let err = guard.ensure_within_budget("tenant", &ep, 1000, 1000, 0).err();
    let e = err.unwrap_or_else(|| panic!("必须拒绝超预算调用"));
    assert!(matches!(e, DomainError::QuotaExceeded { .. }), "必须是配额错误: {e}");
    eq!(e.code(), "quota_exceeded");
    eq!(e.status_code(), 429);
}

#[test]
pub(crate) fn budget_guard_refuses_over_total_cap() {
    let ep = endpoint(paid_pricing());
    let guard = BudgetGuard::new(0, 5_000);
    assert!(guard.ensure_within_budget("t", &ep, 1000, 100, 0).is_ok());
    let err = guard.ensure_within_budget("t", &ep, 1000, 100, 4_500).err();
    assert!(err.is_some(), "累计超限必须拒绝");
    let e = err.unwrap_or_else(|| panic!("必须拒绝"));
    assert!(e.to_string().contains("total"), "错误里应能看出是累计维度: {e}");
}

#[test]
pub(crate) fn unlimited_guard_never_refuses() {
    let ep = endpoint(paid_pricing());
    let guard = BudgetGuard::unlimited();
    assert!(!guard.is_limited());
    assert!(guard.ensure_within_budget("t", &ep, 1_000_000, 1_000_000, u64::MAX / 2).is_ok());
    assert!(!BudgetGuard::default().is_limited());
}

#[test]
pub(crate) fn projected_cost_uses_max_tokens_conservatively() {
    let ep = endpoint(paid_pricing());
    // 上限估计：1000 prompt + 4096 completion = 2000 + 32768
    eq!(BudgetGuard::projected_micro(&ep, 1000, 4096), 34_768);
}

#[test]
pub(crate) fn cache_breakpoints_reserve_anthropic_write_premiums() {
    use crate::wire::{AnthropicNativeRequest, ChatRequest};

    let mut ep = endpoint(paid_pricing());
    ep.provider = LlmProvider::Anthropic;
    let mut request = ChatRequest::simple("claude", "x".repeat(4_000));
    request.max_tokens = Some(100);
    let prompt = request.estimate_prompt_tokens();
    let output = 800;
    let normal = 2_000 * prompt / 1_000 + output;
    eq!(BudgetGuard::projected_micro_for_request(&ep, &request), normal);

    request.anthropic_native = Some(AnthropicNativeRequest {
        body: serde_json::json!({"cache_control":{"type":"ephemeral"}}),
        messages: request.messages.clone(),
    });
    let five_minutes = 2_000 * prompt * 5 / 4_000 + output;
    eq!(BudgetGuard::projected_micro_for_request(&ep, &request), five_minutes);
    assert!(
        BudgetGuard::single(five_minutes - 1).ensure_within_budget_for_request("tenant", &ep, &request, 0).is_err()
    );

    request.anthropic_native.as_mut().unwrap().body = serde_json::json!({
        "messages":[{"content":[{"type":"text","cache_control":{"type":"ephemeral","ttl":"1h"}}]}]
    });
    let one_hour = 2_000 * prompt * 2 / 1_000 + output;
    eq!(BudgetGuard::projected_micro_for_request(&ep, &request), one_hour);
    assert!(BudgetGuard::single(one_hour).ensure_within_budget_for_request("tenant", &ep, &request, 0).is_ok());

    // A tool input can contain user data named cache_control; it is not a cache breakpoint.
    request.anthropic_native.as_mut().unwrap().body = serde_json::json!({
        "messages":[{"content":[{"type":"tool_use","input":{"cache_control":{"ttl":"1h"}}}]}]
    });
    eq!(BudgetGuard::projected_micro_for_request(&ep, &request), normal);
}

#[test]
pub(crate) fn free_endpoint_never_trips_budget() {
    let ep = endpoint(ModelPricing::default());
    let guard = BudgetGuard::single(1);
    assert!(guard.ensure_within_budget("t", &ep, 1_000_000, 1_000_000, 0).is_ok());
}

#[test]
pub(crate) fn snapshot_defaults_are_zero() {
    let s = MeterSnapshot::default();
    eq!(s.cost_micro(), 0);
    assert!((s.cost_yuan() - 0.0).abs() < f64::EPSILON);
    assert!(s.generated_at.is_none());
}

#[test]
pub(crate) fn cost_breakdown_default_is_consistent() {
    assert!(CostBreakdown::default().is_consistent());
}
