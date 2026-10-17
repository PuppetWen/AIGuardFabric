//! Public API cost consistency. All fixtures are offline and use positive pricing.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use agf_aigw::gateway::{AiGateway, CallContext};
use agf_aigw::meter::Meter;
use agf_aigw::wire::{ChatRequest, Usage};
use agf_core::enums::{DataClass, LlmProvider};
use agf_core::ids::{Id, TenantId};
use agf_core::model::{Modality, ModelEndpoint, ModelPricing, UsageRecord};
use agf_core::time::Timestamp;

fn paid_endpoint() -> ModelEndpoint {
    let now = Timestamp::now();
    ModelEndpoint {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        asset_id: Id::new(),
        name: "synthetic-paid-model".into(),
        provider: LlmProvider::OpenAi,
        base_url: "https://never-contacted.invalid/v1".into(),
        model: "synthetic-paid-model".into(),
        modalities: vec![Modality::Text],
        context_window: Some(32_000),
        max_output_tokens: Some(4096),
        supports_streaming: true,
        supports_tools: true,
        credential_ref: Some(Id::new()),
        local_deployment: false,
        max_data_class: DataClass::Confidential,
        pricing: ModelPricing {
            prompt_micro_per_1k: 2000,
            completion_micro_per_1k: 8000,
            cached_prompt_micro_per_1k: 500,
        },
        enabled: true,
        fallback: false,
        priority: 1,
        extra_headers: BTreeMap::new(),
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn positive_pricing_mock_gateway_has_zero_response_record_and_meter_cost() {
    let ep = paid_endpoint();
    let gateway = AiGateway::new(vec![ep.clone()]).with_mock_mode(true);
    let result =
        gateway.chat(CallContext::new(ep.tenant_id), ChatRequest::simple(ep.model, "analyze event")).await.unwrap();
    assert!(result.mocked);
    assert!(!result.cached);
    assert_eq!(result.cost_micro, 0);
    assert_eq!(result.usage_record.cost_micro, 0);
    assert!(result.usage_record.mocked);
    assert!(result.usage.total() > 0);
    let totals = gateway.meter().snapshot().total;
    assert_eq!(totals.cost_micro, 0);
    assert_eq!(totals.calls, 1);
    assert_eq!(totals.mocked_calls, 1);
    assert_eq!(totals.prompt_tokens, result.usage.prompt_tokens);
    assert_eq!(totals.completion_tokens, result.usage.completion_tokens);
}

#[test]
fn paid_chat_and_exact_hit_keep_logical_usage_and_distinct_actual_costs() {
    let meter = Meter::new();
    let ep = paid_endpoint();
    let usage = Usage::new(100, 20, 0);
    let paid = meter.record(ep.tenant_id, "paid", None, &ep, usage, false, false, 10);
    let hit = meter.record(ep.tenant_id, "hit", None, &ep, usage, true, false, 1);
    assert_eq!(paid.cost_micro, 360);
    assert_eq!(hit.cost_micro, 0);
    assert_eq!(hit.prompt_tokens, 100);
    assert_eq!(hit.completion_tokens, 20);
    let totals = meter.snapshot().total;
    assert_eq!(totals.calls, 2);
    assert_eq!(totals.cache_hits, 1);
    assert_eq!(totals.total_tokens(), 240);
    assert_eq!(totals.cost_micro, 360);
}

#[test]
fn absorb_keeps_explicit_component_cost_even_when_logical_reply_is_cached() {
    // This guards the existing external-record contract, not an embedding implementation.
    let ep = paid_endpoint();
    let record = UsageRecord {
        id: Id::new(),
        tenant_id: ep.tenant_id,
        session_id: "explicit-paid-component".into(),
        agent_id: None,
        endpoint_id: ep.id,
        provider: ep.provider,
        model: ep.model,
        prompt_tokens: 10,
        completion_tokens: 0,
        cached_tokens: 0,
        cache_write_tokens: 0,
        cache_write_1h_tokens: 0,
        cache_hit: true,
        cost_micro: 123,
        mocked: false,
        latency_ms: 1,
        at: Timestamp::now(),
    };
    let meter = Meter::new();
    meter.absorb(&record);
    assert_eq!(meter.snapshot().total.cost_micro, 123);
    assert_eq!(meter.snapshot().total.calls, 1);
    assert_eq!(meter.snapshot().total.prompt_tokens, 10);
}
