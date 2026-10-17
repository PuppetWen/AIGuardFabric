//! Actual owner reducers: one request, every physical fee, original bucket and immutable completion.
use super::{chat_components::*, components::ComponentOutcome, records::*, reducer, tests_fixture::*};
use crate::{
    gateway_quota::{self, settlement as gateway},
    runtime_quota::settlement as runtime,
};
use agf_core::{enums::QuotaDimension, error::DomainResult, ids::Id, model::ModelPricing, quota::QuotaConsumption};
use serde_json::json;

fn chain() -> DomainResult<Fixture> {
    let mut f = fixture(864_100)?;
    let charge = f.fact.charge.as_mut().ok_or_else(super::store::missing)?;
    charge.chats = (0..2)
        .map(|ordinal| ChatAnchor {
            usage_id: super::chat_components::usage_id(f.fact.origin.tenant, f.fact.attempt, ordinal),
            endpoint: if ordinal == 0 { charge.endpoint } else { Id::new() },
            provider: agf_core::enums::LlmProvider::OpenAi,
            model: "owned-model".into(),
            pricing: ModelPricing {
                prompt_micro_per_1k: 2000,
                completion_micro_per_1k: 1000,
                cached_prompt_micro_per_1k: 0,
            },
            mocked: false,
            tokens: 20,
            cost: 30,
        })
        .collect();
    let plan = gateway::Plan {
        endpoint: charge.endpoint,
        tokens: 40,
        cost: 60,
        agent: None,
        route: "owned-route".into(),
        route_budget: 0,
        max_total: 0,
    };
    (f.gateway, charge.gateway) =
        gateway::reserve(None, &gateway_quota::Limits::default(), &plan, f.fact.attempt, 864_100)?;
    let estimated = QuotaConsumption { tokens: 40, requests: 1, concurrency: 1, cost_micro: 60 };
    (f.runtime, charge.runtime) = runtime::reserve(
        None,
        &runtime::Reserve {
            tenant: f.fact.origin.tenant,
            agent: None,
            session: &charge.session,
            reservation: f.fact.attempt,
            now: f.fact.submitted_at,
            estimated: &estimated,
            quotas: &f.quotas,
        },
    )?;
    charge.runtime_charged = charge.runtime.charges.iter().map(|row| row.amount).collect();
    f.pending.outcome.components =
        vec![ComponentOutcome { usage_id: charge.chats[1].usage_id, evidence: Evidence::NotSent, usage: None }];
    Ok(f)
}

#[test]
fn unknown_first_provider_and_paid_fallback_charge_both_but_count_one_request() -> DomainResult<()> {
    let mut f = chain()?;
    let anchor = &f.fact.charge.as_ref().ok_or_else(super::store::missing)?.chats[1];
    let mut row = f.pending.outcome.usage.take().ok_or_else(super::store::missing)?;
    row.id = anchor.usage_id;
    row.endpoint_id = anchor.endpoint;
    f.pending.outcome.evidence = Evidence::SentUsageUnknown;
    f.pending.outcome.components[0] =
        ComponentOutcome { usage_id: row.id, evidence: Evidence::SentUsageKnown, usage: Some(row) };
    let next = write(&f.fact, &f.pending, f.gateway.clone(), f.runtime.clone(), 864_101)?;
    assert_eq!(next.gateway.as_ref().map(|row| &row["totals"]), Some(&json!({"tokens":27,"cost":41})));
    let ledger = next.runtime.as_ref().ok_or_else(super::store::missing)?;
    assert_eq!(counter(ledger, &next.fact, QuotaDimension::Requests)?, 1);
    assert_eq!(counter(ledger, &next.fact, QuotaDimension::Concurrency)?, 0);
    assert_eq!(super::components::usage_rows(&f.pending.outcome).count(), 1);
    assert!(matches!(next.fact.charge.as_ref().ok_or_else(super::store::missing)?.state, ChargeState::Conservative));
    let digest = super::codec::hash(&(&next.gateway, &next.runtime))?;
    assert!(matches!(
        reducer::reduce(&next.fact, &f.pending, next.gateway.clone(), next.runtime.clone(), 864_102)?,
        reducer::Decision::Unchanged
    ));
    assert_eq!(super::codec::hash(&(&next.gateway, &next.runtime))?, digest);
    Ok(())
}

#[test]
fn cancelled_partial_below_reservation_keeps_the_estimate_and_actual_lower_bound() -> DomainResult<()> {
    let mut f = chain()?;
    f.pending.outcome.evidence = Evidence::SentUsagePartial;
    f.pending.outcome.rejection =
        Some(Rejection { stage: Stage::Stream, reason: Reason::Cancelled, rule_ids: Vec::new() });
    let next = write(&f.fact, &f.pending, f.gateway, f.runtime, 864_101)?;
    assert_eq!(next.gateway.as_ref().map(|row| &row["totals"]), Some(&json!({"tokens":20,"cost":30})));
    assert_eq!(f.pending.outcome.usage.as_ref().map(|row| row.cost_micro), Some(11));
    assert!(matches!(next.fact.charge.as_ref().ok_or_else(super::store::missing)?.state, ChargeState::Conservative));
    assert_eq!(
        counter(next.runtime.as_ref().ok_or_else(super::store::missing)?, &next.fact, QuotaDimension::Concurrency)?,
        0
    );
    Ok(())
}

#[test]
fn partial_overage_is_never_clamped_and_corrects_only_the_original_cold_bucket() -> DomainResult<()> {
    let mut f = chain()?;
    f.pending.outcome.evidence = Evidence::SentUsagePartial;
    let row = f.pending.outcome.usage.as_mut().ok_or_else(super::store::missing)?;
    row.prompt_tokens = 40;
    row.completion_tokens = 3;
    row.cost_micro = 83;
    let next = write(&f.fact, &f.pending, f.gateway, f.runtime, 900_100)?;
    let charged = next.fact.charge.as_ref().ok_or_else(super::store::missing)?.gateway_charged;
    assert_eq!((charged.tokens, charged.cost), (43, 83));
    let snapshot = next.fact.charge.as_ref().ok_or_else(super::store::missing)?;
    let cost = snapshot
        .runtime
        .charges
        .iter()
        .position(|row| row.dimension == QuotaDimension::Cost)
        .ok_or_else(super::store::missing)?;
    assert_eq!(snapshot.runtime_charged[cost], 83);
    let ledger = next.runtime.as_ref().ok_or_else(super::store::missing)?;
    assert!(ledger["counters"].get(&snapshot.runtime.charges[cost].key).is_none());
    assert_eq!(super::components::usage_rows(&f.pending.outcome).count(), 1);
    Ok(())
}

#[test]
fn forged_component_id_pricing_and_duplicate_outcome_cannot_mutate_candidate_ledgers() -> DomainResult<()> {
    let mut f = chain()?;
    let before = super::codec::hash(&(&f.gateway, &f.runtime))?;
    f.pending.outcome.components[0].usage_id = Id::new();
    assert!(reducer::reduce(&f.fact, &f.pending, Some(f.gateway.clone()), Some(f.runtime.clone()), 864_101).is_err());
    f.pending.outcome.components[0].usage_id =
        f.fact.charge.as_ref().ok_or_else(super::store::missing)?.chats[1].usage_id;
    f.pending.outcome.usage.as_mut().ok_or_else(super::store::missing)?.cost_micro = 0;
    assert!(reducer::reduce(&f.fact, &f.pending, Some(f.gateway.clone()), Some(f.runtime.clone()), 864_101).is_err());
    assert_eq!(super::codec::hash(&(&f.gateway, &f.runtime))?, before);
    Ok(())
}

#[test]
fn old_charge_payload_keeps_its_single_endpoint_semantics_without_fake_chat_anchors() -> DomainResult<()> {
    let f = fixture(864_100)?;
    let mut encoded = serde_json::to_value(f.fact.charge.as_ref().ok_or_else(super::store::missing)?)?;
    encoded.as_object_mut().ok_or_else(super::store::missing)?.remove("chats");
    let restored: ChargeSnapshot = serde_json::from_value(encoded)?;
    assert!(restored.chats.is_empty());
    let next = write(&f.fact, &f.pending, f.gateway, f.runtime, 864_101)?;
    assert_eq!(next.gateway.as_ref().map(|row| &row["totals"]), Some(&json!({"tokens":7,"cost":11})));
    Ok(())
}
