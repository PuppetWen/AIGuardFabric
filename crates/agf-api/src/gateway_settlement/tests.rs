//! These call the owner reducers; expected balances are independently computed from business input.
use super::{codec, records::*, reducer, tests_fixture::*};
use agf_core::{
    enums::QuotaDimension,
    error::{DomainError, DomainResult},
};
use serde_json::{Value, json};

#[test]
fn actual_usage_settles_both_ledgers_once_and_releases_concurrency() -> DomainResult<()> {
    let f = fixture(864_100)?;
    let next = write(&f.fact, &f.pending, f.gateway, f.runtime, 864_101)?;
    let gateway = next.gateway.ok_or_else(|| DomainError::Internal("gateway".into()))?;
    let runtime = next.runtime.ok_or_else(|| DomainError::Internal("runtime".into()))?;
    assert_eq!(gateway["totals"], json!({"tokens":7,"cost":11}));
    for (dimension, expected) in [
        (QuotaDimension::Tokens, 7),
        (QuotaDimension::Requests, 1),
        (QuotaDimension::Concurrency, 0),
        (QuotaDimension::Cost, 11),
    ] {
        assert_eq!(counter(&runtime, &next.fact, dimension)?, expected);
    }
    assert_eq!(gateway["reservations"], json!({}));
    assert_eq!(runtime["reservations"], json!({}));
    assert!(matches!(
        reducer::reduce(&next.fact, &f.pending, Some(gateway.clone()), Some(runtime.clone()), 864_102)?,
        reducer::Decision::Unchanged
    ));
    let mut different = f.pending.clone();
    different.outcome.usage.as_mut().ok_or_else(|| DomainError::Internal("usage".into()))?.cost_micro = 12;
    assert!(matches!(
        reducer::reduce(&next.fact, &different, Some(gateway), Some(runtime), 864_102),
        Err(DomainError::Conflict(_))
    ));
    Ok(())
}
#[test]
fn unknown_sent_usage_keeps_original_estimate_and_one_request() -> DomainResult<()> {
    let mut f = fixture(864_100)?;
    f.pending.outcome.usage = None;
    f.pending.outcome.evidence = Evidence::SentUsageUnknown;
    let next = write(&f.fact, &f.pending, f.gateway, f.runtime, 864_101)?;
    assert_eq!(next.gateway.as_ref().map(|row| &row["totals"]), Some(&json!({"tokens":20,"cost":30})));
    let runtime = next.runtime.ok_or_else(|| DomainError::Internal("runtime".into()))?;
    assert_eq!(counter(&runtime, &next.fact, QuotaDimension::Requests)?, 1);
    assert_eq!(counter(&runtime, &next.fact, QuotaDimension::Concurrency)?, 0);
    Ok(())
}
#[test]
fn not_sent_refunds_reservation_without_counting_a_model_request() -> DomainResult<()> {
    let mut f = fixture(864_100)?;
    f.pending.outcome.usage = None;
    f.pending.outcome.evidence = Evidence::NotSent;
    let next = write(&f.fact, &f.pending, f.gateway, f.runtime, 864_101)?;
    assert_eq!(next.gateway.as_ref().map(|row| &row["totals"]), Some(&json!({"tokens":0,"cost":0})));
    let runtime = next.runtime.ok_or_else(|| DomainError::Internal("runtime".into()))?;
    for dimension in
        [QuotaDimension::Tokens, QuotaDimension::Requests, QuotaDimension::Concurrency, QuotaDimension::Cost]
    {
        assert_eq!(counter(&runtime, &next.fact, dimension)?, 0);
    }
    Ok(())
}
#[test]
fn exact_cache_reply_counts_logical_tokens_and_request_with_zero_paid_fee() -> DomainResult<()> {
    let mut f = fixture(864_100)?;
    f.pending.outcome.evidence = Evidence::LocalReply;
    let usage = f.pending.outcome.usage.as_mut().ok_or_else(|| DomainError::Internal("usage".into()))?;
    usage.cache_hit = true;
    usage.cost_micro = 0;
    let next = write(&f.fact, &f.pending, f.gateway, f.runtime, 864_101)?;
    assert_eq!(next.gateway.as_ref().map(|row| &row["totals"]), Some(&json!({"tokens":7,"cost":0})));
    let runtime = next.runtime.ok_or_else(|| DomainError::Internal("runtime".into()))?;
    assert_eq!(counter(&runtime, &next.fact, QuotaDimension::Tokens)?, 7);
    assert_eq!(counter(&runtime, &next.fact, QuotaDimension::Requests)?, 1);
    assert_eq!(counter(&runtime, &next.fact, QuotaDimension::Cost)?, 0);
    Ok(())
}
#[test]
fn expiry_releases_concurrency_and_late_actual_corrects_original_charge_once() -> DomainResult<()> {
    let f = fixture(864_100)?;
    let reducer::Decision::Write(conservative) = reducer::conservative(&f.fact, f.gateway, f.runtime, 865_000)? else {
        return Err(DomainError::Internal("conservative".into()));
    };
    let gateway = conservative.gateway.clone().ok_or_else(|| DomainError::Internal("gateway".into()))?;
    let runtime = conservative.runtime.clone().ok_or_else(|| DomainError::Internal("runtime".into()))?;
    assert_eq!(gateway["totals"], json!({"tokens":20,"cost":30}));
    assert_eq!(counter(&runtime, &conservative.fact, QuotaDimension::Concurrency)?, 0);
    assert!(matches!(
        reducer::conservative(&conservative.fact, gateway.clone(), runtime.clone(), 865_001)?,
        reducer::Decision::Unchanged
    ));
    let next = write(&conservative.fact, &f.pending, gateway, runtime, 865_002)?;
    assert_eq!(next.gateway.as_ref().map(|row| &row["totals"]), Some(&json!({"tokens":7,"cost":11})));
    let charged = next.fact.charge.as_ref().ok_or_else(|| DomainError::Internal("charge".into()))?;
    assert!(charged.state == ChargeState::Actual);
    assert_eq!(charged.gateway_charged.cost, 11);
    Ok(())
}
#[test]
fn expired_old_bucket_correction_never_refunds_the_new_bucket() -> DomainResult<()> {
    use crate::{
        gateway_quota::{self, settlement as gateway},
        runtime_quota::settlement as runtime,
    };
    use agf_core::{ids::Id, quota::QuotaConsumption, time::Timestamp};
    let f = fixture(86390)?;
    let reducer::Decision::Write(old) = reducer::conservative(&f.fact, f.gateway, f.runtime, 87290)? else {
        return Err(DomainError::Internal("conservative".into()));
    };
    let id = Id::new();
    let now = Timestamp::from_unix_secs(90000).map_err(DomainError::Validation)?;
    let plan = gateway::Plan {
        tokens: 50,
        cost: 60,
        endpoint: Id::new(),
        agent: None,
        route: "owned-route".into(),
        route_budget: 0,
        max_total: 0,
    };
    let (gateway, anchor) = gateway::reserve(old.gateway, &gateway_quota::Limits::default(), &plan, id, 90000)?;
    let (runtime, new_anchor) = runtime::reserve(
        old.runtime,
        &runtime::Reserve {
            tenant: f.fact.origin.tenant,
            agent: None,
            session: "owned-session",
            reservation: id,
            now,
            estimated: &QuotaConsumption { tokens: 50, requests: 1, concurrency: 1, cost_micro: 60 },
            quotas: &f.quotas,
        },
    )?;
    let original_new_runtime = runtime.clone();
    let next = write(&old.fact, &f.pending, gateway, runtime, 90001)?;
    assert_eq!(next.gateway.as_ref().map(|row| &row["totals"]), Some(&json!({"tokens":0,"cost":0})));
    assert_eq!(
        next.gateway.as_ref().map(|row| &row["reservations"][anchor.attempt.to_string()]),
        Some(
            &json!({"expires":90900,"tokens":50,"cost":60,"agent":"unassigned","route":"owned-route","atomic_day":1,"atomic_hour":25})
        )
    );
    let runtime = next.runtime.ok_or_else(|| DomainError::Internal("runtime".into()))?;
    for charge in new_anchor.charges {
        assert_eq!(runtime["counters"][&charge.key], original_new_runtime["counters"][&charge.key]);
    }
    assert_eq!(next.fact.charge.as_ref().map(|row| row.gateway_charged.cost), Some(11));
    Ok(())
}
#[test]
fn early_maintenance_is_rejected_and_original_values_remain_unchanged() -> DomainResult<()> {
    let f = fixture(864_100)?;
    let before = codec::hash(&(&f.fact, &f.gateway, &f.runtime))?;
    assert!(reducer::conservative(&f.fact, f.gateway.clone(), f.runtime.clone(), 864_999).is_err());
    assert_eq!(codec::hash(&(&f.fact, &f.gateway, &f.runtime))?, before);
    Ok(())
}
#[test]
fn altered_identity_usage_or_anchor_cannot_settle_either_ledger() -> DomainResult<()> {
    let f = fixture(864_100)?;
    let before = codec::hash(&(&f.gateway, &f.runtime))?;
    for field in ["subject", "usage_id", "endpoint", "expires"] {
        let mut pending = f.pending.clone();
        let mut fact = f.fact.clone();
        match field {
            "subject" => pending.origin.subject = agf_core::ids::Id::new(),
            "usage_id" => {
                pending.outcome.usage.as_mut().ok_or_else(|| DomainError::Internal("usage".into()))?.id =
                    agf_core::ids::Id::new();
            }
            "endpoint" => {
                pending.outcome.usage.as_mut().ok_or_else(|| DomainError::Internal("usage".into()))?.endpoint_id =
                    agf_core::ids::Id::new();
            }
            _ => fact.charge.as_mut().ok_or_else(|| DomainError::Internal("charge".into()))?.gateway.expires = i64::MIN,
        }
        assert!(
            reducer::reduce(&fact, &pending, Some(f.gateway.clone()), Some(f.runtime.clone()), 864_101).is_err(),
            "{field}"
        );
    }
    assert_eq!(codec::hash(&(&f.gateway, &f.runtime))?, before);
    Ok(())
}
#[test]
fn missing_or_foreign_reservation_cannot_produce_a_candidate() -> DomainResult<()> {
    let f = fixture(864_100)?;
    let mut missing = f.gateway.clone();
    missing["reservations"] = json!({});
    assert!(reducer::reduce(&f.fact, &f.pending, Some(missing), Some(f.runtime.clone()), 864_101).is_err());
    let mut foreign = f.runtime;
    foreign["reservations"][f.fact.attempt.to_string()]["owner"] = Value::String("legacy-mcp".into());
    assert!(reducer::reduce(&f.fact, &f.pending, Some(f.gateway), Some(foreign), 864_101).is_err());
    Ok(())
}
