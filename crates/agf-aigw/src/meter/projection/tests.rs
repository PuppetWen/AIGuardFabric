use super::*;

fn row(tenant: TenantId, session: &str, model: &str, fee: u64) -> UsageRecord {
    UsageRecord {
        id: Id::new(),
        tenant_id: tenant,
        session_id: session.into(),
        agent_id: None,
        endpoint_id: Id::new(),
        provider: LlmProvider::OpenAi,
        model: model.into(),
        prompt_tokens: 3,
        completion_tokens: 2,
        cached_tokens: 0,
        cache_write_tokens: 0,
        cache_write_1h_tokens: 0,
        cache_hit: false,
        cost_micro: fee,
        mocked: false,
        latency_ms: 1,
        at: Timestamp::now(),
    }
}

#[test]
fn restart_replay_and_out_of_order_projection_preserve_exact_totals() -> DomainResult<()> {
    let tenant = TenantId::default_tenant();
    let first = CommittedMeterProjection::new(tenant)?.append(&[row(tenant, "session", "chat", 10)])?;
    let second = first.append(&[row(tenant, "session", "embedding", 2)])?;
    let meter = Meter::new();
    assert!(meter.absorb_committed_projection(&second)?);
    assert!(!meter.absorb_committed_projection(&first)?);
    assert!(!meter.absorb_committed_projection(&second)?);
    assert_eq!(meter.snapshot().total.calls, 2);
    assert_eq!(meter.snapshot().total.cost_micro, 12);
    let restarted = Meter::new();
    let durable = serde_json::from_value(serde_json::to_value(&second)?)?;
    assert!(restarted.absorb_committed_projection(&durable)?);
    assert_eq!(restarted.snapshot().total, meter.snapshot().total);
    let mut conflicting = second.clone();
    conflicting.recent[0].latency_ms += 1;
    assert!(matches!(meter.absorb_committed_projection(&conflicting), Err(DomainError::Conflict(_))));
    assert_eq!(meter.snapshot().total.cost_micro, 12);
    Ok(())
}

#[test]
fn group_overflow_merges_display_only_and_keeps_legacy_and_tenant_fees() -> DomainResult<()> {
    let tenant = TenantId::default_tenant();
    let mut projection = CommittedMeterProjection::new(tenant)?;
    for n in 0..70 {
        projection = projection.append(&[row(tenant, &format!("session{n}"), &format!("model{n}"), 10)])?;
    }
    assert_eq!(projection.by_session.len(), 33);
    assert_eq!(projection.by_model.len(), 33);
    assert_eq!(projection.recent.len(), 16);
    let meter = Meter::new();
    let endpoint = crate::meter::tests::endpoint(crate::meter::tests::paid_pricing());
    let legacy = meter.record(tenant, "legacy", None, &endpoint, Usage::new(1000, 500, 0), false, false, 1);
    assert!(meter.absorb_committed_projection(&projection)?);
    assert_eq!(meter.snapshot().total.cost_micro, legacy.cost_micro + 700);
    assert!(meter.snapshot().committed_groups_merged);
    let other = TenantId::from_uuid(Id::new().as_uuid());
    let another = CommittedMeterProjection::new(other)?.append(&[row(other, "other", "chat", 5)])?;
    assert!(meter.absorb_committed_projection(&another)?);
    assert_eq!(meter.snapshot().total.cost_micro, legacy.cost_micro + 705);
    assert!(!meter.absorb_committed_projection(&projection)?);
    assert_eq!(meter.snapshot().total.cost_micro, legacy.cost_micro + 705);
    Ok(())
}

#[test]
fn overflowing_revision_or_fee_and_foreign_rows_do_not_change_original_checkpoint() -> DomainResult<()> {
    let tenant = TenantId::default_tenant();
    let original = CommittedMeterProjection::new(tenant)?.append(&[row(tenant, "s", "m", u64::MAX)])?;
    let before = serde_json::to_value(&original)?;
    assert!(original.append(&[row(tenant, "s", "m", 1)]).is_err());
    assert_eq!(serde_json::to_value(&original)?, before);
    let mut max = CommittedMeterProjection::new(tenant)?;
    max.revision = u64::MAX;
    assert!(max.append(&[]).is_err());
    assert_eq!(max.revision, u64::MAX);
    let other = TenantId::from_uuid(Id::new().as_uuid());
    assert!(original.append(&[row(other, "s", "m", 0)]).is_err());
    let meter = Meter::new();
    let mut corrupt = original;
    corrupt.total.cost_micro = 0;
    assert!(meter.absorb_committed_projection(&corrupt).is_err());
    assert_eq!(meter.snapshot().total.calls, 0);
    Ok(())
}

#[test]
fn tenant_capacity_refuses_new_projection_without_evicting_old_exact_totals() -> DomainResult<()> {
    let meter = Meter::new();
    let mut first = None;
    for _ in 0..TENANTS {
        let tenant = TenantId::from_uuid(Id::new().as_uuid());
        let checkpoint = CommittedMeterProjection::new(tenant)?.append(&[row(tenant, "s", "m", 1)])?;
        meter.absorb_committed_projection(&checkpoint)?;
        first.get_or_insert(checkpoint);
    }
    let extra = TenantId::from_uuid(Id::new().as_uuid());
    assert!(
        meter
            .absorb_committed_projection(&CommittedMeterProjection::new(extra)?.append(&[row(extra, "s", "m", 2)])?)
            .is_err()
    );
    assert!(meter.snapshot().committed_projection_incomplete);
    assert_eq!(meter.snapshot().total.cost_micro, u64::try_from(TENANTS).map_err(|_| invalid())?);
    assert!(!meter.absorb_committed_projection(&first.ok_or_else(invalid)?)?);
    Ok(())
}

#[test]
fn bounded_legacy_dedup_refuses_growth_but_never_recharges_an_evicted_identity() -> DomainResult<()> {
    let meter = Meter::new();
    let tenant = TenantId::default_tenant();
    let original = row(tenant, "s", "m", 7);
    meter.absorb_once(&original)?;
    {
        let mut inner = meter.inner.lock();
        while inner.seen.len() < 65_536 {
            inner.seen.insert((tenant, Id::new()), "synthetic-capacity-entry".into());
        }
    }
    assert!(!meter.absorb_once(&original)?);
    assert!(meter.absorb_once(&row(tenant, "s", "m", 9)).is_err());
    assert_eq!(meter.snapshot().total.cost_micro, 7);
    assert_eq!(meter.snapshot().total.calls, 1);
    assert!(meter.snapshot().committed_projection_incomplete);
    Ok(())
}

#[test]
fn escaped_legal_display_keys_fit_encoded_budget_without_losing_exact_usage() -> DomainResult<()> {
    let tenant = TenantId::default_tenant();
    let mut checkpoint = CommittedMeterProjection::new(tenant)?;
    for n in 0..70 {
        // JSON expands each control byte sixfold; both inputs remain exactly 256 UTF-8 bytes.
        let key = format!("{n:03}{}", "\u{0001}".repeat(253));
        let mut usage = row(tenant, &key, &key, 2);
        usage.agent_id = Some(Id::new());
        checkpoint = checkpoint.append(&[usage])?;
        assert!(serde_json::to_vec(&checkpoint)?.len() <= MAX_ENCODED);
        assert_eq!(checkpoint.total.calls, n + 1);
        assert_eq!(checkpoint.total.cost_micro, (n + 1) * 2);
    }
    assert!(checkpoint.grouped);
    assert_eq!(checkpoint.by_model.values().map(|row| row.cost_micro).sum::<u64>(), 140);
    let restored: CommittedMeterProjection = serde_json::from_slice(&serde_json::to_vec(&checkpoint)?)?;
    let meter = Meter::new();
    assert!(meter.absorb_committed_projection(&restored)?);
    assert_eq!(meter.snapshot().total.cost_micro, 140);
    assert!(!meter.absorb_committed_projection(&restored)?);
    assert_eq!(meter.snapshot().total.calls, 70);
    Ok(())
}
