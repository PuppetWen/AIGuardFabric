//! A stable committed UUID is the common hydration/publication deduplication boundary.
use super::*;

#[test]
fn pure_deferred_creation_does_not_change_any_meter_projection() -> DomainResult<()> {
    let meter = Meter::new();
    let endpoint = tests::endpoint(tests::paid_pricing());
    let id = Id::new();
    let record = Meter::record_deferred(UsageInput {
        id,
        tenant: endpoint.tenant_id,
        session_id: "owned-session",
        agent_id: None,
        endpoint: &endpoint,
        usage: Usage::new(1000, 500, 0),
        cache_hit: false,
        mocked: false,
        latency_ms: 3,
    })?;
    assert_eq!(record.id, id);
    assert_eq!(record.cost_micro, 6000);
    assert_eq!(meter.snapshot().total.calls, 0);
    assert_eq!(meter.snapshot().total.cost_micro, 0);
    assert!(meter.absorb_once(&record)?);
    assert!(!meter.absorb_once(&record)?);
    assert_eq!(meter.snapshot().total.calls, 1);
    assert_eq!(meter.snapshot().total.cost_micro, 6000);
    Ok(())
}
#[test]
fn restart_hydration_and_same_uuid_publication_do_not_double_count() -> DomainResult<()> {
    let endpoint = tests::endpoint(tests::paid_pricing());
    let original = Meter::new();
    let row = Meter::record_deferred(UsageInput {
        id: Id::new(),
        tenant: endpoint.tenant_id,
        session_id: "session",
        agent_id: Some(Id::new()),
        endpoint: &endpoint,
        usage: Usage::new(1000, 500, 0),
        cache_hit: false,
        mocked: false,
        latency_ms: 5,
    })?;
    assert!(original.absorb_once(&row)?);
    let restarted = Meter::new();
    let durable: UsageRecord = serde_json::from_value(serde_json::to_value(&row)?)?;
    assert!(restarted.absorb_once(&durable)?);
    assert!(!restarted.absorb_once(&row)?);
    assert_eq!(restarted.snapshot().total, original.snapshot().total);
    let before = serde_json::to_value(restarted.snapshot())?;
    let mut changed = row;
    changed.cost_micro += 1;
    assert!(matches!(restarted.absorb_once(&changed), Err(DomainError::Conflict(_))));
    let after = restarted.snapshot();
    assert_eq!(serde_json::to_value(after.total)?, before["total"]);
    Ok(())
}
#[test]
fn local_hits_and_mock_keep_logical_tokens_but_never_paid_cost() -> DomainResult<()> {
    let endpoint = tests::endpoint(tests::paid_pricing());
    for (hit, mocked) in [(true, false), (false, true)] {
        let row = Meter::record_deferred(UsageInput {
            id: Id::new(),
            tenant: endpoint.tenant_id,
            session_id: "session",
            agent_id: None,
            endpoint: &endpoint,
            usage: Usage::new(1000, 500, 400),
            cache_hit: hit,
            mocked,
            latency_ms: 1,
        })?;
        assert_eq!(row.prompt_tokens, 1000);
        assert_eq!(row.completion_tokens, 500);
        assert_eq!(row.cost_micro, 0);
        let meter = Meter::new();
        assert!(meter.absorb_once(&row)?);
        assert_eq!(meter.snapshot().total.total_tokens(), 1500);
        assert_eq!(meter.snapshot().total.calls, 1);
    }
    Ok(())
}
#[test]
fn foreign_tenant_or_nil_usage_id_cannot_form_a_deferred_record() {
    let endpoint = tests::endpoint(tests::paid_pricing());
    for (id, tenant) in [(Id::nil(), endpoint.tenant_id), (Id::new(), TenantId::from_uuid(Id::new().as_uuid()))] {
        assert!(
            Meter::record_deferred(UsageInput {
                id,
                tenant,
                session_id: "s",
                agent_id: None,
                endpoint: &endpoint,
                usage: Usage::new(1, 1, 0),
                cache_hit: false,
                mocked: false,
                latency_ms: 1
            })
            .is_err()
        );
    }
}
