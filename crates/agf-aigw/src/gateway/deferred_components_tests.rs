//! The same safe journal used by real providers: stable identities, partial lower bounds and no repeat entry.
use super::{deferred_components::ComponentJournal, tests::endpoint, *};

fn journal(endpoints: &[ModelEndpoint]) -> DomainResult<ComponentJournal> {
    ComponentJournal::new(
        endpoints.iter().map(|row| DeferredComponentAnchor { usage_id: Id::new(), endpoint_id: row.id }).collect(),
    )
}
fn input(endpoint: &ModelEndpoint, usage: Usage) -> crate::meter::UsageInput<'_> {
    crate::meter::UsageInput {
        id: Id::new(),
        tenant: endpoint.tenant_id,
        session_id: "owned-session",
        agent_id: None,
        endpoint,
        usage,
        cache_hit: false,
        mocked: false,
        latency_ms: 1,
    }
}

#[test]
fn physically_entered_unknown_can_fall_back_once_with_independent_usage_identity() -> DomainResult<()> {
    let left = endpoint("left", LlmProvider::OpenAi, false, true, Some(Id::new()));
    let right = endpoint("right", LlmProvider::OpenAi, false, true, Some(Id::new()));
    let journal = journal(&[left.clone(), right.clone()])?;
    let original = journal.anchors();
    journal.entered(left.id)?;
    assert!(journal.entered(left.id).is_err());
    journal.entered(right.id)?;
    journal.observe(input(&right, Usage::new(4, 3, 0)), true)?;
    let rows = journal.snapshot();
    assert!(matches!(rows[0].evidence, DeferredEvidence::SentUsageUnknown));
    assert!(rows[0].usage.is_none());
    assert!(matches!(rows[1].evidence, DeferredEvidence::SentUsageKnown));
    assert_eq!(rows[1].usage.as_ref().map(|row| row.id), Some(original[1].usage_id));
    assert_ne!(original[0].usage_id, original[1].usage_id);
    assert!(journal.entered(right.id).is_err());
    assert!(journal.entered(left.id).is_err());
    Ok(())
}

#[test]
fn partial_usage_cannot_be_lowered_or_used_to_start_another_provider() -> DomainResult<()> {
    let left = endpoint("left", LlmProvider::OpenAi, false, true, Some(Id::new()));
    let right = endpoint("right", LlmProvider::OpenAi, false, true, Some(Id::new()));
    let journal = journal(&[left.clone(), right.clone()])?;
    journal.entered(left.id)?;
    journal.observe(input(&left, Usage::new(40, 3, 0)), false)?;
    assert!(journal.observe(input(&left, Usage::new(4, 3, 0)), false).is_err());
    assert!(journal.entered(right.id).is_err());
    let rows = journal.snapshot();
    assert!(matches!(rows[0].evidence, DeferredEvidence::SentUsagePartial));
    assert_eq!(rows[0].usage.as_ref().map(|row| row.prompt_tokens), Some(40));
    assert!(matches!(rows[1].evidence, DeferredEvidence::NotSent));
    journal.observe(input(&left, Usage::new(40, 4, 0)), true)?;
    assert!(matches!(journal.snapshot()[0].evidence, DeferredEvidence::SentUsageKnown));
    Ok(())
}

#[test]
fn component_bound_duplicate_endpoint_and_out_of_order_entry_fail_closed() -> DomainResult<()> {
    let anchors = (0..MAX_CHAT_COMPONENTS)
        .map(|_| DeferredComponentAnchor { usage_id: Id::new(), endpoint_id: Id::new() })
        .collect::<Vec<_>>();
    let journal = ComponentJournal::new(anchors.clone())?;
    journal.entered(anchors[7].endpoint_id)?;
    assert!(journal.entered(anchors[0].endpoint_id).is_err());
    let mut oversized = anchors.clone();
    oversized.push(DeferredComponentAnchor { usage_id: Id::new(), endpoint_id: Id::new() });
    assert!(ComponentJournal::new(oversized).is_err());
    let mut repeated = anchors;
    repeated[1].endpoint_id = repeated[0].endpoint_id;
    assert!(ComponentJournal::new(repeated).is_err());
    assert!(ComponentJournal::new(Vec::new()).is_err());
    Ok(())
}
