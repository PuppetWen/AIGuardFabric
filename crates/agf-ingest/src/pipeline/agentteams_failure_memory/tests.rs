use super::*;
use serde_json::json;
fn row(tenant: TenantId, scope: Id, source: Id, index: usize, at: Timestamp) -> DomainResult<AgentTeamsAuditRecord> {
    let external = format!("owned-error-{index}");
    let id = agf_core::ids::deterministic_id("agf.agentteams.event", &format!("{tenant}:{scope}:{external}"));
    Ok(serde_json::from_value(json!({"id":id,"tenant_id":tenant,"scope_id":scope,"source_id":source,
        "binding_id":Id::new(),"external_event_id":external,"content_hash":"a".repeat(64),
        "event_time":at,"received_at":at,"kind":"task","from_team":"team","from_worker":"worker",
        "from_asset":Id::new(),"to_team":null,"to_worker":null,"to_asset":null,
        "task_id":"task","trace_id":null,"span_id":null,"parent_span_id":null,
        "status":"error","duration_ms":null,"message_preview":"private-opaque-collector-field","mocked":true}))?)
}
fn query(tenant: TenantId, at: Timestamp) -> AgentTeamsFailureQuery {
    AgentTeamsFailureQuery {
        tenant_id: tenant,
        source_id: None,
        scope_id: None,
        from: at.offset_secs(-1),
        until: at.offset_secs(1),
        received_until: at,
    }
}
#[test]
fn full_total_and_newest_bounded_rows_share_the_original_memory_snapshot() -> DomainResult<()> {
    let tenant = TenantId::new();
    let scope = Id::new();
    let source = Id::new();
    let at = Timestamp::now();
    let mut state = MemoryState::default();
    for index in 0..2001 {
        let row = row(tenant, scope, source, index, at)?;
        state.agentteams.insert((tenant, scope, row.external_event_id.clone()), row);
    }
    let result = snapshot(&state, &query(tenant, at))?;
    assert_eq!(result.total, 2001);
    assert_eq!(result.records.len(), 2000);
    assert!(result.truncated);
    assert!(result.records.windows(2).all(|pair| pair[0].id > pair[1].id));
    assert!(snapshot(&state, &query(TenantId::new(), at))?.records.is_empty());
    Ok(())
}
#[test]
fn strict_error_filter_and_source_scope_receive_watermarks_are_not_inferred() -> DomainResult<()> {
    let tenant = TenantId::new();
    let scope = Id::new();
    let source = Id::new();
    let at = Timestamp::now();
    let mut state = MemoryState::default();
    for (index, status) in [(0, "error"), (1, "unknown"), (2, "success")] {
        let mut row = row(tenant, scope, source, index, at)?;
        row.status = status.into();
        state.agentteams.insert((tenant, scope, row.external_event_id.clone()), row);
    }
    let mut input = query(tenant, at);
    let result = snapshot(&state, &input)?;
    assert_eq!(result.total, 1);
    input.source_id = Some(Id::new());
    assert_eq!(snapshot(&state, &input)?.total, 0);
    input.source_id = Some(source);
    input.scope_id = Some(Id::new());
    assert_eq!(snapshot(&state, &input)?.total, 0);
    input.scope_id = Some(scope);
    input.received_until = at.offset_secs(-1);
    assert_eq!(snapshot(&state, &input)?.total, 0);
    input.until = at.offset_secs(60);
    input.from = input.until.offset_secs(-30 * 86_400 - 1);
    assert!(snapshot(&state, &input).is_err());
    Ok(())
}
#[test]
fn column_payload_identity_disagreement_and_forged_original_ids_fail_closed() -> DomainResult<()> {
    let tenant = TenantId::new();
    let scope = Id::new();
    let source = Id::new();
    let at = Timestamp::now();
    let original = row(tenant, scope, source, 0, at)?;
    let mut envelope = json!({"id":original.id,"tenant_id":tenant,"scope_id":scope,"source_id":source,
        "binding_id":original.binding_id,"external_event_id":original.external_event_id,"content_hash":original.content_hash,
        "event_time":at,"received_at":at,"kind":"task","payload":original});
    assert_eq!(agentteams_failure_from_envelope(envelope.clone(), tenant)?.id, original.id);
    envelope["source_id"] = json!(Id::new());
    assert!(agentteams_failure_from_envelope(envelope, tenant).is_err());
    let mut forged = original;
    forged.id = Id::new();
    assert!(validate_agentteams_failure_record(&forged, tenant).is_err());
    Ok(())
}
