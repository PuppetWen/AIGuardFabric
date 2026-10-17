//! Offline storage obeys the same business idempotency and query-window contract as SQL.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use agf_core::{
    enums::IngestProtocol,
    error::DomainError,
    event::{Event, RawLog},
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_ingest::pipeline::*;

fn guard() -> AgentTeamsBindingGuard {
    AgentTeamsBindingGuard {
        tenant_id: TenantId::default_tenant(),
        source_id: Id::new(),
        binding_id: Id::new(),
        binding_version: 1,
        cloud_config_id: Id::new(),
        cloud_version: 1,
        scope_id: Id::new(),
        source_updated_at: Timestamp::now(),
        inventory_updated_at: Timestamp::now(),
    }
}

fn item(guard: &AgentTeamsBindingGuard, external_id: &str, kind: &str, at: Timestamp) -> AgentTeamsIngestItem {
    let received_at = Timestamp::now();
    let mut event = Event::new(guard.tenant_id, guard.source_id, IngestProtocol::Webhook);
    event.time = at;
    AgentTeamsIngestItem {
        audit: AgentTeamsAuditRecord {
            id: event.id,
            tenant_id: guard.tenant_id,
            scope_id: guard.scope_id,
            source_id: guard.source_id,
            binding_id: guard.binding_id,
            external_event_id: external_id.into(),
            content_hash: "a".repeat(64),
            event_time: at,
            received_at,
            kind: kind.into(),
            from_team: Some("team-a".into()),
            from_worker: Some("worker-a".into()),
            from_asset: None,
            to_team: Some("team-b".into()),
            to_worker: Some("worker-b".into()),
            to_asset: None,
            task_id: None,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            status: "unknown".into(),
            duration_ms: None,
            message_preview: String::new(),
            mocked: false,
        },
        write: IngestWrite {
            raw: RawLog {
                id: Id::new(),
                tenant_id: guard.tenant_id,
                source_id: guard.source_id,
                received_at,
                protocol: IngestProtocol::Webhook,
                payload_b64: "e30=".into(),
                payload_hash: "fixture".into(),
                bytes: 2,
                origin: "agentteams-memory-test".into(),
                parsed: true,
                parse_error: None,
                event_id: Some(event.id),
            },
            event: Some(event),
        },
    }
}

fn query(guard: &AgentTeamsBindingGuard, from: Timestamp, until: Timestamp, limit: usize) -> AgentTeamsAuditQuery {
    AgentTeamsAuditQuery { tenant_id: guard.tenant_id, scope_id: guard.scope_id, from, until, before: None, limit }
}

#[tokio::test]
async fn competing_senders_and_cross_source_retries_store_one_event_and_conflicts_roll_back() {
    let sink = InMemorySink::new();
    let first_guard = guard();
    let at = Timestamp::now().offset_secs(-1);
    let one = item(&first_guard, "business-one", "call", at);
    let retry = item(&first_guard, "business-one", "call", at);
    let (first, second) = tokio::join!(
        sink.persist_agentteams(&first_guard, std::slice::from_ref(&one)),
        sink.persist_agentteams(&first_guard, std::slice::from_ref(&retry)),
    );
    assert_eq!(first.unwrap(), AgentTeamsIngestResult { accepted: 1, deduped: 0 });
    assert_eq!(second.unwrap(), AgentTeamsIngestResult { accepted: 0, deduped: 1 });

    let mut other_source = first_guard.clone();
    other_source.source_id = Id::new();
    other_source.binding_id = Id::new();
    let cross_source_retry = item(&other_source, "business-one", "call", at);
    assert_eq!(sink.persist_agentteams(&other_source, &[cross_source_retry]).await.unwrap().deduped, 1);
    let fresh = item(&first_guard, "fresh", "message", at);
    let mut conflict = item(&first_guard, "business-one", "call", at);
    conflict.audit.content_hash = "b".repeat(64);
    assert!(matches!(
        sink.persist_agentteams(&first_guard, &[fresh.clone(), conflict]).await,
        Err(DomainError::Conflict(_))
    ));
    assert_eq!(sink.raw_count(first_guard.tenant_id).await.unwrap(), 1);
    assert_eq!(sink.event_count(first_guard.tenant_id).await.unwrap(), 1);
    assert_eq!(sink.persist_agentteams(&first_guard, &[fresh]).await.unwrap().accepted, 1);
    assert_eq!(sink.raw_count(first_guard.tenant_id).await.unwrap(), 2);
}

#[tokio::test]
async fn pages_do_not_limit_metrics_and_event_window_tenant_scope_and_source_observations_are_exact() {
    let sink = InMemorySink::new();
    let first = guard();
    let until = Timestamp::now();
    let from = until.offset_secs(-86_400);
    let mut items: Vec<_> =
        (0..25).map(|i| item(&first, &format!("call-{i}"), "call", until.offset_secs(-1))).collect();
    items.extend([
        item(&first, "on-left-boundary", "call", from),
        item(&first, "outside-left", "call", from.offset_secs(-1)),
        item(&first, "on-right-boundary", "call", until),
        item(&first, "message", "message", until.offset_secs(-2)),
        item(&first, "task", "task", until.offset_secs(-2)),
        item(&first, "heartbeat", "heartbeat", until.offset_secs(-2)),
    ]);
    sink.persist_agentteams(&first, &items).await.unwrap();
    let mut second = first.clone();
    second.source_id = Id::new();
    second.binding_id = Id::new();
    let second_items = [
        item(&second, "second-source-call", "call", until.offset_secs(-3)),
        item(&second, "second-source-heartbeat", "heartbeat", until.offset_secs(-3)),
    ];
    sink.persist_agentteams(&second, &second_items).await.unwrap();
    let mut page_query = query(&first, from, until, 2);
    let first_page = sink.agentteams_audit_records(&page_query).await.unwrap();
    assert_eq!(first_page.len(), 2);
    let last = first_page.last().unwrap();
    page_query.before = Some(AgentTeamsAuditCursor { event_time: last.event_time, id: last.id });
    let second_page = sink.agentteams_audit_records(&page_query).await.unwrap();
    assert!(second_page.iter().all(|row| !first_page.iter().any(|first| first.id == row.id)));
    let totals = sink.agentteams_audit_aggregate(first.tenant_id, first.scope_id, from, until).await.unwrap();
    assert_eq!((totals.invocations, totals.messages, totals.tasks, totals.heartbeats), (27, 1, 1, 2));
    assert_eq!(totals.workers.len(), 1);
    assert_eq!(totals.workers[0].worker, "worker-b");
    assert_eq!(totals.workers[0].invocations, 27, "callee is counted once per call");
    assert_eq!(totals.cross_team_calls[0].count, 27);
    assert_eq!(totals.sources.len(), 2);
    for expected in [&first, &second] {
        let observation = totals.sources.iter().find(|source| source.source_id == expected.source_id).unwrap();
        let source_items = if expected.source_id == first.source_id { &items[..] } else { &second_items[..] };
        let window_items: Vec<_> =
            source_items.iter().filter(|item| item.audit.event_time >= from && item.audit.event_time < until).collect();
        assert_eq!(
            observation.first_received_at,
            window_items.iter().map(|item| item.audit.received_at).min().unwrap()
        );
        assert_eq!(observation.last_received_at, window_items.iter().map(|item| item.audit.received_at).max().unwrap());
        assert_eq!(
            observation.last_heartbeat_at,
            window_items.iter().filter(|item| item.audit.kind == "heartbeat").map(|item| item.audit.received_at).max()
        );
    }
    let foreign = sink.agentteams_audit_aggregate(TenantId::new(), first.scope_id, from, until).await.unwrap();
    assert_eq!(foreign.invocations, 0);
    assert_eq!(sink.agentteams_audit_aggregate(first.tenant_id, Id::new(), from, until).await.unwrap().invocations, 0);
    let mut other_scope = first.clone();
    other_scope.scope_id = Id::new();
    assert_eq!(
        sink.persist_agentteams(&other_scope, &[item(&other_scope, "call-0", "call", until.offset_secs(-1))])
            .await
            .unwrap()
            .accepted,
        1
    );
    assert_eq!(
        sink.agentteams_audit_aggregate(first.tenant_id, first.scope_id, from, until).await.unwrap().invocations,
        27
    );
}

#[tokio::test]
async fn invalid_later_item_cannot_partially_commit_evidence_or_audit() {
    let sink = InMemorySink::new();
    let guard = guard();
    let at = Timestamp::now().offset_secs(-1);
    let good = item(&guard, "good", "call", at);
    let mut bad = item(&guard, "bad", "message", at);
    bad.write.event.as_mut().unwrap().tenant_id = TenantId::new();
    assert!(sink.persist_agentteams(&guard, &[good, bad]).await.is_err());
    assert_eq!(sink.raw_count(guard.tenant_id).await.unwrap(), 0);
    assert_eq!(sink.event_count(guard.tenant_id).await.unwrap(), 0);
    assert!(
        sink.agentteams_audit_records(&query(&guard, at.offset_secs(-1), at.offset_secs(1), 200))
            .await
            .unwrap()
            .is_empty()
    );
    assert!(sink.agentteams_audit_records(&query(&guard, at.offset_secs(-1), at.offset_secs(1), 201)).await.is_err());
}
