//! Isolated PostgreSQL verifies guarded AgentTeams identity, atomic effects and tenant isolation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use agf_core::{
    enums::{HealthState, IngestProtocol},
    error::DomainError,
    event::{Event, RawLog},
    ids::{Id, TenantId},
    source::{CollectionMode, LogSource, SourceConnection, SourceRecord},
    time::Timestamp,
};
use agf_ingest::pipeline::{
    AgentTeamsAuditCursor, AgentTeamsAuditQuery, AgentTeamsAuditRecord, AgentTeamsBindingGuard, AgentTeamsIngestItem,
    IngestWrite, Sink, SqlSink,
};
use agf_storage::{Database, Store, configuration::ConfigStore, objectstore::MemoryObjectStore};
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::Arc, time::Duration};

async fn store() -> Arc<Store> {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let db = Database::from_pool(pool);
    db.migrate().await.unwrap();
    Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())))
}

async fn tenant(store: &Store) -> TenantId {
    let id = TenantId::new();
    sqlx::query("INSERT INTO tenants(id,slug,name) VALUES ($1,$2,'AgentTeams audit regression')")
        .bind(id.as_uuid())
        .bind(format!("agentteams-audit-{id}"))
        .execute(store.db().pool())
        .await
        .unwrap();
    id
}

async fn binding(store: &Arc<Store>, tenant: TenantId) -> AgentTeamsBindingGuard {
    let guard = AgentTeamsBindingGuard {
        tenant_id: tenant,
        source_id: Id::new(),
        binding_id: Id::new(),
        binding_version: 1,
        cloud_config_id: Id::new(),
        cloud_version: 1,
        scope_id: Id::new(),
        source_updated_at: Timestamp::parse_rfc3339("2026-09-30T12:34:56.123456789Z").unwrap(),
        inventory_updated_at: Timestamp::parse_rfc3339("2026-09-30T12:34:56.234567890Z").unwrap(),
    };
    save_binding(store, &guard).await;
    guard
}

async fn save_binding(store: &Arc<Store>, guard: &AgentTeamsBindingGuard) {
    let configs = ConfigStore::new(Some(store.clone()));
    let source = LogSource {
        id: guard.source_id,
        tenant_id: guard.tenant_id,
        name: "Verified webhook fixture".into(),
        protocol: IngestProtocol::Webhook,
        vendor: String::new(),
        product: "AgentTeams".into(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: CollectionMode::Push,
        poll_interval_secs: None,
        require_mtls: false,
        allowed_cidrs: vec![],
        max_message_bytes: 2_097_152,
        max_eps: 1000,
        tags: vec![],
        health: HealthState::Healthy,
        last_event_at: None,
        total_events: 0,
        last_error: None,
        created_at: guard.source_updated_at,
        updated_at: guard.source_updated_at,
    };
    configs
        .put(
            guard.tenant_id,
            "log-source",
            guard.source_id,
            &SourceRecord { source: Some(source), ..SourceRecord::default() },
        )
        .await
        .unwrap();
    for kind in ["cloud-integration", "cloud-inventory"] {
        configs
            .put(
                guard.tenant_id,
                kind,
                guard.cloud_config_id,
                &json!({"id":guard.cloud_config_id,"enabled":true,"version":guard.cloud_version,
                "updated_at":guard.inventory_updated_at}),
            )
            .await
            .unwrap();
    }
    configs
        .put(
            guard.tenant_id,
            "agentteams-audit-source",
            guard.source_id,
            &json!({"enabled":true,"version":guard.binding_version,"cloud_version":guard.cloud_version,
            "binding_id":guard.binding_id,"scope_id":guard.scope_id,
            "source_updated_at":guard.source_updated_at,"inventory_updated_at":guard.inventory_updated_at}),
        )
        .await
        .unwrap();
}

fn item(guard: &AgentTeamsBindingGuard, external: &str, kind: &str, at: Timestamp) -> AgentTeamsIngestItem {
    let mut event = Event::new(guard.tenant_id, guard.source_id, IngestProtocol::Webhook);
    event.time = at;
    event.message = "Safe fixture preview".into();
    let received = Timestamp::from_unix_millis(Timestamp::now().unix_millis()).unwrap();
    let audit = AgentTeamsAuditRecord {
        id: event.id,
        tenant_id: guard.tenant_id,
        scope_id: guard.scope_id,
        source_id: guard.source_id,
        binding_id: guard.binding_id,
        external_event_id: external.into(),
        content_hash: "a".repeat(64),
        event_time: at,
        received_at: received,
        kind: kind.into(),
        from_team: Some("team-one".into()),
        from_worker: Some("worker-one".into()),
        from_asset: None,
        to_team: Some("team-two".into()),
        to_worker: Some("worker-two".into()),
        to_asset: None,
        task_id: None,
        trace_id: Some("fixture-trace".into()),
        span_id: Some(external.into()),
        parent_span_id: None,
        status: "unknown".into(),
        duration_ms: Some(25),
        message_preview: "Safe fixture preview".into(),
        mocked: false,
    };
    let raw = RawLog {
        id: Id::new(),
        tenant_id: guard.tenant_id,
        source_id: guard.source_id,
        received_at: received,
        protocol: IngestProtocol::Webhook,
        payload_b64: "dGVzdA==".into(),
        payload_hash: "fixture".into(),
        bytes: 4,
        origin: "agentteams-audit-test".into(),
        parsed: true,
        parse_error: None,
        event_id: Some(event.id),
    };
    AgentTeamsIngestItem { write: IngestWrite { raw, event: Some(event) }, audit }
}

fn window(guard: &AgentTeamsBindingGuard) -> AgentTeamsAuditQuery {
    let until = Timestamp::from_unix_millis(Timestamp::now().unix_millis()).unwrap();
    AgentTeamsAuditQuery {
        tenant_id: guard.tenant_id,
        scope_id: guard.scope_id,
        from: until.offset_secs(-86_400),
        until,
        before: None,
        limit: 200,
    }
}

async fn counts(store: &Store, tenant: TenantId) -> (i64, i64, i64, i64) {
    let mut tx = store.db().begin_tenant(tenant).await.unwrap();
    let result = sqlx::query_as(
        "SELECT (SELECT count(*) FROM raw_logs),
        (SELECT count(*) FROM events),(SELECT count(*) FROM agentteams_audit),
        (SELECT count(*) FROM event_delivery_outbox)",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    result
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn concurrent_sinks_restart_and_sources_claim_a_business_event_once() {
    let db = store().await;
    let guard = binding(&db, tenant(&db).await).await;
    let first = SqlSink::new(db.clone()).with_event_outbox(true);
    let second = SqlSink::new(store().await).with_event_outbox(true);
    let at = window(&guard).until.offset_secs(-1);
    let left = [item(&guard, "shared-event", "call", at)];
    let right = [item(&guard, "shared-event", "call", at)];
    let (left, right) =
        tokio::join!(first.persist_agentteams(&guard, &left), second.persist_agentteams(&guard, &right));
    let (left, right) = (left.unwrap(), right.unwrap());
    assert_eq!((left.accepted + right.accepted, left.deduped + right.deduped), (1, 1));
    assert_eq!(counts(&db, guard.tenant_id).await, (1, 1, 1, 1));
    let restarted = SqlSink::new(store().await).with_event_outbox(true);
    let retry = restarted.persist_agentteams(&guard, &[item(&guard, "shared-event", "call", at)]).await.unwrap();
    assert_eq!((retry.accepted, retry.deduped), (0, 1));
    // Redundant collectors for one immutable cloud scope share the business event namespace.
    let mut another_source = guard.clone();
    another_source.source_id = Id::new();
    another_source.binding_id = Id::new();
    save_binding(&db, &another_source).await;
    let retry =
        second.persist_agentteams(&another_source, &[item(&another_source, "shared-event", "call", at)]).await.unwrap();
    assert_eq!((retry.accepted, retry.deduped), (0, 1));
    assert_eq!(counts(&db, guard.tenant_id).await, (1, 1, 1, 1));
    let mut heartbeat = item(&another_source, "second-source-heartbeat", "heartbeat", at);
    let received = at.offset_secs(-30);
    heartbeat.audit.received_at = received;
    heartbeat.write.raw.received_at = received;
    second.persist_agentteams(&another_source, &[heartbeat]).await.unwrap();
    let aggregate = second
        .agentteams_audit_aggregate(guard.tenant_id, guard.scope_id, at.offset_secs(-86_400), at.offset_secs(1))
        .await
        .unwrap();
    assert_eq!((aggregate.invocations, aggregate.heartbeats, aggregate.sources.len()), (1, 1, 2));
    let original = aggregate.sources.iter().find(|source| source.source_id == guard.source_id).unwrap();
    assert_eq!(original.last_heartbeat_at, None, "one collector must not inherit another collector's heartbeat");
    let second = aggregate.sources.iter().find(|source| source.source_id == another_source.source_id).unwrap();
    assert_eq!(second.binding_id, another_source.binding_id);
    assert_eq!(
        (second.first_received_at, second.last_received_at, second.last_heartbeat_at),
        (received, received, Some(received))
    );
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn conflict_and_late_sql_failure_roll_back_all_four_effects_and_allow_retry() {
    let db = store().await;
    let guard = binding(&db, tenant(&db).await).await;
    let sink = SqlSink::new(db.clone()).with_event_outbox(true);
    let at = window(&guard).until.offset_secs(-1);
    sink.persist_agentteams(&guard, &[item(&guard, "original", "call", at)]).await.unwrap();
    let mut batch = vec![item(&guard, "must-roll-back", "call", at), item(&guard, "original", "call", at)];
    batch[1].audit.content_hash = "b".repeat(64);
    assert!(matches!(sink.persist_agentteams(&guard, &batch).await, Err(DomainError::Conflict(_))));
    assert_eq!(counts(&db, guard.tenant_id).await, (1, 1, 1, 1));
    batch[1].audit.content_hash = "a".repeat(64);
    let retried = sink.persist_agentteams(&guard, &batch).await.unwrap();
    assert_eq!((retried.accepted, retried.deduped), (1, 1));
    assert_eq!(counts(&db, guard.tenant_id).await, (2, 2, 2, 2));
    let mut batch = vec![item(&guard, "sql-first", "message", at), item(&guard, "sql-second", "call", at)];
    // Audit validation succeeds; PostgreSQL rejects the second normalized event's text.
    batch[1].write.event.as_mut().unwrap().message = "invalid PostgreSQL text\0fixture".into();
    assert!(sink.persist_agentteams(&guard, &batch).await.is_err());
    assert_eq!(counts(&db, guard.tenant_id).await, (2, 2, 2, 2));
    batch[1].write.event.as_mut().unwrap().message = "retry after SQL rollback".into();
    assert_eq!(sink.persist_agentteams(&guard, &batch).await.unwrap().accepted, 2);
    assert_eq!(counts(&db, guard.tenant_id).await, (4, 4, 4, 4));
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn pagination_ties_and_half_open_whole_window_counts_are_exact() {
    let db = store().await;
    let guard = binding(&db, tenant(&db).await).await;
    let sink = SqlSink::new(db.clone());
    let mut query = window(&guard);
    let tie = query.until.offset_secs(-1);
    let mut batch: Vec<_> = (0..205).map(|index| item(&guard, &format!("call-{index}"), "call", tie)).collect();
    batch.extend([
        item(&guard, "at-window-start", "call", query.from),
        item(&guard, "before-window", "call", query.from.offset_secs(-1)),
        item(&guard, "at-window-end", "call", query.until),
        item(&guard, "message", "message", tie),
        item(&guard, "task", "task", tie),
        item(&guard, "heartbeat", "heartbeat", tie),
    ]);
    sink.persist_agentteams(&guard, &batch).await.unwrap();
    query.limit = 1;
    assert_eq!(sink.agentteams_audit_records(&query).await.unwrap().len(), 1);
    let total =
        sink.agentteams_audit_aggregate(guard.tenant_id, guard.scope_id, query.from, query.until).await.unwrap();
    assert_eq!((total.invocations, total.messages, total.tasks, total.heartbeats), (206, 1, 1, 1));
    assert_eq!(total.workers.len(), 1);
    assert_eq!(total.workers[0].worker, "worker-two");
    assert_eq!(total.workers[0].invocations, 206);
    assert_eq!(total.cross_team_calls.len(), 1);
    assert_eq!(total.cross_team_calls[0].count, 206);
    assert!(total.last_heartbeat_at.is_some());
    query.limit = 37;
    let mut ids = BTreeSet::new();
    loop {
        let page = sink.agentteams_audit_records(&query).await.unwrap();
        if page.is_empty() {
            break;
        }
        for row in &page {
            assert!(ids.insert(row.id), "equal-time cursor must not repeat or skip an ID");
            assert!(row.event_time >= query.from && row.event_time < query.until);
        }
        let last = page.last().unwrap();
        query.before = Some(AgentTeamsAuditCursor { event_time: last.event_time, id: last.id });
    }
    assert_eq!(ids.len(), 209, "pagination must include every in-window audit kind");
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn source_cloud_inventory_binding_and_tenant_changes_reject_without_effects() {
    let db = store().await;
    let guard = binding(&db, tenant(&db).await).await;
    let configs = ConfigStore::new(Some(db.clone()));
    let sink = SqlSink::new(db.clone()).with_event_outbox(true);
    let payload = [item(&guard, "lifecycle-event", "call", window(&guard).until.offset_secs(-1))];
    for (kind, id, label, path, replacement) in [
        ("log-source", guard.source_id, "disabled source", "/source/enabled", json!(false)),
        ("log-source", guard.source_id, "source tombstone", "/source", Value::Null),
        ("log-source", guard.source_id, "source is no longer push", "/source/mode", json!("pull")),
        (
            "log-source",
            guard.source_id,
            "new source revision",
            "/source/updated_at",
            json!(guard.source_updated_at.offset_secs(1)),
        ),
        ("cloud-integration", guard.cloud_config_id, "disabled cloud", "/enabled", json!(false)),
        ("cloud-integration", guard.cloud_config_id, "different account revision", "/version", json!(2)),
        (
            "cloud-inventory",
            guard.cloud_config_id,
            "same-version new inventory",
            "/updated_at",
            // Display strings would collapse these revisions to the same millisecond.
            json!(Timestamp::parse_rfc3339("2026-09-30T12:34:56.234567891Z").unwrap()),
        ),
        ("agentteams-audit-source", guard.source_id, "disabled binding", "/enabled", json!(false)),
        ("agentteams-audit-source", guard.source_id, "new binding revision", "/version", json!(2)),
        (
            "agentteams-audit-source",
            guard.source_id,
            "different pinned source revision",
            "/source_updated_at",
            json!(Timestamp::parse_rfc3339("2026-09-30T12:34:56.123456790Z").unwrap()),
        ),
        (
            "agentteams-audit-source",
            guard.source_id,
            "different pinned inventory revision",
            "/inventory_updated_at",
            json!(Timestamp::parse_rfc3339("2026-09-30T12:34:56.234567891Z").unwrap()),
        ),
    ] {
        let original: Value = configs.get(guard.tenant_id, kind, id).await.unwrap().unwrap();
        let mut changed = original.clone();
        *changed.pointer_mut(path).unwrap() = replacement;
        configs.put(guard.tenant_id, kind, id, &changed).await.unwrap();
        assert!(matches!(sink.persist_agentteams(&guard, &payload).await, Err(DomainError::Conflict(_))), "{label}");
        assert_eq!(counts(&db, guard.tenant_id).await, (0, 0, 0, 0), "{label}");
        configs.put(guard.tenant_id, kind, id, &original).await.unwrap();
    }
    configs.delete(guard.tenant_id, "log-source", guard.source_id).await.unwrap();
    assert!(matches!(sink.persist_agentteams(&guard, &payload).await, Err(DomainError::Conflict(_))));
    assert_eq!(counts(&db, guard.tenant_id).await, (0, 0, 0, 0));
    save_binding(&db, &guard).await;
    sqlx::query("UPDATE tenants SET enabled=false WHERE id=$1")
        .bind(guard.tenant_id.as_uuid())
        .execute(db.db().pool())
        .await
        .unwrap();
    assert!(matches!(sink.persist_agentteams(&guard, &payload).await, Err(DomainError::Forbidden(_))));
    assert_eq!(counts(&db, guard.tenant_id).await, (0, 0, 0, 0));
    sqlx::query("UPDATE tenants SET enabled=true WHERE id=$1")
        .bind(guard.tenant_id.as_uuid())
        .execute(db.db().pool())
        .await
        .unwrap();
    assert_eq!(sink.persist_agentteams(&guard, &payload).await.unwrap().accepted, 1);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn source_update_commits_before_waiting_ingest_rechecks_the_locked_row() {
    let db = store().await;
    let guard = binding(&db, tenant(&db).await).await;
    let configs = ConfigStore::new(Some(db.clone()));
    let mut source: Value = configs.get(guard.tenant_id, "log-source", guard.source_id).await.unwrap().unwrap();
    source["source"]["enabled"] = json!(false);
    let mut changing = db.db().begin_tenant(guard.tenant_id).await.unwrap();
    sqlx::query("UPDATE console_configurations SET payload=$1 WHERE kind='log-source' AND id=$2")
        .bind(source)
        .bind(guard.source_id.as_uuid())
        .execute(&mut *changing)
        .await
        .unwrap();
    let sink = SqlSink::new(db.clone()).with_event_outbox(true);
    let payload = vec![item(&guard, "waiting-event", "call", window(&guard).until.offset_secs(-1))];
    let tenant = guard.tenant_id;
    let mut pending = tokio::spawn(async move { sink.persist_agentteams(&guard, &payload).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut pending).await.is_err(),
        "ingest must wait for source row lock"
    );
    changing.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), pending).await.unwrap().unwrap();
    assert!(matches!(result, Err(DomainError::Conflict(_))));
    assert_eq!(counts(&db, tenant).await, (0, 0, 0, 0));
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn runtime_rls_hides_another_tenant_and_rejects_forged_tenant_insert() {
    let db = store().await;
    let guard = binding(&db, tenant(&db).await).await;
    let foreign = tenant(&db).await;
    let flags: (bool, bool) = sqlx::query_as(
        "SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='public.agentteams_audit'::regclass",
    )
    .fetch_one(db.db().pool())
    .await
    .unwrap();
    assert_eq!(flags, (true, true), "migration must enable and force audit RLS");
    let policies: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_policies WHERE schemaname='public' AND tablename='agentteams_audit'",
    )
    .fetch_one(db.db().pool())
    .await
    .unwrap();
    assert_eq!(policies, 1, "additional permissive policies could bypass the tenant boundary");
    let sink = SqlSink::new(db.clone()).with_event_outbox(true);
    let saved = item(&guard, "owned-event", "call", window(&guard).until.offset_secs(-1));
    sink.persist_agentteams(&guard, std::slice::from_ref(&saved)).await.unwrap();
    let mut query = window(&guard);
    query.tenant_id = foreign;
    assert!(sink.agentteams_audit_records(&query).await.unwrap().is_empty());
    assert_eq!(
        sink.agentteams_audit_aggregate(foreign, guard.scope_id, query.from, query.until).await.unwrap().invocations,
        0
    );
    assert_eq!(counts(&db, foreign).await, (0, 0, 0, 0), "raw SQL without tenant filters must still respect RLS");
    let mut tx = db.db().begin_tenant(foreign).await.unwrap();
    assert!(sqlx::query_scalar::<_, bool>("SELECT agf_agentteams_lock_tenant()").fetch_one(&mut *tx).await.unwrap());
    let error = sqlx::query(
        "INSERT INTO agentteams_audit
        (tenant_id,scope_id,external_event_id,content_hash,id,source_id,binding_id,event_time,received_at,kind,payload)
        VALUES ($1,$2,'forged-event',$3,$4,$5,$6,$7,$8,'call',$9)",
    )
    .bind(guard.tenant_id.as_uuid())
    .bind(guard.scope_id.as_uuid())
    .bind("a".repeat(64))
    .bind(Id::new().as_uuid())
    .bind(guard.source_id.as_uuid())
    .bind(guard.binding_id.as_uuid())
    .bind(saved.audit.event_time.as_datetime())
    .bind(saved.audit.received_at.as_datetime())
    .bind(serde_json::to_value(&saved.audit).unwrap())
    .execute(&mut *tx)
    .await
    .unwrap_err();
    assert_eq!(error.as_database_error().unwrap().code().as_deref(), Some("42501"));
    tx.rollback().await.unwrap();
    assert_eq!(counts(&db, guard.tenant_id).await, (1, 1, 1, 1));
}
