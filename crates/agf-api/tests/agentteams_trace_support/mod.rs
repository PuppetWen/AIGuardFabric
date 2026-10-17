//! Dedicated SQL tenants, actual audit ingestion and synthetic historical trace rows.
use crate::{common::*, configuration_audit_support::SqlCase};
use agf_api::agentteams_audit::binding::{self, Binding};
use agf_core::{credential::SecretMaterial, ids::Id};
use agf_ingest::pipeline::{AgentTeamsAuditRecord, AgentTeamsTraceQuery, SqlSink};
use agf_storage::{Database, Store, TenantTransaction, objectstore::MemoryObjectStore};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::ExposeSecret;

pub(crate) const CLOUD: &str = "/api/v1/alicloud/connections/alicloud-agentteams";
pub(crate) const SYNC: &str = "/api/v1/alicloud/agentteams/sync";
pub(crate) const BASE: &str = "/api/v1/alicloud/agentteams/traces";
pub(crate) const TRACE: &str = "owned-trace";

pub(crate) struct Fixture {
    pub(crate) case: SqlCase,
    pub(crate) h: Harness,
    pub(crate) binding: Binding,
    pub(crate) from: Timestamp,
    pub(crate) until: Timestamp,
    pub(crate) clock: Timestamp,
}

pub(crate) fn sql_router(mut h: Harness, pool: sqlx::PgPool) -> Harness {
    let store = Arc::new(Store::new(Database::from_pool(pool), None, Arc::new(MemoryObjectStore::new())));
    h.state.ingest_sink = Arc::new(SqlSink::new(store).with_event_outbox(true));
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    let tenant = h.tenant;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        request.headers_mut().insert("x-agf-tenant", tenant.to_string().parse().unwrap());
        async move { request }
    }));
    h
}

impl Fixture {
    pub(crate) async fn open(label: &str) -> Self {
        owner_check().await;
        let case = SqlCase::open(label).await;
        let h = sql_router(case.h.clone(), case.pool.clone());
        let binding = configure(&h).await;
        let clock = Timestamp::from_unix_millis(Timestamp::now().unix_millis()).unwrap();
        Self { case, h, binding, from: clock.offset_secs(-3600), until: clock.offset_secs(30), clock }
    }

    pub(crate) fn query(&self, limit: usize) -> AgentTeamsTraceQuery {
        AgentTeamsTraceQuery {
            tenant_id: self.h.tenant,
            scope_id: self.binding.scope_id,
            trace_id: TRACE.into(),
            from: self.from,
            until: self.until,
            received_until: self.clock,
            limit,
        }
    }

    pub(crate) fn record(&self, index: usize) -> AgentTeamsAuditRecord {
        AgentTeamsAuditRecord {
            id: Id::new(),
            tenant_id: self.h.tenant,
            scope_id: self.binding.scope_id,
            source_id: self.binding.source_id,
            binding_id: self.binding.binding_id,
            external_event_id: format!("owned-event-{index}"),
            content_hash: "a".repeat(64),
            event_time: self.clock.offset_secs(-1),
            received_at: self.clock,
            kind: "task".into(),
            from_team: Some("my-team".into()),
            from_worker: Some("worker-demo".into()),
            from_asset: Some(self.binding.members["worker-demo"].asset_id),
            to_team: None,
            to_worker: None,
            to_asset: None,
            task_id: Some("owned-task".into()),
            trace_id: Some(TRACE.into()),
            span_id: Some(format!("owned-span-{index}")),
            parent_span_id: None,
            status: "unknown".into(),
            duration_ms: None,
            message_preview: "owned synthetic observation".into(),
            mocked: true,
        }
    }

    pub(crate) fn uri(&self, trace: &str, cursor: Option<&str>, limit: usize) -> String {
        trace_uri(trace, cursor, limit, self.from, self.until)
    }

    pub(crate) async fn page(&self, cursor: Option<&str>, limit: usize) -> Resp {
        self.h.get(&self.uri(TRACE, cursor, limit)).await
    }

    pub(crate) async fn seed(&self, records: &[AgentTeamsAuditRecord]) {
        let store = self.h.state.ingest_sink.database().unwrap();
        let mut tx = store.db().begin_tenant(self.h.tenant).await.unwrap();
        insert(&mut tx, records).await;
        tx.commit().await.unwrap();
    }

    pub(crate) async fn ingest(&self, count: usize) {
        let events: Vec<_> = (0..count)
            .map(|index| {
                json!({"event_id":format!("http-{index}"),
            "event_time":Timestamp::now(),"kind":"task","from_team":"my-team","from_worker":"worker-demo",
            "trace_id":TRACE,"span_id":format!("http-span-{index}"),"status":"unknown"})
            })
            .collect();
        let result = self
            .h
            .post(
                &format!("/api/v1/alicloud/agentteams/audit-sources/{}/events", self.binding.source_id),
                json!({"binding_id":self.binding.binding_id,"events":events}),
            )
            .await;
        assert_eq!(result.status, StatusCode::OK, "{}", result.text);
        assert_eq!(result.json()["accepted"], count);
        assert_eq!(result.json()["durable"], true);
    }
}

pub(crate) async fn configure(h: &Harness) -> Binding {
    let response = h
        .request(
            "PUT",
            CLOUD,
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true,
        "mock":true,"settings":{"instance_id":format!("trace-owned-{}",Id::new()),"account_id":"trace-owned-mock"}})),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let response = h.post(SYNC, json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":false})).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let source =
        h.post("/api/v1/ingest/sources", json!({"name":"trace-owned-webhook","protocol":"http-webhook"})).await;
    assert_eq!(source.status, StatusCode::CREATED, "{}", source.text);
    let source = Id::parse(source.json()["id"].as_str().unwrap()).unwrap();
    let response = h
        .request(
            "PUT",
            &format!("/api/v1/alicloud/agentteams/audit-sources/{source}"),
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true})),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    binding::load(&h.state, h.tenant, source).await.unwrap().unwrap()
}

pub(crate) async fn insert(tx: &mut TenantTransaction<'_>, records: &[AgentTeamsAuditRecord]) {
    assert!(!records.is_empty());
    assert!(records.iter().all(|record| record.tenant_id == records[0].tenant_id));
    // Direct fixtures model stored historical observations, including stale scopes. They
    // do not bypass an HTTP business mutation or claim these were sent by a real provider.
    sqlx::query(
        "INSERT INTO agentteams_audit
        (tenant_id,scope_id,external_event_id,content_hash,id,source_id,binding_id,event_time,received_at,kind,payload)
        SELECT (r->>'tenant_id')::uuid,(r->>'scope_id')::uuid,r->>'external_event_id',r->>'content_hash',
          (r->>'id')::uuid,(r->>'source_id')::uuid,(r->>'binding_id')::uuid,
          (r->>'event_time')::timestamptz,(r->>'received_at')::timestamptz,r->>'kind',r
        FROM jsonb_array_elements($1::jsonb) r",
    )
    .bind(serde_json::to_value(records).unwrap())
    .execute(&mut **tx)
    .await
    .unwrap();
}

async fn owner_check() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let expected = std::env::var("AGF_TRACE_DATABASE_OWNER").expect("set the unique owned Trace SQL database comment");
    let identity = expected.strip_prefix("AIGuardFabric Trace SQL ").expect("invalid Trace SQL owner prefix");
    assert!(
        identity.len() == 32 && identity.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Trace SQL owner must contain the dedicated run's 32 lowercase hex digits"
    );
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(owner.as_deref(), Some(expected.as_str()), "Trace SQL database belongs to another task");
    pool.close().await;
}

pub(crate) fn cursor(response: &Resp) -> String {
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response.json()["nextCursor"].as_str().unwrap().to_owned()
}

pub(crate) fn trace_uri(trace: &str, cursor: Option<&str>, limit: usize, from: Timestamp, until: Timestamp) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("from", &from.as_datetime().to_rfc3339());
    query.append_pair("until", &until.as_datetime().to_rfc3339());
    query.append_pair("limit", &limit.to_string());
    if let Some(cursor) = cursor {
        query.append_pair("cursor", cursor);
    }
    format!("{BASE}/{trace}?{}", query.finish())
}

pub(crate) fn expired_cursor(f: &Fixture, cursor: &str) -> String {
    // Only an owned server fixture has this cipher. Never expose plaintext or Key in logs.
    let encrypted: SecretMaterial = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(cursor).unwrap()).unwrap();
    let text = agf_api::model_gateway::cipher(&f.h.state).unwrap().decrypt(&encrypted).unwrap();
    let mut fields: Value = serde_json::from_str(text.expose_secret()).unwrap();
    fields["issued_at"] = json!(Timestamp::now().offset_secs(-1801));
    let encrypted = agf_api::model_gateway::encrypt(
        &f.h.state,
        f.h.tenant,
        f.binding.scope_id,
        serde_json::to_string(&fields).unwrap(),
    )
    .unwrap();
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&encrypted).unwrap())
}
