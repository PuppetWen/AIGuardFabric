//! Isolated SQL regression for broker redelivery, canonical evidence and automatic alert persistence.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
#[path = "common/sql_runtime_identity.rs"]
mod sql_runtime_identity;
use agf_core::{
    asset::Asset,
    enums::AssetKind,
    enums::IngestProtocol,
    event::{Event, EventCategory},
    ids::Id,
    rule::Detection,
};
use agf_ingest::{
    bus::{EventBus, JetStreamEventBus},
    pipeline::SqlSink,
};
use agf_storage::{AssetRepo, Database, EventRepo, FindingRepo, Store, objectstore::MemoryObjectStore};
use common::*;
use futures::StreamExt;
use std::time::Duration;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

async fn setup_sql() -> (Harness, Arc<Store>) {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let db = Database::from_pool(pool);
    db.migrate().await.unwrap();
    let db = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.ingest_sink = Arc::new(SqlSink::new(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    sql_runtime_identity::rebind(&mut h.state, &[h.tenant, h.other_tenant]).await.unwrap();
    let mut rule = agf_api::state::fallback_rules().remove(0);
    rule.key = "requirements-event-rule".into();
    rule.name = "Requirements event detection".into();
    rule.detection = Detection::Keyword { any: vec!["requirements-event-warning".into()] };
    rule.samples.positive = vec!["requirements-event-warning".into()];
    rule.samples.negative = vec!["normal-event".into()];
    h.state.rules = Arc::new(agf_scan::loader::RulePackLoader::strict().load_inline(vec![rule]).unwrap());
    h.app = build_router(h.state.clone());
    (h, db)
}

async fn save_event(db: &Store, tenant: TenantId, host: &str, message: &str) -> Event {
    let mut event = Event::new(tenant, Id::new(), IngestProtocol::Otlp);
    event.category = EventCategory::AiSession;
    event.message = message.into();
    event.host.name = Some(host.into());
    event.raw_hash = agf_core::secret::content_hash(message);
    insert_event(db, event).await
}

async fn insert_event(db: &Store, event: Event) -> Event {
    let tenant = event.tenant_id;
    let write = event.clone();
    db.with_tenant(tenant, move |tx| Box::pin(async move { EventRepo::insert(tx, &write).await })).await.unwrap();
    event
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn discovered_asset_flows_into_event_alert_case_and_actual_interceptor() {
    let (h, db) = setup_sql().await;
    let fingerprint = format!("analysis-chain-{}", Id::new());
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":7,"result":{"tools":[]}})))
        .mount(&upstream)
        .await;
    let endpoint = h
        .post(
            "/api/v1/mcp/endpoints",
            json!({"expected_version":0,
        "name":fingerprint,"url":format!("{}/mcp",upstream.uri()),"enabled":true,
        "idle_timeout_secs":5}),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::OK, "{}", endpoint.text);
    let asset_id = Id::parse(endpoint.json()["id"].as_str().unwrap()).unwrap();
    let assets = h.get("/api/v1/assets").await;
    assert_eq!(assets.status, StatusCode::OK, "{}", assets.text);
    assert!(
        assets.json()["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|asset| asset["id"] == asset_id.to_string() && asset["fingerprint"] == format!("mcp-http:{asset_id}"))
    );

    let mut foreign_tenant = agf_api::tenant_directory::new(format!("foreign-{}", Id::new()), "Foreign chain".into());
    foreign_tenant.id = h.other_tenant;
    agf_api::tenant_directory::save(&h.state, foreign_tenant, true).await.unwrap();
    let foreign =
        Asset::new(h.other_tenant, AssetKind::ModelEndpoint, "Foreign model", format!("foreign-{fingerprint}"));
    let foreign_id = foreign.id;
    db.with_tenant(h.other_tenant, move |tx| {
        Box::pin(async move { AssetRepo::upsert(tx, &foreign).await.map(|_| ()) })
    })
    .await
    .unwrap();
    let definition = json!({"enabled":true,"reason":"Reviewed automatic response","playbook":{
        "key":"event-chain","name":"Event chain response","trigger":{"min_severity":"high"},
        "require_approval":true,"steps":[{"name":"Block test domain","action":"block-domain",
        "params":{"domain":"analysis-chain.example"}}]}});
    let configured = h.post("/api/v1/soar/automations", definition).await;
    assert_eq!(configured.status, StatusCode::OK, "{}", configured.text);
    let mut event = Event::new(h.tenant, Id::new(), IngestProtocol::Otlp);
    event.category = EventCategory::AiSession;
    event.message = "requirements-event-warning".into();
    event.raw_hash = agf_core::secret::content_hash(&event.message);
    event.host.name = Some("Unverified shared host name".into());
    event.ai.mcp_server_id = Some(asset_id);
    event.ai.agent_id = Some(asset_id); // Wrong asset kind must not create another link.
    event.ai.model_endpoint_id = Some(foreign_id); // Other tenant's asset must remain invisible.
    let event = insert_event(&db, event).await;
    let result = agf_api::event_analysis::process(&h.state, &event).await.unwrap();
    assert_eq!(result.finding_ids.len(), 1);
    assert_eq!(result.alert_ids.len(), 1);
    let alert_id = result.alert_ids[0];
    let alert = h.get(&format!("/api/v1/alerts/{alert_id}")).await;
    assert_eq!(alert.status, StatusCode::OK, "{}", alert.text);
    assert_eq!(alert.json()["alert"]["asset_ids"], json!([asset_id]));
    assert_eq!(alert.json()["alert"]["finding_ids"], json!(result.finding_ids));
    let finding_id = result.finding_ids[0];
    let finding = db
        .with_tenant(h.tenant, move |tx| Box::pin(async move { FindingRepo::get(tx, finding_id).await }))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(finding.asset_id, Some(asset_id));
    let asset = h.get(&format!("/api/v1/assets/{asset_id}")).await;
    assert_eq!(asset.status, StatusCode::OK, "{}", asset.text);
    assert_eq!(asset.json()["asset"]["open_findings"], 1);

    assert!(h.state.store.case_list_durable(h.tenant).await.unwrap().is_empty());
    agf_api::soar_automation::tick(&h.state).await.unwrap();
    let cases = h.state.store.case_list_durable(h.tenant).await.unwrap();
    assert_eq!(cases.len(), 1, "a new detected alert should open one case");
    assert_eq!(cases[0].alert_ids, vec![alert_id]);
    assert_eq!(cases[0].asset_ids, vec![asset_id]);
    assert!(agf_api::containment::list(&h.state, h.tenant).await.unwrap().is_empty());
    let token = format!("Bearer {}", h.admin);
    let proxy_path = format!("/api/v1/mcp/proxy/{asset_id}");
    let allowed = h
        .request_with(
            "POST",
            &proxy_path,
            &[
                ("authorization", &token),
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/list"),
                ("accept", "application/json, text/event-stream"),
            ],
            Some(json!({"jsonrpc":"2.0","id":7,"method":"tools/list","params":{
                "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}
            }})),
        )
        .await;
    assert_eq!(allowed.status, StatusCode::OK, "{}", allowed.text);
    assert_eq!(upstream.received_requests().await.unwrap().len(), 1);

    let policy = h
        .post(
            "/api/v1/policies",
            json!({"name":"analysis-chain-deny",
        "structured":{"command_deny":["analysis-chain-danger"]},"action":"deny",
        "intercept_points":["mcp-proxy"]}),
        )
        .await;
    assert_eq!(policy.status, StatusCode::CREATED, "{}", policy.text);
    assert_eq!(h.post("/api/v1/policies/reload", json!({})).await.status, StatusCode::OK);
    let enforced = h
        .post(
            "/api/v1/runtime/mcp/check",
            json!({"session_id":"analysis-chain",
        "frame":{"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"query","arguments":{"command":"analysis-chain-danger"}}}}),
        )
        .await;
    assert_eq!(enforced.status, StatusCode::OK, "{}", enforced.text);
    assert_eq!(enforced.json()["allowed"], false, "{}", enforced.text);
    let proxied = h
        .request_with(
            "POST",
            &proxy_path,
            &[
                ("authorization", &token),
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/call"),
                ("mcp-name", "query"),
                ("accept", "application/json, text/event-stream"),
            ],
            Some(json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{
                "name":"query","arguments":{"command":"analysis-chain-danger"},
                "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}
            }})),
        )
        .await;
    assert_eq!(proxied.status, StatusCode::FORBIDDEN, "{}", proxied.text);
    assert_eq!(upstream.received_requests().await.unwrap().len(), 1, "blocked tool reached MCP upstream");
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn concurrent_redelivery_commits_one_alert_and_persists_evidence() {
    let (h, db) = setup_sql().await;
    let host = format!("analysis-{}", Id::new());
    let event = save_event(&db, h.tenant, &host, "requirements-event-warning").await;
    let (a, b) = tokio::join!(
        agf_api::event_analysis::process(&h.state, &event),
        agf_api::event_analysis::process(&h.state, &event)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_ne!(a.duplicate, b.duplicate);
    assert_eq!(a.alert_ids, b.alert_ids);
    assert_eq!(a.finding_ids, b.finding_ids);
    assert_eq!(a.alert_ids.len(), 1);
    let alert_id = a.alert_ids[0];
    let detail = h.get(&format!("/api/v1/alerts/{alert_id}")).await;
    assert_eq!(detail.status, StatusCode::OK, "{}", detail.text);
    assert_eq!(detail.json()["alert"]["dedup_count"], 1);
    assert_eq!(detail.json()["alert"]["event_ids"][0], event.id.to_string());
    let finding_id = a.finding_ids[0];
    let event_uri = format!("/api/v1/ingest/events/{}", event.id);
    assert_eq!(h.request("GET", &event_uri, None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.get(&event_uri).await.json()["event"]["raw_hash"], event.raw_hash);
    let foreign_event = h
        .request_with(
            "GET",
            &event_uri,
            &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.other_tenant.to_string())],
            None,
        )
        .await;
    assert_eq!(foreign_event.status, StatusCode::NOT_FOUND);

    let finding = db
        .with_tenant(h.tenant, move |tx| Box::pin(async move { FindingRepo::get(tx, finding_id).await }))
        .await
        .unwrap()
        .unwrap();
    assert!(finding.evidence.iter().any(|e| e.code == "EV-EVENT" && e.content_hash == event.raw_hash));
    let second = save_event(&db, h.tenant, &host, "requirements-event-warning again").await;
    let next = agf_api::event_analysis::process(&h.state, &second).await.unwrap();
    assert_eq!(next.alert_ids, a.alert_ids);
    assert_eq!(h.get(&format!("/api/v1/alerts/{alert_id}")).await.json()["alert"]["dedup_count"], 2);

    // A changed broker payload cannot replace the immutable, benign SQL event.
    let mut benign = save_event(&db, h.tenant, &host, "normal-event").await;
    benign.message = "requirements-event-warning".into();
    assert!(agf_api::event_analysis::process(&h.state, &benign).await.unwrap().alert_ids.is_empty());
    let mut missing = event.clone();
    missing.id = Id::new();
    assert!(agf_api::event_analysis::process(&h.state, &missing).await.is_err());
    let payload = serde_json::to_vec(&event).unwrap();
    assert!(
        agf_api::event_analysis::process_delivery(
            &h.state,
            "agf.events",
            &format!("agf.events.{}.info", TenantId::new()),
            &payload
        )
        .await
        .is_err()
    );
    let mut foreign = event.clone();
    foreign.tenant_id = h.other_tenant;
    assert!(agf_api::event_analysis::process(&h.state, &foreign).await.is_err());

    // No local alert cache is needed after replacing the API instance.
    let mut fresh = h.clone();
    fresh.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    fresh.app = build_router(fresh.state.clone());
    assert_eq!(fresh.get(&format!("/api/v1/alerts/{alert_id}")).await.status, StatusCode::OK);
    assert!(agf_api::event_analysis::process(&fresh.state, &event).await.unwrap().duplicate);
    let detail = fresh.get(&format!("/api/v1/findings/{finding_id}")).await;
    assert_eq!(detail.status, StatusCode::OK, "{}", detail.text);
    assert!(detail.json()["finding"]["evidence"].as_array().unwrap().iter().any(|e| e["code"] == "EV-EVENT"));
    let listed = fresh.get(&format!("/api/v1/findings?q={}&page_size=1", event.id)).await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.text);
    assert_eq!(listed.json()["total"], 1);
    let multi = fresh
        .get(&format!(
            "/api/v1/findings?q={}&severity=high,low&domain=prompt-attack,tool-abuse&state=pending,verified",
            event.id
        ))
        .await;
    assert_eq!(multi.status, StatusCode::OK, "{}", multi.text);
    assert_eq!(multi.json()["total"], 1);
    let exact = fresh.get(&format!("/api/v1/findings?q={}&severity=low", event.id)).await;
    assert_eq!(exact.json()["total"], 0, "severity selection must be exact, not a minimum threshold");

    let changed = fresh
        .post(&format!("/api/v1/findings/{finding_id}/state"), json!({"state":"verified","evidence_level":"confirmed"}))
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    assert_eq!(h.get(&format!("/api/v1/findings/{finding_id}")).await.json()["finding"]["state"], "verified");
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL and local AGF_TEST_NATS_URL"]
async fn durable_broker_redelivers_unacknowledged_events_without_duplicate_alerts() {
    let (h, db) = setup_sql().await;
    let url = std::env::var("AGF_TEST_NATS_URL").unwrap();
    assert!(url.starts_with("nats://127.0.0.1:") || url.starts_with("nats://localhost:"));
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let stream = format!("AGF_REQUIREMENTS_{suffix}");
    let prefix = format!("agf.requirements.{suffix}");
    let bus = JetStreamEventBus::connect(&url, &stream, &prefix).await.unwrap();
    let event = save_event(&db, h.tenant, &format!("broker-{suffix}"), "requirements-event-warning").await;
    bus.publish(&event).await.unwrap();
    let consumer = bus.consumer("agf-requirements-analysis").await.unwrap();
    let mut batch = consumer.batch().max_messages(1).expires(Duration::from_secs(5)).messages().await.unwrap();
    let message = batch.next().await.unwrap().unwrap();
    let result =
        agf_api::event_analysis::process_delivery(&h.state, &prefix, &message.subject, &message.payload).await.unwrap();
    assert_eq!(result.alert_ids.len(), 1);
    // Simulate a worker disappearing before acknowledgement, then request immediate redelivery.
    message.ack_with(async_nats::jetstream::AckKind::Nak(None)).await.unwrap();
    drop(batch);
    drop(consumer);
    drop(bus);
    let bus = JetStreamEventBus::connect(&url, &stream, &prefix).await.unwrap();
    let consumer = bus.consumer("agf-requirements-analysis").await.unwrap();
    let mut batch = consumer.batch().max_messages(1).expires(Duration::from_secs(5)).messages().await.unwrap();
    let message = batch.next().await.unwrap().unwrap();
    assert!(message.info().unwrap().delivered >= 2);
    let repeated =
        agf_api::event_analysis::process_delivery(&h.state, &prefix, &message.subject, &message.payload).await.unwrap();
    assert!(repeated.duplicate);
    assert_eq!(repeated.alert_ids, result.alert_ids);
    message.double_ack().await.unwrap();
    let alert = h.state.store.alert_get_durable(h.tenant, result.alert_ids[0]).await.unwrap().unwrap();
    assert_eq!(alert.dedup_count, 1);
    let client = async_nats::connect(&url).await.unwrap();
    async_nats::jetstream::new(client).delete_stream(&stream).await.unwrap();
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL and local AGF_TEST_NATS_URL"]
async fn broker_failure_handoff_is_durable_and_does_not_spend_retries_on_redelivery() {
    let (mut h, db) = setup_sql().await;
    let tenant =
        agf_api::tenant_directory::new(format!("broker-handoff-{}", Id::new()), "Broker recovery validation".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.tenant = tenant.id;
    let mut rule = agf_api::state::fallback_rules().remove(0);
    rule.key = "broker-recovery".into();
    rule.name = "Invalid SQL output\0".into();
    rule.detection = Detection::Keyword { any: vec!["handoff-fixture".into()] };
    rule.samples.positive = vec!["handoff-fixture".into()];
    rule.samples.negative = vec!["benign".into()];
    h.state.rules = Arc::new(agf_scan::loader::RulePackLoader::strict().load_inline(vec![rule.clone()]).unwrap());
    let url = std::env::var("AGF_TEST_NATS_URL").unwrap();
    assert!(url.starts_with("nats://127.0.0.1:") || url.starts_with("nats://localhost:"));
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let stream = format!("AGF_REQUIREMENTS_{suffix}");
    let prefix = format!("agf.requirements.{suffix}");
    let bus = JetStreamEventBus::connect(&url, &stream, &prefix).await.unwrap();
    let event = save_event(&db, h.tenant, &suffix, "handoff-fixture").await;
    bus.publish(&event).await.unwrap();
    let mut consumer = bus.consumer("requirements-handoff").await.unwrap();
    let mut batch = consumer.batch().max_messages(1).expires(Duration::from_secs(5)).messages().await.unwrap();
    let message = batch.next().await.unwrap().unwrap();
    assert!(
        agf_api::event_analysis::process_or_defer_delivery(&h.state, &prefix, &message.subject, &message.payload)
            .await
            .unwrap()
            .is_none()
    );
    let original_subject = message.subject.to_string();
    let payload = message.payload.clone();
    message.double_ack().await.unwrap();
    drop(batch);
    assert_eq!(consumer.info().await.unwrap().num_ack_pending, 0);
    // Fresh process state recognizes SQL ownership and does not charge another failed attempt.
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    sql_runtime_identity::rebind(&mut h.state, &[h.tenant, h.other_tenant]).await.unwrap();
    assert!(
        agf_api::event_analysis::process_or_defer_delivery(&h.state, &prefix, &original_subject, &payload)
            .await
            .unwrap()
            .is_none()
    );
    let event_id = event.id;
    let attempts: i32 = db
        .with_tenant(h.tenant, move |tx| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT attempts FROM event_analysis_retries WHERE event_id=$1")
                    .bind(event_id.as_uuid())
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(|e| agf_storage::map_sqlx_err("handoff_attempts", &e))
            })
        })
        .await
        .unwrap();
    assert_eq!(attempts, 1);
    let mut absent = event.clone();
    absent.id = Id::new();
    assert!(
        agf_api::event_analysis::process_or_defer_delivery(
            &h.state,
            &prefix,
            &original_subject,
            &serde_json::to_vec(&absent).unwrap()
        )
        .await
        .is_err()
    );
    assert!(
        agf_api::event_analysis::process_or_defer_delivery(
            &h.state,
            &prefix,
            &format!("{prefix}.{}.info", TenantId::new()),
            &payload
        )
        .await
        .is_err()
    );
    assert!(
        agf_api::event_analysis::process_or_defer_delivery(&h.state, &prefix, &original_subject, b"invalid-json")
            .await
            .is_err()
    );
    rule.name = "Repaired output".into();
    h.state.rules = Arc::new(agf_scan::loader::RulePackLoader::strict().load_inline(vec![rule]).unwrap());
    db.with_tenant(h.tenant, move |tx| {
        Box::pin(async move {
            sqlx::query("UPDATE event_analysis_retries SET available_at=now()-interval '1 second' WHERE event_id=$1")
                .bind(event_id.as_uuid())
                .execute(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("handoff_due", &e))?;
            Ok(())
        })
    })
    .await
    .unwrap();
    assert_eq!(agf_api::event_analysis::recover_pending(&h.state, h.tenant).await.unwrap().0, 1);
    assert!(
        agf_api::event_analysis::process_or_defer_delivery(&h.state, &prefix, &original_subject, &payload)
            .await
            .unwrap()
            .unwrap()
            .duplicate
    );
    let client = async_nats::connect(&url).await.unwrap();
    async_nats::jetstream::new(client).delete_stream(&stream).await.unwrap();
}
