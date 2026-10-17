//! External webhook to durable broker, background analysis, response and MCP policy.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
#[path = "common/sql_runtime_identity.rs"]
mod sql_runtime_identity;

use agf_core::{
    ids::Id,
    rule::{Detection, RuleTarget},
};
use agf_ingest::{bus::JetStreamEventBus, pipeline::SqlSink};
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;
use std::{sync::Arc, time::Duration};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

async fn sql_harness(url: &str, stream: &str) -> (Harness, Arc<Store>) {
    let database_url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&database_url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(12).connect(&database_url).await.unwrap();
    let database = Database::from_pool(pool);
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    let config = Arc::make_mut(&mut h.state.config);
    config.nats.enabled = true;
    config.nats.url = url.into();
    config.nats.stream = stream.into();
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    h.state.ingest_sink = Arc::new(SqlSink::new(store.clone()).with_event_outbox(true));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store.clone())));
    sql_runtime_identity::rebind(&mut h.state, &[h.tenant, h.other_tenant]).await.unwrap();
    let mut rule = agf_api::state::fallback_rules().remove(3);
    rule.key = "requirements-webhook-rule".into();
    rule.name = "Webhook event detection".into();
    rule.detection = Detection::Keyword { any: vec!["requirements-event-warning".into()] };
    rule.target = RuleTarget::ToolArguments;
    rule.samples.positive = vec!["requirements-event-warning".into()];
    rule.samples.negative = vec!["normal-event".into()];
    h.state.rules = Arc::new(agf_scan::loader::RulePackLoader::strict().load_inline(vec![rule]).unwrap());
    h.app = build_router(h.state.clone());
    (h, store)
}

async fn exercise(h: &Harness, store: &Arc<Store>) {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":7,"result":{"tools":[]}
        })))
        .mount(&upstream)
        .await;
    let endpoint = h
        .post(
            "/api/v1/mcp/endpoints",
            json!({
                "expected_version":0,"name":"webhook-chain","url":format!("{}/mcp",upstream.uri()),
                "enabled":true,"idle_timeout_secs":5
            }),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::OK, "{}", endpoint.text);
    let asset_id = Id::parse(endpoint.json()["id"].as_str().unwrap()).unwrap();
    let automation = h
        .post(
            "/api/v1/soar/automations",
            json!({
                "enabled":true,"reason":"Verify automatic webhook response","playbook":{
                    "key":"webhook-chain","name":"Webhook response",
                    "trigger":{"min_severity":"high"},"require_approval":true,
                    "steps":[{"name":"Block test domain","action":"block-domain",
                        "params":{"domain":"webhook-chain.example"}}]
                }
            }),
        )
        .await;
    assert_eq!(automation.status, StatusCode::OK, "{}", automation.text);
    let key = format!("requirements-webhook-{}", Id::new());
    let payload = json!({"message":"requirements-event-warning", "severity":"high",
        "category":"ai-tool-call", "mcp":asset_id.to_string()});
    let parser = h
        .post(
            "/api/v1/parsers",
            json!({
                "definition":{"key":key,"name":"Webhook AI event","engine":"json-path",
                    "pattern":"$","required_fields":["message","mcp"],"mapping":{"map":{
                        "message":"message","severity":"event.severity",
                        "category":"event.category","mcp":"ai.mcp_server_id"}}},
                "sample":payload.to_string(),"enabled":true,"priority":1
            }),
        )
        .await;
    assert_eq!(parser.status, StatusCode::CREATED, "{}", parser.text);
    let source = h
        .post(
            "/api/v1/ingest/sources",
            json!({"name":"Webhook AI events",
        "protocol":"http-webhook","parserId":parser.json()["id"]}),
        )
        .await;
    assert_eq!(source.status, StatusCode::CREATED, "{}", source.text);
    let source_id = source.json()["id"].as_str().unwrap().to_owned();
    let push_uri = format!("/api/v1/ingest/sources/{source_id}/events");
    let pushed = h.post(&push_uri, payload).await;
    assert_eq!(pushed.status, StatusCode::OK, "{}", pushed.text);
    assert_eq!(pushed.json()["accepted"], 1);
    assert_eq!(pushed.json()["matched"], 1);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let (event_id, alert_id, finding_id) = loop {
        let status = h.get("/api/v1/sources/delivery").await;
        assert_eq!(status.status, StatusCode::OK, "{}", status.text);
        let cases = h.state.store.case_list_durable(h.tenant).await.unwrap();
        if status.json()["analysis"]["processed"] == 1 && cases.len() == 1 {
            let tenant = h.tenant;
            let row: (uuid::Uuid, bool, serde_json::Value, serde_json::Value) = store
                .with_tenant(tenant, |tx| {
                    Box::pin(async move {
                        sqlx::query_as(
                            "SELECT e.id, q.delivered_at IS NOT NULL, r.alert_ids, r.finding_ids \
                    FROM events e JOIN event_delivery_outbox q ON q.event_id=e.id \
                    JOIN event_analysis_receipts r ON r.event_id=e.id LIMIT 1",
                        )
                        .fetch_one(&mut **tx)
                        .await
                        .map_err(|e| agf_storage::map_sqlx_err("webhook_chain", &e))
                    })
                })
                .await
                .unwrap();
            if row.1 {
                let alert_id = Id::parse(row.2[0].as_str().unwrap()).unwrap();
                let finding_id = Id::parse(row.3[0].as_str().unwrap()).unwrap();
                assert_eq!(cases[0].alert_ids, vec![alert_id]);
                assert_eq!(cases[0].asset_ids, vec![asset_id]);
                break (Id::from_uuid(row.0), alert_id, finding_id);
            }
        }
        assert!(tokio::time::Instant::now() < deadline, "webhook/background chain timed out: {}", status.text);
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let event = h.get(&format!("/api/v1/ingest/events/{event_id}")).await;
    assert_eq!(event.status, StatusCode::OK, "{}", event.text);
    assert_eq!(event.json()["event"]["ai"]["mcp_server_id"], asset_id.to_string());
    let alert = h.get(&format!("/api/v1/alerts/{alert_id}")).await;
    assert_eq!(alert.status, StatusCode::OK, "{}", alert.text);
    assert_eq!(alert.json()["alert"]["asset_ids"], json!([asset_id]));
    assert_eq!(alert.json()["alert"]["finding_ids"], json!([finding_id]));
    let asset = h.get(&format!("/api/v1/assets/{asset_id}")).await;
    assert_eq!(asset.json()["asset"]["open_findings"], 1);
    let bus =
        JetStreamEventBus::connect(&h.state.config.nats.url, &h.state.config.nats.stream, "agf.events").await.unwrap();
    let mut consumer = bus.consumer("agf-correlation-v1").await.unwrap();
    let broker_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let info = consumer.info().await.unwrap();
        if info.ack_floor.stream_sequence >= 1 && info.num_ack_pending == 0 {
            break;
        }
        assert!(tokio::time::Instant::now() < broker_deadline, "event did not receive broker consumer ACK");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut restarted = h.clone();
    restarted.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    restarted.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store.clone())));
    sql_runtime_identity::rebind(&mut restarted.state, &[h.tenant, h.other_tenant]).await.unwrap();
    restarted.app = build_router(restarted.state.clone());
    assert_eq!(restarted.get(&format!("/api/v1/alerts/{alert_id}")).await.status, StatusCode::OK);
    assert_eq!(restarted.state.store.case_list_durable(h.tenant).await.unwrap().len(), 1);

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
            json!({"name":"webhook-chain-deny",
        "structured":{"command_deny":["webhook-chain-danger"]},"action":"deny",
        "intercept_points":["mcp-proxy"]}),
        )
        .await;
    assert_eq!(policy.status, StatusCode::CREATED, "{}", policy.text);
    assert_eq!(h.post("/api/v1/policies/reload", json!({})).await.status, StatusCode::OK);
    let blocked = h
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
                "name":"query","arguments":{"command":"webhook-chain-danger"},
                "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}
            }})),
        )
        .await;
    assert_eq!(blocked.status, StatusCode::FORBIDDEN, "{}", blocked.text);
    assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
    assert!(agf_api::containment::list(&h.state, h.tenant).await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL and local AGF_TEST_NATS_URL"]
async fn external_webhook_reaches_broker_background_case_and_real_proxy() {
    let url = std::env::var("AGF_TEST_NATS_URL").unwrap();
    assert!(url.starts_with("nats://127.0.0.1:") || url.starts_with("nats://localhost:"));
    let stream = format!("AGF_REQUIREMENTS_{}", uuid::Uuid::new_v4().simple());
    let (h, store) = sql_harness(&url, &stream).await;
    JetStreamEventBus::connect(&url, &stream, "agf.events").await.unwrap();
    let delivery = tokio::spawn(agf_api::event_delivery::run_loop(h.state.clone()));
    let analysis = tokio::spawn(agf_api::event_analysis::run_loop(h.state.clone()));
    let response = tokio::spawn(agf_api::soar_workflow::run_loop(h.state.clone()));
    let trial = tokio::spawn(async move { exercise(&h, &store).await }).await;
    delivery.abort();
    analysis.abort();
    response.abort();
    async_nats::jetstream::new(async_nats::connect(&url).await.unwrap()).delete_stream(&stream).await.unwrap();
    trial.unwrap();
}
