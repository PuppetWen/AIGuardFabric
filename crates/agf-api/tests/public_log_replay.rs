//! Five public captures through production Webhook ingestion and GET-preview / POST-replay.
//! Axum HTTP requests use original bodies; no listener, database or external network is needed.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

mod common;

use agf_core::{enums::IngestProtocol, event::Event, ids::Id};
use agf_ingest::pipeline::InMemorySink;
use base64::Engine as _;
use common::*;

const MANIFEST: &str = include_str!("../../../tests/fixtures/logs/public/manifest.json");
const FIXTURES: &[(&str, &str)] = &[
    ("aws-cloudtrail-json", include_str!("../../../tests/fixtures/logs/public/aws-cloudtrail-json.log")),
    (
        "azure-entra-service-principal-json",
        include_str!("../../../tests/fixtures/logs/public/azure-entra-service-principal-json.log"),
    ),
    (
        "crowdstrike-falcon-fdr-process-json",
        include_str!("../../../tests/fixtures/logs/public/crowdstrike-falcon-fdr-process-json.log"),
    ),
    ("paloalto-panos-threat-csv", include_str!("../../../tests/fixtures/logs/public/paloalto-panos-threat-csv.log")),
    ("zeek-conn-json", include_str!("../../../tests/fixtures/logs/public/zeek-conn-json.log")),
];

fn event_field(event: &Event, path: &str) -> Option<String> {
    match path {
        "event.category" => Some(event.category.as_str().to_owned()),
        "event.severity" => Some(event.severity.as_str().to_owned()),
        "event.action_raw" => Some(event.action_raw.clone()),
        "source.ip" => event.network.source_ip.clone(),
        "destination.ip" => event.network.destination_ip.clone(),
        "network.transport" => event.network.transport.clone(),
        "host.id" => event.host.id.clone(),
        "user.id" => event.user.id.clone(),
        "user.name" => event.user.name.clone(),
        // Vendor event IDs remain extra fields; replay assigns its own new Event.id.
        _ => event.extra.get(path).and_then(agf_ingest::engine::value_to_text),
    }
}

fn source_input(key: &str, protocol: &str) -> Value {
    match protocol {
        "object-storage" => json!({"name":key,"protocol":"native","nativeReceiver":"object-pull",
            "parserId":key,"enabled":false}),
        "syslog" => json!({"name":key,"protocol":"native","nativeReceiver":"syslog-tcp",
            "parserId":key,"enabled":false}),
        // Zeek also supports HTTP pull. This disabled source only binds the production parser;
        // its transport is never invoked by the raw-log preview/replay routes.
        "file" => json!({"name":key,"protocol":"http-pull","endpoint":"http://127.0.0.1:9/public-fixture",
            "parserId":key,"enabled":false}),
        _ => panic!("unexpected public fixture protocol"),
    }
}

async fn replay_sample(h: &Harness, sink: &InMemorySink, row: &Value) {
    let key = row["key"].as_str().unwrap();
    let text = FIXTURES.iter().find(|(name, _)| *name == key).expect("known fixture").1;
    let parser = h.state.parsers.find_key(key).expect("production YAML parser must be loaded");
    assert_eq!(parser.definition.vendor, row["vendor"].as_str().unwrap());
    assert_eq!(parser.definition.product, row["product"].as_str().unwrap());
    let created = h.post("/api/v1/ingest/sources", source_input(key, row["protocol"].as_str().unwrap())).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    assert_eq!(created.json()["parser_id"], parser.id.to_string());
    let source = Id::parse(created.json()["id"].as_str().unwrap()).unwrap();
    let protocol = IngestProtocol::all().into_iter().find(|p| Some(p.as_str()) == row["protocol"].as_str()).unwrap();
    let raw = replay_raw_log(h.tenant, key, source, protocol, text, None);
    let encoded = base64::engine::general_purpose::STANDARD.decode(&raw.payload_b64).unwrap();
    assert_eq!(encoded.as_slice(), text.as_bytes(), "original line ending and whitespace");
    assert_eq!(raw.payload_hash.to_uppercase(), row["fixtureSha256"].as_str().unwrap());
    h.state.ingest_sink.put_raw(&raw).await.unwrap();
    let foreign = replay_raw_log(h.other_tenant, key, source, protocol, text, None);
    h.state.ingest_sink.put_raw(&foreign).await.unwrap();
    let event_count = h.state.ingest_sink.event_count(h.tenant).await.unwrap();
    let audit_count = h.state.store.audit_chain(h.tenant, 0, 10_000).unwrap().len();
    let uri = format!("/api/v1/ingest/replay?sourceId={source}");
    let denied = h.request("GET", &uri, Some(&h.viewer), None).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    let preview = h.get(&uri).await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.text);
    let preview = preview.json();
    assert_eq!(preview["preview_only"], true);
    assert_eq!(preview["replayed"], 0);
    assert_eq!(preview["unparsed_total_for_source"], 1, "foreign tenant must be excluded");
    assert_original_preview(&preview, text);
    assert_eq!(h.state.ingest_sink.event_count(h.tenant).await.unwrap(), event_count);
    assert_eq!(h.state.store.audit_chain(h.tenant, 0, 10_000).unwrap().len(), audit_count);
    assert!(h.state.ingest_sink.unparsed_raw(h.tenant, 100).await.unwrap().iter().any(|r| r.id == raw.id));

    let response = h.post("/api/v1/ingest/replay", json!({"sourceId":source})).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let report = response.json();
    assert_eq!(report["replayed"], 1, "{key}: {report}");
    assert_eq!(report["newly_parsed"], 1, "{key}: {report}");
    assert_eq!(report["failed"], 0, "{key}: {report}");
    assert_eq!(report["parser_used"][key], 1, "configured production parser: {report}");
    assert!(report["diffs"].as_array().unwrap().is_empty(), "no previous event exists for these raw rows");
    assert_original_preview(&report, text);
    assert_eq!(h.state.ingest_sink.event_count(h.tenant).await.unwrap(), event_count + 1);
    let events = sink.events().unwrap();
    let events: Vec<_> =
        events.iter().filter(|event| event.tenant_id == h.tenant && event.source_id == source).collect();
    assert_eq!(events.len(), 1);
    assert_replayed_event(events[0], row, text, parser.id);
    let retained = sink.raws().unwrap();
    let retained = retained.iter().find(|stored| stored.id == raw.id).unwrap();
    assert!(retained.parsed);
    assert_eq!(retained.event_id, Some(events[0].id));
    assert_eq!(retained.payload_b64, raw.payload_b64);
    assert_eq!(retained.payload_hash, raw.payload_hash);
    assert_eq!(retained.bytes, raw.bytes);
    assert!(!h.state.ingest_sink.unparsed_raw(h.tenant, 100).await.unwrap().iter().any(|r| r.id == raw.id));
    assert!(h.state.ingest_sink.unparsed_raw(h.other_tenant, 100).await.unwrap().iter().any(|r| r.id == foreign.id));
    assert_eq!(h.state.ingest_sink.event_count(h.other_tenant).await.unwrap(), 0);
    let repeated = h.post("/api/v1/ingest/replay", json!({"sourceId":source})).await;
    assert_eq!(repeated.status, StatusCode::OK, "{}", repeated.text);
    assert_eq!(repeated.json()["replayed"], 0);
    assert_eq!(repeated.json()["newly_parsed"], 0);
    assert_eq!(h.state.ingest_sink.event_count(h.tenant).await.unwrap(), event_count + 1);
}

fn assert_original_preview(response: &Value, text: &str) {
    let rows = response["raw_logs"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["payload"].as_str().unwrap().as_bytes(), text.as_bytes());
    assert_eq!(rows[0]["bytes"].as_u64(), Some(u64::try_from(text.len()).unwrap()));
    assert_eq!(
        agf_core::secret::content_hash(rows[0]["payload"].as_str().unwrap()),
        agf_core::secret::content_hash(text)
    );
}

fn assert_replayed_event(event: &Event, row: &Value, text: &str, parser: Id) {
    assert_eq!(event.parser_id, Some(parser));
    assert_eq!(event.parser_name.as_deref(), row["key"].as_str());
    assert_eq!(event.raw_hash.to_uppercase(), row["fixtureSha256"].as_str().unwrap());
    assert_eq!(event.raw, agf_ingest::normalize::parse_raw_value(text));
    for (path, expected) in row["expect"].as_object().unwrap() {
        assert_eq!(event_field(event, path).as_deref(), expected.as_str(), "{}: {path}", row["key"]);
    }
}

#[tokio::test]
async fn five_public_originals_get_preview_then_post_replay_with_bound_production_parsers() {
    let mut h = Box::pin(setup_console()).await;
    let sink = Arc::new(InMemorySink::new());
    h.state.ingest_sink = sink.clone();
    h.app = build_router(h.state.clone());
    let manifest: Value = serde_json::from_str(MANIFEST).unwrap();
    let rows = manifest["samples"].as_array().unwrap();
    assert_eq!(rows.len(), 5);
    assert_eq!(h.state.ingest_sink.event_count(h.tenant).await.unwrap(), 0);
    for row in rows {
        Box::pin(replay_sample(&h, &sink, row)).await;
    }
    assert_eq!(h.state.ingest_sink.event_count(h.tenant).await.unwrap(), 5);
    assert!(h.state.ingest_sink.unparsed_raw(h.tenant, 100).await.unwrap().is_empty());
    assert_eq!(h.state.ingest_sink.unparsed_raw(h.other_tenant, 100).await.unwrap().len(), 5);
}

async fn receive_public_original_then_replay(h: &Harness, sink: &Arc<InMemorySink>, row: &Value) {
    use agf_ingest::{
        bus::NoopEventBus,
        pipeline::{IngestConfig, IngestPipeline},
        receiver::{WebhookReceiver, webhook_router},
        registry::ParserRegistry,
    };

    let key = row["key"].as_str().unwrap();
    let text = FIXTURES.iter().find(|(name, _)| *name == key).unwrap().1;
    let parser = h.state.parsers.find_key(key).expect("production parser");
    let created = h.post("/api/v1/ingest/sources", json!({"name":key,"protocol":"http-webhook"})).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let id = Id::parse(created.json()["id"].as_str().unwrap()).unwrap();
    let source = agf_api::source_store::load(&h.state, h.tenant, id).await.unwrap().source.unwrap();
    assert!(source.enabled);
    assert!(source.parser_id.is_none());
    // The capture arrives before this receiver has a parser. The production pipeline
    // must retain the unmatched original; the console binds its parser before replay.
    let pipeline = Arc::new(IngestPipeline::new(
        ParserRegistry::new(),
        sink.clone(),
        Arc::new(NoopEventBus),
        IngestConfig { emit_to_bus: false, ..IngestConfig::default() },
    ));
    let app = webhook_router(Arc::new(
        WebhookReceiver::new(pipeline, source, "/public-capture").with_token("public-capture-token"),
    ));
    let before = sink.raws().unwrap().len();
    for token in [None, Some("Bearer wrong-token")] {
        let mut request = Request::builder().method("POST").uri("/public-capture");
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, token);
        }
        let denied = send(&app, request.body(Body::from(text.as_bytes().to_vec())).unwrap()).await;
        assert_eq!(denied.status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(sink.raws().unwrap().len(), before);
    let received = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/public-capture")
            .header(header::AUTHORIZATION, "Bearer public-capture-token")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(text.as_bytes().to_vec()))
            .unwrap(),
    )
    .await;
    assert_eq!(received.status, StatusCode::ACCEPTED, "{key}: {}", received.text);
    assert_eq!(received.json()["accepted"], 1);
    assert_eq!(received.json()["matched"], 0);
    let raw = sink.raws().unwrap().into_iter().find(|raw| raw.source_id == id).unwrap();
    assert_eq!(raw.tenant_id, h.tenant);
    assert_eq!(raw.protocol, IngestProtocol::Webhook);
    assert!(!raw.parsed);
    assert_eq!(base64::engine::general_purpose::STANDARD.decode(&raw.payload_b64).unwrap(), text.as_bytes());
    assert_eq!(raw.payload_hash.to_uppercase(), row["fixtureSha256"].as_str().unwrap());
    assert_eq!(raw.bytes, text.len());
    let bound = h
        .request(
            "PUT",
            &format!("/api/v1/ingest/sources/{id}"),
            Some(&h.admin),
            Some(json!({"name":key,"protocol":"http-webhook","parserId":key})),
        )
        .await;
    assert_eq!(bound.status, StatusCode::OK, "{}", bound.text);
    assert_eq!(bound.json()["parser_id"], parser.id.to_string());
    let uri = format!("/api/v1/ingest/replay?sourceId={id}");
    let events_before = h.state.ingest_sink.event_count(h.tenant).await.unwrap();
    let audit_before = h.state.store.audit_chain(h.tenant, 0, 10_000).unwrap().len();
    assert_eq!(h.request("GET", &uri, Some(&h.viewer), None).await.status, StatusCode::FORBIDDEN);
    let preview = h.get(&uri).await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.text);
    assert_eq!(preview.json()["preview_only"], true);
    assert_eq!(preview.json()["replayed"], 0);
    assert_original_preview(&preview.json(), text);
    assert_eq!(h.state.ingest_sink.event_count(h.tenant).await.unwrap(), events_before);
    assert_eq!(h.state.store.audit_chain(h.tenant, 0, 10_000).unwrap().len(), audit_before);
    assert!(!sink.raws().unwrap().into_iter().find(|stored| stored.id == raw.id).unwrap().parsed);
    let replay = h.post("/api/v1/ingest/replay", json!({"sourceId":id})).await;
    assert_eq!(replay.status, StatusCode::OK, "{key}: {}", replay.text);
    assert_eq!(replay.json()["newly_parsed"], 1);
    assert_eq!(replay.json()["failed"], 0);
    assert_eq!(replay.json()["parser_used"][key], 1);
    assert_original_preview(&replay.json(), text);
    assert_eq!(h.state.ingest_sink.event_count(h.tenant).await.unwrap(), events_before + 1);
    let events = sink.events().unwrap();
    let event = events.iter().find(|event| event.source_id == id && event.parser_id == Some(parser.id)).unwrap();
    assert_replayed_event(event, row, text, parser.id);
    let retained = sink.raws().unwrap().into_iter().find(|stored| stored.id == raw.id).unwrap();
    assert!(retained.parsed);
    assert_eq!(retained.event_id, Some(event.id));
    assert_eq!(retained.payload_b64, raw.payload_b64);
    assert_eq!(retained.payload_hash, raw.payload_hash);
    assert_eq!(retained.bytes, raw.bytes);
    let repeated = h.post("/api/v1/ingest/replay", json!({"sourceId":id})).await;
    assert_eq!(repeated.status, StatusCode::OK);
    assert_eq!(repeated.json()["newly_parsed"], 0);
    assert_eq!(h.state.ingest_sink.event_count(h.tenant).await.unwrap(), events_before + 1);
}

#[tokio::test]
async fn five_public_originals_enter_authenticated_webhook_before_preview_and_replay() {
    let mut h = Box::pin(setup_console()).await;
    let sink = Arc::new(InMemorySink::new());
    h.state.ingest_sink = sink.clone();
    h.app = build_router(h.state.clone());
    let manifest: Value = serde_json::from_str(MANIFEST).unwrap();
    for row in manifest["samples"].as_array().unwrap() {
        Box::pin(receive_public_original_then_replay(&h, &sink, row)).await;
    }
    assert_eq!(h.state.ingest_sink.raw_count(h.tenant).await.unwrap(), 5);
    assert!(h.state.ingest_sink.unparsed_raw(h.tenant, 100).await.unwrap().is_empty());
}
