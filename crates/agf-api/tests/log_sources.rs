//! Configured sources drive actual ingestion and bounded, credential-safe pull requests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::{
    source_store::{self, KIND, Record},
    source_worker,
};
use agf_core::ids::Id;
use common::*;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

#[tokio::test]
async fn source_crud_permissions_tenant_isolation_and_push() {
    let h = setup().await;
    let query_source = h
        .post(
            "/api/v1/ingest/sources",
            json!({"name":"query-source", "protocol":"http-pull",
        "endpoint":"https://logs.example.test/events?limit=100", "enabled":false}),
        )
        .await;
    assert_eq!(query_source.status, StatusCode::CREATED, "{}", query_source.text);
    let query_id = query_source.json()["id"].as_str().unwrap().to_owned();
    assert_eq!(
        h.request("DELETE", &format!("/api/v1/ingest/sources/{query_id}"), Some(&h.admin), None).await.status,
        StatusCode::OK
    );
    let input = json!({"name":"audit", "protocol":"http-webhook"});
    assert_eq!(
        h.request("POST", "/api/v1/ingest/sources", None, Some(input.clone())).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h.request("POST", "/api/v1/ingest/sources", Some(&h.viewer), Some(input.clone())).await.status,
        StatusCode::FORBIDDEN
    );
    let created = h.post("/api/v1/ingest/sources", input).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let id = created.json()["id"].as_str().unwrap().to_string();
    let uri = format!("/api/v1/ingest/sources/{id}");
    let events = format!("{uri}/events");
    let foreign = h
        .request_with(
            "GET",
            &uri,
            &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.other_tenant.to_string())],
            None,
        )
        .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);
    let pushed = h.post(&events, json!([{"message":"one"},{"message":"two"}])).await;
    assert_eq!(pushed.status, StatusCode::OK, "{}", pushed.text);
    assert_eq!(pushed.json()["received"], 2);
    assert_eq!(pushed.json()["accepted"], 2);
    let row = h.get(&uri).await.json();
    assert_eq!(row["source"]["total_events"], 2);
    assert_eq!(h.get("/api/v1/ingest/sources?q=audit").await.json()["total"], 1);
    assert_eq!(h.get("/api/v1/ingest/sources?q=missing").await.json()["total"], 0);
    let oversized = h.post(&events, json!(vec![json!({"message":"x"}); 1001])).await;
    assert_eq!(oversized.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.get(&uri).await.json()["source"]["total_events"], 2);
    assert_eq!(h.request("PATCH", &uri, Some(&h.admin), Some(json!({"enabled":false}))).await.status, StatusCode::OK);
    assert_eq!(h.post(&events, json!({"message":"disabled"})).await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.request("DELETE", &uri, Some(&h.admin), None).await.status, StatusCode::OK);
    assert_eq!(h.get(&uri).await.status, StatusCode::NOT_FOUND);
    assert_eq!(h.get("/api/v1/ingest/sources").await.json()["total"], 0);
}

#[tokio::test]
async fn pulling_seals_credentials_persists_cursor_and_keeps_only_one_lease() {
    let h = setup().await;
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/logs"))
        .and(header("authorization", "Bearer local-test-secret"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-agf-next-cursor", "page-2")
                .set_body_json(json!([{"message":"first"}])),
        )
        .expect(1)
        .mount(&upstream)
        .await;
    let created = h
        .post(
            "/api/v1/ingest/sources",
            json!({
                "name":"local pull", "protocol":"http-pull", "endpoint":format!("{}/logs",upstream.uri()),
                "headers":{"Authorization":"Bearer local-test-secret"}, "pollIntervalSecs":5
            }),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    assert!(!created.text.contains("local-test-secret"));
    let id = Id::parse(created.json()["id"].as_str().unwrap()).unwrap();
    let record: Record = h.state.configurations.get(h.tenant, KIND, id).await.unwrap().unwrap();
    assert!(!serde_json::to_string(&record).unwrap().contains("local-test-secret"));
    let summary = source_worker::poll(&h.state, h.tenant, id, true).await.unwrap().unwrap();
    assert_eq!(summary.accepted, 1);
    let record = source_store::load(&h.state, h.tenant, id).await.unwrap();
    assert_eq!(record.cursor.as_deref(), Some("page-2"));
    upstream.verify().await;
    upstream.reset().await;
    Mock::given(method("GET"))
        .and(path("/logs"))
        .and(header("x-agf-cursor", "page-2"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(60))
                .insert_header("x-agf-next-cursor", "page-3")
                .set_body_json(json!([{"message":"second"}])),
        )
        .expect(1)
        .mount(&upstream)
        .await;
    let (one, two) = tokio::join!(
        source_worker::poll(&h.state, h.tenant, id, true),
        source_worker::poll(&h.state, h.tenant, id, true)
    );
    assert_ne!(one.unwrap().is_some(), two.unwrap().is_some());
    assert_eq!(source_store::load(&h.state, h.tenant, id).await.unwrap().cursor.as_deref(), Some("page-3"));
    assert!(source_worker::poll(&h.state, h.tenant, id, false).await.unwrap().is_none());
    let scheduled = h.post(&format!("/api/v1/ingest/sources/{id}/poll?manual=false"), json!({})).await;
    assert_eq!(scheduled.status, StatusCode::OK, "{}", scheduled.text);
    assert_eq!(scheduled.json()["skipped"], true);
    let invalid = h.post(&format!("/api/v1/ingest/sources/{id}/poll?manual=maybe"), json!({})).await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn failed_pull_does_not_advance_cursor_or_follow_redirect() {
    let h = setup().await;
    let upstream = MockServer::start().await;
    Mock::given(path("/oversized"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-agf-next-cursor", "lost")
                .set_body_json(json!(vec![json!({"x":1}); 1001])),
        )
        .mount(&upstream)
        .await;
    let created = h
        .post(
            "/api/v1/ingest/sources",
            json!({"name":"oversized","protocol":"http-pull",
        "endpoint":format!("{}/oversized",upstream.uri())}),
        )
        .await
        .json();
    let id = Id::parse(created["id"].as_str().unwrap()).unwrap();
    assert!(source_worker::poll(&h.state, h.tenant, id, true).await.is_err());
    let record = source_store::load(&h.state, h.tenant, id).await.unwrap();
    assert!(record.cursor.is_none());
    assert_eq!(record.lease_until, 0);
    assert!(record.source.unwrap().last_error.is_some());
    Mock::given(path("/redirect"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", format!("{}/leak", upstream.uri())))
        .mount(&upstream)
        .await;
    Mock::given(path("/leak")).respond_with(ResponseTemplate::new(200)).expect(0).mount(&upstream).await;
    let created = h
        .post(
            "/api/v1/ingest/sources",
            json!({"name":"redirect","protocol":"http-pull",
        "endpoint":format!("{}/redirect",upstream.uri()),"headers":{"Authorization":"Bearer never-leak"}}),
        )
        .await
        .json();
    let id = Id::parse(created["id"].as_str().unwrap()).unwrap();
    let error = source_worker::poll(&h.state, h.tenant, id, true).await.unwrap_err().to_string();
    assert!(error.contains("302"));
    assert!(!error.contains("never-leak"));
}

#[tokio::test]
async fn selected_loaded_parser_is_used_by_ingestion_pipeline() {
    let mut h = setup().await;
    let sink = Arc::new(agf_ingest::pipeline::InMemorySink::new());
    h.state.ingest_sink = sink.clone();
    let mut definition = h.state.parsers.find_key("aliyun-waf-webhook").unwrap().definition.clone();
    definition.key = "custom-loaded-waf".into();
    let parser = Arc::make_mut(&mut h.state.parsers).register(definition, 1).unwrap();
    h.app = build_router(h.state.clone());
    let response = h
        .post("/api/v1/ingest/sources", json!({"name":"loaded parser","protocol":"http-webhook","parserId":parser}))
        .await
        .json();
    let source_id = Id::parse(response["id"].as_str().unwrap()).unwrap();
    let events = format!("/api/v1/ingest/sources/{source_id}/events");
    let payload = json!({"time":"2026-09-20T00:00:00Z","host":"example.test","real_client_ip":"192.0.2.1",
        "request_method":"GET","request_uri":"/","rule_id":"waf-test","acl_action":"block","status":403});
    let result = h.post(&events, payload.clone()).await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
    assert_eq!(result.json()["matched"], 1, "{}", result.text);
    let rows = sink.events().unwrap();
    assert!(rows.iter().any(|event| event.parser_id == Some(parser)), "source parser binding must be honored");
    let raw = replay_raw_log(
        h.tenant,
        "loaded-parser-replay",
        source_id,
        agf_core::enums::IngestProtocol::Webhook,
        &payload.to_string(),
        None,
    );
    h.state.ingest_sink.put_raw(&raw).await.unwrap();
    let replay = h.post("/api/v1/ingest/replay", json!({"source_id":source_id})).await;
    assert_eq!(replay.status, StatusCode::OK, "{}", replay.text);
    assert_eq!(replay.json()["parser_used"]["custom-loaded-waf"], 1);
}
