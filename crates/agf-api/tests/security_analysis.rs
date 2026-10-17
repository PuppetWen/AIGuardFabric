//! Owned loopback provider replay exercises gateway policy/classification, metering and grounded output.
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
use agf_core::{
    asset::Asset,
    enums::{AssetKind, DataClass},
    ids::Id,
};
use common::*;
use std::sync::atomic::{AtomicUsize, Ordering};

async fn alert(h: &Harness) -> String {
    let response = h
        .post(
            "/api/v1/alerts",
            json!({"title":"Evidence fixture","severity":"medium",
        "description":"DO_NOT_SEND_RAW_OR_SECRET"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    response.json()["alert_id"].as_str().unwrap().into()
}

async fn mock_endpoint(h: &Harness) {
    let response = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":"owned-analysis-mock",
        "provider":"mock","model":"fixture-analysis","base_url":"http://mock.invalid/v1",
        "local_deployment":true,"max_data_class":"internal"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
}

#[tokio::test]
async fn mock_analysis_has_actual_usage_and_requires_permissions_and_tenant_scope() {
    let h = setup().await;
    mock_endpoint(&h).await;
    let id = alert(&h).await;
    let path = format!("/api/v1/alerts/{id}/analysis");
    let denied = h.request("POST", &path, Some(&h.viewer), Some(json!({}))).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    let key = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("alerts:read"), Permission::from_raw("alerts:write")],
        ..ApiKeyIssueRequest::named(h.tenant, "analysis-no-model-permission", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&key.record).await.unwrap();
    assert_eq!(
        h.request_with("POST", &path, &[("x-agf-key", &key.plaintext)], Some(json!({}))).await.status,
        StatusCode::FORBIDDEN
    );
    let other = h
        .request_with(
            "POST",
            &path,
            &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.other_tenant.to_string())],
            Some(json!({})),
        )
        .await;
    assert_ne!(other.status, StatusCode::OK);
    assert!(agf_api::gateway_quota::usage(&h.state, h.tenant).await.unwrap().is_empty());
    assert_eq!(
        h.post(&path, json!({"tenant_id":h.other_tenant,"raw":"not allowed"})).await.status,
        StatusCode::BAD_REQUEST
    );
    let result = h.post(&path, json!({})).await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
    let value = result.json()["analysis"].clone();
    assert_eq!(value["mocked"], true);
    assert_eq!(value["cached"], false);
    assert_eq!(value["model_response_used"], false);
    assert_eq!(value["context_budget_tokens"], 2048);
    assert!(!value["snapshot"].to_string().contains("DO_NOT_SEND_RAW_OR_SECRET"));
    assert_eq!(value["assessment"]["verdict"], "unknown");
    assert!(value["assessment"]["summary"].as_str().unwrap().contains("Mock demonstration"));
    let usage = agf_api::gateway_quota::usage(&h.state, h.tenant).await.unwrap();
    assert_eq!(usage.len(), 1);
    assert!(usage[0].mocked);
    assert_eq!(value["usage_record_id"], json!(usage[0].id));
    assert_eq!(value["prompt_tokens"], usage[0].prompt_tokens);
    assert_eq!(value["completion_tokens"], usage[0].completion_tokens);
    assert_eq!(value["cost_micro_cny"], usage[0].cost_micro);
    assert_eq!(h.get(&path).await.json()["analysis"]["id"], value["id"]);
    assert!(h.state.store.audit_verify_durable(h.tenant).await.unwrap().passed);
}

async fn provider(
    axum::extract::State((mode, calls)): axum::extract::State<(Arc<AtomicUsize>, Arc<AtomicUsize>)>,
    axum::Json(body): axum::Json<Value>,
) -> axum::Json<Value> {
    calls.fetch_add(1, Ordering::SeqCst);
    assert_eq!(body["response_format"]["type"], "json_schema");
    assert_eq!(body["response_format"]["json_schema"]["name"], "agf_security_assessment");
    assert_eq!(body["response_format"]["json_schema"]["strict"], true);
    let schema = &body["response_format"]["json_schema"]["schema"];
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert!(body["tools"].is_null());
    let input: Value = serde_json::from_str(body["messages"][1]["content"].as_str().unwrap()).unwrap();
    assert!(!input.to_string().contains("DO_NOT_SEND_RAW_OR_SECRET"));
    let refs: Vec<_> = input["facts"].as_array().unwrap().iter().map(|fact| fact["reference"].clone()).collect();
    assert_eq!(schema["properties"]["evidence_refs"]["items"]["enum"], json!(refs));
    let current_mode = mode.load(Ordering::SeqCst);
    let content = match current_mode {
        1 => "invalid model JSON".into(),
        2 => json!({"verdict":"suspicious","confidence":0.7,"summary":"Replay assessment","evidence_refs":["event:invented"],"observations":[],"timeline":[],"hypotheses":[]}).to_string(),
        _ => json!({"verdict":"suspicious","confidence":0.7,"summary":"Replay assessment","evidence_refs":refs,"observations":[],"timeline":[],"hypotheses":[]}).to_string(),
    };
    let finish_reason = match current_mode {
        3 => "length",
        4 => "content_filter",
        5 => "tool_calls",
        _ => "stop",
    };
    axum::Json(json!({"id":"owned-replay","object":"chat.completion","model":"fixture-analysis","choices":[
        {"index":0,"message":{"role":"assistant","content":content},"finish_reason":finish_reason}],
        "usage":{"prompt_tokens":24,"completion_tokens":12}}))
}

#[tokio::test]
async fn live_replay_invalid_output_and_classification_preserve_prior_analysis_and_usage_truth() {
    let mode = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().fallback(axum::routing::post(provider)).with_state((mode.clone(), calls.clone()));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let endpoint=h.post("/api/v1/gateway/endpoints",json!({"name":"owned-analysis-replay","provider":"ollama","model":"fixture-analysis","base_url":address,"local_deployment":true,"max_data_class":"internal",
        "pricing":{"prompt_micro_per_1k":1000,"completion_micro_per_1k":2000,"cached_prompt_micro_per_1k":0}})).await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let id = alert(&h).await;
    let path = format!("/api/v1/alerts/{id}/analysis");
    let success = h.post(&path, json!({})).await;
    assert_eq!(success.status, StatusCode::OK, "{}", success.text);
    let analysis = success.json()["analysis"].clone();
    assert_eq!(analysis["mocked"], false);
    assert_eq!(analysis["model_response_used"], true);
    assert_eq!(analysis["prompt_tokens"], 24);
    assert_eq!(analysis["completion_tokens"], 12);
    assert_eq!(analysis["cost_micro_cny"], 48);
    for invalid in [1, 2, 3, 4, 5] {
        mode.store(invalid, Ordering::SeqCst);
        assert_eq!(h.post(&path, json!({})).await.status, StatusCode::BAD_REQUEST);
        assert_eq!(h.get(&path).await.json()["analysis"]["id"], analysis["id"]);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 6);
    let usage = agf_api::gateway_quota::usage(&h.state, h.tenant).await.unwrap();
    assert_eq!(usage.len(), 6, "Invalid and incomplete output is still a real metered provider call");
    assert!(usage.iter().all(|row| row.cost_micro == 48));
    let mut asset = Asset::new(h.tenant, AssetKind::Agent, "Restricted fixture", Id::new().to_string());
    asset.data_class = DataClass::Restricted;
    h.state.store.asset_upsert(&asset).unwrap();
    let restricted =
        h.post("/api/v1/alerts", json!({"title":"Restricted classification","asset_ids":[asset.id]})).await;
    let restricted_id = restricted.json()["alert_id"].as_str().unwrap().to_string();
    assert_ne!(h.post(&format!("/api/v1/alerts/{restricted_id}/analysis"), json!({})).await.status, StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 6, "Source classification cannot be lowered by request input");
    server.abort();
}

#[tokio::test]
async fn projected_metadata_never_sends_arbitrary_rule_codes_or_hash_fields() {
    use agf_core::{
        enums::{IngestProtocol, RiskDomain, Severity},
        event::Event,
        rbac::SubjectKind,
        risk::{Evidence, Finding},
    };
    let h = setup().await;
    let sentinel = "DO_NOT_SEND_RAW_OR_SECRET";
    let mut event = Event::new(h.tenant, Id::new(), IngestProtocol::Webhook);
    event.message = sentinel.into();
    event.raw = json!({"secret":sentinel});
    event.raw_hash = sentinel.into();
    event.ai.rule_keys = vec![sentinel.into()];
    h.state.ingest_sink.put_event(&event).await.unwrap();
    let mut finding =
        Finding::new(h.tenant, RiskDomain::PromptAttack, Severity::Medium, sentinel, sentinel, sentinel, sentinel);
    finding.rule_keys = vec![sentinel.into()];
    let mut evidence = Evidence::new(sentinel, sentinel, sentinel, sentinel);
    evidence.artifact_ref = Some(format!("event:{}:{}", h.tenant, event.id));
    finding.evidence = vec![evidence];
    h.state.store.finding_insert_durable(&finding).await.unwrap();
    let created = h.post("/api/v1/alerts", json!({"title":"Metadata boundary","finding_ids":[finding.id]})).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let alert_id = Id::parse(created.json()["alert_id"].as_str().unwrap()).unwrap();
    let key = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![
            Permission::from_raw("alerts:read"),
            Permission::from_raw("alerts:write"),
            Permission::from_raw("models:write"),
        ],
        ..ApiKeyIssueRequest::named(h.tenant, "analysis-no-evidence-permission", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&key.record).await.unwrap();
    let denied = h
        .request_with(
            "POST",
            &format!("/api/v1/alerts/{alert_id}/analysis"),
            &[("x-agf-key", &key.plaintext)],
            Some(json!({})),
        )
        .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert!(agf_api::gateway_quota::usage(&h.state, h.tenant).await.unwrap().is_empty());
    let principal = agf_api::Principal {
        subject_id: None,
        agent_id: None,
        subject_kind: SubjectKind::ApiKey,
        tenant: h.tenant,
        identity_tenant: h.tenant,
        roles: vec![],
        superadmin: true,
        must_change_password: false,
        must_setup_mfa: false,
        session_id: None,
        scopes: vec![],
        source_ip: None,
        user_agent: None,
        department: None,
    };
    let snapshot = agf_api::security_analysis::load_alert(&h.state, &principal, alert_id).await.unwrap();
    let encoded = serde_json::to_string(&snapshot).unwrap();
    assert!(!encoded.contains(sentinel));
    let event_fact = snapshot.facts.iter().find(|fact| fact.kind == "event").unwrap();
    assert!(event_fact.content_hash.is_none());
    assert_eq!(event_fact.metadata["unpublished_rule_keys_omitted"], 1);
    let finding_fact = snapshot.facts.iter().find(|fact| fact.kind == "finding").unwrap();
    assert!(finding_fact.metadata["evidence_hashes"][0]["hash"].is_null());
    assert!(finding_fact.metadata["evidence_hashes"][0].get("code").is_none());
}

#[tokio::test]
async fn case_metadata_and_model_assisted_pdf_reuse_real_artifact_hashes() {
    let h = setup().await;
    mock_endpoint(&h).await;
    let id = alert(&h).await;
    let case = h
        .post("/api/v1/cases", json!({"title":"Case metadata","summary":"DO_NOT_SEND_RAW_OR_SECRET","alert_ids":[id]}))
        .await;
    assert_eq!(case.status, StatusCode::CREATED, "{}", case.text);
    let case_id = case.json()["case"]["id"].as_str().unwrap().to_string();
    let analyzed = h.post(&format!("/api/v1/cases/{case_id}/analysis"), json!({})).await;
    assert_eq!(analyzed.status, StatusCode::OK, "{}", analyzed.text);
    assert!(!analyzed.json()["analysis"]["snapshot"].to_string().contains("DO_NOT_SEND_RAW_OR_SECRET"));
    for format in ["markdown", "pdf"] {
        let created = h.post("/api/v1/reports", json!({"kind":"incident","format":format,"model_assisted":true})).await;
        assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
        let report = created.json()["report"].clone();
        assert!(report["body"].as_str().unwrap().contains("Mock demonstration"));
        let downloaded = h.get(&format!("/api/v1/reports/{}/download", report["id"].as_str().unwrap())).await;
        assert_eq!(downloaded.status, StatusCode::OK);
        use sha2::Digest;
        assert_eq!(report["content_hash"], hex::encode(sha2::Sha256::digest(&downloaded.bytes)));
        if format == "pdf" {
            assert!(downloaded.bytes.starts_with(b"%PDF-1.7"));
        }
    }
    let usage_before = agf_api::gateway_quota::usage(&h.state, h.tenant).await.unwrap().len();
    let ordinary = h.post("/api/v1/reports", json!({"kind":"incident"})).await;
    assert_eq!(ordinary.status, StatusCode::CREATED, "{}", ordinary.text);
    assert!(!ordinary.json()["report"]["body"].as_str().unwrap().contains("Model-assisted evidence review"));
    assert_eq!(
        agf_api::gateway_quota::usage(&h.state, h.tenant).await.unwrap().len(),
        usage_before,
        "Ordinary report generation must not call the model"
    );
}
