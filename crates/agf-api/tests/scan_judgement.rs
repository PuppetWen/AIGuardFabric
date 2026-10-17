//! Mock and local provider replay exercise the actual model-judgement path and its controls.
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
use agf_core::{
    asset::Asset,
    enums::{AssetKind, DataClass},
    ids::Id,
};
use common::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const YAML: &str = "key: SCAN-JUDGE-FIXTURE\nname: Scan judgement fixture\ndomain: prompt-attack\nseverity: high\nkind: keyword\ntarget: prompt\naction: audit\ndetection:\n  type: keyword\n  any: [SCAN_JUDGE_FIXTURE]\nsamples:\n  positive: [SCAN_JUDGE_FIXTURE]\n  negative: [clean]\n";

async fn rule(h: &Harness) {
    let response = h.post("/api/v1/rules", json!({"yaml":YAML})).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
}
fn body() -> Value {
    json!({"use_llm_judge":true,"targets":[{"label":"sample","kind":"prompt","text":"SCAN_JUDGE_FIXTURE"}]})
}
async fn scan(h: &Harness, body: Value) -> Value {
    let response = h.post("/api/v1/scans", body).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let job = response.json()["job"].clone();
    assert_eq!(job["state"], "succeeded", "{job}");
    job
}

#[tokio::test]
async fn offline_judgement_has_evidence_and_requires_model_permission() {
    let h = setup().await;
    rule(&h).await;
    let job = scan(&h, body()).await;
    assert_eq!(job["llm_mocked"], true, "{job}");
    assert_eq!(job["judgement_count"], 1);
    assert_eq!(job["judgement_failures"], 0);
    let finding = h.get(&format!("/api/v1/findings/{}", job["finding_ids"][0].as_str().unwrap())).await.json();
    let judgement = &finding["finding"]["llm_verdict"];
    assert_eq!(judgement["model"], "rule-based-judge", "{finding}");
    assert!(
        judgement["cited_evidence"]
            .as_array()
            .unwrap()
            .iter()
            .all(|code| finding["finding"]["evidence_refs"].as_array().unwrap().contains(code))
    );
    let key = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("scans:execute")],
        ..ApiKeyIssueRequest::named(h.tenant, "scan-only", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&key.record).await.unwrap();
    let denied = h.request_with("POST", "/api/v1/scans", &[("x-agf-key", &key.plaintext)], Some(body())).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN, "{}", denied.text);
}

async fn provider(
    axum::extract::State((invalid, calls)): axum::extract::State<(Arc<AtomicBool>, Arc<AtomicUsize>)>,
    axum::Json(body): axum::Json<Value>,
) -> axum::Json<Value> {
    calls.fetch_add(1, Ordering::SeqCst);
    assert_eq!(body["response_format"]["type"], "json_object");
    assert!(body["tools"].is_null());
    let input: Value = serde_json::from_str(body["messages"][1]["content"].as_str().unwrap()).unwrap();
    let keys: Vec<_> = input["evidence"].as_array().unwrap().iter().map(|e| e["key"].clone()).collect();
    let content = if invalid.load(Ordering::SeqCst) {
        "not a judgement".into()
    } else {
        json!({"verdict":"suspicious","confidence":0.7,"rationale":"Recorded local provider assessment","cited_evidence":keys}).to_string()
    };
    axum::Json(json!({"id":"fixture","object":"chat.completion","model":"fixture-judge","choices":[{
        "index":0,"message":{"role":"assistant","content":content},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":24,"completion_tokens":12}}))
}

#[tokio::test]
async fn provider_judgement_is_metered_and_respects_classification_quota_and_invalid_output() {
    let invalid = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().fallback(axum::routing::post(provider)).with_state((invalid.clone(), calls.clone()));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    rule(&h).await;
    let endpoint = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":"scan-local-replay","provider":"ollama",
        "model":"fixture-judge","base_url":address,"local_deployment":true,"max_data_class":"internal"}),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let success = scan(&h, body()).await;
    assert_eq!(success["judgement_count"], 1, "{success}");
    assert_eq!(success["judgement_failures"], 0);
    assert_eq!(success["llm_mocked"], false);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let usage = agf_api::gateway_quota::usage(&h.state, h.tenant).await.unwrap();
    assert_eq!(usage.len(), 1);
    assert!(!usage[0].mocked);
    assert_eq!(usage[0].prompt_tokens, 24);

    invalid.store(true, Ordering::SeqCst);
    let failed = scan(&h, body()).await;
    assert_eq!(
        failed["judgement_count"],
        0,
        "calls={} success={success} failed={failed}",
        calls.load(Ordering::SeqCst)
    );
    assert_eq!(failed["judgement_failures"], 1);
    assert!(failed["finding_count"].as_u64().unwrap() > 0, "Rule findings must remain");
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let mut asset = Asset::new(h.tenant, AssetKind::Agent, "Restricted fixture", Id::new().to_string());
    asset.data_class = DataClass::Restricted;
    h.state.store.asset_upsert(&asset).unwrap();
    let mut restricted = body();
    restricted["targets"][0]["asset_id"] = json!(asset.id);
    restricted["targets"][0]["data_class"] = json!("public");
    let blocked = scan(&h, restricted).await;
    assert_eq!(blocked["judgement_failures"], 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2, "The request cannot lower asset classification");

    h.state
        .configurations
        .put(
            h.tenant,
            agf_api::gateway_quota::QUOTAS,
            agf_api::model_routes::tenant_record_id(h.tenant),
            &agf_api::gateway_quota::Limits { tenant_tokens_per_day: 1, ..Default::default() },
        )
        .await
        .unwrap();
    let quota = scan(&h, body()).await;
    assert_eq!(quota["judgement_failures"], 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2, "Quota denial must happen before the provider call");
    server.abort();
}
