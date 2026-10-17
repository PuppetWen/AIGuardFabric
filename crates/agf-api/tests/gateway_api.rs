//! 网关真实 HTTP 边界：端点管理、SDK 认证、隔离、流式、计量及删除。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

#[tokio::test]
async fn provider_catalog_uses_the_same_defaults_as_the_gateway() {
    let h = setup().await;
    assert_eq!(h.request("GET", "/api/v1/gateway/providers", None, None).await.status, StatusCode::UNAUTHORIZED);
    let response = h.get("/api/v1/gateway/providers").await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let items = response.json()["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), agf_core::enums::LlmProvider::all().len());
    let openai = items.iter().find(|row| row["value"] == "openai").unwrap();
    assert_eq!(openai["suggestedBaseUrl"], agf_aigw::provider::default_base_url(agf_core::enums::LlmProvider::OpenAi));
    assert_eq!(openai["requiresCustomBaseUrl"], false);
    assert_eq!(items.iter().find(|row| row["value"] == "azure-openai").unwrap()["requiresCustomBaseUrl"], true);
    assert_eq!(items.iter().find(|row| row["value"] == "ollama").unwrap()["localDeployment"], false);
    assert_eq!(items.iter().find(|row| row["value"] == "mock").unwrap()["localDeployment"], true);
}

#[tokio::test]
async fn endpoint_to_sdk_chat_and_revocation() {
    let h = setup().await;
    let created = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":"offline",
        "provider":"mock","model":"recorded-model","base_url":"http://mock.invalid/v1",
        "local_deployment":true}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let id = created.json()["id"].as_str().unwrap().to_string();
    assert_eq!(created.json()["mocked"], true);
    let key = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"sdk",
        "scopes":["models:read","models:write"],"expires_in_secs":3600}),
        )
        .await
        .json();
    let token = key["plaintext"].as_str().unwrap();
    assert_eq!(h.request("GET", "/v1/models", Some(token), None).await.status, StatusCode::OK);
    let body = json!({"model":"auto","messages":[{"role":"user","content":"Hello"}],"max_tokens":16});
    let answer = h.request("POST", "/v1/chat/completions", Some(token), Some(body.clone())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text);
    assert_eq!(answer.header("x-agf-mocked"), "true");
    assert_eq!(answer.json()["object"], "chat.completion");
    assert_eq!(answer.json()["model"], "recorded-model");
    let mut streaming = body.clone();
    streaming["stream"] = json!(true);
    let stream = h.request("POST", "/v1/chat/completions", Some(token), Some(streaming)).await;
    assert_eq!(stream.status, StatusCode::OK, "{}", stream.text);
    assert!(stream.text.contains("data: [DONE]"));
    assert_eq!(stream.header("x-agf-mocked"), "true");
    assert!(stream.text.contains("recorded-model"));
    assert!(!stream.text.contains("\"model\":\"auto\""));
    assert_eq!(stream.text.matches("\"usage\":{").count(), 1);
    assert!(stream.text.contains("chat.completion.chunk"));
    assert_eq!(h.state.meter.recent(10).len(), 2);
    assert_eq!(
        h.request(
            "DELETE",
            &format!("/api/v1/gateway/endpoints/{id}?expected_version={}", created.json()["version"]),
            Some(&h.admin),
            None
        )
        .await
        .status,
        StatusCode::OK
    );
    assert_eq!(h.get("/api/v1/gateway/endpoints").await.json()["items"], json!([]));
    assert!(!h.request("POST", "/v1/chat/completions", Some(token), Some(body)).await.status.is_success());
}

#[tokio::test]
async fn endpoints_enforce_permissions_and_tenant_scope() {
    let h = setup().await;
    let body = json!({"name":"offline","provider":"mock","model":"test","base_url":"http://mock.invalid"});
    assert_eq!(
        h.request("POST", "/api/v1/gateway/endpoints", Some(&h.viewer), Some(body.clone())).await.status,
        StatusCode::FORBIDDEN
    );
    let created = h.post("/api/v1/gateway/endpoints", body).await;
    let id = created.json()["id"].as_str().unwrap().to_string();
    let token = format!("Bearer {}", h.admin);
    let tenant = h.other_tenant.to_string();
    let headers = [("Authorization", token.as_str()), ("X-AGF-Tenant", tenant.as_str())];
    let listed = h.request_with("GET", "/api/v1/gateway/endpoints", &headers, None).await;
    assert_eq!(listed.json()["items"], json!([]));
    assert!(
        !h.request_with(
            "PUT",
            &format!("/api/v1/gateway/endpoints/{id}"),
            &headers,
            Some(json!({"name":"other","provider":"mock","model":"test","base_url":"http://mock.invalid"}))
        )
        .await
        .status
        .is_success()
    );
}

#[tokio::test]
async fn changing_model_destination_never_reuses_previous_api_key() {
    let h = setup().await;
    let created = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":"bound","provider":"openai",
        "model":"fixture","base_url":"https://first.example/v1","api_key":"first-only-key"}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let id = created.json()["id"].as_str().unwrap().to_string();
    let uri = format!("/api/v1/gateway/endpoints/{id}");
    let changed = json!({"name":"bound","provider":"openai","model":"fixture","expected_version":created.json()["version"],
        "base_url":"https://second.example/v1"});
    let rejected = h.request("PUT", &uri, Some(&h.admin), Some(changed.clone())).await;
    assert_eq!(rejected.status, StatusCode::BAD_REQUEST, "{}", rejected.text);
    let still_saved = h.get("/api/v1/gateway/endpoints").await.json();
    assert_eq!(still_saved["items"][0]["base_url"], "https://first.example/v1");
    assert_eq!(still_saved["items"][0]["credential_configured"], true);
    let mut with_new_key = changed;
    with_new_key["api_key"] = json!("second-only-key");
    let saved = h.request("PUT", &uri, Some(&h.admin), Some(with_new_key)).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["base_url"], "https://second.example/v1");
    assert!(!saved.text.contains("first-only-key"));
    assert!(!saved.text.contains("second-only-key"));
}

#[tokio::test]
async fn concurrent_model_edit_and_delete_require_current_version() {
    let h = setup().await;
    let created = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({
                "name":"original","provider":"mock","model":"offline","base_url":"http://mock.invalid/v1"
            }),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    assert_eq!(created.json()["version"], 1);
    let id = created.json()["id"].as_str().unwrap().to_string();
    let uri = format!("/api/v1/gateway/endpoints/{id}");
    let without_version = h
        .request(
            "PUT",
            &uri,
            Some(&h.admin),
            Some(json!({
                "name":"unsafe","provider":"mock","model":"offline","base_url":"http://mock.invalid/v1"
            })),
        )
        .await;
    assert_eq!(without_version.status, StatusCode::BAD_REQUEST);
    let update = json!({"name":"new","provider":"mock","model":"offline",
        "base_url":"http://mock.invalid/v1","expected_version":1});
    let saved = h.request("PUT", &uri, Some(&h.admin), Some(update.clone())).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["version"], 2);
    let stale = h.request("PUT", &uri, Some(&h.admin), Some(update)).await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{}", stale.text);
    let stale_delete = h.request("DELETE", &format!("{uri}?expected_version=1"), Some(&h.admin), None).await;
    assert_eq!(stale_delete.status, StatusCode::CONFLICT);
    let listed = h.get("/api/v1/gateway/endpoints").await.json();
    assert_eq!(listed["items"][0]["name"], "new");
    assert_eq!(listed["items"][0]["version"], 2);
    let deleted = h.request("DELETE", &format!("{uri}?expected_version=2"), Some(&h.admin), None).await;
    assert_eq!(deleted.status, StatusCode::OK, "{}", deleted.text);
}

#[tokio::test]
async fn upstream_failure_is_private_and_audited_for_both_response_modes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let app = axum::Router::new().route(
        "/chat/completions",
        axum::routing::post(|| async { (StatusCode::SERVICE_UNAVAILABLE, "private-prompt-and-api-key") }),
    );
    let upstream = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let endpoint = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({
                "name":"local-failure-test","provider":"ollama","model":"test-model",
                "base_url":base_url,"local_deployment":true
            }),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    for stream in [false, true] {
        let response = h
            .request(
                "POST",
                "/v1/chat/completions",
                Some(&h.admin),
                Some(json!({
                    "model":"auto","messages":[{"role":"user","content":"hello"}],
                    "max_tokens":8,"stream":stream
                })),
            )
            .await;
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE, "{}", response.text);
        assert!(!response.text.contains("private-prompt-and-api-key"));
    }
    let events: Vec<Value> = h.state.configurations.list(h.tenant, "runtime-interception").await.unwrap();
    assert_eq!(events.iter().filter(|event| event["policy_name"] == "gateway-call-error").count(), 2);
    assert!(!serde_json::to_string(&events).unwrap().contains("private-prompt-and-api-key"));
    upstream.abort();
}

#[tokio::test]
async fn upstream_output_over_limit_is_rejected_after_usage_and_audit_are_saved() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let app = axum::Router::new().route(
        "/chat/completions",
        axum::routing::post(|| async {
            axum::Json(json!({
                "id":"fixture-over-limit","model":"test-model",
                "choices":[{"index":0,"message":{"role":"assistant","content":"private-upstream-output"},
                    "finish_reason":"stop"}],
                "usage":{"prompt_tokens":4,"completion_tokens":20,"total_tokens":24}
            }))
        }),
    );
    let upstream = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let endpoint = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({
                "name":"local-limit-test","provider":"ollama","model":"test-model",
                "base_url":base_url,"local_deployment":true
            }),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let answer = h
        .request(
            "POST",
            "/v1/chat/completions",
            Some(&h.admin),
            Some(json!({
                "model":"auto","messages":[{"role":"user","content":"hello"}],"max_tokens":8
            })),
        )
        .await;
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE, "{}", answer.text);
    assert!(!answer.text.contains("private-upstream-output"));
    let usage = h.state.meter.recent(10);
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].completion_tokens, 20);
    let events: Vec<Value> = h.state.configurations.list(h.tenant, "runtime-interception").await.unwrap();
    assert!(events.iter().any(|event| event["policy_name"] == "gateway-output-limit"));
    upstream.abort();
}

#[tokio::test]
async fn stream_over_limit_reports_error_and_settles_actual_usage() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let app = axum::Router::new().route(
        "/chat/completions",
        axum::routing::post(|| async {
            let body = concat!(
                "data: {\"id\":\"fixture\",\"model\":\"test-model\",\"choices\":[{\"index\":0,",
                "\"delta\":{\"role\":\"assistant\",\"content\":\"partial\"},\"finish_reason\":null}]}\n\n",
                "data: {\"id\":\"fixture\",\"model\":\"test-model\",\"choices\":[],",
                "\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":20,\"total_tokens\":24}}\n\n",
                "data: [DONE]\n\n"
            );
            ([(header::CONTENT_TYPE, "text/event-stream")], body)
        }),
    );
    let upstream = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let endpoint = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({
                "name":"local-stream-limit","provider":"ollama","model":"test-model",
                "base_url":base_url,"local_deployment":true
            }),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let answer = h
        .request(
            "POST",
            "/v1/chat/completions",
            Some(&h.admin),
            Some(json!({
                "model":"auto","messages":[{"role":"user","content":"hello"}],
                "max_tokens":8,"stream":true
            })),
        )
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text);
    assert!(answer.text.contains("error"), "{}", answer.text);
    assert!(!answer.text.contains("data: [DONE]"));
    let usage = h.state.meter.recent(10);
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].completion_tokens, 20);
    let events: Vec<Value> = h.state.configurations.list(h.tenant, "runtime-interception").await.unwrap();
    assert!(events.iter().any(|event| event["policy_name"] == "gateway-output-limit"));
    let ledger: Value = h
        .state
        .configurations
        .get(h.tenant, "gateway-ledger", agf_api::model_routes::tenant_record_id(h.tenant))
        .await
        .unwrap()
        .unwrap();
    assert!(ledger["reservations"].as_object().is_some_and(serde_json::Map::is_empty));
    upstream.abort();
}
