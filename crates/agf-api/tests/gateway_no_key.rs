//! Real router boundaries with mock_mode=false; the owned provider must receive zero no-key calls.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod gateway_no_key_support;
mod policy_publication_support;
use common::*;
use gateway_no_key_support::*;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

#[tokio::test]
async fn three_cloud_adapters_without_keys_return_mock_over_chat_and_messages_without_transport() {
    let h = live(setup().await);
    let server = MockServer::start().await;
    for provider in ["openai", "anthropic", "gemini"] {
        let model = format!("no-key-{provider}");
        let endpoint = add(&h, provider, &model, &server.uri(), None, false).await;
        assert_eq!(endpoint["credential_configured"], false);
        assert_eq!(endpoint["mocked"], true);
        let response = call(&h, &model, false).await;
        assert_mock(&response, &model);
        let streaming = call(&h, &model, true).await;
        assert_eq!(streaming.status, StatusCode::OK);
        assert_eq!(streaming.header("x-agf-mocked"), "true");
        assert!(streaming.text.contains("data: [DONE]"));
    }
    let messages = h
        .post(
            "/v1/messages",
            json!({"model":"no-key-anthropic","max_tokens":32,"temperature":1,
            "messages":[{"role":"user","content":"hello no key"}]}),
        )
        .await;
    assert_eq!(messages.status, StatusCode::OK);
    assert_eq!(messages.header("x-agf-mocked"), "true");
    assert_eq!(messages.json()["type"], "message");
    assert_eq!(messages.json()["model"], "no-key-anthropic");
    assert_eq!(h.state.meter.snapshot().total.calls, 7);
    assert_eq!(h.state.meter.snapshot().total.mocked_calls, 7);
    assert_eq!(h.state.meter.snapshot().total.cost_micro, 0);
    let usage = usages(&h).await;
    assert_eq!(usage.len(), 7);
    assert!(usage.iter().all(|row| row.mocked && row.cost_micro == 0));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn no_key_update_keeps_cas_and_new_key_enables_real_dispatch_without_reusing_old_key() {
    let h = live(setup().await);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(reply("edited")))
        .mount(&server)
        .await;
    let endpoint = add(&h, "openai", "edited", &server.uri(), None, false).await;
    let path = format!("/api/v1/gateway/endpoints/{}", endpoint["id"].as_str().unwrap());
    let mut body = endpoint_body("openai", "edited", &server.uri(), None, false);
    body["expected_version"] = endpoint["version"].clone();
    let changed = h.request("PUT", &path, Some(&h.admin), Some(body.clone())).await;
    assert_eq!(changed.status, StatusCode::OK);
    assert_eq!(changed.json()["version"], 2);
    assert_eq!(changed.json()["mocked"], true);
    assert_eq!(h.request("PUT", &path, Some(&h.admin), Some(body.clone())).await.status, StatusCode::CONFLICT);
    body["expected_version"] = json!(2);
    body["api_key"] = json!("synthetic-real-dispatch-key");
    let configured = h.request("PUT", &path, Some(&h.admin), Some(body.clone())).await;
    assert_eq!(configured.status, StatusCode::OK);
    assert_eq!(configured.json()["mocked"], false);
    let response = call(&h, "edited", false).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.header("x-agf-mocked"), "false");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    body["expected_version"] = json!(3);
    body.as_object_mut().unwrap().remove("api_key");
    body["base_url"] = json!("https://different.invalid/v1");
    assert_eq!(h.request("PUT", &path, Some(&h.admin), Some(body)).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.get("/api/v1/gateway/endpoints").await.json()["items"][0]["base_url"], server.uri());
}

#[tokio::test]
async fn signed_deny_still_rejects_no_key_mock_before_usage_or_transport() {
    let h = live(setup().await);
    let server = MockServer::start().await;
    add(&h, "openai", "denied", &server.uri(), None, false).await;
    let policy = policy_publication_support::create(&h, "no-key-signed-deny", "deny").await;
    policy_publication_support::assert_signed(&h, &policy);
    let response = call(&h, "denied", false).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(usages(&h).await.is_empty());
    let intercepts: Vec<Value> = h.state.configurations.list(h.tenant, "runtime-interception").await.unwrap();
    assert!(intercepts.iter().any(|row| row["policy_name"] == policy["name"] && row["action"] == "deny"));
    assert!(h.state.store.audit_verify_durable(h.tenant).await.unwrap().passed);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn bad_aad_ciphertext_and_explicit_empty_secret_never_become_missing_key_mock() {
    let h = live(setup().await);
    let server = MockServer::start().await;
    let endpoint = add(&h, "openai", "protected", &server.uri(), Some("synthetic-secret-marker"), false).await;
    let id = agf_core::ids::Id::parse(endpoint["id"].as_str().unwrap()).unwrap();
    let original: agf_api::model_gateway::StoredEndpoint =
        h.state.configurations.get(h.tenant, agf_api::model_gateway::ENDPOINT_KIND, id).await.unwrap().unwrap();
    for variant in 0..3 {
        let mut invalid = original.clone();
        match variant {
            0 => invalid.secret.as_mut().unwrap().aad = Some("wrong-tenant-binding".into()),
            1 => invalid.secret.as_mut().unwrap().ciphertext_b64 = "invalid-ciphertext".into(),
            _ => {
                invalid.secret = Some(
                    agf_api::model_gateway::encrypt(
                        &h.state,
                        h.tenant,
                        original.endpoint.credential_ref.unwrap(),
                        "   ".into(),
                    )
                    .unwrap(),
                );
            }
        }
        h.state.configurations.put(h.tenant, agf_api::model_gateway::ENDPOINT_KIND, id, &invalid).await.unwrap();
        let response = call(&h, "protected", false).await;
        assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.header("x-agf-mocked"), "");
        assert!(!response.text.contains("synthetic-secret-marker"));
        assert!(usages(&h).await.is_empty());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn explicit_whitespace_keys_are_rejected_and_absent_disabled_or_foreign_endpoints_are_not_created() {
    let h = live(setup().await);
    let server = MockServer::start().await;
    let whitespace = endpoint_body("openai", "blank", &server.uri(), Some("  \t "), false);
    assert_eq!(h.post("/api/v1/gateway/endpoints", whitespace).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(call(&h, "absent", false).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    let endpoint = add(&h, "gemini", "disabled", &server.uri(), None, false).await;
    assert_eq!(
        h.request("POST", "/v1/chat/completions", None, Some(chat("disabled", false))).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h.request("POST", "/v1/chat/completions", Some(&h.viewer), Some(chat("disabled", false))).await.status,
        StatusCode::FORBIDDEN
    );
    let mut body = endpoint_body("gemini", "disabled", &server.uri(), None, false);
    body["expected_version"] = endpoint["version"].clone();
    body["enabled"] = json!(false);
    assert_eq!(
        h.request(
            "PUT",
            &format!("/api/v1/gateway/endpoints/{}", endpoint["id"].as_str().unwrap()),
            Some(&h.admin),
            Some(body)
        )
        .await
        .status,
        StatusCode::OK
    );
    assert_eq!(call(&h, "disabled", false).await.status, StatusCode::INTERNAL_SERVER_ERROR);
    let bearer = format!("Bearer {}", h.admin);
    let tenant = h.other_tenant.to_string();
    let foreign = h
        .request_with(
            "POST",
            "/v1/chat/completions",
            &[("authorization", &bearer), ("x-agf-tenant", &tenant)],
            Some(chat("disabled", false)),
        )
        .await;
    assert_eq!(foreign.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(usages(&h).await.is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn truly_local_ollama_and_vllm_without_keys_keep_real_local_transport() {
    for provider in ["ollama", "vllm"] {
        let h = live(setup().await);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(reply("local")))
            .mount(&server)
            .await;
        let endpoint = add(&h, provider, "local", &server.uri(), None, true).await;
        assert_eq!(endpoint["credential_configured"], false);
        assert_eq!(endpoint["mocked"], false);
        let response = call(&h, "local", false).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.header("x-agf-mocked"), "false");
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn configured_upstream_auth_failure_is_not_converted_into_mock_success() {
    let h = live(setup().await);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({"error":{"message":"invalid synthetic credential"}})),
        )
        .mount(&server)
        .await;
    let endpoint = add(&h, "openai", "rejected", &server.uri(), Some("synthetic-rejected-key"), false).await;
    assert_eq!(endpoint["mocked"], false);
    let response = call(&h, "rejected", false).await;
    assert!(!response.status.is_success());
    assert_eq!(response.header("x-agf-mocked"), "");
    assert!(usages(&h).await.is_empty());
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
