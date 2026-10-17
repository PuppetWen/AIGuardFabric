//! Offline legacy compatibility and the public durable lookup boundary.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

#[tokio::test]
async fn no_database_keeps_successful_local_replay_but_never_claims_a_durable_key() {
    let h = setup().await;
    let endpoint = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":"idempotency-owned-mock",
        "provider":"mock","model":"idempotency-owned","base_url":"http://mock.invalid/v1","local_deployment":true}),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED);
    let bearer = format!("Bearer {}", h.admin);
    let headers = [("authorization", bearer.as_str()), ("idempotency-key", "owned-legacy-key")];
    let body = json!({"model":"idempotency-owned","messages":[{"role":"user","content":"owned compatibility"}]});
    let first = h.request_with("POST", "/v1/chat/completions", &headers, Some(body.clone())).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    assert!(first.header("x-agf-attempt-id").is_empty());
    let calls = h.state.meter.snapshot().total.calls;
    let replay = h.request_with("POST", "/v1/chat/completions", &headers, Some(body)).await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(replay.bytes, first.bytes);
    assert_eq!(replay.header("idempotency-replayed"), "true");
    assert_eq!(h.state.meter.snapshot().total.calls, calls);
    assert!(h.state.configurations.list::<Value>(h.tenant, "gateway-admission-key-v1").await.unwrap().is_empty());
    let lookup = h.request_with("GET", "/api/v1/gateway/attempts/by-idempotency-key", &headers, None).await;
    assert_eq!(lookup.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(h.state.meter.snapshot().total.calls, calls);
}

#[tokio::test]
async fn header_lookup_rejects_missing_or_duplicate_keys_without_initialization() {
    let h = setup().await;
    let path = "/api/v1/gateway/attempts/by-idempotency-key";
    assert_eq!(h.request("GET", path, None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.get(path).await.status, StatusCode::BAD_REQUEST);
    let token = format!("Bearer {}", h.admin);
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header("authorization", token)
        .header("idempotency-key", "first")
        .header("idempotency-key", "second")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&h.app, request).await.status, StatusCode::BAD_REQUEST);
    assert!(h.state.configurations.list::<Value>(h.tenant, "gateway-admission-key-v1").await.unwrap().is_empty());
    assert!(
        h.state.configurations.list::<Value>(h.tenant, "gateway-admission-key-capacity-v1").await.unwrap().is_empty()
    );
}

#[tokio::test]
async fn openapi_describes_both_chat_aliases_and_header_only_original_receipt_lookup() {
    let h = setup().await;
    let response = h.get("/api/v1/openapi.json").await;
    assert_eq!(response.status, StatusCode::OK);
    let doc = response.json();
    for path in ["/api/v1/chat/completions", "/v1/chat/completions"] {
        let operation = &doc["paths"][path]["post"];
        let parameter = operation["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|parameter| parameter["name"] == "Idempotency-Key")
            .unwrap();
        assert_eq!(parameter["in"], "header");
        assert_eq!(parameter["required"], false);
        assert_eq!(parameter["schema"]["maxLength"], 200);
        assert_eq!(operation["responses"]["409"]["headers"]["x-agf-attempt-id"]["schema"]["format"], "uuid");
    }
    let lookup = &doc["paths"]["/api/v1/gateway/attempts/by-idempotency-key"]["get"];
    assert_eq!(lookup["x-required-permissions"], json!(["models:read"]));
    assert_eq!(lookup["parameters"][0]["in"], "header");
    assert_eq!(lookup["parameters"][0]["required"], true);
    assert_eq!(
        lookup["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/GatewaySettlementReceipt"
    );
    let receipt = &doc["components"]["schemas"]["GatewaySettlementReceipt"];
    assert_eq!(receipt["additionalProperties"], false);
    assert_eq!(receipt["properties"]["mayExecute"]["const"], false);
    assert!(receipt["properties"].get("modelResponse").is_none());
    assert!(receipt["properties"].get("idempotencyKey").is_none());
}
