//! Exercise native Claude extensions against a local Anthropic-shaped upstream.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use axum::{http::header, response::IntoResponse};
use common::*;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn native_thinking_context_and_signed_stream_survive_the_gateway() {
    let captured = Arc::new(Mutex::new(Vec::<Value>::new()));
    let sink = captured.clone();
    let app = axum::Router::new().route(
        "/messages",
        axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
            let sink = sink.clone();
            async move {
                sink.lock().unwrap().push(body.clone());
                if body["stream"] == true {
                    let payloads = [
                        json!({"type":"message_start","message":{"id":"msg_stream","type":"message",
                        "role":"assistant","model":"fixture-claude","content":[],
                        "usage":{"input_tokens":11,"cache_creation_input_tokens":3,
                            "cache_creation":{"ephemeral_5m_input_tokens":1,"ephemeral_1h_input_tokens":2},
                            "cache_read_input_tokens":5,"output_tokens":0}}}),
                        json!({"type":"content_block_start","index":0,
                        "content_block":{"type":"thinking","thinking":""}}),
                        json!({"type":"content_block_delta","index":0,
                        "delta":{"type":"thinking_delta","thinking":"reasoned"}}),
                        json!({"type":"content_block_delta","index":0,
                        "delta":{"type":"signature_delta","signature":"signed"}}),
                        json!({"type":"content_block_stop","index":0}),
                        json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},
                        "usage":{"output_tokens":4},"context_management":{
                            "applied_edits":[{"type":"clear_thinking_20251015"}]}}),
                        json!({"type":"message_stop"}),
                    ];
                    let mut events = String::new();
                    for event in &payloads {
                        writeln!(&mut events, "event: {}", event["type"].as_str().unwrap()).unwrap();
                        writeln!(&mut events, "data: {event}\n").unwrap();
                    }
                    ([(header::CONTENT_TYPE, "text/event-stream")], events).into_response()
                } else {
                    axum::Json(json!({"id":"msg_complete","type":"message","role":"assistant",
                    "model":"fixture-claude","content":[
                        {"type":"thinking","thinking":"reasoned","signature":"signed"},
                        {"type":"text","text":"ok"}],"stop_reason":"end_turn",
                    "usage":{"input_tokens":11,"cache_creation_input_tokens":3,
                        "cache_creation":{"ephemeral_5m_input_tokens":1,"ephemeral_1h_input_tokens":2},
                        "cache_read_input_tokens":5,"output_tokens":4}}))
                    .into_response()
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let upstream = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let endpoint = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":"native-local",
        "provider":"anthropic","model":"fixture-claude","base_url":base_url,
        "local_deployment":true,"api_key":"fixture-secret"}),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let mut body = json!({"model":"auto","max_tokens":4096,
        "thinking":{"type":"enabled","budget_tokens":1024},
        "cache_control":{"type":"ephemeral"},"top_k":12,
        "context_management":{"edits":[{"type":"clear_thinking_20251015"}]},
        "messages":[{"role":"user","content":"hello"}]});
    let reply = h.request("POST", "/v1/messages", Some(&h.admin), Some(body.clone())).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    assert_eq!(reply.header("x-agf-mocked"), "false");
    assert_eq!(reply.json()["content"][0]["signature"], "signed");
    body["stream"] = json!(true);
    let stream = h.request("POST", "/v1/messages", Some(&h.admin), Some(body)).await;
    assert_eq!(stream.status, StatusCode::OK, "{}", stream.text);
    assert!(stream.text.contains("signature_delta"), "{}", stream.text);
    assert!(stream.text.contains("applied_edits"));
    assert_eq!(stream.text.matches("event: message_start").count(), 1);
    assert_eq!(stream.text.matches("event: message_stop").count(), 1);
    let sent = captured.lock().unwrap();
    assert_eq!(sent.len(), 2);
    for request in sent.iter() {
        assert_eq!(request["model"], "fixture-claude");
        assert_eq!(request["thinking"]["type"], "enabled");
        assert_eq!(request["cache_control"]["type"], "ephemeral");
        assert_eq!(request["top_k"], 12);
        assert_eq!(request["context_management"]["edits"][0]["type"], "clear_thinking_20251015");
    }
    let metered = h.state.meter.recent(5);
    assert_eq!(metered.len(), 2);
    for usage in metered {
        assert_eq!(usage.prompt_tokens, 19);
        assert_eq!(usage.cached_tokens, 5);
        assert_eq!(usage.cache_write_tokens, 3);
        assert_eq!(usage.cache_write_1h_tokens, 2);
    }
    upstream.abort();
}

#[tokio::test]
async fn native_upstream_error_event_does_not_become_a_successful_message() {
    let app = axum::Router::new().route(
        "/messages",
        axum::routing::post(|| async {
            ([(header::CONTENT_TYPE, "text/event-stream")],
                "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"private-upstream-detail\"}}\n\n")
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let upstream = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let endpoint = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":"native-error",
        "provider":"anthropic","model":"fixture-claude","base_url":base_url,
        "local_deployment":true,"api_key":"fixture-secret"}),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let reply = h
        .request(
            "POST",
            "/v1/messages",
            Some(&h.admin),
            Some(json!({
                "model":"auto","max_tokens":4096,"stream":true,
                "thinking":{"type":"enabled","budget_tokens":1024},
                "messages":[{"role":"user","content":"hello"}]
            })),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    assert!(reply.text.contains("event: error"), "{}", reply.text);
    assert!(!reply.text.contains("message_stop"));
    assert!(!reply.text.contains("private-upstream-detail"));
    upstream.abort();
}
