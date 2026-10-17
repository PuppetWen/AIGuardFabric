//! A local TCP upstream proves client cancellation closes the actual provider connection.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn dropping_client_stream_closes_upstream_and_settles_reservation() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 2048];
        let header_end = loop {
            let count = socket.read(&mut buffer).await.unwrap();
            assert!(count > 0);
            request.extend_from_slice(&buffer[..count]);
            if let Some(i) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
        let length: usize = headers.lines().find_map(|l| l.strip_prefix("content-length: ")).unwrap().parse().unwrap();
        while request.len() < header_end + length {
            let count = socket.read(&mut buffer).await.unwrap();
            assert!(count > 0);
            request.extend_from_slice(&buffer[..count]);
        }
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        socket.flush().await.unwrap();
        // Keep the provider silent. Cancellation must not wait for another token or a timeout.
        tokio::time::timeout(std::time::Duration::from_secs(4), socket.read(&mut buffer)).await.unwrap()
    });
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let endpoint = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":"local-cancel-test","provider":"ollama",
        "model":"test-model","base_url":url,"local_deployment":true}),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let request = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {}", h.admin))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"model":"auto","messages":[{"role":"user","content":"hello"}],"stream":true,"max_tokens":16})
                .to_string(),
        ))
        .unwrap();
    let response = h.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-agf-mocked"], "false");
    drop(response);
    let result = upstream.await.unwrap();
    assert!(matches!(result, Ok(0) | Err(_)), "provider must see EOF or connection reset");
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let record: Value = h
                .state
                .configurations
                .get(h.tenant, "gateway-ledger", agf_api::model_routes::tenant_record_id(h.tenant))
                .await
                .unwrap()
                .unwrap();
            if record["reservations"].as_object().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
