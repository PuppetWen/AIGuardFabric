//! Streaming cancellation and quota lifecycle across MCP protocol revisions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{enums::QuotaDimension, quota::Quota};
use common::*;
use std::{
    convert::Infallible,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

struct Connection(Arc<AtomicUsize>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn disconnect_cancels_modern_stream_but_retains_legacy_reservation() {
    for modern in [true, false] {
        let h = setup().await;
        let closed = Arc::new(AtomicUsize::new(0));
        let counter = closed.clone();
        let app = Router::new().route(
            "/mcp",
            axum::routing::post(move || {
                let guard = Connection(counter.clone());
                async move {
                    let stream = futures::stream::unfold((false, guard), |(sent, guard)| async move {
                        if sent {
                            std::future::pending::<()>().await;
                        }
                        Some((Ok::<_, Infallible>(axum::body::Bytes::from_static(b": connected\n\n")), (true, guard)))
                    });
                    ([("content-type", "text/event-stream")], Body::from_stream(stream))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let endpoint = h
            .post(
                "/api/v1/mcp/endpoints",
                json!({"expected_version":0,"name":"Pending stream",
            "url":format!("http://{address}/mcp"),"enabled":true,"idle_timeout_secs":5}),
            )
            .await
            .json();
        let quota = agf_api::quota_definitions::save(
            &h.state,
            h.tenant,
            Quota::tenant_default(h.tenant, QuotaDimension::Concurrency, 1),
        )
        .await
        .unwrap();
        let mut params = json!({"name":"query","arguments":{"query":"hello"}});
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/mcp/proxy/{}", endpoint["id"].as_str().unwrap()))
            .header("authorization", format!("Bearer {}", h.admin))
            .header("content-type", "application/json");
        if modern {
            params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28"});
            request = request
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call")
                .header("mcp-name", "query");
        }
        let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":params});
        let response = h.app.clone().oneshot(request.body(Body::from(body.to_string())).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap()[&quota.id], 1);
        drop(response);
        for _ in 0..50 {
            if closed.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(closed.load(Ordering::SeqCst), 1, "dropping the downstream body must close upstream");
        let usage = agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap()[&quota.id];
        assert_eq!(usage, i64::from(!modern));
        server.abort();
    }
}

#[tokio::test]
async fn renewal_extends_only_live_reservations_without_double_charge() {
    let h = setup().await;
    let quota = agf_api::quota_definitions::save(
        &h.state,
        h.tenant,
        Quota::tenant_default(h.tenant, QuotaDimension::Requests, 2),
    )
    .await
    .unwrap();
    let lease = agf_api::runtime_quota::Lease::acquire(
        &h.state,
        h.tenant,
        None,
        "renew",
        "owner",
        &agf_core::quota::QuotaConsumption::one_request(),
    )
    .await
    .unwrap();
    lease.renew().await.unwrap();
    lease.renew().await.unwrap();
    assert_eq!(agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap()[&quota.id], 1);
    lease.finish(None).await.unwrap();
    assert_eq!(agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap()[&quota.id], 1);
}

#[tokio::test]
async fn a_connection_refusal_does_not_consume_tool_request_or_concurrency_quota() {
    for modern in [true, false] {
        let h = setup().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let endpoint = h
            .post(
                "/api/v1/mcp/endpoints",
                json!({"expected_version":0,"name":"Unreachable MCP",
                    "url":format!("http://{address}/mcp"),"enabled":true,"idle_timeout_secs":5}),
            )
            .await;
        assert_eq!(endpoint.status, StatusCode::OK, "{}", endpoint.text);
        let requests = agf_api::quota_definitions::save(
            &h.state,
            h.tenant,
            Quota::tenant_default(h.tenant, QuotaDimension::Requests, 1),
        )
        .await
        .unwrap();
        let concurrency = agf_api::quota_definitions::save(
            &h.state,
            h.tenant,
            Quota::tenant_default(h.tenant, QuotaDimension::Concurrency, 1),
        )
        .await
        .unwrap();
        let mut params = json!({"name":"query","arguments":{}});
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/mcp/proxy/{}", endpoint.json()["id"].as_str().unwrap()))
            .header("authorization", format!("Bearer {}", h.admin))
            .header("content-type", "application/json");
        if modern {
            params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28"});
            request = request
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/call")
                .header("mcp-name", "query");
        }
        let frame = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":params});
        let sent = send(&h.app, request.body(Body::from(frame.to_string())).unwrap()).await;
        assert_eq!(sent.status, StatusCode::SERVICE_UNAVAILABLE, "{}", sent.text);
        let used = agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap();
        assert_eq!(used[&requests.id], 0);
        assert_eq!(used[&concurrency.id], 0);
    }
}
