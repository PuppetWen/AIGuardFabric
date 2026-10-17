//! Real two-endpoint 2024 HTTP+SSE flow through the console and proxy.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
#[path = "common/sql_runtime_identity.rs"]
mod sql_runtime_identity;
use agf_core::{enums::QuotaDimension, quota::Quota};
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
};
use common::*;
use futures::StreamExt;
use std::{convert::Infallible, sync::Mutex, time::Duration};
use tokio::sync::{broadcast, oneshot};

#[derive(Clone)]
struct Upstream {
    tx: broadcast::Sender<String>,
    calls: Arc<Mutex<Vec<(String, Value)>>>,
    advertised: String,
    discovery_error: bool,
}

async fn sse(State(upstream): State<Upstream>, headers: HeaderMap) -> impl IntoResponse {
    if headers.get("authorization").and_then(|value| value.to_str().ok()) != Some("Bearer upstream-secret") {
        return (StatusCode::UNAUTHORIZED, Body::empty()).into_response();
    }
    let receiver = upstream.tx.subscribe();
    let first = format!(": connected\n\nevent: endpoint\ndata: {}\n\n", upstream.advertised);
    let stream = futures::stream::unfold((Some(first), receiver), |(initial, mut receiver)| async move {
        let text = match initial {
            Some(text) => text,
            None => receiver.recv().await.ok()?,
        };
        Some((Ok::<_, Infallible>(Bytes::from(text)), (None, receiver)))
    });
    ([("content-type", "text/event-stream")], Body::from_stream(stream)).into_response()
}

async fn message(State(upstream): State<Upstream>, headers: HeaderMap, Json(frame): Json<Value>) -> StatusCode {
    let auth = headers.get("authorization").and_then(|value| value.to_str().ok()).unwrap_or_default().to_owned();
    upstream.calls.lock().unwrap().push((auth.clone(), frame.clone()));
    if auth != "Bearer upstream-secret" {
        return StatusCode::UNAUTHORIZED;
    }
    let Some(id) = frame.get("id") else { return StatusCode::ACCEPTED };
    let result = match frame["method"].as_str() {
        Some("initialize") => json!({"protocolVersion":"2024-11-05","capabilities":{"tools":{}},
            "serverInfo":{"name":"loopback-sse","version":"1"}}),
        Some("tools/list") => json!({"tools":[{"name":"read","description":"Read only",
            "inputSchema":{"type":"object"}}]}),
        Some("tools/call") => json!({"content":[{"type":"text",
            "text":"safe output sk-proj-abcdefghijklmnopqrstuvwx"}]}),
        _ => return StatusCode::BAD_REQUEST,
    };
    let reply = if upstream.discovery_error && frame["method"] == "initialize" {
        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,
            "message":"private-sse-message","data":{"credential":"private-sse-credential"}}})
    } else {
        json!({"jsonrpc":"2.0","id":id,"result":result})
    };
    let _ = upstream.tx.send(format!("event: message\ndata: {reply}\n\n"));
    StatusCode::ACCEPTED
}

struct Fixture {
    address: String,
    calls: Arc<Mutex<Vec<(String, Value)>>>,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn fixture(advertised: &str) -> Fixture {
    fixture_with_error(advertised, false).await
}

async fn fixture_with_error(advertised: &str, discovery_error: bool) -> Fixture {
    let (tx, _) = broadcast::channel(32);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let upstream = Upstream { tx, calls: calls.clone(), advertised: advertised.into(), discovery_error };
    let app = Router::new().route("/sse", get(sse)).route("/messages", post(message)).with_state(upstream);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let (shutdown, stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    Fixture { address, calls, shutdown: Some(shutdown), task }
}

async fn endpoint(h: &Harness, fixture: &Fixture) -> Value {
    let response = h
        .post(
            "/api/v1/mcp/endpoints",
            json!({"expected_version":0,"name":"Legacy SSE loopback",
                "url":format!("http://{}/sse", fixture.address),
                "transport":"legacy-sse","enabled":true,"idle_timeout_secs":5,
                "allowed_origins":["https://client.example"],"bearer_token":"upstream-secret"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["transport"], "legacy-sse");
    assert!(!response.text.contains("upstream-secret"));
    response.json()
}

async fn read(stream: &mut axum::body::BodyDataStream) -> String {
    let chunk = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("SSE message timeout")
        .expect("SSE stream closed")
        .expect("SSE stream failed");
    String::from_utf8(chunk.to_vec()).unwrap()
}

#[tokio::test]
async fn legacy_sse_is_bound_to_caller_and_settles_tool_quota_after_checked_stream_result() {
    let h = setup().await;
    let upstream = fixture("/messages?session=private-upstream-id").await;
    let row = endpoint(&h, &upstream).await;
    let id = row["id"].as_str().unwrap();
    let sse_url = format!("/api/v1/mcp/legacy/{id}/sse");
    let denied = h
        .request_with(
            "GET",
            &sse_url,
            &[("authorization", &format!("Bearer {}", h.admin)), ("origin", "https://other.example")],
            None,
        )
        .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN, "{}", denied.text);
    assert!(upstream.calls.lock().unwrap().is_empty());
    let response = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&sse_url)
                .header("authorization", format!("Bearer {}", h.admin))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let mut stream = response.into_body().into_data_stream();
    let announcement = read(&mut stream).await;
    let proxy_post = announcement.lines().find_map(|line| line.strip_prefix("data: ")).unwrap().to_owned();
    assert!(proxy_post.starts_with(&format!("/api/v1/mcp/legacy/{id}/messages/")));
    assert!(!announcement.contains("private-upstream-id"));
    let other_key = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("mcps:execute"), Permission::from_raw("policies:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "different-sse-caller", Timestamp::now())
    });
    h.state.store.api_key_insert(other_key.record.clone()).unwrap();
    let foreign = h
        .request_with(
            "POST",
            &proxy_post,
            &[("x-agf-key", &other_key.plaintext)],
            Some(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})),
        )
        .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND, "{}", foreign.text);
    let unrelated = h
        .post(
            &format!("/api/v1/mcp/legacy/{id}/messages/{}", agf_core::ids::Id::new()),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .await;
    assert_eq!(unrelated.status, StatusCode::NOT_FOUND);
    let mut concurrent_limit = Quota::tenant_default(h.tenant, QuotaDimension::Concurrency, 1);
    concurrent_limit.limit = 2;
    let quota = agf_api::quota_definitions::save(&h.state, h.tenant, concurrent_limit).await.unwrap();
    let mut request_limit = Quota::tenant_default(h.tenant, QuotaDimension::Requests, 1);
    request_limit.limit = 2;
    let requests = agf_api::quota_definitions::save(&h.state, h.tenant, request_limit).await.unwrap();
    let accepted = h
        .post(
            &proxy_post,
            json!({"jsonrpc":"2.0","id":9,"method":"tools/call",
                "params":{"name":"read","arguments":{}}}),
        )
        .await;
    assert_eq!(accepted.status, StatusCode::ACCEPTED, "{}", accepted.text);
    let usage_path = format!("/api/v1/mcp/endpoints/{id}/usage");
    let pending_usage = h.get(&usage_path).await.json();
    assert_eq!(pending_usage["items"][0]["name"], "read");
    assert_eq!(pending_usage["items"][0]["attempts"], 1);
    assert_eq!(pending_usage["items"][0]["inflight"], 1);
    assert_eq!(agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap()[&quota.id], 1);
    let duplicate = h
        .post(
            &proxy_post,
            json!({"jsonrpc":"2.0","id":9,"method":"tools/call",
                "params":{"name":"read","arguments":{}}}),
        )
        .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT, "{}", duplicate.text);
    let usage = agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap();
    assert_eq!(usage[&quota.id], 1);
    assert_eq!(usage[&requests.id], 1);
    assert_eq!(h.get(&usage_path).await.json()["items"][0]["attempts"], 1);
    let result = read(&mut stream).await;
    assert!(result.contains("safe output"), "{result}");
    assert!(!result.contains("sk-proj-abcdefghijklmnopqrstuvwx"), "{result}");
    assert_eq!(agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap()[&quota.id], 0);
    assert_eq!(agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap()[&requests.id], 1);
    let completed_usage = h.get(&usage_path).await.json();
    assert_eq!(completed_usage["items"][0]["succeeded"], 1);
    assert_eq!(completed_usage["items"][0]["inflight"], 0);
    {
        let calls = upstream.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "Bearer upstream-secret");
        assert_eq!(calls[0].1["method"], "tools/call");
    }
    drop(stream);
    for _ in 0..50 {
        let response = h.post(&proxy_post, json!({"jsonrpc":"2.0","id":10,"method":"tools/list"})).await;
        if response.status == StatusCode::NOT_FOUND {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("SSE session remained usable after the receive stream closed");
}

#[tokio::test]
async fn legacy_sse_probe_discovers_tools_without_calling_them() {
    let h = setup().await;
    let upstream = fixture("/messages?session=probe").await;
    let row = endpoint(&h, &upstream).await;
    let response = h
        .post(&format!("/api/v1/mcp/endpoints/{}/probe", row["id"].as_str().unwrap()), json!({"protocol":"2024-11-05"}))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["server"]["serverInfo"]["name"], "loopback-sse");
    assert_eq!(response.json()["tools"]["tools"][0]["name"], "read");
    assert_eq!(response.json()["session_closed"], true);
    let calls = upstream.calls.lock().unwrap();
    assert_eq!(
        calls.iter().map(|call| call.1["method"].as_str().unwrap()).collect::<Vec<_>>(),
        ["initialize", "notifications/initialized", "tools/list"]
    );
}

#[tokio::test]
async fn legacy_sse_probe_does_not_show_upstream_error_details() {
    let h = setup().await;
    let upstream = fixture_with_error("/messages?session=probe-error", true).await;
    let row = endpoint(&h, &upstream).await;
    let response = h
        .post(&format!("/api/v1/mcp/endpoints/{}/probe", row["id"].as_str().unwrap()), json!({"protocol":"2024-11-05"}))
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST, "{}", response.text);
    assert!(response.text.contains("JSON-RPC code -32601"), "{}", response.text);
    assert!(!response.text.contains("private-sse-message"));
    assert!(!response.text.contains("private-sse-credential"));
    assert_eq!(upstream.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn legacy_sse_rejects_cross_origin_advertised_post_uri() {
    let h = setup().await;
    let upstream = fixture("https://other.example/messages").await;
    let row = endpoint(&h, &upstream).await;
    let response = h.get(&format!("/api/v1/mcp/legacy/{}/sse", row["id"].as_str().unwrap())).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST, "{}", response.text);
    assert!(upstream.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn legacy_sse_connection_refusal_releases_all_tool_quota_without_losing_the_session() {
    let h = setup().await;
    let mut upstream = fixture("/messages?session=will-disconnect").await;
    let row = endpoint(&h, &upstream).await;
    let response = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/mcp/legacy/{}/sse", row["id"].as_str().unwrap()))
                .header("authorization", format!("Bearer {}", h.admin))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body().into_data_stream();
    let announcement = read(&mut stream).await;
    let proxy_post = announcement.lines().find_map(|line| line.strip_prefix("data: ")).unwrap();
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
    upstream.shutdown.take().unwrap().send(()).unwrap();
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(&upstream.address).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(tokio::net::TcpStream::connect(&upstream.address).await.is_err());
    let sent = h
        .post(
            proxy_post,
            json!({"jsonrpc":"2.0","id":17,"method":"tools/call",
                "params":{"name":"read","arguments":{}}}),
        )
        .await;
    assert_eq!(sent.status, StatusCode::SERVICE_UNAVAILABLE, "{}", sent.text);
    let used = agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap();
    assert_eq!(used[&requests.id], 0);
    assert_eq!(used[&concurrency.id], 0);
    assert!(upstream.calls.lock().unwrap().is_empty());
    drop(stream);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn legacy_sse_session_and_post_uri_survive_a_second_api_instance() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let first_store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(first_store.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(first_store)));
    sql_runtime_identity::rebind(&mut h.state, &[h.tenant, h.other_tenant]).await.unwrap();
    let tenant = agf_api::tenant_directory::new(format!("sse-sql-{}", TenantId::new()), "SSE SQL".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.app = build_router(h.state.clone());
    let mut fixture = fixture("/messages?session=sql-upstream-private").await;
    let token = format!("Bearer {}", h.admin);
    let tenant_id = tenant.id.to_string();
    let headers = [("authorization", token.as_str()), ("x-agf-tenant", tenant_id.as_str())];
    let saved = h
        .request_with(
            "POST",
            "/api/v1/mcp/endpoints",
            &headers,
            Some(json!({"expected_version":0,"name":"Cross-instance SSE",
                "url":format!("http://{}/sse",fixture.address),"transport":"legacy-sse",
                "enabled":true,"idle_timeout_secs":5,"bearer_token":"upstream-secret"})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let sse_url = format!("/api/v1/mcp/legacy/{}/sse", saved.json()["id"].as_str().unwrap());
    let response = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(sse_url)
                .header("authorization", &token)
                .header("x-agf-tenant", &tenant_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body().into_data_stream();
    let announcement = read(&mut stream).await;
    let post_url = announcement.lines().find_map(|line| line.strip_prefix("data: ")).unwrap();
    let second_store =
        Arc::new(Store::new(Database::from_pool(pool.clone()), None, Arc::new(MemoryObjectStore::new())));
    let mut second = h.state.clone();
    second.store = Arc::new(agf_api::store::ApiStore::with_database(second_store.clone()));
    second.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(second_store)));
    sql_runtime_identity::rebind(&mut second, &[h.tenant, h.other_tenant]).await.unwrap();
    let second_app = build_router(second.clone());
    let posted = send(
        &second_app,
        Request::builder()
            .method("POST")
            .uri(post_url)
            .header("authorization", &token)
            .header("x-agf-tenant", &tenant_id)
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{"protocolVersion":"2024-11-05","capabilities":{},
                    "clientInfo":{"name":"cross-instance","version":"1"}}})
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(posted.status, StatusCode::ACCEPTED, "{}", posted.text);
    assert!(read(&mut stream).await.contains("loopback-sse"));
    assert_eq!(fixture.calls.lock().unwrap().len(), 1);
    let mut request_limit = Quota::tenant_default(tenant.id, QuotaDimension::Requests, 1);
    request_limit.limit = 2;
    let requests = agf_api::quota_definitions::save(&h.state, tenant.id, request_limit).await.unwrap();
    let mut concurrent_limit = Quota::tenant_default(tenant.id, QuotaDimension::Concurrency, 1);
    concurrent_limit.limit = 2;
    let concurrency = agf_api::quota_definitions::save(&h.state, tenant.id, concurrent_limit).await.unwrap();
    for expected in [StatusCode::ACCEPTED, StatusCode::CONFLICT] {
        let call = send(
            &second_app,
            Request::builder()
                .method("POST")
                .uri(post_url)
                .header("authorization", &token)
                .header("x-agf-tenant", &tenant_id)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
                    "params":{"name":"read","arguments":{}}})
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(call.status, expected, "{}", call.text);
    }
    let used = agf_api::runtime_quota::usage(&second, tenant.id).await.unwrap();
    assert_eq!(used[&requests.id], 1);
    assert_eq!(used[&concurrency.id], 1);
    assert!(read(&mut stream).await.contains("safe output"));
    assert_eq!(agf_api::runtime_quota::usage(&second, tenant.id).await.unwrap()[&concurrency.id], 0);
    let endpoint_id = saved.json()["id"].as_str().unwrap().to_string();
    let usage = h.request_with("GET", &format!("/api/v1/mcp/endpoints/{endpoint_id}/usage"), &headers, None).await;
    assert_eq!(usage.status, StatusCode::OK, "{}", usage.text);
    assert_eq!(usage.json()["items"][0]["attempts"], 1);
    assert_eq!(usage.json()["items"][0]["succeeded"], 1);
    fixture.shutdown.take().unwrap().send(()).unwrap();
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(&fixture.address).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(tokio::net::TcpStream::connect(&fixture.address).await.is_err());
    let rejected = send(
        &second_app,
        Request::builder()
            .method("POST")
            .uri(post_url)
            .header("authorization", &token)
            .header("x-agf-tenant", &tenant_id)
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
                "params":{"name":"read","arguments":{}}})
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(rejected.status, StatusCode::SERVICE_UNAVAILABLE, "{}", rejected.text);
    let used = agf_api::runtime_quota::usage(&second, tenant.id).await.unwrap();
    assert_eq!(used[&requests.id], 1);
    assert_eq!(used[&concurrency.id], 0);
    assert_eq!(fixture.calls.lock().unwrap().len(), 2);
    drop(stream);
    pool.close().await;
}
