//! Actual authenticated gateway requests against an owned, priced HTTP loopback.
#![allow(dead_code)]
use crate::common::*;
use agf_core::ids::Id;
use axum::{Json, routing::post};
use std::{
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{sync::Semaphore, task::JoinHandle};

pub(crate) const QUOTAS: &str = "/api/v1/quotas";
pub(crate) const MODEL: &str = "owned-quota-model";
const PROVIDER_KEY: &str = "synthetic-owned-loopback-only";
const WAIT: Duration = Duration::from_secs(20);

#[derive(Clone)]
pub(crate) struct Identity {
    pub(crate) asset: Id,
    pub(crate) key: String,
}

#[derive(Clone)]
struct ProviderState {
    calls: Arc<AtomicUsize>,
    blocked: Arc<AtomicBool>,
    arrived: Arc<Semaphore>,
    released: Arc<Semaphore>,
}

pub(crate) struct Loopback {
    pub(crate) url: String,
    state: ProviderState,
    server: JoinHandle<()>,
}

impl Loopback {
    pub(crate) async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        assert!(address.ip().is_loopback());
        let state = ProviderState {
            calls: Arc::new(AtomicUsize::new(0)),
            blocked: Arc::new(AtomicBool::new(false)),
            arrived: Arc::new(Semaphore::new(0)),
            released: Arc::new(Semaphore::new(0)),
        };
        let provider = state.clone();
        let app = Router::new().route(
            "/chat/completions",
            post(move |headers: axum::http::HeaderMap, Json(body): Json<Value>| {
                let provider = provider.clone();
                async move {
                    // This counter measures received HTTP requests, including incorrect credentials.
                    provider.calls.fetch_add(1, Ordering::SeqCst);
                    provider.arrived.add_permits(1);
                    assert_eq!(headers["authorization"].to_str().unwrap(), format!("Bearer {PROVIDER_KEY}"));
                    assert_eq!(body["model"], MODEL);
                    if provider.blocked.load(Ordering::SeqCst) {
                        tokio::time::timeout(WAIT, provider.released.acquire()).await.unwrap().unwrap().forget();
                    }
                    Json(json!({
                        "id":"owned-response","object":"chat.completion","created":1,"model":MODEL,
                        "choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],
                        "usage":{"prompt_tokens":96,"completion_tokens":4,"total_tokens":100}
                    }))
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url: format!("http://{address}"), state, server }
    }

    pub(crate) fn calls(&self) -> usize {
        self.state.calls.load(Ordering::SeqCst)
    }

    pub(crate) fn block(&self) {
        self.state.blocked.store(true, Ordering::SeqCst);
    }

    pub(crate) async fn arrived(&self) {
        tokio::time::timeout(WAIT, self.state.arrived.acquire()).await.unwrap().unwrap().forget();
    }

    pub(crate) fn release(&self) {
        self.state.blocked.store(false, Ordering::SeqCst);
        self.state.released.add_permits(16);
    }
}

impl Drop for Loopback {
    fn drop(&mut self) {
        self.release();
        self.server.abort();
    }
}

/// Pending client futures are aborted even when an assertion unwinds before release.
pub(crate) struct Pending(Option<JoinHandle<Resp>>);

impl Pending {
    pub(crate) fn start(h: Harness, identity: Identity, session: &str) -> Self {
        let session = session.to_string();
        Self(Some(tokio::spawn(async move { call(&h, &identity, &session).await })))
    }

    pub(crate) async fn finish(mut self) -> Resp {
        // Keep the handle inside the Drop guard while timeout awaits it.
        let response = tokio::time::timeout(WAIT, self.0.as_mut().unwrap()).await.unwrap().unwrap();
        self.0.take();
        response
    }

    pub(crate) async fn cancel(mut self) {
        let task = self.0.take().unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

/// Per-state mode only; never mutate global environment or force an actual provider.
pub(crate) fn live(mut h: Harness) -> Harness {
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    let tenant = h.tenant;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        request.headers_mut().insert("x-agf-tenant", tenant.to_string().parse().unwrap());
        async move { request }
    }));
    h
}

pub(crate) async fn configure(h: &Harness, upstream: &Loopback) -> [Identity; 2] {
    let endpoint = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":"owned-loopback","provider":"openai","model":MODEL,
            "base_url":upstream.url,"api_key":PROVIDER_KEY,"expected_version":0,
            "pricing":{"prompt_micro_per_1k":1000,"completion_micro_per_1k":1000,"cached_prompt_micro_per_1k":1000}}),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    assert_eq!(endpoint.json()["mocked"], false);
    let discovery = h
        .post(
            "/api/v1/assets/discovery",
            json!({"source":"agent-report","assets":[
                {"kind":"agent","name":"owned-worker-a","fingerprint":"owned-quota-worker-a"},
                {"kind":"agent","name":"owned-worker-b","fingerprint":"owned-quota-worker-b"}
            ]}),
        )
        .await;
    assert_eq!(discovery.status, StatusCode::OK, "{}", discovery.text);
    let assets = h.state.store.asset_list_all_durable(h.tenant).await.unwrap();
    let left = assets.iter().find(|asset| asset.name == "owned-worker-a").unwrap().id;
    let right = assets.iter().find(|asset| asset.name == "owned-worker-b").unwrap().id;
    let endpoints = h.get("/api/v1/gateway/endpoints").await;
    assert_eq!(endpoints.json()["items"].as_array().unwrap().len(), 1, "fixture must own its only endpoint");
    [bound_key(h, left).await, bound_key(h, right).await]
}

async fn bound_key(h: &Harness, asset: Id) -> Identity {
    let response = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":format!("owned-model-{asset}"),"bound_agent_id":asset,
            "scopes":["models:read","models:write"],"expires_in_secs":3600}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "Key creation failed");
    assert_eq!(response.json()["api_key"]["bound_agent_id"], json!(asset));
    Identity { asset, key: response.json()["plaintext"].as_str().unwrap().to_string() }
}

pub(crate) async fn quota(h: &Harness, scope: &str, dimension: &str, window: &str, limit: i64) -> String {
    let name = format!("owned-{scope}-{dimension}-{window}");
    let response = h
        .post(
            QUOTAS,
            json!({"name":name,"expected_version":0,"scope":scope,"dimension":dimension,
            "window":window,"limit":limit,"action":"deny","enabled":true}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{scope}/{dimension}: {}", response.text);
    name
}

pub(crate) async fn used(h: &Harness, name: &str) -> i64 {
    let response = h.get(QUOTAS).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response.json()["items"].as_array().unwrap().iter().find(|row| row["quota"]["name"] == name).unwrap()["used"]
        .as_i64()
        .unwrap()
}

pub(crate) async fn call(h: &Harness, identity: &Identity, session: &str) -> Resp {
    let bearer = format!("Bearer {}", identity.key);
    tokio::time::timeout(
        WAIT,
        h.request_with(
            "POST",
            "/v1/chat/completions",
            &[("authorization", bearer.as_str()), ("x-agf-session", session)],
            // Positive temperature disables exact caching: every accepted case must reach our HTTP server.
            Some(json!({"model":MODEL,"max_tokens":4,"temperature":1,
                "messages":[{"role":"user","content":"hello"}]})),
        ),
    )
    .await
    .unwrap()
}

pub(crate) fn accepted(response: &Resp) {
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.header("x-agf-mocked"), "false");
    assert_eq!(response.header("x-agf-cached"), "false");
    assert_eq!(response.json()["usage"]["total_tokens"], 100);
}

pub(crate) fn denied(response: &Resp, scope: &str, dimension: &str) {
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS, "{scope}/{dimension}: {}", response.text);
    assert_eq!(response.code(), "quota_exceeded", "{}", response.text);
}

pub(crate) async fn assert_settled(h: &Harness, identity: &Identity, session: &str) {
    let rows = agf_api::gateway_quota::usage(&h.state, h.tenant).await.unwrap();
    let row = rows.iter().find(|row| row.agent_id == Some(identity.asset) && row.session_id == session).unwrap();
    assert!(!row.mocked);
    assert!(!row.cache_hit);
    assert_eq!(row.prompt_tokens, 96);
    assert_eq!(row.completion_tokens, 4);
    assert_eq!(row.cost_micro, 100, "positive micro-unit cost must come from actual upstream usage");
}

pub(crate) async fn wait_released(h: &Harness, name: &str) {
    tokio::time::timeout(WAIT, async {
        while used(h, name).await != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancelled gateway request must release its concurrent reservation");
}
