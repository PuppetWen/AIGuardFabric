//! Exact owned HTTP provider, with received-request counters and a bounded response gate.
use super::*;
use axum::{
    Router,
    extract::{Json, State},
    http::HeaderMap,
    routing::post,
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Semaphore, task::JoinHandle};
const KEY: &str = "synthetic-owned-loopback-only";
const MODEL: &str = "owned-settlement-embedding";
const WAIT: Duration = Duration::from_secs(20);
#[derive(Clone)]
struct Provider {
    calls: Arc<AtomicUsize>,
    tokens: Arc<AtomicU64>,
    blocked: Arc<AtomicBool>,
    arrived: Arc<Semaphore>,
    released: Arc<Semaphore>,
}
pub(super) struct Embedding {
    pub(super) address: SocketAddr,
    state: Provider,
    server: JoinHandle<()>,
}
impl Embedding {
    pub(super) async fn start() -> DomainResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|_| invalid())?;
        let address = listener.local_addr().map_err(|_| invalid())?;
        assert_eq!(address.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let state = Provider {
            calls: Arc::new(AtomicUsize::new(0)),
            tokens: Arc::new(AtomicU64::new(2)),
            blocked: Arc::new(AtomicBool::new(false)),
            arrived: Arc::new(Semaphore::new(0)),
            released: Arc::new(Semaphore::new(0)),
        };
        let app = Router::new().route("/v1/embeddings", post(reply)).with_state(state.clone());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self { address, state, server })
    }
    pub(super) fn calls(&self) -> usize {
        self.state.calls.load(Ordering::SeqCst)
    }
    pub(super) fn tokens(&self, value: u64) {
        self.state.tokens.store(value, Ordering::SeqCst);
    }
    pub(super) fn block(&self) {
        self.state.blocked.store(true, Ordering::SeqCst);
    }
    pub(super) async fn arrived(&self) -> DomainResult<()> {
        tokio::time::timeout(WAIT, self.state.arrived.acquire())
            .await
            .map_err(|_| invalid())?
            .map_err(|_| invalid())?
            .forget();
        Ok(())
    }
    pub(super) fn release(&self) {
        self.state.blocked.store(false, Ordering::SeqCst);
        self.state.released.add_permits(4);
    }
}
impl Drop for Embedding {
    fn drop(&mut self) {
        self.release();
        self.server.abort();
    }
}
async fn reply(
    State(state): State<Provider>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    state.calls.fetch_add(1, Ordering::SeqCst);
    state.arrived.add_permits(1);
    let expected = format!("Bearer {KEY}");
    if headers.get("authorization").and_then(|value| value.to_str().ok()) != Some(expected.as_str())
        || body["model"] != MODEL
        || body["input"].as_str().is_none()
        || body["encoding_format"] != "float"
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if state.blocked.load(Ordering::SeqCst) {
        tokio::time::timeout(WAIT, state.released.acquire())
            .await
            .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .forget();
    }
    let tokens = state.tokens.load(Ordering::SeqCst);
    Ok(Json(
        json!({"object":"list","model":MODEL,"data":[{"object":"embedding","index":0,"embedding":[1.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0]}],
        "usage":{"prompt_tokens":tokens,"total_tokens":tokens}}),
    ))
}

pub(super) struct Fixture {
    pub(super) h: Harness,
    pub(super) identity: crate::agentteams_quota_scope_support::Identity,
    pub(super) key_id: Id,
    pub(super) endpoint: Id,
}
impl Fixture {
    pub(super) async fn new(
        h: Harness,
        chat: &crate::agentteams_quota_scope_support::Loopback,
        embedding: &Embedding,
    ) -> DomainResult<Self> {
        let mut h = crate::agentteams_quota_scope_support::live(h);
        let identities = crate::agentteams_quota_scope_support::configure(&h, chat).await;
        let asset = h.state.store.asset_get_durable(h.tenant, identities[0].asset).await?.ok_or_else(invalid)?;
        let update = h
            .request(
                "PATCH",
                &format!("/api/v1/assets/{}", asset.id),
                Some(&h.admin),
                Some(json!({
            "name":asset.name,"owner":"owned-gateway-test","department":"","data_class":"public",
            "expected_updated_at":asset.updated_at,"reason":"owned public test messages only"})),
            )
            .await;
        assert_eq!(update.status, StatusCode::OK);
        let key = h
            .post(
                "/api/v1/settings/api-keys",
                json!({"name":"owned-semantic-caller","bound_agent_id":asset.id,
            "scopes":["models:read","models:write"],"expires_in_secs":3600}),
            )
            .await;
        assert_eq!(key.status, StatusCode::CREATED);
        let identity = crate::agentteams_quota_scope_support::Identity {
            asset: asset.id,
            key: key.json()["plaintext"].as_str().ok_or_else(invalid)?.into(),
        };
        let key_id = serde_json::from_value(key.json()["api_key"]["id"].clone())?;
        let chat_id: Id =
            serde_json::from_value(h.get("/api/v1/gateway/endpoints").await.json()["items"][0]["id"].clone())?;
        let response = h
            .post(
                "/api/v1/gateway/endpoints",
                json!({"expected_version":0,"name":MODEL,"provider":"openai","model":MODEL,
            "base_url":format!("http://{}",embedding.address),"api_key":KEY,"max_data_class":"public",
            "pricing":{"prompt_micro_per_1k":1000,"completion_micro_per_1k":1000,"cached_prompt_micro_per_1k":1000}}),
            )
            .await;
        assert_eq!(response.status, StatusCode::CREATED);
        let endpoint = serde_json::from_value(response.json()["id"].clone())?;
        h.state = h.state.with_gateway_loopback_test_endpoint(h.tenant, endpoint, embedding.address)?;
        h = crate::agentteams_quota_scope_support::live(h);
        let profile = h.request("PUT", "/api/v1/models/semantic-cache/profile", Some(&h.admin), Some(json!({"expected_version":0,"enabled":true,"settings":{
            "chat_endpoint_id":chat_id,"chat_model":crate::agentteams_quota_scope_support::MODEL,"chat_model_revision":"owned-chat-v1",
            "embedding_endpoint_id":endpoint,"embedding_model":MODEL,"embedding_model_revision":"owned-embedding-v1",
            "dimensions":8,"send_dimensions":false,"max_input_tokens":64,"embedding_micro_per_1k":1000,
            "threshold_ppm":950_000,"ttl_seconds":300,"classification_floor":"public","mode":"live"}}))).await;
        assert_eq!(profile.status, StatusCode::OK);
        Ok(Self { h, identity, key_id, endpoint })
    }
    pub(super) async fn restart(&self, owned: &Owned, embedding: &Embedding) -> DomainResult<Harness> {
        let mut h = owned.case.second_instance().await;
        h.state = h.state.with_gateway_loopback_test_endpoint(h.tenant, self.endpoint, embedding.address)?;
        Ok(crate::agentteams_quota_scope_support::live(h))
    }
    pub(super) async fn call(&self, text: &str) -> DomainResult<Resp> {
        call(&self.h, &self.identity, text).await
    }
}
pub(super) async fn call(
    h: &Harness,
    identity: &crate::agentteams_quota_scope_support::Identity,
    text: &str,
) -> DomainResult<Resp> {
    let bearer = format!("Bearer {}", identity.key);
    tokio::time::timeout(
        WAIT,
        h.request_with(
            "POST",
            "/v1/chat/completions",
            &[
                ("authorization", bearer.as_str()),
                ("x-agf-data-class", "public"),
                ("x-agf-session", "owned-paid-semantic"),
            ],
            Some(json!({"model":crate::agentteams_quota_scope_support::MODEL,"temperature":0,"max_tokens":4,
            "messages":[{"role":"user","content":text}]})),
        ),
    )
    .await
    .map_err(|_| invalid())
}
pub(super) async fn cache_count(owned: &Owned) -> DomainResult<i64> {
    owned.ownership.verify(&owned.case.pool).await?;
    sqlx::query_scalar("SELECT count(*) FROM semantic_response_cache_v2 WHERE tenant_id=$1")
        .bind(owned.case.h.tenant.as_uuid())
        .fetch_one(&owned.case.pool)
        .await
        .map_err(|error| sql(&error))
}
pub(super) fn attempt(response: &Resp) -> DomainResult<Id> {
    Id::parse(&response.header("x-agf-attempt-id")).map_err(|_| super::invalid())
}
