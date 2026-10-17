//! Real literal127 output-limit fixture; no production provider or fake usage result.
use crate::{
    agentteams_quota_scope_support::{Identity, MODEL},
    common::*,
};
use agf_core::error::{DomainError, DomainResult};
use axum::{Json, routing::post};
use std::sync::atomic::{AtomicUsize, Ordering};

const KEY: &str = "synthetic-owned-output-limit-only";
pub(crate) const PROVIDER_TEXT: &str = "owned provider output beyond admitted completion tokens";

pub(crate) async fn over_limit_call(h: &Harness, identity: &Identity) -> DomainResult<Resp> {
    let bearer = format!("Bearer {}", identity.key);
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        h.request_with(
            "POST",
            "/v1/chat/completions",
            &[("authorization", bearer.as_str()), ("x-agf-session", "owned-block")],
            Some(json!({"model":MODEL,"max_tokens":4,"temperature":0,"messages":[{"role":"user","content":"hello"}]})),
        ),
    )
    .await
    .map_err(|_| DomainError::Timeout("Owned output fixture call timed out".into()))
}

pub(crate) struct OverLimitReply {
    origin: String,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl OverLimitReply {
    pub(crate) async fn start() -> DomainResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| DomainError::Internal("Owned response fixture listener failed".into()))?;
        let address =
            listener.local_addr().map_err(|_| DomainError::Internal("Owned response fixture address failed".into()))?;
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let app = Router::new().route("/chat/completions", post(
            move |headers: axum::http::HeaderMap, Json(body): Json<Value>| {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(headers.get("authorization").and_then(|value| value.to_str().ok()),
                        Some(format!("Bearer {KEY}").as_str()));
                    assert_eq!(body["model"], MODEL);
                    Json(json!({"id":"owned-screened-response","object":"chat.completion","created":1,"model":MODEL,
                        "choices":[{"index":0,"message":{"role":"assistant","content":PROVIDER_TEXT},"finish_reason":"stop"}],
                        "usage":{"prompt_tokens":95,"completion_tokens":5,"total_tokens":100}}))
                }
            },
        ));
        let task = tokio::spawn(async move {
            assert!(axum::serve(listener, app).await.is_ok());
        });
        Ok(Self { origin: format!("http://{address}"), calls, task })
    }
    pub(crate) async fn configure(&self, h: &Harness) -> DomainResult<()> {
        let endpoints = h.get("/api/v1/gateway/endpoints").await;
        assert_eq!(endpoints.status, StatusCode::OK);
        let document = endpoints.json();
        let rows = document["items"].as_array().ok_or_else(super::invalid)?;
        assert_eq!(rows.len(), 1);
        let id = rows[0]["id"].as_str().ok_or_else(super::invalid)?;
        let response = h.request("PUT", &format!("/api/v1/gateway/endpoints/{id}"), Some(&h.admin), Some(json!({
            "name":"owned-output-block","provider":"openai","model":MODEL,"base_url":self.origin,"api_key":KEY,
            "expected_version":rows[0]["version"],
            "pricing":{"prompt_micro_per_1k":1000,"completion_micro_per_1k":1000,"cached_prompt_micro_per_1k":1000}
        }))).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.json()["mocked"], false);
        Ok(())
    }
    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}
impl Drop for OverLimitReply {
    fn drop(&mut self) {
        self.task.abort();
    }
}
