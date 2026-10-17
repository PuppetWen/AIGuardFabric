use super::*;
use provider::{KEY, MODEL};
use tower::ServiceExt;
#[derive(Clone, Copy)]
pub(crate) struct RequestBody {
    pub(crate) stream: bool,
    pub(crate) max_tokens: u32,
}
pub(crate) struct Fixture {
    pub(crate) h: Harness,
    pub(crate) key_id: Id,
    key: String,
}
impl Fixture {
    pub(crate) async fn new(owned: &Owned, providers: &[&Provider]) -> DomainResult<Self> {
        Self::with_cost(owned, providers, 1_000_000).await
    }
    pub(crate) async fn with_cost(owned: &Owned, providers: &[&Provider], limit: i64) -> DomainResult<Self> {
        owned.verify().await?;
        let mut h = owned.case.h.clone();
        Arc::make_mut(&mut h.state.config).mock_mode = false;
        h = router(h)?;
        for (index, provider) in providers.iter().enumerate() {
            let response = h.post("/api/v1/gateway/endpoints", json!({"expected_version":0,"name":format!("owned-provider-{index}"),"provider":"openai","model":MODEL,
                "base_url":format!("http://{}",provider.address),"api_key":KEY,"priority":index,"supports_streaming":true,
                "pricing":{"prompt_micro_per_1k":1000,"completion_micro_per_1k":1000,"cached_prompt_micro_per_1k":1000}})).await;
            assert!(response.status == StatusCode::CREATED, "Owned endpoint creation failed");
        }
        let key = h
            .post(
                "/api/v1/settings/api-keys",
                json!({"name":"owned-stream-caller","scopes":["models:read","models:write"],"expires_in_secs":3600}),
            )
            .await;
        assert!(key.status == StatusCode::CREATED, "Owned Key creation failed");
        let key_id = serde_json::from_value(key.json()["api_key"]["id"].clone())?;
        let key = key.json()["plaintext"].as_str().ok_or_else(invalid)?.to_owned();
        for (dimension, limit) in [("cost", limit), ("requests", 10), ("concurrency", 2)] {
            let response = h.post("/api/v1/quotas", json!({"expected_version":0,"name":format!("owned-{dimension}"),"scope":"tenant","dimension":dimension,"window":"total","limit":limit,"action":"deny","enabled":true})).await;
            assert!(response.status == StatusCode::OK, "Owned quota creation failed");
        }
        Ok(Self { h, key_id, key })
    }
    pub(crate) async fn restart(&self, owned: &Owned) -> DomainResult<Harness> {
        router(owned.case.second_instance().await)
    }
    fn request(&self, body: RequestBody, key: &str) -> DomainResult<Request<Body>> {
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", format!("Bearer {}", self.key))
            .header("content-type", "application/json")
            .header("x-agf-session", "owned-stream-session")
            .header("idempotency-key", key)
            .body(Body::from(
                json!({"model":MODEL,"stream":body.stream,"temperature":1,"max_tokens":body.max_tokens,
                "messages":[{"role":"user","content":"owned-message"}]})
                .to_string(),
            ))
            .map_err(|_| invalid())
    }
    pub(crate) async fn limited_call(
        &self,
        body: RequestBody,
        key: &str,
        session: &str,
        model: &str,
    ) -> DomainResult<Resp> {
        let mut request = self.request(body, key)?;
        request.headers_mut().insert("x-agf-session", session.parse().map_err(|_| invalid())?);
        *request.body_mut() = Body::from(
            json!({"model":model,"stream":body.stream,"temperature":1,
            "max_tokens":body.max_tokens,"messages":[{"role":"user","content":"owned-message"}]})
            .to_string(),
        );
        let response = tokio::time::timeout(WAIT, self.h.app.clone().oneshot(request))
            .await
            .map_err(|_| invalid())?
            .map_err(|_| invalid())?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = tokio::time::timeout(WAIT, axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024))
            .await
            .map_err(|_| invalid())?
            .map_err(|_| invalid())?;
        Ok(Resp { status, headers, text: String::from_utf8_lossy(&bytes).into_owned(), bytes: bytes.to_vec() })
    }
    pub(crate) async fn response(&self, body: RequestBody, key: &str) -> DomainResult<axum::response::Response> {
        tokio::time::timeout(WAIT, self.h.app.clone().oneshot(self.request(body, key)?))
            .await
            .map_err(|_| invalid())?
            .map_err(|_| invalid())
    }
    pub(crate) async fn call(&self, body: RequestBody, key: &str) -> DomainResult<Resp> {
        self.call_on(&self.h, body, key).await
    }
    pub(crate) async fn call_on(&self, h: &Harness, body: RequestBody, key: &str) -> DomainResult<Resp> {
        let response = tokio::time::timeout(WAIT, h.app.clone().oneshot(self.request(body, key)?))
            .await
            .map_err(|_| invalid())?
            .map_err(|_| invalid())?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = tokio::time::timeout(WAIT, axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024))
            .await
            .map_err(|_| invalid())?
            .map_err(|_| invalid())?;
        Ok(Resp { status, headers, text: String::from_utf8_lossy(&bytes).into_owned(), bytes: bytes.to_vec() })
    }
    pub(crate) async fn receipt(&self, h: &Harness, id: Id, recover: bool) -> Resp {
        let bearer = format!("Bearer {}", self.key);
        h.request_with(
            if recover { "POST" } else { "GET" },
            &format!("/api/v1/gateway/attempts/{id}{}", if recover { "/recover" } else { "" }),
            &[("authorization", bearer.as_str())],
            recover.then(|| json!({})),
        )
        .await
    }
    pub(crate) async fn used(&self, h: &Harness, dimension: &str) -> DomainResult<i64> {
        let response = h.get("/api/v1/quotas").await;
        let value = response.json();
        value["items"]
            .as_array()
            .ok_or_else(invalid)?
            .iter()
            .find(|row| row["quota"]["name"] == format!("owned-{dimension}"))
            .and_then(|row| row["used"].as_i64())
            .ok_or_else(invalid)
    }
}
fn router(mut h: Harness) -> DomainResult<Harness> {
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    let tenant = h.tenant.to_string().parse::<axum::http::HeaderValue>().map_err(|_| invalid())?;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        request.headers_mut().insert("x-agf-tenant", tenant.clone());
        async move { request }
    }));
    Ok(h)
}
pub(crate) fn attempt(response: &Resp) -> DomainResult<Id> {
    response.header("x-agf-attempt-id").parse().map_err(|_| invalid())
}
