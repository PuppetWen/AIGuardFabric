//! Actual OpenAI HTTP and SSE. Counters count received requests, never manufactured outcomes.
use super::*;
use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
    routing::post,
};
use futures::stream;
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::{sync::Semaphore, task::JoinHandle};
pub(super) const MODEL: &str = "owned-stream-settlement";
pub(super) const KEY: &str = "synthetic-literal127-provider-only";
#[derive(Clone, Copy)]
pub(crate) enum Reply {
    Known,
    Partial,
    Unknown,
    HeldPartial,
    HttpFailure,
}
#[derive(Clone)]
struct Wire {
    reply: Reply,
    calls: Arc<AtomicUsize>,
    frames: Arc<Semaphore>,
    release: Arc<Semaphore>,
}
pub(crate) struct Provider {
    pub(crate) address: SocketAddr,
    state: Wire,
    task: JoinHandle<()>,
}
impl Provider {
    pub(crate) async fn start(reply: Reply) -> DomainResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|_| invalid())?;
        let address = listener.local_addr().map_err(|_| invalid())?;
        if address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) {
            return Err(invalid());
        }
        let state = Wire {
            reply,
            calls: Arc::new(AtomicUsize::new(0)),
            frames: Arc::new(Semaphore::new(0)),
            release: Arc::new(Semaphore::new(0)),
        };
        let app = Router::new().route("/chat/completions", post(reply_http)).with_state(state.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self { address, state, task })
    }
    pub(crate) fn calls(&self) -> usize {
        self.state.calls.load(Ordering::SeqCst)
    }
    pub(crate) async fn framed(&self) -> DomainResult<()> {
        tokio::time::timeout(WAIT, self.state.frames.acquire())
            .await
            .map_err(|_| invalid())?
            .map_err(|_| invalid())?
            .forget();
        Ok(())
    }
    pub(crate) fn release(&self) {
        self.state.release.add_permits(2);
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.release();
        self.task.abort();
    }
}
async fn reply_http(State(state): State<Wire>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    state.calls.fetch_add(1, Ordering::SeqCst);
    let expected = format!("Bearer {KEY}");
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(expected.as_str()) || body["model"] != MODEL {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if matches!(state.reply, Reply::HttpFailure) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if body["stream"] != true {
        return Json(json!({"id":"owned-reply","object":"chat.completion","created":1,"model":MODEL,
            "choices":[{"index":0,"message":{"role":"assistant","content":"owned-reply"},"finish_reason":"stop"}],
            "usage":{"prompt_tokens":96,"completion_tokens":4,"total_tokens":100}}))
        .into_response();
    }
    let chunks = stream::unfold((state, 0_u8), |(state, phase)| async move {
        let frame = match phase {
            0 => {
                state.frames.add_permits(1);
                let usage = if matches!(state.reply, Reply::Partial | Reply::HeldPartial) {
                    json!({"prompt_tokens":40,"completion_tokens":3,"total_tokens":43})
                } else {
                    Value::Null
                };
                json!({"id":"owned-chunk","object":"chat.completion.chunk","created":1,"model":MODEL,
                    "choices":[{"index":0,"delta":{"role":"assistant","content":"owned-stream"},"finish_reason":null}],"usage":usage})
            }
            1 if matches!(state.reply, Reply::Known) => {
                json!({"id":"owned-chunk","object":"chat.completion.chunk","created":1,"model":MODEL,
                "choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":96,"completion_tokens":4,"total_tokens":100}})
            }
            1 if matches!(state.reply, Reply::HeldPartial) => {
                let _ = tokio::time::timeout(WAIT, state.release.acquire()).await;
                return None;
            }
            _ => return None,
        };
        let bytes = format!("data: {frame}\n\n").into_bytes();
        Some((Ok::<_, Infallible>(bytes), (state, phase + 1)))
    });
    ([("content-type", "text/event-stream")], Body::from_stream(chunks)).into_response()
}
