//! Owned literal127 HTTP, with exact synthetic credentials and a real partial SSE frame gate.
use agf_aigw::{AiGateway, provider::StaticCredentialResolver, screen::NoopScreen};
use agf_core::{
    enums::{DataClass, LlmProvider},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    model::{Modality, ModelEndpoint, ModelPricing},
    time::Timestamp,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinHandle,
};
pub(crate) const MODEL: &str = "owned-stream-model";
const KEY: &str = "synthetic-owned-wire-only";
#[derive(Clone, Copy)]
pub(crate) enum Reply {
    Failed,
    Known,
    HeldPartial,
}
pub(crate) struct Wire {
    address: SocketAddr,
    calls: Arc<AtomicUsize>,
    release: Arc<Semaphore>,
    task: JoinHandle<()>,
}
impl Wire {
    pub(crate) async fn start(reply: Reply) -> DomainResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| invalid())?;
        let address = listener.local_addr().map_err(|_| invalid())?;
        assert_eq!(address.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Semaphore::new(0));
        let count = calls.clone();
        let gate = release.clone();
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let count = count.clone();
                let gate = gate.clone();
                tokio::spawn(async move {
                    let _ = serve(socket, reply, count, gate).await;
                });
            }
        });
        Ok(Self { address, calls, release, task })
    }
    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
    pub(crate) fn release(&self) {
        self.release.add_permits(4);
    }
    pub(crate) fn endpoint(&self, tenant: TenantId, priority: u32) -> ModelEndpoint {
        let at = Timestamp::now();
        ModelEndpoint {
            id: Id::new(),
            tenant_id: tenant,
            asset_id: Id::new(),
            name: format!("owned-{priority}"),
            provider: LlmProvider::OpenAi,
            base_url: format!("http://{}", self.address),
            model: MODEL.into(),
            modalities: vec![Modality::Text],
            context_window: Some(4096),
            max_output_tokens: Some(4096),
            supports_streaming: true,
            supports_tools: true,
            credential_ref: Some(Id::new()),
            local_deployment: false,
            max_data_class: DataClass::Confidential,
            pricing: ModelPricing {
                prompt_micro_per_1k: 1000,
                completion_micro_per_1k: 1000,
                cached_prompt_micro_per_1k: 1000,
            },
            enabled: true,
            fallback: true,
            priority,
            extra_headers: BTreeMap::new(),
            created_at: at,
            updated_at: at,
        }
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.release();
        self.task.abort();
    }
}
async fn serve(mut socket: TcpStream, reply: Reply, calls: Arc<AtomicUsize>, gate: Arc<Semaphore>) -> DomainResult<()> {
    let mut bytes = Vec::new();
    let mut buffer = vec![0_u8; 4096];
    let (head, end) = loop {
        let size = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buffer))
            .await
            .map_err(|_| invalid())?
            .map_err(|_| invalid())?;
        if size == 0 || bytes.len() + size > 64 * 1024 {
            return Err(invalid());
        }
        bytes.extend_from_slice(&buffer[..size]);
        if let Some(at) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break (String::from_utf8(bytes[..at].to_vec()).map_err(|_| invalid())?, at + 4);
        }
    };
    calls.fetch_add(1, Ordering::SeqCst);
    assert!(head.starts_with("POST /chat/completions HTTP/1.1"), "Unexpected owned HTTP route");
    assert!(
        head.lines().any(|line| line.eq_ignore_ascii_case(&format!("authorization: Bearer {KEY}"))),
        "Synthetic provider authentication mismatch"
    );
    let length = head
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        })
        .ok_or_else(invalid)?;
    if length > 64 * 1024 {
        return Err(invalid());
    }
    while bytes.len() < end + length {
        let count = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buffer))
            .await
            .map_err(|_| invalid())?
            .map_err(|_| invalid())?;
        if count == 0 {
            return Err(invalid());
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let body: Value = serde_json::from_slice(&bytes[end..end + length]).map_err(|_| invalid())?;
    assert!(body["model"] == MODEL, "Unexpected owned model");
    if matches!(reply, Reply::Failed) {
        socket
            .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .map_err(|_| invalid())?;
        return Ok(());
    }
    if body["stream"] != true {
        let content=json!({"id":"owned-response","object":"chat.completion","created":1,"model":MODEL,"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":96,"completion_tokens":4,"total_tokens":100}}).to_string();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            content.len()
        );
        socket.write_all(head.as_bytes()).await.map_err(|_| invalid())?;
        socket.write_all(content.as_bytes()).await.map_err(|_| invalid())?;
        return Ok(());
    }
    let first = frame(
        json!({"choices":[{"index":0,"delta":{"role":"assistant","content":"partial"},"finish_reason":null}],"usage":{"prompt_tokens":40,"completion_tokens":3,"total_tokens":43}}),
    );
    let last = frame(
        json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":0,"completion_tokens":1,"total_tokens":1}}),
    );
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        first.len() + last.len()
    );
    socket.write_all(header.as_bytes()).await.map_err(|_| invalid())?;
    socket.write_all(first.as_bytes()).await.map_err(|_| invalid())?;
    socket.flush().await.map_err(|_| invalid())?;
    if matches!(reply, Reply::HeldPartial) {
        tokio::time::timeout(Duration::from_secs(5), gate.acquire())
            .await
            .map_err(|_| invalid())?
            .map_err(|_| invalid())?
            .forget();
    }
    let _ = socket.write_all(last.as_bytes()).await;
    Ok(())
}
fn frame(body: Value) -> String {
    format!("data: {body}\n\n")
}
pub(crate) fn gateway(endpoints: Vec<ModelEndpoint>) -> DomainResult<AiGateway> {
    let mut credentials = StaticCredentialResolver::new();
    for endpoint in &endpoints {
        credentials = credentials.with_key(endpoint.credential_ref.ok_or_else(invalid)?, KEY);
    }
    Ok(AiGateway::new(endpoints)
        .with_credentials(Arc::new(credentials))
        .with_screen(Arc::new(NoopScreen))
        .with_mock_mode(false))
}
pub(crate) fn invalid() -> DomainError {
    DomainError::PreconditionFailed("Owned deferred transport invariant failed".into())
}
