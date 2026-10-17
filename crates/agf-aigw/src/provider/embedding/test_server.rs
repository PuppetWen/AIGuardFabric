use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use agf_core::ids::{Id, TenantId};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::Duration,
};

use super::{EmbeddingClient, EmbeddingConfiguration, EmbeddingProfile, EmbeddingReservation, MAX_REQUEST_BYTES};

pub(super) const KEY: &str = "synthetic-owned-embedding-key-no-cloud";

pub(super) fn configuration(origin: String) -> EmbeddingConfiguration {
    EmbeddingConfiguration {
        tenant_id: TenantId::new(),
        endpoint_id: Id::new(),
        configuration_version: 7,
        provider: "openai-compatible".into(),
        origin,
        model: "owned-embedding-model".into(),
        model_revision: "owned-revision-20261001".into(),
        dimensions: 3,
        send_dimensions: true,
        max_input_tokens: 8192,
        input_micro_per_1k: 500,
    }
}

pub(super) fn reservation(tokens: u64) -> EmbeddingReservation {
    EmbeddingReservation { reserved_tokens: tokens, reserved_cost_micro: tokens.div_ceil(2) }
}

pub(super) fn valid_response(tokens: u64) -> Value {
    json!({"object":"list", "model":"owned-embedding-model", "data":[{
        "object":"embedding", "index":0, "embedding":[0.25, -0.5, 0.75]
    }], "usage":{"prompt_tokens":tokens, "total_tokens":tokens}})
}

#[derive(Debug, Clone)]
pub(super) struct Reply {
    pub(super) status: u16,
    pub(super) body: Vec<u8>,
    pub(super) extra_headers: Vec<(String, String)>,
    pub(super) header_delay: Duration,
    pub(super) chunk_delay: Duration,
    pub(super) chunk_bytes: usize,
    pub(super) chunked: bool,
    pub(super) declared_length: Option<usize>,
    pub(super) close_without_response: bool,
    pub(super) content_type: String,
}

impl Reply {
    pub(super) fn json(value: &Value) -> Self {
        Self {
            status: 200,
            body: serde_json::to_vec(value).unwrap(),
            extra_headers: Vec::new(),
            header_delay: Duration::ZERO,
            chunk_delay: Duration::ZERO,
            chunk_bytes: usize::MAX,
            chunked: false,
            declared_length: None,
            close_without_response: false,
            content_type: "application/json".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct ObservedRequest {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) authorization_matches: bool,
    pub(super) accepts_identity: bool,
    pub(super) json: Value,
}

#[derive(Debug)]
pub(super) struct Server {
    pub(super) origin: String,
    requests: Arc<Mutex<Vec<ObservedRequest>>>,
    accepted: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Server {
    pub(super) async fn new(reply: Reply) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let accepted = Arc::new(AtomicUsize::new(0));
        let task_requests = Arc::clone(&requests);
        let task_accepted = Arc::clone(&accepted);
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                task_accepted.fetch_add(1, Ordering::SeqCst);
                let Some(request) = read_request(&mut stream).await else {
                    continue;
                };
                task_requests.lock().unwrap().push(request);
                if !reply.close_without_response {
                    let _ = write_reply(&mut stream, &reply).await;
                }
            }
        });
        Self { origin, requests, accepted, task }
    }

    pub(super) fn client(&self) -> EmbeddingClient {
        let profile = EmbeddingProfile::literal_loopback_for_test(configuration(self.origin.clone())).unwrap();
        EmbeddingClient::from_service_profile(profile, KEY).unwrap()
    }

    pub(super) fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    pub(super) fn requests(&self) -> Vec<ObservedRequest> {
        self.requests.lock().unwrap().clone()
    }

    pub(super) async fn wait_for_request(&self) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.requests.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_request(stream: &mut TcpStream) -> Option<ObservedRequest> {
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        if bytes.len() > 8192 {
            return None;
        }
        let mut chunk = [0u8; 1024];
        let length = stream.read(&mut chunk).await.ok()?;
        if length == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..length]);
    };
    let header = String::from_utf8(bytes[..header_end].to_vec()).ok()?;
    let mut lines = header.lines();
    let mut first = lines.next()?.split_ascii_whitespace();
    let method = first.next()?.to_owned();
    let path = first.next()?.to_owned();
    let fields = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_owned()))
        .collect::<Vec<_>>();
    let lookup = |name| fields.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str());
    let length: usize = lookup("content-length")?.parse().ok()?;
    if length > MAX_REQUEST_BYTES {
        return None;
    }
    while bytes.len() < header_end + length {
        let mut chunk = [0u8; 1024];
        let length = stream.read(&mut chunk).await.ok()?;
        if length == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..length]);
    }
    let expected_authorization = format!("Bearer {KEY}");
    Some(ObservedRequest {
        method,
        path,
        authorization_matches: lookup("authorization") == Some(expected_authorization.as_str()),
        accepts_identity: lookup("accept-encoding") == Some("identity"),
        json: serde_json::from_slice(&bytes[header_end..header_end + length]).ok()?,
    })
}

async fn write_reply(stream: &mut TcpStream, reply: &Reply) -> std::io::Result<()> {
    tokio::time::sleep(reply.header_delay).await;
    let mut header =
        format!("HTTP/1.1 {} Test\r\nContent-Type: {}\r\nConnection: close\r\n", reply.status, reply.content_type);
    if reply.chunked {
        header.push_str("Transfer-Encoding: chunked\r\n");
    } else {
        header.push_str(&format!("Content-Length: {}\r\n", reply.declared_length.unwrap_or(reply.body.len())));
    }
    for (name, value) in &reply.extra_headers {
        header.push_str(&format!("{name}: {value}\r\n"));
    }
    header.push_str("\r\n");
    stream.write_all(header.as_bytes()).await?;
    for chunk in reply.body.chunks(reply.chunk_bytes.max(1)) {
        tokio::time::sleep(reply.chunk_delay).await;
        if reply.chunked {
            stream.write_all(format!("{:x}\r\n", chunk.len()).as_bytes()).await?;
        }
        stream.write_all(chunk).await?;
        if reply.chunked {
            stream.write_all(b"\r\n").await?;
        }
    }
    if reply.chunked {
        stream.write_all(b"0\r\n\r\n").await?;
    }
    stream.shutdown().await
}
