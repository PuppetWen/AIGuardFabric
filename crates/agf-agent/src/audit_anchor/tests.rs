use super::*;
use agf_core::{
    audit::{AuditChainAnchor, GENESIS_HASH},
    ids::TenantId,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

struct MockPlatform {
    endpoint: String,
    fail_next: Arc<AtomicBool>,
    received: Arc<Mutex<Vec<AgentAuditBatch>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for MockPlatform {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl MockPlatform {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/api/v1/runtime/audit/anchors", listener.local_addr().unwrap());
        let fail_next = Arc::new(AtomicBool::new(false));
        let fail = fail_next.clone();
        let received = Arc::new(Mutex::new(Vec::new()));
        let calls = received.clone();
        let tenant = TenantId::new();
        let agent = Id::new();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0u8; 4096];
                let boundary = loop {
                    let n = socket.read(&mut buffer).await.unwrap();
                    if n == 0 {
                        break None;
                    }
                    bytes.extend_from_slice(&buffer[..n]);
                    if let Some(at) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
                        break Some(at + 4);
                    }
                    assert!(bytes.len() < 64 * 1024);
                };
                let Some(boundary) = boundary else {
                    continue;
                };
                let headers = String::from_utf8(bytes[..boundary].to_vec()).unwrap();
                assert!(headers.to_ascii_lowercase().contains("x-agf-key: owned-test-key"));
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                while bytes.len() - boundary < length {
                    let n = socket.read(&mut buffer).await.unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buffer[..n]);
                    assert!(bytes.len() < 64 * 1024);
                }
                let batch: AgentAuditBatch = serde_json::from_slice(&bytes[boundary..boundary + length]).unwrap();
                calls.lock().await.push(batch.clone());
                if fail.swap(false, Ordering::SeqCst) {
                    socket
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                    continue;
                }
                let (sequence, hash) = batch
                    .entries
                    .last()
                    .map_or((0, GENESIS_HASH.to_owned()), |entry| (entry.sequence, entry.entry_hash.clone()));
                let checkpoint = SignedAuditAnchor {
                    kind: AuditChainKind::AgentRuntime,
                    chain_id: batch.chain_id,
                    agent_id: Some(agent),
                    previous_anchor_id: batch.previous.as_ref().map(|value| value.anchor.id),
                    previous_anchor_hash: batch.previous.as_ref().map(SignedAuditAnchor::witness_hash),
                    anchor: AuditChainAnchor {
                        id: Id::new(),
                        tenant_id: tenant,
                        up_to_sequence: sequence,
                        tail_hash: hash,
                        entry_count: sequence,
                        created_at: Timestamp::now(),
                        signature: "a".repeat(64),
                    },
                };
                // 此传输夹具验证 Agent 确认结构及日志恢复；真实主密钥密码学
                // 由存储层及已认证 API 测试覆盖。
                let body =
                    serde_json::to_vec(&AgentAuditAcknowledgement { checkpoint, durable: true, replayed: false })
                        .unwrap();
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            }
        });
        Self { endpoint, fail_next, received, task }
    }
}

#[tokio::test]
async fn real_http_ack_failure_keeps_exact_pending_segment_then_restart_resumes_before_new_decision() {
    let platform = MockPlatform::start().await;
    let directory = tempfile::tempdir().unwrap();
    let open = || {
        AgentAuditClient::open(
            Client::new(),
            platform.endpoint.clone(),
            HeaderValue::from_static("owned-test-key"),
            directory.path(),
        )
        .unwrap()
    };
    let client = open();
    client.resume().await.unwrap();
    platform.fail_next.store(true, Ordering::SeqCst);
    let frame =
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"secret":"must-not-be-journaled"}}});
    let denied = json!({"allowed":false,"frame":null});
    assert!(client.record(&frame, false, "owned-session", &denied).await.is_err());
    let pending = client.journal.lock().await.state.pending.clone();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].outcome, AuditOutcome::Denied);
    let text = serde_json::to_string(&pending).unwrap();
    assert!(!text.contains("must-not-be-journaled"));
    drop(client);
    let resumed = open();
    resumed.resume().await.unwrap();
    let state = resumed.journal.lock().await;
    assert!(state.state.pending.is_empty());
    assert_eq!(state.state.ack.as_ref().unwrap().anchor.up_to_sequence, 1);
    drop(state);
    let calls = platform.received.lock().await;
    assert_eq!(calls.len(), 3);
    assert_eq!(serde_json::to_vec(&calls[1]).unwrap(), serde_json::to_vec(&calls[2]).unwrap());
    drop(calls);
    resumed
        .record(
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
            false,
            "after-restart",
            &json!({"allowed":true,"frame":{"jsonrpc":"2.0","id":2,"result":{}}}),
        )
        .await
        .unwrap();
    assert_eq!(resumed.journal.lock().await.state.ack.as_ref().unwrap().anchor.up_to_sequence, 2);
}

#[tokio::test]
async fn journal_owner_lock_identity_and_durable_ack_are_required() {
    let platform = MockPlatform::start().await;
    let directory = tempfile::tempdir().unwrap();
    let client = AgentAuditClient::open(
        Client::new(),
        platform.endpoint.clone(),
        HeaderValue::from_static("owned-test-key"),
        directory.path(),
    )
    .unwrap();
    assert!(
        AgentAuditClient::open(
            Client::new(),
            platform.endpoint.clone(),
            HeaderValue::from_static("owned-test-key"),
            directory.path()
        )
        .is_err()
    );
    client.resume().await.unwrap();
    let previous = client.journal.lock().await.state.ack.clone().unwrap();
    let batch = AgentAuditBatch { chain_id: previous.chain_id, previous: None, entries: Vec::new() };
    let mut ack = AgentAuditAcknowledgement { checkpoint: previous, durable: false, replayed: false };
    assert!(verify_ack(&batch, &ack).is_err());
    ack.durable = true;
    ack.checkpoint.chain_id = Id::new();
    assert!(verify_ack(&batch, &ack).is_err());
    assert!(
        AgentAuditClient::open(
            Client::new(),
            "http://192.0.2.1/api/v1/runtime/audit/anchors".into(),
            HeaderValue::from_static("owned-test-key"),
            directory.path()
        )
        .is_err()
    );
}
