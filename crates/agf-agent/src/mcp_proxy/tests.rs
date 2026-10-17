#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use agf_core::{
    audit::{
        AgentAuditAcknowledgement, AgentAuditBatch, AuditChainAnchor, AuditChainKind, GENESIS_HASH, SignedAuditAnchor,
    },
    ids::{Id, TenantId},
    time::Timestamp,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[tokio::test]
async fn real_mcp_guard_requires_audit_ack_before_returning_a_forwardable_frame() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let fail = Arc::new(AtomicBool::new(false));
    let fail_server = fail.clone();
    let decisions = Arc::new(AtomicUsize::new(0));
    let count = decisions.clone();
    let task = tokio::spawn(async move {
        let tenant = TenantId::new();
        let agent = Id::new();
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut data = Vec::new();
            let mut buffer = [0u8; 4096];
            let boundary = loop {
                let n = socket.read(&mut buffer).await.unwrap();
                assert!(n > 0);
                data.extend_from_slice(&buffer[..n]);
                if let Some(at) = data.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break at + 4;
                }
                assert!(data.len() < 64 * 1024);
            };
            let header = String::from_utf8(data[..boundary].to_vec()).unwrap();
            assert!(header.to_ascii_lowercase().contains("x-agf-key: owned-guard-key"));
            let length = header
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|value| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            while data.len() - boundary < length {
                let n = socket.read(&mut buffer).await.unwrap();
                assert!(n > 0);
                data.extend_from_slice(&buffer[..n]);
            }
            let request: Value = serde_json::from_slice(&data[boundary..boundary + length]).unwrap();
            let response = if header.starts_with("POST /api/v1/runtime/mcp/check ") {
                json!({"allowed":true,"frame":request["frame"]})
            } else {
                assert!(header.starts_with("POST /api/v1/runtime/audit/anchors "));
                let batch: AgentAuditBatch = serde_json::from_value(request).unwrap();
                if !batch.entries.is_empty() {
                    count.fetch_add(1, Ordering::SeqCst);
                }
                if fail_server.swap(false, Ordering::SeqCst) {
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
                serde_json::to_value(AgentAuditAcknowledgement {
                    checkpoint: SignedAuditAnchor {
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
                    },
                    durable: true,
                    replayed: false,
                })
                .unwrap()
            };
            let body = response.to_string();
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        }
    });
    let directory = tempfile::tempdir().unwrap();
    let client = reqwest::Client::new();
    let token = reqwest::header::HeaderValue::from_static("owned-guard-key");
    let audit = agf_agent::audit_anchor::AgentAuditClient::open(
        client.clone(),
        format!("{base}/api/v1/runtime/audit/anchors"),
        token.clone(),
        directory.path(),
    )
    .unwrap();
    let guard = Guard {
        client,
        endpoint: format!("{base}/api/v1/runtime/mcp/check"),
        token,
        session: "owned-guard-session".into(),
        leases: Mutex::new(BTreeMap::new()),
        audit,
    };
    guard.audit.resume().await.unwrap();
    let frame = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
    assert_eq!(guard.check(&frame, false).await.unwrap(), frame);
    assert_eq!(decisions.load(Ordering::SeqCst), 1);
    fail.store(true, Ordering::SeqCst);
    assert!(guard.check(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}), false).await.is_err());
    assert_eq!(decisions.load(Ordering::SeqCst), 2);
    task.abort();
}
