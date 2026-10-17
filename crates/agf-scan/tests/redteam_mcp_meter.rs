//! TCP fixtures distinguish calls that never arrived from interrupted responses.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use agf_core::{ids::Id, redteam::RedteamCase};
use agf_scan::redteam::{McpHttpTarget, TargetUnderTest, ToolCallOutcome, ToolCallReceipt};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

type Receipts = Arc<Mutex<Vec<ToolCallOutcome>>>;

fn case() -> RedteamCase {
    serde_yaml::from_str(include_str!("../../../redteam/credential-theft/RT-MCP-001.yaml")).unwrap()
}

fn target(address: std::net::SocketAddr, receipts: Receipts) -> McpHttpTarget {
    McpHttpTarget::new(
        "TCP meter fixture".into(),
        Id::new(),
        &format!("http://{address}/mcp"),
        "safe_query".into(),
        "query".into(),
        None,
        "MCP_ProtectedTcp_28463e019".into(),
    )
    .unwrap()
    .with_tool_meter(move |name| {
        assert_eq!(name, "safe_query", "discovery must not reserve tool usage");
        let receipts = receipts.clone();
        Box::pin(async move {
            let receipt = ToolCallReceipt::new(move |outcome| {
                Box::pin(async move {
                    receipts.lock().unwrap().push(outcome);
                    Ok(())
                })
            });
            Ok(receipt)
        })
    })
}

async fn read_request(stream: &mut TcpStream) -> Value {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let body_start = loop {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0, "client closed before sending its request headers");
        bytes.extend_from_slice(&buffer[..read]);
        assert!(bytes.len() < 16 * 1024, "fixture request exceeded its expected size");
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..body_start]).unwrap();
    let length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
        .expect("reqwest's fixed JSON body has a Content-Length header");
    assert!(length < 8 * 1024, "fixture request body exceeded its expected size");
    while bytes.len() < body_start + length {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0, "client closed before sending the complete tool request");
        bytes.extend_from_slice(&buffer[..read]);
    }
    serde_json::from_slice(&bytes[body_start..body_start + length]).unwrap()
}

async fn send_discovery(stream: &mut TcpStream) {
    let body = json!({"jsonrpc":"2.0","id":1,"result":{"tools":[{
        "name":"safe_query","annotations":{"readOnlyHint":true},
        "inputSchema":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}
    }]}})
    .to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
}

#[tokio::test]
async fn tool_connection_refused_is_not_delivered_after_successful_discovery() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Stop listening before discovery succeeds. Connection: close prevents reuse.
            drop(listener);
            assert_eq!(read_request(&mut stream).await["method"], "tools/list");
            send_discovery(&mut stream).await;
        });
        let receipts = Receipts::default();
        let result = target(address, receipts.clone()).observe_case(&case()).await;
        assert!(result.is_err(), "an unavailable tool must not produce an evaluated observation");
        server.await.unwrap();
        assert_eq!(*receipts.lock().unwrap(), vec![ToolCallOutcome::NotDelivered]);
    })
    .await
    .expect("connection refusal fixture must finish promptly");
}

#[tokio::test]
async fn interrupted_response_after_received_tool_call_is_unknown() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(read_request(&mut stream).await["method"], "tools/list");
            send_discovery(&mut stream).await;
            drop(stream);
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            assert_eq!(request["method"], "tools/call");
            assert_eq!(request["params"]["name"], "safe_query");
            // The tool could execute: its full request arrived, but no complete result followed.
            stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 200\r\nConnection: close\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":["
            ).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let receipts = Receipts::default();
        let result = target(address, receipts.clone()).observe_case(&case()).await;
        assert!(result.is_err(), "an interrupted result must not produce an evaluated observation");
        server.await.unwrap();
        assert_eq!(*receipts.lock().unwrap(), vec![ToolCallOutcome::Unknown]);
    })
    .await
    .expect("truncated response fixture must finish promptly");
}

#[tokio::test]
async fn dropped_receipt_distinguishes_unsent_reservation_from_sending() {
    for (sending, expected) in [(false, ToolCallOutcome::NotDelivered), (true, ToolCallOutcome::Cancelled)] {
        let (settled, result) = tokio::sync::oneshot::channel();
        let mut receipt = ToolCallReceipt::new(move |outcome| {
            Box::pin(async move {
                settled.send(outcome).expect("receipt callback has one receiver");
                Ok(())
            })
        });
        if sending {
            receipt.mark_sending();
        }
        drop(receipt);
        let actual = tokio::time::timeout(Duration::from_secs(2), result)
            .await
            .expect("dropped receipt must settle promptly")
            .expect("settlement callback must execute");
        assert_eq!(actual, expected);
    }
}

#[tokio::test]
async fn settlement_finishes_when_the_caller_is_cancelled() {
    let (started, start) = tokio::sync::oneshot::channel();
    let (resume, resumed) = tokio::sync::oneshot::channel();
    let (settled, result) = tokio::sync::oneshot::channel();
    let mut receipt = ToolCallReceipt::new(move |outcome| {
        Box::pin(async move {
            started.send(()).unwrap();
            resumed.await.unwrap();
            settled.send(outcome).unwrap();
            Ok(())
        })
    });
    receipt.mark_sending();
    let caller = tokio::spawn(async move { receipt.finish(ToolCallOutcome::Succeeded).await });
    tokio::time::timeout(Duration::from_secs(2), start).await.unwrap().unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    resume.send(()).unwrap();
    let actual = tokio::time::timeout(Duration::from_secs(2), result)
        .await
        .expect("settlement must outlive the cancelled caller")
        .expect("settlement callback must finish");
    assert_eq!(actual, ToolCallOutcome::Succeeded);
}
