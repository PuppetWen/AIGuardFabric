use super::owned::failure;
use agf_core::error::DomainResult;
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
    task::JoinHandle,
};
#[derive(Clone)]
pub(crate) struct Gate {
    arrived: Arc<Notify>,
    release: Arc<Notify>,
    seen: Arc<AtomicBool>,
}
impl Gate {
    fn new() -> Self {
        Self {
            arrived: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            seen: Arc::new(AtomicBool::new(false)),
        }
    }
    pub(crate) async fn wait(&self) -> DomainResult<()> {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let next = self.arrived.notified();
                if self.seen.load(Ordering::SeqCst) {
                    break;
                }
                next.await;
            }
        })
        .await
        .map_err(|_| failure())?;
        Ok(())
    }
    pub(crate) fn release(&self) {
        self.release.notify_one();
    }
}
pub(crate) struct Wire {
    pub(crate) address: SocketAddr,
    rows: Arc<Mutex<Vec<Value>>>,
    task: JoinHandle<()>,
    pub(crate) gate: Option<Gate>,
}
#[derive(Clone, Copy)]
pub(crate) enum Protocol {
    Json,
    CurrentMcp,
    LegacyMcp,
}
pub(crate) struct ProtocolOptions {
    pub(crate) protocol: Protocol,
    pub(crate) readonly_tools: bool,
    pub(crate) hold_first_request: bool,
}
impl Wire {
    pub(crate) async fn start(body: Value, tools: bool, readonly: bool, held: bool) -> DomainResult<Self> {
        Self::start_protocol(
            body,
            ProtocolOptions {
                protocol: if tools { Protocol::CurrentMcp } else { Protocol::Json },
                readonly_tools: readonly,
                hold_first_request: held,
            },
        )
        .await
    }
    pub(crate) async fn start_protocol(body: Value, options: ProtocolOptions) -> DomainResult<Self> {
        let tools = !matches!(options.protocol, Protocol::Json);
        let legacy = matches!(options.protocol, Protocol::LegacyMcp);
        let readonly = options.readonly_tools;
        let held = options.hold_first_request;
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| failure())?;
        let address = listener.local_addr().map_err(|_| failure())?;
        let rows = Arc::new(Mutex::new(Vec::new()));
        let captured = rows.clone();
        let gate = held.then(Gate::new);
        let wait = gate.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let (input, headers) = match receive(&mut stream).await {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                {
                    let mut rows = match captured.lock() {
                        Ok(rows) => rows,
                        Err(_) => break,
                    };
                    rows.push(input.clone());
                }
                if let Some(gate) = &wait {
                    if !gate.seen.swap(true, Ordering::SeqCst) {
                        gate.arrived.notify_one();
                        gate.release.notified().await;
                    }
                }
                let accepted = !tools || valid(&input, &headers, legacy);
                let notification = tools && legacy && input["method"] == "notifications/initialized";
                let response = if tools && legacy && input["method"] == "initialize" {
                    json!({"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"owned","version":"1"}}})
                } else if tools && input["method"] == "tools/list" {
                    json!({"jsonrpc":"2.0","id":1,"result":{"tools":[{
                    "name":"safe_query","annotations":{"readOnlyHint":readonly},"inputSchema":{"type":"object",
                    "properties":{"query":{"type":"string"}},"required":["query"]}}]}})
                } else {
                    body.clone()
                };
                if let Ok(raw) = if notification { Ok(vec![]) } else { serde_json::to_vec(&response) } {
                    let status = if !accepted {
                        400
                    } else if notification {
                        202
                    } else {
                        200
                    };
                    let session = if legacy && tools { "Mcp-Session-Id: owned-private-session\r\n" } else { "" };
                    let head = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n{session}Content-Length: {}\r\nConnection: close\r\n\r\n",
                        raw.len()
                    );
                    // A cancelled actual client can close the socket; never fabricate a successful delivery.
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&raw).await;
                }
            }
        });
        Ok(Self { address, rows, task, gate })
    }
    pub(crate) fn url(&self) -> String {
        format!("http://{}/target", self.address)
    }
    pub(crate) fn requests(&self) -> DomainResult<Vec<Value>> {
        self.rows.lock().map(|rows| rows.clone()).map_err(|_| failure())
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        if let Some(gate) = &self.gate {
            gate.release();
        }
        self.task.abort();
    }
}
fn valid(input: &Value, headers: &std::collections::BTreeMap<String, String>, legacy: bool) -> bool {
    let accept = headers
        .get("accept")
        .is_some_and(|value| value.contains("application/json") && value.contains("text/event-stream"));
    if !accept {
        return false;
    }
    if legacy {
        if input["method"] == "initialize" {
            return input["params"]["protocolVersion"] == "2025-11-25" && !headers.contains_key("mcp-session-id");
        }
        return headers.get("mcp-protocol-version").is_some_and(|value| value == "2025-11-25")
            && headers.get("mcp-session-id").is_some_and(|value| value == "owned-private-session");
    }
    headers.get("mcp-protocol-version").is_some_and(|value| value == "2026-07-28")
        && headers.get("mcp-method").is_some_and(|value| input["method"].as_str() == Some(value.as_str()))
        && input["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
        && input["params"]["_meta"]["io.modelcontextprotocol/clientInfo"].is_object()
        && input["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"].is_object()
        && (input["method"] != "tools/call" || headers.get("mcp-name").is_some_and(|value| value == "safe_query"))
}
async fn receive(stream: &mut TcpStream) -> DomainResult<(Value, std::collections::BTreeMap<String, String>)> {
    tokio::time::timeout(std::time::Duration::from_secs(12), async {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 1024];
        let split = loop {
            let count = stream.read(&mut chunk).await.map_err(|_| failure())?;
            if count == 0 || bytes.len() + count > 64 * 1024 {
                return Err(failure());
            }
            bytes.extend_from_slice(&chunk[..count]);
            if let Some(i) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                break i;
            }
        };
        let head = std::str::from_utf8(&bytes[..split]).map_err(|_| failure())?;
        if !head.starts_with("POST /target HTTP/1.1") {
            return Err(failure());
        }
        let size = head
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            })
            .filter(|size| *size <= 48 * 1024)
            .ok_or_else(failure)?;
        let headers = head
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        while bytes.len() < split + 4 + size {
            let count = stream.read(&mut chunk).await.map_err(|_| failure())?;
            if count == 0 {
                return Err(failure());
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        let body = serde_json::from_slice(&bytes[split + 4..split + 4 + size]).map_err(|_| failure())?;
        Ok((body, headers))
    })
    .await
    .map_err(|_| failure())?
}
