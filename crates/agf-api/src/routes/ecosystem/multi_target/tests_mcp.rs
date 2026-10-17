//! Actual literal127 transport fixtures. No external target, fake delivery or automatic call replay.
use super::{mcp::Session, mcp_frames::invalid, mcp_headers};
use agf_core::error::DomainResult;
use reqwest::{Client, Url, header::HeaderMap};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
struct Fixture {
    url: Url,
    rows: Arc<Mutex<Vec<(BTreeMap<String, String>, Value)>>>,
    task: JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn start(legacy: bool, bad_session: bool) -> DomainResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| invalid())?;
        let url = Url::parse(&format!("http://{}/mcp", listener.local_addr().map_err(|_| invalid())?))
            .map_err(|_| invalid())?;
        let rows = Arc::new(Mutex::new(vec![]));
        let captured = rows.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let Ok((headers, body)) = receive(&mut stream).await else {
                    continue;
                };
                if let Ok(mut rows) = captured.lock() {
                    rows.push((headers, body.clone()));
                } else {
                    break;
                }
                let method = body["method"].as_str().unwrap_or("");
                let (status,content_type,extra,raw)=match method {
                    "initialize" if legacy=>(200,"application/json","Mcp-Session-Id: owned-session\r\n",
                        json!({"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"owned","version":"1"}}}).to_string()),
                    "notifications/initialized" if legacy=>(202,"application/json","",String::new()),
                    _=>{
                        let extra=if legacy {if bad_session {"Mcp-Session-Id: rotated-session\r\n"}else{"Mcp-Session-Id: owned-session\r\n"}}else{""};
                        let result=json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"safe actual response"}]}});
                        if legacy {(200,"application/json",extra,result.to_string())}
                        else {(200,"text/event-stream",extra,format!(":keepalive\r\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}}\r\n\r\ndata: {result}\r\n\r\n"))}
                    }
                };
                let head = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    raw.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(raw.as_bytes()).await;
            }
        });
        Ok(Self { url, rows, task })
    }
    fn rows(&self) -> DomainResult<Vec<(BTreeMap<String, String>, Value)>> {
        self.rows.lock().map(|rows| rows.clone()).map_err(|_| invalid())
    }
}
async fn receive(stream: &mut TcpStream) -> DomainResult<(BTreeMap<String, String>, Value)> {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 1024];
        let end = loop {
            let count = stream.read(&mut chunk).await.map_err(|_| invalid())?;
            if count == 0 || bytes.len() + count > 64 * 1024 {
                return Err(invalid());
            }
            bytes.extend_from_slice(&chunk[..count]);
            if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                break end;
            }
        };
        let head = std::str::from_utf8(&bytes[..end]).map_err(|_| invalid())?;
        if !head.starts_with("POST /mcp HTTP/1.1") {
            return Err(invalid());
        }
        let headers: BTreeMap<_, _> = head
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        let size = headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|size| *size <= 48 * 1024)
            .ok_or_else(invalid)?;
        while bytes.len() < end + 4 + size {
            let count = stream.read(&mut chunk).await.map_err(|_| invalid())?;
            if count == 0 || bytes.len() + count > 64 * 1024 {
                return Err(invalid());
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        let body = serde_json::from_slice(&bytes[end + 4..end + 4 + size]).map_err(|_| invalid())?;
        Ok((headers, body))
    })
    .await
    .map_err(|_| invalid())?
}
fn client() -> DomainResult<Client> {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|_| invalid())
}
#[tokio::test]
async fn modern_actual_sse_and_header_encoding_keep_complete_metadata_and_send_once() -> DomainResult<()> {
    let fixture = Fixture::start(false, false).await?;
    let client = client()?;
    let session = Session::modern();
    let schema = json!({"properties":{"query":{"type":"string","x-mcp-header":"Query"}}});
    let name = mcp_headers::tool(&schema, "query")?;
    let body = session.body("tools/call", json!({"name":"安全工具","arguments":{"query":" 汉字 "}}))?;
    let result =
        session.request(&client, &fixture.url, None, &body, mcp_headers::parameters(name.as_ref(), " 汉字 ")?).await?;
    assert_eq!(result.content["result"]["content"][0]["text"], "safe actual response");
    let rows = fixture.rows()?;
    assert_eq!(rows.len(), 1);
    let (headers, body) = &rows[0];
    assert!(
        headers
            .get("accept")
            .is_some_and(|value| value.contains("application/json") && value.contains("text/event-stream"))
    );
    assert!(headers.get("mcp-name").is_some_and(|value| value.starts_with("=?base64?")));
    assert!(headers.get("mcp-param-query").is_some_and(|value| value.starts_with("=?base64?")));
    assert!(
        body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
            && body["params"]["_meta"]["io.modelcontextprotocol/clientInfo"].is_object()
            && body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"].is_object()
    );
    Ok(())
}
#[tokio::test]
async fn explicit_legacy_initializes_once_and_carries_only_captured_session() -> DomainResult<()> {
    let fixture = Fixture::start(true, false).await?;
    let client = client()?;
    let session = Session::initialize(&client, &fixture.url, None).await?;
    session.initialized(&client, &fixture.url, None).await?;
    let body = session.body("tools/call", json!({"name":"safe","arguments":{"query":"public"}}))?;
    session.request(&client, &fixture.url, None, &body, HeaderMap::new()).await?;
    let rows = fixture.rows()?;
    assert_eq!(rows.len(), 3);
    assert!(rows[0].1["method"] == "initialize" && !rows[0].0.contains_key("mcp-session-id"));
    assert!(rows[1].1["method"] == "notifications/initialized" && rows[2].1["method"] == "tools/call");
    for row in &rows[1..] {
        assert!(row.0.get("mcp-session-id").is_some_and(|value| value == "owned-session"));
        assert!(row.0.get("mcp-protocol-version").is_some_and(|value| value == "2025-11-25"));
        assert!(row.1["params"].get("_meta").is_none());
    }
    Ok(())
}
#[tokio::test]
async fn legacy_session_rotation_rejects_response_without_repeating_tools_call() -> DomainResult<()> {
    let fixture = Fixture::start(true, true).await?;
    let client = client()?;
    let session = Session::initialize(&client, &fixture.url, None).await?;
    session.initialized(&client, &fixture.url, None).await?;
    let body = session.body("tools/call", json!({"name":"safe","arguments":{"query":"public"}}))?;
    assert!(session.request(&client, &fixture.url, None, &body, HeaderMap::new()).await.is_err());
    assert_eq!(fixture.rows()?.iter().filter(|row| row.1["method"] == "tools/call").count(), 1);
    Ok(())
}
