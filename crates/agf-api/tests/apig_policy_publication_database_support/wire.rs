use crate::common::*;
use agf_core::error::{DomainError, DomainResult};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
    task::{JoinHandle, JoinSet},
    time::{Duration, timeout},
};

pub(crate) fn fixture_error(message: &str) -> DomainError {
    DomainError::Internal(format!("Owned APIG transport fixture: {message}"))
}

#[derive(Clone)]
pub(crate) struct Captured {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) body: String,
}

impl fmt::Debug for Captured {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Captured")
            .field("method", &self.method)
            .field("target", &self.target)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
pub(crate) struct Gate {
    entered: AtomicBool,
    opened: AtomicBool,
    entered_notify: Notify,
    release_notify: Notify,
}

impl Gate {
    pub(crate) async fn wait_entered(&self) -> DomainResult<()> {
        timeout(Duration::from_secs(5), async {
            loop {
                let notified = self.entered_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.entered.load(Ordering::SeqCst) {
                    break;
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| fixture_error("request did not enter the gate"))
    }

    pub(crate) async fn wait(&self) {
        self.entered.store(true, Ordering::SeqCst);
        self.entered_notify.notify_waiters();
        loop {
            let notified = self.release_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.opened.load(Ordering::SeqCst) {
                break;
            }
            notified.await;
        }
    }

    pub(crate) fn release(&self) {
        self.opened.store(true, Ordering::SeqCst);
        self.release_notify.notify_waiters();
    }

    pub(crate) fn release_on_drop(self: &Arc<Self>) -> Release {
        Release(self.clone())
    }
}

#[derive(Debug)]
pub(crate) struct Release(Arc<Gate>);

impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Reply {
    bytes: Vec<u8>,
    gate: Option<Arc<Gate>>,
}

impl Reply {
    pub(crate) fn json(status: u16, body: &Value) -> Self {
        Self::body(status, body.to_string().into_bytes(), &[])
    }

    pub(crate) fn body(status: u16, body: Vec<u8>, headers: &[(&str, String)]) -> Self {
        let mut extra = String::new();
        for (key, value) in headers {
            extra.push_str(key);
            extra.push_str(": ");
            extra.push_str(value);
            extra.push_str("\r\n");
        }
        let mut bytes = format!("HTTP/1.1 {status} Owned\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n", body.len()).into_bytes();
        bytes.extend(body);
        Self { bytes, gate: None }
    }

    pub(crate) fn truncated() -> Self {
        Self { bytes: b"HTTP/1.1 200 Owned\r\nContent-Type: application/json\r\nContent-Length: 200\r\nConnection: close\r\n\r\n{\"code\":\"Ok\"".to_vec(), gate: None }
    }

    pub(crate) fn held(mut self, gate: &Arc<Gate>) -> Self {
        self.gate = Some(gate.clone());
        self
    }
}

type Handler = dyn Fn(&Captured) -> DomainResult<Reply> + Send + Sync;

pub(crate) struct Server {
    pub(crate) origin: String,
    captured: Arc<Mutex<Vec<Captured>>>,
    errors: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl fmt::Debug for Server {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Server").field("origin", &self.origin).finish_non_exhaustive()
    }
}

impl Server {
    pub(crate) async fn start(
        handler: impl Fn(&Captured) -> DomainResult<Reply> + Send + Sync + 'static,
    ) -> DomainResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| fixture_error("bind failed"))?;
        let address = listener.local_addr().map_err(|_| fixture_error("local address failed"))?;
        let origin = format!("http://{address}");
        let captured = Arc::new(Mutex::new(Vec::new()));
        let errors = Arc::new(Mutex::new(Vec::new()));
        let (records, failures, handler): (_, _, Arc<Handler>) = (captured.clone(), errors.clone(), Arc::new(handler));
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let Ok((stream, _)) = result else { break; };
                        let (records, failures, handler) = (records.clone(), failures.clone(), handler.clone());
                        children.spawn(async move {
                            let result = timeout(Duration::from_secs(10), serve(stream, &records, &handler)).await;
                            let error = match result {
                                Ok(Ok(())) => None,
                                Ok(Err(_)) => Some("owned server rejected an invalid request"),
                                Err(_) => Some("owned server request timeout"),
                            };
                            if let Some(error) = error {
                                if let Ok(mut failures) = failures.lock() { failures.push(error.into()); }
                            }
                        });
                    }
                    _ = children.join_next(), if !children.is_empty() => {}
                }
            }
        });
        Ok(Self { origin, captured, errors, task })
    }

    pub(crate) fn requests(&self) -> DomainResult<Vec<Captured>> {
        Ok(self.captured.lock().map_err(|_| fixture_error("capture mutex poisoned"))?.clone())
    }

    pub(crate) fn count(&self, method: &str) -> DomainResult<usize> {
        Ok(self.requests()?.iter().filter(|request| request.method == method).count())
    }

    pub(crate) fn healthy(&self) -> DomainResult<()> {
        if self.errors.lock().map_err(|_| fixture_error("error mutex poisoned"))?.is_empty() {
            Ok(())
        } else {
            Err(fixture_error("owned server recorded a request failure"))
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(mut stream: TcpStream, records: &Mutex<Vec<Captured>>, handler: &Arc<Handler>) -> DomainResult<()> {
    let request = read(&mut stream).await?;
    records.lock().map_err(|_| fixture_error("capture mutex poisoned"))?.push(request.clone());
    let reply = handler(&request)?;
    if let Some(gate) = reply.gate {
        gate.wait().await;
    }
    // A closed client after a deliberately delayed response is expected.
    let _ = stream.write_all(&reply.bytes).await;
    Ok(())
}

async fn read(stream: &mut TcpStream) -> DomainResult<Captured> {
    let mut bytes = Vec::new();
    let boundary = loop {
        let mut buffer = [0_u8; 1024];
        let size = stream.read(&mut buffer).await.map_err(|_| fixture_error("header read failed"))?;
        if size == 0 {
            return Err(fixture_error("incomplete header"));
        }
        bytes.extend_from_slice(&buffer[..size]);
        if bytes.len() > 160 * 1024 {
            return Err(fixture_error("request exceeds fixture bounds"));
        }
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
    if boundary > 32 * 1024 {
        return Err(fixture_error("header exceeds fixture bounds"));
    }
    let head = std::str::from_utf8(&bytes[..boundary]).map_err(|_| fixture_error("invalid header UTF-8"))?;
    let mut lines = head.split("\r\n");
    let first: Vec<_> = lines.next().ok_or_else(|| fixture_error("missing request line"))?.split_whitespace().collect();
    if first.len() != 3 || first[2] != "HTTP/1.1" {
        return Err(fixture_error("invalid request line"));
    }
    let (method, target) = (first[0].to_owned(), first[1].to_owned());
    let mut headers = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (key, value) = line.split_once(':').ok_or_else(|| fixture_error("invalid header"))?;
        if headers.insert(key.to_ascii_lowercase(), value.trim().to_owned()).is_some() {
            return Err(fixture_error("duplicate header"));
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err(fixture_error("unexpected transfer encoding"));
    }
    let length = headers
        .get("content-length")
        .map_or(Ok(0), |raw| raw.parse::<usize>().map_err(|_| fixture_error("invalid body length")))?;
    if length > 128 * 1024 {
        return Err(fixture_error("body exceeds fixture bounds"));
    }
    while bytes.len() < boundary + length {
        let mut buffer = [0_u8; 1024];
        let size = stream.read(&mut buffer).await.map_err(|_| fixture_error("body read failed"))?;
        if size == 0 {
            return Err(fixture_error("incomplete request body"));
        }
        bytes.extend_from_slice(&buffer[..size]);
    }
    let body = String::from_utf8(bytes[boundary..boundary + length].to_vec())
        .map_err(|_| fixture_error("invalid body UTF-8"))?;
    Ok(Captured { method, target, headers, body })
}

pub(crate) const ACCESS_KEY: &str = "agf-owned-synthetic-key";
pub(crate) const SECRET: &str = "agf-owned-synthetic-signing-secret-no-cloud";
// RFC 2104 block construction, independent of the provider's signing implementation.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

#[test]
fn independent_mac_matches_rfc4231_short_and_long_key_vectors() {
    assert_eq!(
        hex::encode(hmac_sha256(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex::encode(hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

// Independent reconstruction: do not call the production sign_v3 function to verify its own output.
pub(crate) fn verify_signature(request: &Captured, origin: &str) -> DomainResult<()> {
    let authorization = request.headers.get("authorization").ok_or_else(|| fixture_error("signature absent"))?;
    let parts: BTreeMap<_, _> = authorization
        .strip_prefix("ACS3-HMAC-SHA256 ")
        .ok_or_else(|| fixture_error("signature algorithm differs"))?
        .split(',')
        .filter_map(|part| part.split_once('='))
        .collect();
    if parts.get("Credential").copied() != Some(ACCESS_KEY) {
        return Err(fixture_error("credential differs"));
    }
    let signed = parts.get("SignedHeaders").ok_or_else(|| fixture_error("signed headers absent"))?;
    let names: Vec<_> = signed.split(';').collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted != names {
        return Err(fixture_error("signed headers are not canonical"));
    }
    for required in
        ["host", "x-acs-action", "x-acs-version", "x-acs-date", "x-acs-signature-nonce", "x-acs-content-sha256"]
    {
        if !names.contains(&required) {
            return Err(fixture_error("required header is unsigned"));
        }
    }
    let host = origin.strip_prefix("http://").ok_or_else(|| fixture_error("invalid origin"))?;
    if request.headers.get("host").map(String::as_str) != Some(host)
        || request.headers.get("x-acs-version").map(String::as_str) != Some("2024-03-27")
    {
        return Err(fixture_error("signed endpoint or metadata differs"));
    }
    let payload_hash = hex::encode(Sha256::digest(request.body.as_bytes()));
    if request.headers.get("x-acs-content-sha256") != Some(&payload_hash) {
        return Err(fixture_error("payload hash differs"));
    }
    let (path, query) = request.target.split_once('?').unwrap_or((&request.target, ""));
    let mut canonical_headers = String::new();
    for name in &names {
        let value = request.headers.get(*name).ok_or_else(|| fixture_error("signed header missing"))?;
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(value.trim());
        canonical_headers.push('\n');
    }
    let canonical = format!("{}\n{path}\n{query}\n{canonical_headers}\n{signed}\n{payload_hash}", request.method);
    let to_sign = format!("ACS3-HMAC-SHA256\n{}", hex::encode(Sha256::digest(canonical.as_bytes())));
    let expected = hex::encode(hmac_sha256(SECRET.as_bytes(), to_sign.as_bytes()));
    if parts.get("Signature").copied() != Some(expected.as_str()) {
        return Err(fixture_error("MAC differs"));
    }
    Ok(())
}

pub(crate) struct Pending(Option<JoinHandle<Resp>>);
impl Pending {
    pub(crate) fn start(h: Harness, path: String, token: String, body: Value) -> Self {
        Self(Some(tokio::spawn(async move { h.request("POST", &path, Some(&token), Some(body)).await })))
    }
    pub(crate) async fn finish(mut self) -> DomainResult<Resp> {
        let task = self.0.as_mut().ok_or_else(|| fixture_error("pending request absent"))?;
        let result = timeout(Duration::from_secs(20), task)
            .await
            .map_err(|_| fixture_error("API request timeout"))?
            .map_err(|_| fixture_error("API task failed"))?;
        self.0.take();
        Ok(result)
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}
