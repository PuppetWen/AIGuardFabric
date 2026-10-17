use agf_core::error::{DomainError, DomainResult};
use serde_json::Value;
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
