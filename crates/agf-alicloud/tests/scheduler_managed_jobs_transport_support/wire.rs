use agf_core::error::{DomainError, DomainResult};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
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
    DomainError::Internal(format!("Owned Scheduler transport fixture: {message}"))
}

#[derive(Clone)]
pub(crate) struct Captured {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) body: String,
}

// RPC queries contain the synthetic STS token. Even assertion diagnostics must not expose it.
impl fmt::Debug for Captured {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Captured")
            .field("method", &self.method)
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

    async fn wait(&self) {
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

pub(crate) struct Reply {
    bytes: Vec<u8>,
    gate: Option<Arc<Gate>>,
}

impl fmt::Debug for Reply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Reply").field("bytes", &self.bytes.len()).field("held", &self.gate.is_some()).finish()
    }
}

impl Reply {
    pub(crate) fn disconnected() -> Self {
        Self { bytes: Vec::new(), gate: None }
    }
    pub(crate) fn json(body: &Value) -> Self {
        let body = body.to_string().into_bytes();
        let mut bytes = format!(
            "HTTP/1.1 200 Owned\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        bytes.extend(body);
        Self { bytes, gate: None }
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
    completed: Arc<AtomicUsize>,
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
        let captured = Arc::new(Mutex::new(Vec::new()));
        let errors = Arc::new(Mutex::new(Vec::new()));
        let completed = Arc::new(AtomicUsize::new(0));
        let (records, failures, finished, handler): (_, _, _, Arc<Handler>) =
            (captured.clone(), errors.clone(), completed.clone(), Arc::new(handler));
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let Ok((stream, _)) = result else { break; };
                        let (records, failures, finished, handler) =
                            (records.clone(), failures.clone(), finished.clone(), handler.clone());
                        children.spawn(async move {
                            let result = timeout(Duration::from_secs(10), serve(stream, &records, &handler)).await;
                            if !matches!(result, Ok(Ok(()))) {
                                if let Ok(mut errors) = failures.lock() {
                                    errors.push("owned server request did not complete".into());
                                }
                            }
                            finished.fetch_add(1, Ordering::SeqCst);
                        });
                    }
                    _ = children.join_next(), if !children.is_empty() => {}
                }
            }
        });
        Ok(Self { origin: format!("http://{address}"), captured, errors, completed, task })
    }

    pub(crate) fn requests(&self) -> DomainResult<Vec<Captured>> {
        Ok(self.captured.lock().map_err(|_| fixture_error("capture mutex poisoned"))?.clone())
    }

    pub(crate) async fn settled(&self, expected: usize) -> DomainResult<()> {
        timeout(Duration::from_secs(3), async {
            while self.completed.load(Ordering::SeqCst) < expected {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| fixture_error("owned replies did not settle"))?;
        if !self.errors.lock().map_err(|_| fixture_error("error mutex poisoned"))?.is_empty() {
            return Err(fixture_error("owned server recorded an invalid request"));
        }
        if self.requests()?.len() != expected || self.completed.load(Ordering::SeqCst) != expected {
            return Err(fixture_error("unexpected actual provider request count"));
        }
        Ok(())
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
    // The read future may have timed out or been cancelled after this actual request arrived.
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
        if bytes.len() > 32 * 1024 {
            return Err(fixture_error("request exceeds fixture bounds"));
        }
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
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
    let length = headers
        .get("content-length")
        .map_or(Ok(0), |value| value.parse::<usize>().map_err(|_| fixture_error("invalid body length")))?;
    if length > 16 * 1024 || headers.contains_key("transfer-encoding") || bytes.len() > boundary + length {
        return Err(fixture_error("invalid bounded body framing"));
    }
    while bytes.len() < boundary + length {
        let remaining = boundary + length - bytes.len();
        let mut buffer = [0_u8; 1024];
        let size =
            stream.read(&mut buffer[..remaining.min(1024)]).await.map_err(|_| fixture_error("body read failed"))?;
        if size == 0 {
            return Err(fixture_error("incomplete body"));
        }
        bytes.extend_from_slice(&buffer[..size]);
    }
    let body = String::from_utf8(bytes[boundary..].to_vec()).map_err(|_| fixture_error("invalid form UTF-8"))?;
    Ok(Captured { method, target, headers, body })
}
