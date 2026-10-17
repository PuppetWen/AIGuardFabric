//! An owned HTTP engine: real requests, real CAS content, bounded gates and no external endpoint.
use crate::common::*;
use agf_alicloud::mse::config_cas::content_md5;
use agf_core::error::{DomainError, DomainResult};
use axum::{
    extract::{Query, State},
    response::Response,
    routing::get,
};
use futures::StreamExt;
use std::{collections::BTreeMap, net::SocketAddr, time::Duration};
use tokio::{
    sync::{Mutex, Semaphore},
    task::JoinHandle,
};

pub(crate) const INITIAL: &str = "{\"说明\":\"owned UTF-8 baseline\"}\n";
pub(crate) const ACCESS: &str = "owned-loopback-access-key";
const WAIT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reply {
    Normal,
    MissingMd5,
    WrongMd5,
    Conflict,
    Lost,
    Different,
    Unavailable,
    Error,
    False,
}

#[derive(Clone)]
pub(crate) struct Seen {
    pub(crate) method: String,
    pub(crate) fields: BTreeMap<String, String>,
    pub(crate) cas: Option<String>,
    pub(crate) authenticated: bool,
}
struct Data {
    content: String,
    reply: Reply,
    seen: Vec<Seen>,
    gate: Option<(String, usize)>,
}
struct Shared {
    data: Mutex<Data>,
    release: Semaphore,
}
pub(crate) struct Engine {
    shared: Arc<Shared>,
    task: JoinHandle<()>,
    pub(crate) address: SocketAddr,
}

impl Engine {
    pub(crate) async fn start() -> DomainResult<Self> {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        assert!(address.ip().is_loopback() && address.port() != 0);
        let shared = Arc::new(Shared {
            data: Mutex::new(Data { content: INITIAL.into(), reply: Reply::Normal, seen: Vec::new(), gate: None }),
            release: Semaphore::new(0),
        });
        let app = Router::new().route("/nacos/v2/cs/config", get(query).post(publish)).with_state(shared.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self { shared, task, address })
    }
    pub(crate) async fn reply(&self, reply: Reply) {
        self.shared.data.lock().await.reply = reply;
    }
    pub(crate) async fn content(&self) -> String {
        self.shared.data.lock().await.content.clone()
    }
    pub(crate) async fn seen(&self) -> Vec<Seen> {
        self.shared.data.lock().await.seen.clone()
    }
    pub(crate) async fn counts(&self) -> (usize, usize) {
        let data = self.shared.data.lock().await;
        (
            data.seen.iter().filter(|r| r.method == "GET").count(),
            data.seen.iter().filter(|r| r.method == "POST").count(),
        )
    }
    pub(crate) async fn hold(&self, method: &str, ordinal: usize) {
        assert!(["GET", "POST"].contains(&method) && ordinal > 0);
        self.shared.data.lock().await.gate = Some((method.into(), ordinal));
    }
    pub(crate) async fn waiting(&self, method: &str, ordinal: usize) -> DomainResult<()> {
        tokio::time::timeout(WAIT, async {
            loop {
                if self.shared.data.lock().await.seen.iter().filter(|r| r.method == method).count() >= ordinal {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .map_err(|_| DomainError::Internal("owned engine did not receive its gated request".into()))
    }
    pub(crate) fn release(&self) {
        self.shared.release.add_permits(1);
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        self.shared.release.add_permits(8);
        self.task.abort();
    }
}

fn identity(fields: &BTreeMap<String, String>, post: bool) -> bool {
    fields.get("namespaceId").is_some_and(String::is_empty)
        && fields.get("group").is_some_and(|v| v == "AGF")
        && fields.get("dataId").is_some_and(|v| v == "agf-policies.json")
        && (!post || fields.get("type").is_some_and(|v| v == "json"))
}
async fn record(shared: &Shared, method: &str, fields: BTreeMap<String, String>, headers: &HeaderMap) -> bool {
    let authenticated = headers.get("spas-accesskey").is_some_and(|v| v == ACCESS)
        && headers.get("timestamp").and_then(|v| v.to_str().ok()).is_some_and(|v| v.parse::<u64>().is_ok())
        && headers.get("spas-signature").is_some_and(|v| !v.is_empty());
    let mut data = shared.data.lock().await;
    data.seen.push(Seen {
        method: method.into(),
        fields,
        authenticated,
        cas: headers.get("casmd5").and_then(|v| v.to_str().ok()).map(str::to_owned),
    });
    let ordinal = data.seen.iter().filter(|r| r.method == method).count();
    data.gate.as_ref().is_some_and(|(m, n)| m == method && *n == ordinal)
}
async fn wait(shared: &Shared, held: bool) {
    if held && let Ok(Ok(permit)) = tokio::time::timeout(WAIT, shared.release.acquire()).await {
        permit.forget();
    }
}
fn envelope(status: StatusCode, code: u32, data: Value) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(json!({"code":code,"message":"owned response","data":data}).to_string()))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}
async fn query(
    State(shared): State<Arc<Shared>>,
    Query(fields): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if !identity(&fields, false) {
        return envelope(StatusCode::BAD_REQUEST, 20002, Value::Null);
    }
    let held = record(&shared, "GET", fields, &headers).await;
    let (content, reply, posts) = {
        let data = shared.data.lock().await;
        (data.content.clone(), data.reply, data.seen.iter().filter(|r| r.method == "POST").count())
    };
    wait(&shared, held).await;
    if reply == Reply::Unavailable && posts > 0 {
        return envelope(StatusCode::SERVICE_UNAVAILABLE, 99999, Value::Null);
    }
    let mut response = envelope(StatusCode::OK, 0, Value::String(content.clone()));
    if reply != Reply::MissingMd5 {
        let hash =
            if reply == Reply::WrongMd5 { "00000000000000000000000000000000".into() } else { content_md5(&content) };
        if let Ok(header) = hash.parse() {
            response.headers_mut().insert("content-md5", header);
        }
    }
    response
}
async fn publish(State(shared): State<Arc<Shared>>, request: Request<Body>) -> Response {
    let headers = request.headers().clone();
    let Ok(bytes) = axum::body::to_bytes(request.into_body(), 320 * 1024).await else {
        return envelope(StatusCode::BAD_REQUEST, 20002, Value::Null);
    };
    let fields: BTreeMap<String, String> = url::form_urlencoded::parse(&bytes).into_owned().collect();
    if !identity(&fields, true) {
        return envelope(StatusCode::BAD_REQUEST, 20002, Value::Null);
    }
    let held = record(&shared, "POST", fields.clone(), &headers).await;
    let reply = {
        let mut data = shared.data.lock().await;
        let cas = headers.get("casmd5").and_then(|v| v.to_str().ok());
        if reply_conflict(data.reply, cas, &data.content) {
            Reply::Conflict
        } else {
            let reply = data.reply;
            if !matches!(reply, Reply::Error | Reply::False)
                && let Some(content) = fields.get("content")
            {
                data.content.clone_from(content);
            }
            if reply == Reply::Different {
                data.content = "{\"concurrent\":\"different\"}".into();
            }
            reply
        }
    };
    wait(&shared, held).await;
    match reply {
        Reply::Conflict => envelope(StatusCode::INTERNAL_SERVER_ERROR, 20005, Value::Null),
        Reply::Error => envelope(StatusCode::INTERNAL_SERVER_ERROR, 99999, Value::Null),
        Reply::False => envelope(StatusCode::OK, 0, Value::Bool(false)),
        Reply::Lost => {
            let chunks = futures::stream::once(async { Ok(bytes::Bytes::from_static(b"{\"code\":0,\"data\":")) })
                .chain(futures::stream::once(async {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "owned truncated response"))
                }));
            Response::builder()
                .header("content-type", "application/json")
                .body(Body::from_stream(chunks))
                .unwrap_or_else(|_| Response::new(Body::empty()))
        }
        _ => envelope(StatusCode::OK, 0, Value::Bool(true)),
    }
}
fn reply_conflict(reply: Reply, cas: Option<&str>, content: &str) -> bool {
    reply == Reply::Conflict || cas != Some(content_md5(content).as_str())
}

pub(crate) struct Pending(Option<JoinHandle<Resp>>);
impl Pending {
    pub(crate) fn start(h: Harness, path: String, token: String, body: Value) -> Self {
        Self(Some(tokio::spawn(async move { h.request("POST", &path, Some(&token), Some(body)).await })))
    }
    pub(crate) async fn finish(mut self) -> DomainResult<Resp> {
        let task = self.0.take().ok_or_else(|| DomainError::Internal("owned pending response missing".into()))?;
        // Keep ownership until completion, so timeout aborts the original request.
        self.0 = Some(task);
        let task = self.0.as_mut().ok_or_else(|| DomainError::Internal("owned pending response missing".into()))?;
        let response = tokio::time::timeout(WAIT, task)
            .await
            .map_err(|_| DomainError::Internal("owned API response timed out".into()))?
            .map_err(|_| DomainError::Internal("owned API task failed".into()))?;
        self.0.take();
        Ok(response)
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}
