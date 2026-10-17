//! Real loopback GETs supply typed Scheduler evidence and actual pull bytes.
use super::{fixtures, platform::Server, signature};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

pub(super) const ACCESS_KEY: &str = "callback-business-owned-ak";
pub(super) const SECRET: &str = "callback-business-owned-signing-secret";
#[derive(Default)]
struct Counters {
    actions: Vec<String>,
    errors: usize,
    host: String,
}
pub(super) struct Provider {
    server: Server,
    counters: Arc<Mutex<Counters>>,
}
async fn scheduler(State(counters): State<Arc<Mutex<Counters>>>, headers: HeaderMap, uri: Uri) -> Response {
    let result = (|| -> anyhow::Result<Value> {
        let input = signature::verify(&headers, &uri)?;
        anyhow::ensure!(
            headers.get("host").and_then(|value| value.to_str().ok())
                == Some(counters.lock().map_err(|_| anyhow::anyhow!("provider counter poisoned"))?.host.as_str()),
            "RPC host differs from owned listener"
        );
        anyhow::ensure!(
            input.get("ClusterId").map(String::as_str) == Some("cluster-agf-demo")
                && input.get("AppName").map(String::as_str) == Some("app-agf-demo"),
            "RPC target differs"
        );
        let action = headers
            .get("x-acs-action")
            .and_then(|header| header.to_str().ok())
            .ok_or_else(|| anyhow::anyhow!("RPC action absent"))?;
        counters.lock().map_err(|_| anyhow::anyhow!("provider counter poisoned"))?.actions.push(action.into());
        match action {
            "GetApp" => {
                anyhow::ensure!(input.len() == 2, "GetApp fields differ");
                Ok(
                    json!({"Code":200,"Success":true,"RequestId":"cb-owned-getapp","Data":{"Id":fixtures::APP,"AppName":"app-agf-demo","AppType":1,"AccessToken":"SYNTHETIC-NOT-EXPOSED"}}),
                )
            }
            "ListJobs" => {
                anyhow::ensure!(
                    input.len() == 4
                        && input.get("PageNum").map(String::as_str) == Some("1")
                        && input.get("PageSize").map(String::as_str) == Some("100"),
                    "ListJobs fields differ"
                );
                let records=fixtures::JOBS.map(|(kind,id)|json!({"JobId":id,"AppGroupId":fixtures::APP,"AppName":"app-agf-demo","Name":kind,"JobType":"http","Status":1,"JobHandler":"SYNTHETIC-NOT-EXPOSED","Parameters":"SYNTHETIC-NOT-EXPOSED"}));
                Ok(
                    json!({"Code":200,"Success":true,"RequestId":"cb-owned-listjobs","Data":{"PageNumber":1,"PageSize":100,"Total":6,"Records":records}}),
                )
            }
            _ => anyhow::bail!("unexpected provider action"),
        }
    })();
    match result {
        Ok(value) => Json(value).into_response(),
        Err(_) => {
            if let Ok(mut value) = counters.lock() {
                value.errors += 1;
            }
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"Code":500,"Success":false,"RequestId":"cb-invalid"})))
                .into_response()
        }
    }
}
impl Provider {
    pub(super) async fn close(mut self) {
        self.server.stop().await;
    }
    pub(super) async fn new() -> anyhow::Result<Self> {
        let counters = Arc::new(Mutex::new(Counters::default()));
        let server = Server::start(Router::new().route("/", get(scheduler)).with_state(counters.clone())).await?;
        counters.lock().map_err(|_| anyhow::anyhow!("provider counter poisoned"))?.host =
            server.origin.trim_start_matches("http://").into();
        Ok(Self { server, counters })
    }
    pub(super) fn address(&self) -> anyhow::Result<std::net::SocketAddr> {
        Ok(self.server.origin.trim_start_matches("http://").parse()?)
    }
    pub(super) fn assert_initial_reads_only(&self) -> anyhow::Result<()> {
        let counters = self.counters.lock().map_err(|_| anyhow::anyhow!("provider counter poisoned"))?;
        assert_eq!(counters.errors, 0);
        assert_eq!(counters.actions, ["GetApp", "ListJobs"]);
        Ok(())
    }
}
pub(super) struct Pull {
    pub(super) server: Server,
    count: Arc<AtomicUsize>,
}
async fn logs(State(count): State<Arc<AtomicUsize>>, headers: HeaderMap) -> impl IntoResponse {
    if headers.contains_key("x-agf-key") || headers.contains_key("authorization") {
        return (StatusCode::FORBIDDEN, HeaderMap::new(), "forbidden".to_owned());
    }
    count.fetch_add(1, Ordering::SeqCst);
    let mut result = HeaderMap::new();
    result.insert("x-agf-next-cursor", axum::http::HeaderValue::from_static("owned-next-1"));
    (StatusCode::OK, result, "{\"callback_signal\":\"pulled\"}".into())
}
impl Pull {
    pub(super) async fn close(mut self) {
        self.server.stop().await;
    }
    pub(super) async fn new() -> anyhow::Result<Self> {
        let count = Arc::new(AtomicUsize::new(0));
        let server = Server::start(Router::new().route("/logs", get(logs)).with_state(count.clone())).await?;
        Ok(Self { server, count })
    }
    pub(super) fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}
