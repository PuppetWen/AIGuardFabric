//! Dedicated loopback MSE provider with explicit page gates and no external endpoints.
#![allow(dead_code)]
use crate::common::*;
use agf_core::ids::Id;
use axum::{
    Json,
    extract::{RawQuery, State},
    routing::get,
};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};
use tokio::{
    sync::{Semaphore, mpsc},
    task::JoinHandle,
};

pub(crate) const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-mse";
pub(crate) const VIEW: &str = "/api/v1/alicloud/mse/inventory";
pub(crate) const SYNC: &str = "/api/v1/alicloud/mse/inventory/sync";
pub(crate) const KIND: &str = "mse-inventory";
pub(crate) const RUN_TARGET: &str = "mse-inventory-run";

pub(crate) fn body(version: u64) -> Value {
    json!({"request_id":Id::new(),"configuration_version":version,"confirm_live":true})
}
pub(crate) fn service(name: &str) -> Value {
    json!({"Name":name,"GroupName":"owned-group","IpCount":0,"HealthyInstanceCount":0,"ClusterCount":0})
}
pub(crate) fn page(number: u64, total: usize, services: Vec<Value>) -> Value {
    json!({"Success":true,"HttpCode":"200","RequestId":format!("owned-mse-{number}"),
        "TotalCount":total,"PageNumber":number,"PageSize":100,"Data":services})
}
#[derive(Clone)]
struct Rpc {
    pages: Arc<Mutex<Vec<Value>>>,
    blocked: Arc<AtomicU64>,
    calls: Arc<AtomicU64>,
    gate: Arc<Semaphore>,
    observed: mpsc::UnboundedSender<u64>,
}
async fn respond(State(rpc): State<Rpc>, RawQuery(query): RawQuery, headers: HeaderMap) -> Json<Value> {
    let params: BTreeMap<String, String> =
        url::form_urlencoded::parse(query.as_deref().unwrap_or("").as_bytes()).into_owned().collect();
    let action = headers
        .get("x-acs-action")
        .and_then(|value| value.to_str().ok())
        .or_else(|| params.get("Action").map(String::as_str))
        .unwrap_or("");
    assert_eq!(action, "ListAnsServices", "MSE fixture permits only public readonly listing");
    assert_eq!(params.get("InstanceId").map(String::as_str), Some("owned-mse"));
    assert_eq!(params.get("NamespaceId").map(String::as_str), Some(""));
    assert_eq!(params.get("PageSize").map(String::as_str), Some("100"));
    let number: u64 = params["PageNum"].parse().unwrap();
    rpc.calls.fetch_add(1, Ordering::SeqCst);
    let response = rpc.pages.lock().unwrap().get(usize::try_from(number - 1).unwrap()).cloned().unwrap();
    let _ = rpc.observed.send(number);
    if rpc.blocked.load(Ordering::SeqCst) == number {
        rpc.gate.acquire().await.unwrap().forget();
    }
    Json(response)
}

pub(crate) struct Fixture {
    pub(crate) h: Harness,
    pub(crate) settings: Value,
    pub(crate) pages: Arc<Mutex<Vec<Value>>>,
    pub(crate) blocked: Arc<AtomicU64>,
    pub(crate) gate: Arc<Semaphore>,
    calls: Arc<AtomicU64>,
    observed: UnboundedReceiver<u64>,
    job: JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.job.abort();
    }
}
impl Fixture {
    pub(crate) async fn new(mocked: bool) -> Self {
        Self::attach(setup().await, mocked).await
    }
    pub(crate) async fn attach(mut h: Harness, mocked: bool) -> Self {
        Arc::make_mut(&mut h.state.config).mock_mode = false;
        let tenant = h.tenant;
        h.app =
            build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
                request.headers_mut().insert("x-agf-tenant", tenant.to_string().parse().unwrap());
                async move { request }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let pages = Arc::new(Mutex::new(vec![page(1, 1, vec![service("original-service")])]));
        let blocked = Arc::new(AtomicU64::new(0));
        let calls = Arc::new(AtomicU64::new(0));
        let gate = Arc::new(Semaphore::new(0));
        let (events, observed) = mpsc::unbounded_channel();
        let router = Router::new().route("/", get(respond)).with_state(Rpc {
            pages: pages.clone(),
            blocked: blocked.clone(),
            calls: calls.clone(),
            gate: gate.clone(),
            observed: events,
        });
        let job = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let settings = json!({"endpoint":endpoint,"region_id":"cn-hangzhou","instance_id":"owned-mse","namespace_id":"","account_id":"owned-mse-account"});
        let response = h.request("PUT",CONFIG,Some(&h.admin),Some(json!({"expected_version":0,"enabled":true,"mock":mocked,
            "settings":settings,"secrets":{"access_key_id":"owned-mse-id","access_key_secret":"owned-mse-signing-secret"}}))).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        Self { h, settings, pages, blocked, gate, calls, observed, job }
    }
    pub(crate) fn count(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
    pub(crate) fn replace(&self, pages: Vec<Value>) {
        *self.pages.lock().unwrap() = pages;
    }
    pub(crate) async fn wait(&mut self, number: u64) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if self.observed.recv().await.unwrap() == number {
                    break;
                }
            }
        })
        .await
        .unwrap();
    }
    pub(crate) async fn change(&self, version: u64, enabled: bool, mocked: bool, settings: Value) {
        let response = self
            .h
            .request(
                "PUT",
                CONFIG,
                Some(&self.h.admin),
                Some(json!({"expected_version":version,"enabled":enabled,"mock":mocked,"settings":settings})),
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    }
}
pub(crate) async fn ledger(h: &Harness) -> Option<Value> {
    h.state.configurations.get(h.tenant, KIND, agf_api::integration_store::id(h.tenant, "alicloud-mse")).await.unwrap()
}
pub(crate) async fn snapshot(h: &Harness) -> Option<Value> {
    ledger(h).await.and_then(|row| row.get("snapshot").cloned())
}
pub(crate) async fn publications(h: &Harness) -> usize {
    h.state
        .store
        .audit_chain_durable(h.tenant, 0, i64::MAX)
        .await
        .unwrap()
        .into_iter()
        .filter(|audit| {
            audit.target.kind == RUN_TARGET
                && audit.action == agf_core::audit::AuditAction::Execute
                && audit.outcome == agf_core::audit::AuditOutcome::Success
        })
        .count()
}
pub(crate) async fn success(h: &Harness, input: Value) -> Value {
    let response = h.post(SYNC, input).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let result = response.json();
    assert_eq!(result["status"], "succeeded");
    assert_eq!(result["published"], true);
    result
}
