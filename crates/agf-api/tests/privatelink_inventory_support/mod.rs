//! Owned loopback supplies only the three public read actions for one explicit endpoint.
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

pub(crate) const NAME: &str = "alicloud-privatelink";
pub(crate) const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-privatelink";
pub(crate) const VIEW: &str = "/api/v1/alicloud/privatelink/inventory";
pub(crate) const SYNC: &str = "/api/v1/alicloud/privatelink/inventory/sync";
pub(crate) const ARCHIVE: &str = "/api/v1/alicloud/privatelink/operations/archive";
pub(crate) const KIND: &str = "privatelink-inventory";
pub(crate) const ARCHIVES: &str = "privatelink-inventory-archive";
pub(crate) const DETAIL: &str = "GetVpcEndpointAttribute";
pub(crate) const ZONES: &str = "ListVpcEndpointZones";
pub(crate) const GROUPS: &str = "ListVpcEndpointSecurityGroups";

pub(crate) fn body(version: u64) -> Value {
    json!({"request_id":Id::new(),"configuration_version":version,"confirm_live":true})
}
pub(crate) fn example() -> Value {
    serde_json::from_str(include_str!("../fixtures/alicloud/privatelink-inventory.json")).unwrap()
}
pub(crate) fn zone(id: &str) -> Value {
    json!({"ZoneId":id,"RegionId":"cn-hangzhou","ZoneStatus":"Connected"})
}
pub(crate) fn page(key: &str, total: usize, items: Vec<Value>, next: Option<&str>) -> Value {
    let mut value = json!({"RequestId":"owned-privatelink-page","TotalCount":total,"MaxResults":50});
    value[key] = json!(items);
    if let Some(next) = next {
        value["NextToken"] = json!(next);
    }
    value
}

#[derive(Clone)]
struct Rpc {
    values: Arc<Mutex<BTreeMap<String, Vec<Value>>>>,
    blocked: Arc<Mutex<String>>,
    calls: Arc<AtomicU64>,
    gate: Arc<Semaphore>,
    observed: mpsc::UnboundedSender<String>,
}

async fn respond(State(rpc): State<Rpc>, RawQuery(query): RawQuery, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    let params: BTreeMap<String, String> =
        url::form_urlencoded::parse(query.as_deref().unwrap_or("").as_bytes()).into_owned().collect();
    let action = headers
        .get("x-acs-action")
        .and_then(|value| value.to_str().ok())
        .or_else(|| params.get("Action").map(String::as_str))
        .unwrap_or("");
    assert!(matches!(action, DETAIL | ZONES | GROUPS), "no cloud write or unrelated resource query");
    assert_eq!(params.get("EndpointId").map(String::as_str), Some("ep-agf-demo"));
    assert_eq!(params.get("RegionId").map(String::as_str), Some("cn-hangzhou"));
    if action != DETAIL {
        assert_eq!(params.get("MaxResults").map(String::as_str), Some("50"));
    }
    let index = params
        .get("NextToken")
        .and_then(|token| token.strip_prefix("page-"))
        .and_then(|index| index.parse::<usize>().ok())
        .unwrap_or(0);
    rpc.calls.fetch_add(1, Ordering::SeqCst);
    let mut response = rpc.values.lock().unwrap()[action][index].clone();
    let _ = rpc.observed.send(action.into());
    let blocked = rpc.blocked.lock().unwrap().as_str() == action;
    if blocked {
        rpc.gate.acquire().await.unwrap().forget();
    }
    let status = response
        .get("_status")
        .and_then(Value::as_u64)
        .map_or(StatusCode::OK, |status| StatusCode::from_u16(u16::try_from(status).unwrap()).unwrap());
    response.as_object_mut().unwrap().remove("_status");
    (status, Json(response))
}

pub(crate) struct Fixture {
    pub(crate) h: Harness,
    pub(crate) settings: Value,
    pub(crate) values: Arc<Mutex<BTreeMap<String, Vec<Value>>>>,
    pub(crate) blocked: Arc<Mutex<String>>,
    pub(crate) gate: Arc<Semaphore>,
    calls: Arc<AtomicU64>,
    observed: UnboundedReceiver<String>,
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
        let example = example();
        let values = Arc::new(Mutex::new(
            [DETAIL, ZONES, GROUPS].into_iter().map(|action| (action.into(), vec![example[action].clone()])).collect(),
        ));
        let blocked = Arc::new(Mutex::new(String::new()));
        let calls = Arc::new(AtomicU64::new(0));
        let gate = Arc::new(Semaphore::new(0));
        let (events, observed) = mpsc::unbounded_channel();
        let router = Router::new().route("/", get(respond)).with_state(Rpc {
            values: values.clone(),
            blocked: blocked.clone(),
            calls: calls.clone(),
            gate: gate.clone(),
            observed: events,
        });
        let job = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let settings = json!({"endpoint":endpoint,"region_id":"cn-hangzhou","endpoint_id":"ep-agf-demo","account_id":"owned-privatelink-account"});
        let response=h.request("PUT",CONFIG,Some(&h.admin),Some(json!({"expected_version":0,"enabled":true,"mock":mocked,
            "settings":settings,"secrets":{"access_key_id":"owned-privatelink-id","access_key_secret":"owned-privatelink-signing-secret"}}))).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        Self { h, settings, values, blocked, gate, calls, observed, job }
    }
    pub(crate) fn count(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
    pub(crate) fn replace(&self, action: &str, values: Vec<Value>) {
        self.values.lock().unwrap().insert(action.into(), values);
    }
    pub(crate) async fn wait(&mut self, action: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while self.observed.recv().await.unwrap() != action {}
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
    h.state.configurations.get(h.tenant, KIND, agf_api::integration_store::id(h.tenant, NAME)).await.unwrap()
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
            audit.target.kind == "privatelink-inventory-run"
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
pub(crate) async fn assets(h: &Harness) -> Value {
    serde_json::to_value(h.state.store.asset_list_all_durable(h.tenant).await.unwrap()).unwrap()
}
pub(crate) async fn archive(h: &Harness, ids: Vec<Value>) -> Resp {
    let generation = h.get(VIEW).await.json()["generation"].clone();
    h.post(ARCHIVE, json!({"expected_generation":generation,"request_ids":ids})).await
}
