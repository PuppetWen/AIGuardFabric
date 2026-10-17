//! Owned loopback transport with explicit gates; no timing-based dispatch races.
#![allow(dead_code)]
use crate::common::*;
use agf_core::ids::Id;
use axum::{
    Json,
    extract::{RawQuery, State},
    routing::get,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{
    sync::{Semaphore, mpsc},
    task::JoinHandle,
};

pub(crate) const NAME: &str = "alicloud-cms";
pub(crate) const PATH: &str = "/api/v1/alicloud/connections/alicloud-cms";
#[derive(Clone)]
struct Rpc {
    observed: mpsc::UnboundedSender<String>,
    gate: Arc<Semaphore>,
    block: &'static str,
    writes: Arc<AtomicUsize>,
    sts: Arc<AtomicUsize>,
}
async fn respond(State(rpc): State<Rpc>, headers: HeaderMap, RawQuery(query): RawQuery) -> Json<Value> {
    let params: BTreeMap<String, String> =
        url::form_urlencoded::parse(query.as_deref().unwrap_or("").as_bytes()).into_owned().collect();
    let action = headers
        .get("x-acs-action")
        .and_then(|value| value.to_str().ok())
        .or_else(|| params.get("Action").map(String::as_str))
        .unwrap_or("");
    if action == "PutCustomEvent" {
        rpc.writes.fetch_add(1, Ordering::SeqCst);
    }
    if action == "AssumeRole" {
        rpc.sts.fetch_add(1, Ordering::SeqCst);
    }
    let _ = rpc.observed.send(action.into());
    if action == rpc.block {
        rpc.gate.acquire().await.unwrap().forget();
    }
    Json(if action == "AssumeRole" {
        json!({"RequestId":"owned-sts", "Credentials":{
            "AccessKeyId":"GUARD-STS-ID", "AccessKeySecret":"GUARD-STS-SECRET",
            "SecurityToken":"GUARD-STS-TOKEN", "Expiration":Timestamp::now().offset_secs(1800).to_rfc3339()}})
    } else {
        json!({"Code":"200", "RequestId":"owned-cloud", "AlarmHistoryList":{"AlarmHistory":[]}})
    })
}

pub(crate) struct Fixture {
    pub(crate) h: Harness,
    pub(crate) endpoint: String,
    pub(crate) settings: Value,
    pub(crate) gate: Arc<Semaphore>,
    pub(crate) writes: Arc<AtomicUsize>,
    pub(crate) sts: Arc<AtomicUsize>,
    events: UnboundedReceiver<String>,
    job: JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.job.abort();
    }
}
impl Fixture {
    pub(crate) async fn new(block: &'static str, role: bool) -> Self {
        let mut h = setup().await;
        Arc::make_mut(&mut h.state.config).mock_mode = false;
        h.app = build_router(h.state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (observed, events) = mpsc::unbounded_channel();
        let gate = Arc::new(Semaphore::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let sts = Arc::new(AtomicUsize::new(0));
        let router = Router::new().route("/", get(respond).post(respond)).with_state(Rpc {
            observed,
            gate: gate.clone(),
            block,
            writes: writes.clone(),
            sts: sts.clone(),
        });
        let job = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let mut settings = json!({"endpoint":endpoint,"account_id":"guard-account","region_id":"cn-hangzhou"});
        if role {
            settings["credential_source"] = json!("assume-role");
            settings["sts_endpoint"] = json!(endpoint);
            settings["role_arn"] = json!("acs:ram::1234567890123456:role/guard-test");
        }
        let saved = h
            .request(
                "PUT",
                PATH,
                Some(&h.admin),
                Some(json!({"expected_version":0,
            "enabled":true,"mock":false,"settings":settings,
            "secrets":{"access_key_id":"GUARD-ID","access_key_secret":"GUARD-SECRET"}})),
            )
            .await;
        assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
        Self { h, endpoint, settings, gate, writes, sts, events, job }
    }
    pub(crate) async fn wait(&mut self, action: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if self.events.recv().await.unwrap() == action {
                    break;
                }
            }
        })
        .await
        .unwrap();
    }
    pub(crate) async fn claimed(&self, id: Id) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if self
                    .h
                    .state
                    .configurations
                    .list::<agf_api::integration_receipts::Run>(self.h.tenant, "integration-operation")
                    .await
                    .unwrap()
                    .iter()
                    .any(|run| run.request_id == id)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    pub(crate) async fn change(&self, settings: Value, enabled: bool, mocked: bool) {
        let secrets = if settings["endpoint"] != self.settings["endpoint"]
            || settings["account_id"] != self.settings["account_id"]
        {
            json!({"access_key_id":"SECOND-GUARD-ID","access_key_secret":"SECOND-GUARD-SECRET"})
        } else {
            json!({})
        };
        let saved = self
            .h
            .request(
                "PUT",
                PATH,
                Some(&self.h.admin),
                Some(json!({"expected_version":1,
                    "enabled":enabled,"mock":mocked,"settings":settings,"secrets":secrets})),
            )
            .await;
        assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    }
    pub(crate) fn count(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }
}
pub(crate) fn write(version: u64, id: Id) -> Value {
    json!({"request_id":id,"configuration_version":version,"action":"PutCustomEvent","confirm_live":true,
        "parameters":{"EventInfo":[{"EventName":"guard-test","Content":"owned-test"}]}})
}
pub(crate) async fn pending(h: Harness, token: String, id: Id) -> Resp {
    h.request("POST", &format!("{PATH}/operations"), Some(&token), Some(write(1, id))).await
}
pub(crate) async fn blocking(h: Harness) -> Resp {
    h.post(
        &format!("{PATH}/operations"),
        json!({"request_id":Id::new(),"configuration_version":1,
        "action":"DescribeAlertHistoryList","confirm_live":true,"parameters":{"PageSize":1,"Page":1}}),
    )
    .await
}
pub(crate) fn failed(response: &Resp) {
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["status"], "failed", "{}", response.text);
    for secret in ["GUARD-SECRET", "GUARD-STS-SECRET", "GUARD-STS-TOKEN"] {
        assert!(!response.text.contains(secret));
    }
}
