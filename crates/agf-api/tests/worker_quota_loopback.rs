//! Only owned loopback RPCs: loss of write/readback receipts must not become verified.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{enums::AlertState, ids::Id};
use common::*;
use std::sync::Mutex;
use wiremock::{Mock, MockServer, Request as CloudRequest, Respond, ResponseTemplate, matchers::header};

const BASE: &str = "/api/v1/alicloud/agentteams/worker-quotas";
const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-agentteams";

#[derive(Clone, Copy)]
enum Mode {
    Normal,
    WriteUnknown,
    WriteTimeout,
    ReadbackUnknown,
    DelayedWrite,
    DelayedObservation,
}
struct Cloud {
    limit: i64,
    gets: u32,
    updates: u32,
    used: u64,
}
#[derive(Clone)]
struct Rpc {
    state: Arc<Mutex<Cloud>>,
    mode: Mode,
    written: tokio::sync::mpsc::UnboundedSender<()>,
}
impl Respond for Rpc {
    fn respond(&self, request: &CloudRequest) -> ResponseTemplate {
        let mut cloud = self.state.lock().unwrap();
        let action = request.headers.get("x-acs-action").unwrap().to_str().unwrap();
        if action == "UpdateWorker" {
            let parameters = request.url.query_pairs().find(|(name, _)| name == "LimitConfig").unwrap().1.into_owned();
            let limit: Value = serde_json::from_str(&parameters).unwrap();
            assert_eq!(limit.as_object().unwrap().len(), 3, "only documented writable fields may be sent");
            assert_eq!(limit["LimitType"], "token");
            assert_eq!(limit["PeriodType"], "day");
            cloud.limit = limit["UsageLimit"].as_i64().unwrap();
            cloud.updates += 1;
            let _ = self.written.send(());
            if matches!(self.mode, Mode::WriteUnknown) {
                return ResponseTemplate::new(500)
                    .set_body_json(json!({"Code":"InternalError","Message":"lost write receipt"}));
            }
            let response = ResponseTemplate::new(200).set_body_json(json!({"Success":true,"Data":{
                "Name":"worker-local","InstanceId":"instance-local","LimitConfig":limit}}));
            return if matches!(self.mode, Mode::WriteTimeout) {
                response.set_delay(std::time::Duration::from_secs(21))
            } else if matches!(self.mode, Mode::DelayedWrite) {
                response.set_delay(std::time::Duration::from_secs(2))
            } else {
                response
            };
        }
        cloud.gets += 1;
        if matches!(self.mode, Mode::ReadbackUnknown) && cloud.gets == 3 {
            return ResponseTemplate::new(500).set_body_json(json!({"Code":"InternalError","Message":"lost readback"}));
        }
        let response = ResponseTemplate::new(200).set_body_json(json!({"Success":true,"Data":{
            "Name":"worker-local","InstanceId":"instance-local","Model":{"ModelName":"preserve-this-model"},
            "LimitConfig":{"UsageLimit":cloud.limit,"LimitType":"token","PeriodType":"day",
                "UsedAmount":cloud.used,"OverLimit":false,"RuleStatus":"active"}}}));
        if matches!(self.mode, Mode::DelayedObservation) && cloud.gets == 2 {
            let _ = self.written.send(());
            response.set_delay(std::time::Duration::from_millis(250))
        } else {
            response
        }
    }
}

struct Fixture {
    h: Harness,
    server: MockServer,
    cloud: Arc<Mutex<Cloud>>,
    asset: Id,
    preview: Id,
    written: tokio::sync::mpsc::UnboundedReceiver<()>,
}
async fn fixture(mode: Mode) -> Fixture {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let server = MockServer::start().await;
    let cloud = Arc::new(Mutex::new(Cloud { limit: 1000, gets: 0, updates: 0, used: 0 }));
    let (tx, written) = tokio::sync::mpsc::unbounded_channel();
    let rpc = Rpc { state: cloud.clone(), mode: Mode::Normal, written: tx.clone() };
    mount_reads(&server, rpc).await;
    let config = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true,"mock":false,
        "settings":{"endpoint":server.uri(),"instance_id":"instance-local"},
        "secrets":{"access_key_id":"LOOPBACK-ID","access_key_secret":"LOOPBACK-SECRET"}})),
        )
        .await;
    assert_eq!(config.status, StatusCode::OK, "{}", config.text);
    let sync = h
        .post(
            "/api/v1/alicloud/agentteams/sync",
            json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":true}),
        )
        .await;
    assert_eq!(sync.status, StatusCode::OK, "{}", sync.text);
    let inventory = agf_api::cloud_inventory::load(&h.state, h.tenant).await.unwrap().unwrap();
    let asset = inventory.assets["worker-local"];
    let quota = h
        .post(
            "/api/v1/quotas",
            json!({"name":"loopback-worker","scope":"agent","target_id":asset,
        "dimension":"tokens","window":"day","limit":100,"expected_version":0}),
        )
        .await;
    assert_eq!(quota.status, StatusCode::OK, "{}", quota.text);
    let binding = h
        .request(
            "PUT",
            &format!("{BASE}/{asset}"),
            Some(&h.admin),
            Some(json!({"expected_version":0,
        "quota_id":quota.json()["quota"]["id"],"quota_version":1,"enabled":true})),
        )
        .await;
    assert_eq!(binding.status, StatusCode::OK, "{}", binding.text);
    server.reset().await;
    cloud.lock().unwrap().gets = 0;
    let rpc = Rpc { state: cloud.clone(), mode, written: tx };
    for action in ["GetWorker", "UpdateWorker"] {
        Mock::given(header("x-acs-action", action)).respond_with(rpc.clone()).mount(&server).await;
    }
    let preview = Id::new();
    let observed = h.post(&format!("{BASE}/{asset}/observe"), observe_input(preview)).await;
    assert_eq!(observed.status, StatusCode::OK, "{}", observed.text);
    assert_eq!(observed.json()["binding"]["state"], "drift");
    Fixture { h, server, cloud, asset, preview, written }
}

async fn mount_reads(server: &MockServer, rpc: Rpc) {
    for (action, body) in [
        ("ListTeams", json!({"Items":[{"Name":"local-team","WorkerNames":["worker-local"]}]})),
        ("GetTeam", json!({"Data":{"InstanceId":"instance-local","Name":"local-team","WorkerNames":["worker-local"]}})),
        ("ListWorkers", json!({"Items":[{"Name":"worker-local"}]})),
        ("ListTeamTasks", json!({"Items":[]})),
    ] {
        Mock::given(header("x-acs-action", action))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }
    Mock::given(header("x-acs-action", "GetWorker")).respond_with(rpc).mount(server).await;
}
fn observe_input(request: Id) -> Value {
    json!({"request_id":request,"expected_binding_version":1,"expected_quota_version":1,
        "configuration_version":1,"confirm_live":true})
}
fn sync_input(preview: Id, request: Id) -> Value {
    let mut input = observe_input(request);
    input["preview_id"] = json!(preview);
    input
}
async fn synchronize(f: &Fixture, input: Value) -> Resp {
    f.h.post(&format!("{BASE}/{}/sync", f.asset), input).await
}

#[tokio::test]
async fn cloud_configuration_change_since_preview_aborts_before_update() {
    let f = fixture(Mode::Normal).await;
    f.cloud.lock().unwrap().limit = 2000;
    let response = synchronize(&f, sync_input(f.preview, Id::new())).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["operation"]["status"], "failed");
    assert_eq!(response.json()["binding"]["state"], "unverified");
    assert_eq!(f.cloud.lock().unwrap().updates, 0);
    assert_eq!(f.cloud.lock().unwrap().limit, 2000);
}

#[tokio::test]
async fn older_slow_observation_cannot_override_newer_readback_or_reopen_drift_alert() {
    let mut f = fixture(Mode::DelayedObservation).await;
    let alert = f.h.get(BASE).await.json()["items"][0]["driftAlertId"].as_str().unwrap().to_owned();
    let alert = Id::parse(&alert).unwrap();
    let h = f.h.clone();
    let path = format!("{BASE}/{}/observe", f.asset);
    let old_input = observe_input(Id::new());
    let pending = tokio::spawn(async move { h.post(&path, old_input).await });
    tokio::time::timeout(std::time::Duration::from_secs(10), f.written.recv()).await.unwrap().unwrap();
    f.cloud.lock().unwrap().limit = 100;
    let current = Id::new();
    let accepted = f.h.post(&format!("{BASE}/{}/observe", f.asset), observe_input(current)).await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.text);
    assert_eq!(accepted.json()["binding"]["state"], "in-sync");
    let rejected = pending.await.unwrap();
    assert_eq!(rejected.status, StatusCode::CONFLICT, "{}", rejected.text);
    let current_row = f.h.get(BASE).await.json()["items"][0].clone();
    assert_eq!(current_row["observation"]["id"], json!(current));
    assert_eq!(current_row["observation"]["usageLimit"], 100);
    assert_eq!(current_row["state"], "in-sync");
    assert_eq!(f.h.state.store.alert_get(f.h.tenant, alert).unwrap().unwrap().state, AlertState::Closed);
    assert_eq!(f.h.state.store.alert_list(f.h.tenant, None, None).unwrap().len(), 1);
    assert_eq!(f.cloud.lock().unwrap().updates, 0);
}

#[tokio::test]
async fn closing_environment_mock_cannot_turn_old_mock_binding_into_a_live_request() {
    let mut h = setup().await;
    let server = MockServer::start().await;
    Mock::given(header("x-acs-action", "GetWorker"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Data":{"Name":"worker-demo","InstanceId":"foreign-instance",
                "LimitConfig":{"UsageLimit":1000,"LimitType":"token","PeriodType":"day"}}
        })))
        .mount(&server)
        .await;
    let config = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true,"mock":false,
        "settings":{"endpoint":server.uri(),"instance_id":"instance-local"},
        "secrets":{"access_key_id":"LOOPBACK-ID","access_key_secret":"LOOPBACK-SECRET"}})),
        )
        .await;
    assert_eq!(config.status, StatusCode::OK, "{}", config.text);
    let inventory = h
        .post(
            "/api/v1/alicloud/agentteams/sync",
            json!({"request_id":Id::new(),"configuration_version":1,
        "confirm_live":false}),
        )
        .await;
    assert_eq!(inventory.status, StatusCode::OK, "{}", inventory.text);
    let inventory = agf_api::cloud_inventory::load(&h.state, h.tenant).await.unwrap().unwrap();
    assert!(inventory.mocked);
    let asset = inventory.assets["worker-demo"];
    let quota = h
        .post(
            "/api/v1/quotas",
            json!({"name":"mode-worker","scope":"agent","target_id":asset,
        "dimension":"tokens","window":"day","limit":100,"expected_version":0}),
        )
        .await;
    assert_eq!(quota.status, StatusCode::OK, "{}", quota.text);
    let bind = json!({"expected_version":0,"quota_id":quota.json()["quota"]["id"],"quota_version":1,"enabled":true});
    let bound = h.request("PUT", &format!("{BASE}/{asset}"), Some(&h.admin), Some(bind.clone())).await;
    assert_eq!(bound.status, StatusCode::OK, "{}", bound.text);
    let preview = Id::new();
    let observed = h.post(&format!("{BASE}/{asset}/observe"), observe_input(preview)).await;
    assert_eq!(observed.status, StatusCode::OK, "{}", observed.text);
    assert_eq!(observed.json()["binding"]["mocked"], true);
    // Model a restart with the environment override disabled; stored cloud version stays 1.
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let list = h.get(BASE).await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.text);
    assert_eq!(list.json()["inventoryAvailable"], false);
    assert_eq!(list.json()["mocked"], Value::Null);
    assert_eq!(list.json()["items"][0]["state"], "stale");
    assert_eq!(list.json()["items"][0]["canObserve"], false);
    assert_eq!(h.post(&format!("{BASE}/{asset}/observe"), observe_input(Id::new())).await.status, StatusCode::CONFLICT);
    assert_eq!(
        h.post(&format!("{BASE}/{asset}/sync"), sync_input(preview, Id::new())).await.status,
        StatusCode::CONFLICT
    );
    let mut rebind = bind;
    rebind["expected_version"] = json!(1);
    assert_eq!(
        h.request("PUT", &format!("{BASE}/{asset}"), Some(&h.admin), Some(rebind)).await.status,
        StatusCode::CONFLICT
    );
    assert!(server.received_requests().await.unwrap().is_empty(), "a Mock snapshot must never authorize live RPC");
}

#[tokio::test]
async fn changing_read_only_used_amount_does_not_make_configuration_preview_stale() {
    let f = fixture(Mode::Normal).await;
    f.cloud.lock().unwrap().used = 42;
    let response = synchronize(&f, sync_input(f.preview, Id::new())).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["operation"]["status"], "verified");
    assert_eq!(response.json()["binding"]["observation"]["usedAmount"], 42);
    assert_eq!(f.cloud.lock().unwrap().limit, 100);
    assert_eq!(f.cloud.lock().unwrap().updates, 1);
    let requests = f.server.received_requests().await.unwrap();
    let update =
        requests.iter().find(|request| request.headers.get("x-acs-action").unwrap() == "UpdateWorker").unwrap();
    assert!(
        String::from_utf8_lossy(&update.body).contains("ClientToken="),
        "vendor idempotency token must accompany write"
    );
}

#[tokio::test]
async fn uncertain_or_timed_out_update_is_not_retried_and_new_observation_recovers_real_configuration() {
    for mode in [Mode::WriteUnknown, Mode::WriteTimeout] {
        let f = fixture(mode).await;
        let input = sync_input(f.preview, Id::new());
        let response = synchronize(&f, input.clone()).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        assert_eq!(response.json()["operation"]["status"], "uncertain");
        assert_eq!(response.json()["operation"]["changed"], false);
        assert_eq!(response.json()["binding"]["state"], "unverified");
        assert_eq!(response.json()["binding"]["observation"]["previewUsable"], false);
        assert_eq!(f.cloud.lock().unwrap().limit, 100, "remote may execute even though response is lost");
        assert_eq!(synchronize(&f, input).await.json()["operation"]["status"], "uncertain");
        assert_eq!(f.cloud.lock().unwrap().updates, 1);
        assert_eq!(synchronize(&f, sync_input(f.preview, Id::new())).await.status, StatusCode::CONFLICT);
        let observed = f.h.post(&format!("{BASE}/{}/observe", f.asset), observe_input(Id::new())).await;
        assert_eq!(observed.status, StatusCode::OK, "{}", observed.text);
        assert_eq!(observed.json()["observation"]["usageLimit"], 100);
        assert_eq!(observed.json()["binding"]["state"], "in-sync");
        assert!(!response.text.contains("LOOPBACK-SECRET"));
    }
}

#[tokio::test]
async fn accepted_write_with_failed_readback_stays_uncertain_until_fresh_observation() {
    let f = fixture(Mode::ReadbackUnknown).await;
    let alert = f.h.get(BASE).await.json()["items"][0]["driftAlertId"].as_str().unwrap().to_owned();
    let alert = Id::parse(&alert).unwrap();
    let response = synchronize(&f, sync_input(f.preview, Id::new())).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["operation"]["status"], "uncertain");
    assert_eq!(response.json()["operation"]["changed"], true);
    assert_eq!(response.json()["binding"]["state"], "unverified");
    assert_eq!(f.h.state.store.alert_get(f.h.tenant, alert).unwrap().unwrap().state, AlertState::Open);
    let observed = f.h.post(&format!("{BASE}/{}/observe", f.asset), observe_input(Id::new())).await;
    assert_eq!(observed.status, StatusCode::OK, "{}", observed.text);
    assert_eq!(observed.json()["binding"]["state"], "in-sync");
    assert_eq!(f.h.state.store.alert_get(f.h.tenant, alert).unwrap().unwrap().state, AlertState::Closed);
    assert_eq!(f.cloud.lock().unwrap().updates, 1);
}

#[tokio::test]
async fn canceled_client_cannot_replay_sent_update_and_expired_lease_allows_new_read() {
    let mut f = fixture(Mode::DelayedWrite).await;
    let request = Id::new();
    let input = sync_input(f.preview, request);
    let h = f.h.clone();
    let path = format!("{BASE}/{}/sync", f.asset);
    let body = input.clone();
    let task = tokio::spawn(async move { h.post(&path, body).await });
    tokio::time::timeout(std::time::Duration::from_secs(10), f.written.recv()).await.unwrap().unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(f.cloud.lock().unwrap().limit, 100);
    assert_eq!(synchronize(&f, input.clone()).await.status, StatusCode::CONFLICT);
    let run = agf_core::ids::deterministic_id("agf.worker-quota.run", &format!("{}:{}:{request}", f.h.tenant, f.asset));
    f.h.state
        .configurations
        .mutate::<Value, _>(f.h.tenant, "agentteams-worker-quota-run", run, |row| {
            row["started_at"] = json!(Timestamp::now().offset_secs(-121));
            Ok(())
        })
        .await
        .unwrap();
    f.h.state
        .configurations
        .mutate::<Value, _>(f.h.tenant, "agentteams-worker-quota", f.asset, |row| {
            row["active"]["expires_at"] = json!(Timestamp::now().offset_secs(-1));
            Ok(())
        })
        .await
        .unwrap();
    let list = f.h.get(BASE).await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.text);
    assert_eq!(list.json()["items"][0]["lastOperation"]["status"], "uncertain");
    assert_eq!(list.json()["items"][0]["canObserve"], true);
    let observed = f.h.post(&format!("{BASE}/{}/observe", f.asset), observe_input(Id::new())).await;
    assert_eq!(observed.status, StatusCode::OK, "{}", observed.text);
    assert_eq!(observed.json()["observation"]["usageLimit"], 100);
    assert_eq!(synchronize(&f, input).await.status, StatusCode::CONFLICT);
    assert_eq!(f.cloud.lock().unwrap().updates, 1);
}
