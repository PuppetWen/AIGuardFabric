//! Recheck the confirming key after the Worker write has entered the cloud queue.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::ids::{Id, deterministic_id};
use axum::{Json, extract::RawQuery, routing::get};
use common::*;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use tokio::{sync::Semaphore, task::JoinHandle};

const BASE: &str = "/api/v1/alicloud/agentteams/worker-quotas";
const CLOUD: &str = "/api/v1/alicloud/connections/alicloud-agentteams";

#[derive(Clone)]
struct Rpc {
    limit: Arc<AtomicI64>,
    updates: Arc<AtomicUsize>,
    block_worker: Arc<AtomicBool>,
    worker_gate: Arc<Semaphore>,
    user_gate: Arc<Semaphore>,
    observed: tokio::sync::mpsc::UnboundedSender<String>,
}

async fn respond(
    axum::extract::State(rpc): axum::extract::State<Rpc>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Json<Value> {
    let params: BTreeMap<String, String> =
        url::form_urlencoded::parse(query.as_deref().unwrap_or("").as_bytes()).into_owned().collect();
    let action = headers.get("x-acs-action").unwrap().to_str().unwrap();
    let mut data = json!({"Name":"worker-local","InstanceId":"instance-local",
        "LimitConfig":{"UsageLimit":rpc.limit.load(Ordering::SeqCst),"LimitType":"token","PeriodType":"day"}});
    let body = match action {
        "ListTeams" => json!({"Items":[{"Name":"local-team","WorkerNames":["worker-local"]}]}),
        "ListWorkers" => json!({"Items":[{"Name":"worker-local"}]}),
        "GetTeam" => json!({"Data":{"Name":"local-team","InstanceId":"instance-local",
            "WorkerNames":["worker-local"]}}),
        "ListTeamTasks" => json!({"Items":[]}),
        "GetWorker" => {
            if rpc.block_worker.swap(false, Ordering::SeqCst) {
                rpc.observed.send("before-worker".into()).unwrap();
                rpc.worker_gate.acquire().await.unwrap().forget();
            }
            json!({"Data":data})
        }
        "GetUser" => {
            rpc.observed.send("blocking-user".into()).unwrap();
            rpc.user_gate.acquire().await.unwrap().forget();
            json!({"Data":{"Name":"member-user","InstanceId":"instance-local"}})
        }
        "UpdateWorker" => {
            rpc.updates.fetch_add(1, Ordering::SeqCst);
            let limit: Value = serde_json::from_str(&params["LimitConfig"]).unwrap();
            rpc.limit.store(limit["UsageLimit"].as_i64().unwrap(), Ordering::SeqCst);
            data["LimitConfig"] = limit;
            json!({"Data":data})
        }
        _ => panic!("unexpected owned cloud action {action}"),
    };
    let mut body = body;
    body["RequestId"] = json!("owned-worker-queue");
    body["Success"] = json!(true);
    Json(body)
}

struct Fixture {
    h: Harness,
    rpc: Rpc,
    events: UnboundedReceiver<String>,
    job: JoinHandle<()>,
    asset: Id,
    preview: Id,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.rpc.worker_gate.add_permits(1);
        self.rpc.user_gate.add_permits(1);
        self.job.abort();
    }
}

impl Fixture {
    async fn new() -> Self {
        let mut h = setup().await;
        Arc::make_mut(&mut h.state.config).mock_mode = false;
        h.app = build_router(h.state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (observed, events) = tokio::sync::mpsc::unbounded_channel();
        let rpc = Rpc {
            limit: Arc::new(AtomicI64::new(1000)),
            updates: Arc::new(AtomicUsize::new(0)),
            block_worker: Arc::new(AtomicBool::new(false)),
            worker_gate: Arc::new(Semaphore::new(0)),
            user_gate: Arc::new(Semaphore::new(0)),
            observed,
        };
        let router = Router::new().route("/", get(respond).post(respond)).with_state(rpc.clone());
        let job = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let saved = h
            .request(
                "PUT",
                CLOUD,
                Some(&h.admin),
                Some(json!({"expected_version":0,"enabled":true,"mock":false,
                    "settings":{"endpoint":endpoint,"instance_id":"instance-local"},
                    "secrets":{"access_key_id":"OWNED-QUEUE-ID","access_key_secret":"OWNED-QUEUE-SECRET"}})),
            )
            .await;
        assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
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
                json!({"name":"queued-worker","scope":"agent","target_id":asset,
                    "dimension":"tokens","window":"day","limit":100,"expected_version":0}),
            )
            .await;
        assert_eq!(quota.status, StatusCode::OK, "{}", quota.text);
        let bound = h
            .request(
                "PUT",
                &format!("{BASE}/{asset}"),
                Some(&h.admin),
                Some(json!({"expected_version":0,"quota_id":quota.json()["quota"]["id"],
                    "quota_version":1,"enabled":true})),
            )
            .await;
        assert_eq!(bound.status, StatusCode::OK, "{}", bound.text);
        let preview = Id::new();
        let observed = h.post(&format!("{BASE}/{asset}/observe"), input(preview)).await;
        assert_eq!(observed.status, StatusCode::OK, "{}", observed.text);
        assert_eq!(observed.json()["binding"]["state"], "drift");
        Self { h, rpc, events, job, asset, preview }
    }

    async fn wait(&mut self, signal: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while self.events.recv().await.unwrap() != signal {}
        })
        .await
        .unwrap();
    }

    async fn claimed(&self, request: Id) {
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
                    .any(|run| run.request_id == request)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

fn input(request: Id) -> Value {
    json!({"request_id":request,"expected_binding_version":1,"expected_quota_version":1,
        "configuration_version":1,"confirm_live":true})
}

async fn confirming_key(f: &Fixture) -> (String, Id) {
    let issued =
        f.h.post(
            "/api/v1/settings/api-keys",
            json!({"name":"worker-queue-confirmation","scopes":["alicloud:write","quotas:write"]}),
        )
        .await;
    assert_eq!(issued.status, StatusCode::CREATED, "{}", issued.text);
    let key = issued.json()["plaintext"].as_str().unwrap().to_owned();
    let key_id = Id::parse(issued.json()["api_key"]["id"].as_str().unwrap()).unwrap();
    (key, key_id)
}

async fn queued_update(f: &mut Fixture, token: String) -> (JoinHandle<Resp>, JoinHandle<Resp>) {
    f.rpc.block_worker.store(true, Ordering::SeqCst);
    let request = Id::new();
    let mut body = input(request);
    body["preview_id"] = json!(f.preview);
    let h = f.h.clone();
    let path = format!("{BASE}/{}/sync", f.asset);
    let operation = tokio::spawn(async move { h.request("POST", &path, Some(&token), Some(body)).await });
    f.wait("before-worker").await;

    // Claim a read behind GetWorker, so UpdateWorker subsequently queues behind that read.
    let blocker_id = Id::new();
    let h = f.h.clone();
    let blocker = tokio::spawn(async move {
        h.post(
            &format!("{CLOUD}/operations"),
            json!({"request_id":blocker_id,"configuration_version":1,"confirm_live":true,
                "action":"GetUser","parameters":{"Name":"member-user"}}),
        )
        .await
    });
    f.claimed(blocker_id).await;
    f.rpc.worker_gate.add_permits(1);
    f.wait("blocking-user").await;
    let write_phase = deterministic_id("agf.worker-quota.phase", &format!("{}:{request}:write", f.asset));
    f.claimed(write_phase).await;
    assert_eq!(f.rpc.updates.load(Ordering::SeqCst), 0);
    (operation, blocker)
}

async fn rejected_without_write(f: &Fixture, operation: JoinHandle<Resp>, blocker: JoinHandle<Resp>) {
    f.rpc.user_gate.add_permits(1);
    let blocker = blocker.await.unwrap();
    assert_eq!(blocker.status, StatusCode::OK, "{}", blocker.text);
    assert_eq!(blocker.json()["status"], "succeeded");
    let completed = operation.await.unwrap();
    assert_eq!(completed.status, StatusCode::OK, "{}", completed.text);
    assert!(matches!(completed.json()["operation"]["status"].as_str(), Some("failed" | "superseded" | "uncertain")));
    assert_eq!(completed.json()["operation"]["changed"], false);
    assert_eq!(f.rpc.updates.load(Ordering::SeqCst), 0, "a revoked confirming key must never reach UpdateWorker");
    assert_eq!(f.rpc.limit.load(Ordering::SeqCst), 1000);
    let retained =
        f.h.state.configurations.get::<Value>(f.h.tenant, "agentteams-worker-quota", f.asset).await.unwrap().unwrap();
    assert_eq!(retained["observation"]["preview_usable"], false);
    assert_eq!(retained["active"], Value::Null);
    assert!(!completed.text.contains("OWNED-QUEUE-SECRET"));
}

#[tokio::test]
async fn revoking_the_confirming_key_after_update_worker_is_queued_prevents_provider_write() {
    let mut f = Fixture::new().await;
    let (key, key_id) = confirming_key(&f).await;
    let (operation, blocker) = queued_update(&mut f, key).await;
    let revoked = f.h.request("DELETE", &format!("/api/v1/settings/api-keys/{key_id}"), Some(&f.h.admin), None).await;
    assert!(revoked.status.is_success(), "{}", revoked.text);
    rejected_without_write(&f, operation, blocker).await;
}

#[tokio::test]
async fn removing_only_quota_write_scope_while_queued_preserves_cloud_scope_but_prevents_worker_update() {
    let mut f = Fixture::new().await;
    let (key, key_id) = confirming_key(&f).await;
    let (operation, blocker) = queued_update(&mut f, key).await;
    let mut record =
        f.h.state
            .store
            .api_key_list_durable(f.h.tenant)
            .await
            .unwrap()
            .into_iter()
            .find(|key| key.id == key_id)
            .unwrap();
    record.scopes = vec![Permission::from_raw("alicloud:write")];
    // Apply a control-plane authority change without revoking, rotating or replacing the identity.
    f.h.state.store.api_key_create_durable(&record).await.unwrap();
    let current =
        f.h.state
            .store
            .api_key_list_durable(f.h.tenant)
            .await
            .unwrap()
            .into_iter()
            .find(|key| key.id == key_id)
            .unwrap();
    assert!(!current.revoked);
    assert_eq!(current.scopes, record.scopes);
    rejected_without_write(&f, operation, blocker).await;
}

#[tokio::test]
async fn password_security_change_during_before_read_invalidates_the_original_sync_session() {
    let mut f = Fixture::new().await;
    f.rpc.block_worker.store(true, Ordering::SeqCst);
    let request = Id::new();
    let mut body = input(request);
    body["preview_id"] = json!(f.preview);
    let h = f.h.clone();
    let path = format!("{BASE}/{}/sync", f.asset);
    let operation = tokio::spawn(async move { h.post(&path, body).await });
    f.wait("before-worker").await;
    let run_id = deterministic_id("agf.worker-quota.run", &format!("{}:{}:{request}", f.h.tenant, f.asset));
    let run =
        f.h.state
            .configurations
            .get::<Value>(f.h.tenant, "agentteams-worker-quota-run", run_id)
            .await
            .unwrap()
            .unwrap();
    let started: Timestamp = serde_json::from_value(run["started_at"].clone()).unwrap();
    // Cross a clock millisecond explicitly; the queue remains blocked independently of this delay.
    while Timestamp::now().unix_millis() <= started.unix_millis() {
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    let mut user = f.h.state.auth_backend.find_user_with_secret(f.h.tenant, "admin").await.unwrap().unwrap().user;
    user.password_changed_at = Some(Timestamp::now());
    f.h.state.auth_backend.save_user(&user, None).await.unwrap();
    assert!(!f.h.state.auth_backend.session_valid(f.h.tenant, &user, started.unix_millis()).await.unwrap());
    f.rpc.worker_gate.add_permits(1);
    let completed = operation.await.unwrap();
    assert_eq!(completed.status, StatusCode::OK, "{}", completed.text);
    assert!(matches!(completed.json()["operation"]["status"].as_str(), Some("failed" | "superseded" | "uncertain")));
    assert_eq!(completed.json()["operation"]["changed"], false);
    assert_eq!(f.rpc.updates.load(Ordering::SeqCst), 0);
    assert_eq!(f.rpc.limit.load(Ordering::SeqCst), 1000);
}
