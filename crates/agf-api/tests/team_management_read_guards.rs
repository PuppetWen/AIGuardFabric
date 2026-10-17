//! Native preparation rechecks read authority after queue waits without changing generic writes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod team_management_helpers;
mod team_management_loopback_helpers;
use agf_core::ids::Id;
use axum::{Json, extract::RawQuery, routing::get};
use common::*;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use team_management_helpers::*;
use team_management_loopback_helpers::Cloud;
use tokio::{sync::Semaphore, task::JoinHandle};

const DIRECTORIES: &str = "agentteams-user-directory";

#[derive(Clone)]
struct ReadRpc {
    cloud: Arc<Mutex<Cloud>>,
    block_worker: Arc<AtomicBool>,
    block_team: Arc<AtomicBool>,
    worker_gate: Arc<Semaphore>,
    team_gate: Arc<Semaphore>,
    seen: tokio::sync::mpsc::UnboundedSender<String>,
    actions: Arc<Mutex<Vec<String>>>,
}

async fn respond(
    axum::extract::State(rpc): axum::extract::State<ReadRpc>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Json<Value> {
    let params: BTreeMap<String, String> =
        url::form_urlencoded::parse(query.as_deref().unwrap_or("").as_bytes()).into_owned().collect();
    let action = headers.get("x-acs-action").unwrap().to_str().unwrap();
    rpc.actions.lock().unwrap().push(action.into());
    if action == "GetWorker" && rpc.block_worker.swap(false, Ordering::SeqCst) {
        rpc.seen.send("blocked-worker".into()).unwrap();
        rpc.worker_gate.acquire().await.unwrap().forget();
    }
    if action == "GetTeam" && rpc.block_team.swap(false, Ordering::SeqCst) {
        rpc.seen.send("blocked-team".into()).unwrap();
        rpc.team_gate.acquire().await.unwrap().forget();
    }
    let cloud = rpc.cloud.lock().unwrap();
    let name = params.get("Name").map(String::as_str).unwrap_or("");
    let mut body = match action {
        "ListTeams" => json!({"Items":cloud.teams.values().collect::<Vec<_>>(),
            "TotalCount":cloud.teams.len(),"NextToken":null}),
        "GetTeam" => json!({"Data":cloud.teams.get(name).unwrap()}),
        "ListWorkers" => json!({"Items":cloud.workers,"TotalCount":cloud.workers.len(),"NextToken":null}),
        "GetWorker" => json!({"Data":cloud.workers.iter().find(|worker|worker["Name"]==name).unwrap()}),
        "ListTeamTasks" => json!({"Items":[],"TotalCount":0,"NextToken":null}),
        "ListUsers" => json!({"Items":cloud.users.values().collect::<Vec<_>>(),
            "TotalCount":cloud.users.len(),"NextToken":null}),
        "GetUser" => json!({"Data":cloud.users.get(name).unwrap()}),
        other => panic!("Unexpected preparation cloud action {other}"),
    };
    body["Success"] = json!(true);
    body["RequestId"] = json!("owned-team-read-guard");
    Json(body)
}

struct FixtureRead {
    f: Fixture,
    rpc: ReadRpc,
    seen: UnboundedReceiver<String>,
    job: JoinHandle<()>,
}
impl Drop for FixtureRead {
    fn drop(&mut self) {
        self.rpc.worker_gate.add_permits(1);
        self.rpc.team_gate.add_permits(1);
        self.job.abort();
    }
}
impl FixtureRead {
    async fn new() -> Self {
        let mut h = setup().await;
        Arc::make_mut(&mut h.state.config).mock_mode = false;
        h.app = build_router(h.state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (seen, received) = tokio::sync::mpsc::unbounded_channel();
        let rpc = ReadRpc {
            cloud: Arc::new(Mutex::new(Cloud::seeded())),
            block_worker: Arc::new(AtomicBool::new(false)),
            block_team: Arc::new(AtomicBool::new(false)),
            worker_gate: Arc::new(Semaphore::new(0)),
            team_gate: Arc::new(Semaphore::new(0)),
            seen,
            actions: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new().route("/", get(respond).post(respond)).with_state(rpc.clone());
        let job = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let f = Fixture::configured(h, false, Some(&endpoint)).await;
        Self { f, rpc, seen: received, job }
    }

    async fn wait(&mut self, wanted: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while self.seen.recv().await.unwrap() != wanted {}
        })
        .await
        .unwrap();
    }

    async fn key_claimed(&self, key: Id, action: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let runs = self
                    .f
                    .h
                    .state
                    .configurations
                    .list::<agf_api::integration_receipts::Run>(self.f.h.tenant, "integration-operation")
                    .await
                    .unwrap();
                if runs.iter().any(|run| run.operation == action && run.actor.ends_with(&key.to_string())) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    async fn request_claimed(&self, request: Id) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let runs = self
                    .f
                    .h
                    .state
                    .configurations
                    .list::<agf_api::integration_receipts::Run>(self.f.h.tenant, "integration-operation")
                    .await
                    .unwrap();
                if runs.iter().any(|run| run.request_id == request) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    fn count(&self, action: &str) -> usize {
        self.rpc.actions.lock().unwrap().iter().filter(|name| *name == action).count()
    }

    fn start_blocker(&self) -> (Id, JoinHandle<Resp>) {
        self.rpc.block_worker.store(true, Ordering::SeqCst);
        let request = Id::new();
        let h = self.f.h.clone();
        let job = tokio::spawn(async move {
            h.post(
                &format!("{CLOUD}/operations"),
                json!({"request_id":request,
                "configuration_version":1,"confirm_live":true,"action":"GetWorker",
                "parameters":{"Name":"worker-demo"}}),
            )
            .await
        });
        (request, job)
    }
}

async fn read_key(f: &Fixture) -> (String, Id) {
    let issued = result(
        f.h.post(
            "/api/v1/settings/api-keys",
            json!({"name":"native-preparation-read","scopes":["alicloud:read","alicloud:write"]}),
        )
        .await,
    );
    (issued["plaintext"].as_str().unwrap().to_owned(), Id::parse(issued["api_key"]["id"].as_str().unwrap()).unwrap())
}

async fn remove_read(f: &Fixture, id: Id) {
    let mut key =
        f.h.state.store.api_key_list_durable(f.h.tenant).await.unwrap().into_iter().find(|key| key.id == id).unwrap();
    key.scopes = vec![Permission::from_raw("alicloud:write")];
    f.h.state.store.api_key_create_durable(&key).await.unwrap();
    let persisted =
        f.h.state.store.api_key_list_durable(f.h.tenant).await.unwrap().into_iter().find(|key| key.id == id).unwrap();
    assert!(!persisted.revoked);
    assert_eq!(persisted.scopes, key.scopes);
}

async fn preparation_state(f: &Fixture) -> Vec<Value> {
    f.h.state.configurations.list(f.h.tenant, STATE_KIND).await.unwrap()
}

async fn rejected(f: &FixtureRead, pending: JoinHandle<Resp>, blocker: JoinHandle<Resp>, action: &str, count: usize) {
    f.rpc.worker_gate.add_permits(1);
    assert_eq!(result(blocker.await.unwrap())["status"], "succeeded");
    let response = pending.await.unwrap();
    assert!(!response.status.is_success(), "read permission was removed: {}", response.text);
    assert_eq!(f.count(action), count, "queued {action} must not reach the provider");
}

#[tokio::test]
async fn removing_only_read_scope_while_list_users_is_queued_does_not_publish_a_directory_page() {
    let mut f = FixtureRead::new().await;
    let previous = result(f.f.users(json!({})).await);
    let (key, id) = read_key(&f.f).await;
    let before = snapshot(&f.f.h).await;
    let count = f.count("ListUsers");
    let (_, blocker) = f.start_blocker();
    f.wait("blocked-worker").await;
    let request = Id::new();
    let h = f.f.h.clone();
    let pending = tokio::spawn(async move {
        h.request(
            "POST",
            &format!("{BASE}/users/observe"),
            Some(&key),
            Some(json!({"request_id":request,"configuration_version":1,"confirm_live":true})),
        )
        .await
    });
    f.key_claimed(id, "ListUsers").await;
    remove_read(&f.f, id).await;
    rejected(&f, pending, blocker, "ListUsers", count).await;
    let rows = f.f.h.state.configurations.list::<Value>(f.f.h.tenant, DIRECTORIES).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["latest"]["snapshotId"], previous["snapshotId"]);
    assert_eq!(rows[0]["latest"]["selectionUsable"], false);
    assert_eq!(rows[0]["requests"][request.to_string()][1], Value::Null);
    assert_eq!(snapshot(&f.f.h).await, before);
}

#[tokio::test]
async fn removing_only_read_scope_while_get_team_is_queued_does_not_publish_a_preview() {
    let mut f = FixtureRead::new().await;
    let (key, id) = read_key(&f.f).await;
    let state = preparation_state(&f.f).await;
    let before = snapshot(&f.f.h).await;
    let count = f.count("GetTeam");
    let (_, blocker) = f.start_blocker();
    f.wait("blocked-worker").await;
    let h = f.f.h.clone();
    let body = preview_body(update(TEAM, "Retain this unsubmitted draft"), 0, true);
    let pending =
        tokio::spawn(async move { h.request("POST", &format!("{BASE}/previews"), Some(&key), Some(body)).await });
    f.key_claimed(id, "GetTeam").await;
    remove_read(&f.f, id).await;
    rejected(&f, pending, blocker, "GetTeam", count).await;
    assert_eq!(preparation_state(&f.f).await, state);
    assert_eq!(snapshot(&f.f.h).await, before);
}

#[tokio::test]
async fn removing_only_read_scope_after_the_baseline_while_get_user_is_queued_does_not_publish_a_preview() {
    let mut f = FixtureRead::new().await;
    let directory = result(f.f.users(json!({})).await);
    let (key, id) = read_key(&f.f).await;
    let state = preparation_state(&f.f).await;
    let before = snapshot(&f.f.h).await;
    let count = f.count("GetUser");
    f.rpc.block_team.store(true, Ordering::SeqCst);
    let mut body = preview_body(replace(TEAM, json!(["member-user"])), 0, true);
    body["user_snapshot_id"] = directory["snapshotId"].clone();
    let h = f.f.h.clone();
    let pending =
        tokio::spawn(async move { h.request("POST", &format!("{BASE}/previews"), Some(&key), Some(body)).await });
    f.wait("blocked-team").await;
    let (request, blocker) = f.start_blocker();
    f.request_claimed(request).await;
    f.rpc.team_gate.add_permits(1);
    f.wait("blocked-worker").await;
    f.key_claimed(id, "GetUser").await;
    remove_read(&f.f, id).await;
    rejected(&f, pending, blocker, "GetUser", count).await;
    assert_eq!(preparation_state(&f.f).await, state);
    assert_eq!(snapshot(&f.f.h).await, before);
}
