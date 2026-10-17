//! Actual authenticated CMS queue routes, Mock acceptance/audit, and lost HTTP replies.
use super::*;
use crate::tasks::cms_queue_outbox::{Outbox, fingerprint};
use agf_api::{AppState, BootstrapOutcome};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
struct Faults {
    calls: Mutex<BTreeMap<String, usize>>,
    lose_enqueue: AtomicBool,
    lose_send: AtomicBool,
    hide_send: AtomicBool,
    send: Mutex<String>,
}
async fn observe(State(faults): State<Arc<Faults>>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let method = request.method().to_string();
    *faults.calls.lock().unwrap().entry(format!("{method} {path}")).or_default() += 1;
    if method == "GET" && faults.hide_send.load(Ordering::SeqCst) && path == *faults.send.lock().unwrap() {
        return Response::builder().status(404).body(Body::empty()).unwrap();
    }
    let response = next.run(request).await;
    let lost = method == "POST"
        && ((path.ends_with("/enqueue") && faults.lose_enqueue.swap(false, Ordering::SeqCst))
            || (path.ends_with("/send") && faults.lose_send.swap(false, Ordering::SeqCst)));
    if lost {
        let chunks = futures::stream::iter([
            Ok(Bytes::from_static(b"{\"id\":")),
            Err(std::io::Error::other("owned lost CMS reply")),
        ]);
        Response::builder().status(200).body(Body::from_stream(chunks)).unwrap()
    } else {
        response
    }
}
struct Fixture {
    config: CmsQueueConfig,
    state: AppState,
    faults: Arc<Faults>,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new(configure: bool) -> Self {
        Self::new_mode(configure, true).await
    }
    async fn new_mode(configure: bool, mocked: bool) -> Self {
        let output = std::env::temp_dir().join(format!("agf-scheduler-cms-{}", Id::new()));
        std::fs::create_dir(&output).unwrap();
        let env = [
            ("AGF_ENV", "test"),
            ("AGF_MOCK_MODE", if mocked { "1" } else { "0" }),
            ("AGF_JWT_SECRET", "owned-cms-test-secret-more-than-32-bytes"),
            ("AGF_MASTER_KEY_BASE64", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
            ("AGF_DATA_DIR", output.to_str().unwrap()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let state = AppState::offline(agf_core::config::from_env_map(&env).unwrap()).unwrap();
        let tenant = TenantId::default_tenant();
        let bootstrap = state
            .ensure_bootstrap_admin(tenant, "cms-admin", "cms@owned.local", Some("Owned#CMS-2026-test-only"), false)
            .await
            .unwrap();
        let user = match bootstrap {
            BootstrapOutcome::Created { user, .. } | BootstrapOutcome::AlreadyExists { user } => user,
        };
        let admin = state.auth.issue_for_user(&user, tenant, vec!["superadmin".into()]).unwrap().access_token;
        let faults = Arc::new(Faults::default());
        let app: Router =
            agf_api::build_router(state.clone()).layer(axum::middleware::from_fn_with_state(faults.clone(), observe));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let http = reqwest::Client::new();
        let issued: Value = http
            .post(format!("{server_url}/api/v1/settings/api-keys"))
            .bearer_auth(&admin)
            .json(&json!({"name":"owned scheduler CMS","scopes":["alicloud:read","alicloud:write"]}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let key = issued["plaintext"].as_str().unwrap().to_owned();
        if configure {
            http.put(format!("{server_url}/api/v1/alicloud/connections/alicloud-cms")).bearer_auth(&admin)
                .json(&json!({"expected_version":0,"enabled":true,"mock":mocked,"settings":{"region_id":"cn-hangzhou","group_id":if mocked {"agf-cms-demo"} else {"42"}},
                    "secrets":if mocked {json!({})} else {json!({"access_key_id":"owned-test-not-a-real-key","access_key_secret":"owned-test-not-a-real-secret"})}}))
                .send().await.unwrap().error_for_status().unwrap();
        }
        Self {
            config: CmsQueueConfig {
                server: server_url,
                auth: Some(ApiAuth::ApiKey(key)),
                tenant,
                output,
                confirm_live: false,
            },
            state,
            faults,
            server,
        }
    }
    async fn run(&self, execution: &str, rules: usize) -> TaskOutcome {
        crate::dispatch::EXECUTION_ID
            .scope(execution.to_owned(), run_cms_queue(&self.config, vec![], Some(rules), Some(0.5)))
            .await
    }
    fn count(&self, path: &str) -> usize {
        *self.faults.calls.lock().unwrap().get(&format!("POST {BASE}/{path}")).unwrap_or(&0)
    }
    async fn records(&self, kind: &str) -> Vec<Value> {
        self.state.configurations.list(self.config.tenant, kind).await.unwrap()
    }
    fn inspect(&self, execution: &str, name: &str) -> Value {
        let outbox = Outbox::open(&self.config.output, self.config.tenant).unwrap();
        outbox.run(identity(self.config.tenant, execution, "run")).unwrap().read(name).unwrap().unwrap()
    }
}
#[tokio::test]
async fn actual_mock_queue_retains_every_metric_hash_and_audit_without_duplicate_send_after_restart() {
    let fixture = Fixture::new(true).await;
    let execution = "local:alicloud-cms-push:owned-42";
    let first = fixture.run(execution, 7).await;
    assert!(first.ok && first.degraded, "{}", first.note);
    assert!(first.note.contains("4/4") && first.note.contains("providerWriteAttempted=false"));
    let payload = fixture.inspect(execution, "payload");
    let enqueue = fixture.inspect(execution, "enqueue");
    let send = fixture.inspect(execution, "send");
    let client =
        Client::new(&fixture.config.server, fixture.config.auth.as_ref().unwrap(), fixture.config.tenant).unwrap();
    let receipt = client.original(serde_json::from_value(send["request_id"].clone()).unwrap()).await.unwrap().unwrap();
    cms_queue_delivery::check(&receipt, &send, "send", &payload).unwrap();
    assert_eq!(receipt["items"].as_array().unwrap().len(), 4);
    assert_eq!(fixture.records("cms-queue-body").await.len(), 4);
    assert_eq!(fixture.records("cms-queue-attempt").await.len(), 4);
    assert_eq!(fixture.records("cms-queue-request").await.len(), 2);
    let before = fixture.state.store.audit_chain_durable(fixture.config.tenant, 0, i64::MAX).await.unwrap();
    assert_eq!(before.iter().filter(|a| a.target.kind == "cms-queue-attempt").count(), 4);
    assert!(fixture.state.store.audit_verify_durable(fixture.config.tenant).await.unwrap().passed);
    let restarted = fixture.run(execution, 999).await;
    assert!(restarted.ok, "{}", restarted.note);
    assert_eq!(fixture.inspect(execution, "payload"), payload, "same period metrics/at changed on retry");
    assert_eq!(fixture.inspect(execution, "enqueue"), enqueue);
    assert_eq!(fixture.inspect(execution, "send"), send);
    assert_eq!((fixture.count("enqueue"), fixture.count("send")), (1, 1));
    assert_eq!(
        serde_json::to_value(
            fixture.state.store.audit_chain_durable(fixture.config.tenant, 0, i64::MAX).await.unwrap()
        )
        .unwrap(),
        serde_json::to_value(before).unwrap()
    );
}
#[tokio::test]
async fn lost_enqueue_reply_recovers_original_uuid_and_all_payloads_before_sending() {
    let fixture = Fixture::new(true).await;
    fixture.faults.lose_enqueue.store(true, Ordering::SeqCst);
    let first = fixture.run("lost-enqueue", 5).await;
    assert!(!first.ok && fixture.count("send") == 0);
    let original = fixture.inspect("lost-enqueue", "payload");
    assert_eq!(fixture.records("cms-queue-body").await.len(), 4);
    let recovered = fixture.run("lost-enqueue", 999).await;
    assert!(recovered.ok, "{}", recovered.note);
    assert_eq!(fixture.inspect("lost-enqueue", "payload"), original);
    assert_eq!((fixture.count("enqueue"), fixture.count("send")), (1, 1));
}
#[tokio::test]
async fn lost_send_reply_is_only_queried_and_never_reposted_when_original_status_is_unknown() {
    let fixture = Fixture::new(true).await;
    fixture.faults.lose_send.store(true, Ordering::SeqCst);
    let first = fixture.run("lost-send", 5).await;
    assert!(!first.ok);
    let send = fixture.inspect("lost-send", "send");
    *fixture.faults.send.lock().unwrap() = format!("{BASE}/requests/{}", send["request_id"].as_str().unwrap());
    fixture.faults.hide_send.store(true, Ordering::SeqCst);
    let second = fixture.run("lost-send", 999).await;
    assert!(!second.ok && second.note.contains("状态未知"), "{}", second.note);
    assert_eq!(fixture.count("send"), 1);
    assert_eq!(fixture.records("cms-queue-attempt").await.len(), 4);
    fixture.faults.hide_send.store(false, Ordering::SeqCst);
    let recovered = fixture.run("lost-send", 999).await;
    assert!(recovered.ok, "{}", recovered.note);
    assert_eq!(fixture.count("send"), 1);
}
#[tokio::test]
async fn live_source_default_is_enqueue_only_without_provider_write() {
    let fixture = Fixture::new_mode(true, false).await;
    let outcome = fixture.run("live-enqueue-only", 7).await;
    assert!(outcome.ok && outcome.degraded && outcome.note.contains("未发送"), "{}", outcome.note);
    assert_eq!((fixture.count("enqueue"), fixture.count("send")), (1, 0));
    assert_eq!(fixture.records("cms-queue-body").await.len(), 4);
    assert!(fixture.records("cms-queue-attempt").await.is_empty());
    assert_eq!(fixture.inspect("live-enqueue-only", "enqueue")["initialize_mock_fixture"], false);
}
#[tokio::test]
async fn no_identity_or_source_keeps_all_payloads_and_never_claims_cloud_acceptance() {
    let mut fixture = Fixture::new(false).await;
    fixture.config.auth = None;
    let offline = fixture.run("offline", 7).await;
    assert!(offline.ok && offline.degraded && offline.note.contains("未入平台队列"));
    assert_eq!(fixture.inspect("offline", "payload")["items"].as_array().unwrap().len(), 4);
    assert_eq!((fixture.count("enqueue"), fixture.count("send")), (0, 0));
    fixture.config.auth = Some(ApiAuth::ApiKey("invalid-service-key".into()));
    let denied = fixture.run("denied", 7).await;
    assert!(!denied.ok && denied.degraded);
    assert_eq!(fixture.inspect("denied", "payload")["items"].as_array().unwrap().len(), 4);
    assert!(fixture.records("cms-queue-body").await.is_empty());
    let configured = Fixture::new(false).await;
    let absent = configured.run("source-absent", 7).await;
    assert!(!absent.ok && absent.degraded && absent.note.contains("没有启用"), "{}", absent.note);
    assert_eq!(configured.inspect("source-absent", "payload")["items"].as_array().unwrap().len(), 4);
    assert_eq!((configured.count("enqueue"), configured.count("send")), (0, 0));
}
#[test]
fn outbox_lock_partial_commit_hash_tenant_and_budget_are_enforced() {
    let output = std::env::temp_dir().join(format!("agf-cms-outbox-{}", Id::new()));
    std::fs::create_dir(&output).unwrap();
    let tenant = TenantId::default_tenant();
    let outbox = Outbox::open(&output, tenant).unwrap();
    assert!(Outbox::open(&output, tenant).is_err(), "concurrent writer acquired same tenant lock");
    let id = identity(tenant, "crash", "run");
    let run = outbox.run(id).unwrap();
    run.save("payload", &json!({"retained":"every metric"})).unwrap();
    let artifact = PathBuf::from(run.artifact());
    std::fs::rename(&artifact, artifact.with_extension("pending")).unwrap();
    assert_eq!(
        run.read("payload").unwrap().unwrap(),
        json!({"retained":"every metric"}),
        "complete pending file did not recover"
    );
    assert!(run.save("payload", &json!({"retained":"changed"})).is_err());
    assert!(run.save("send", &json!({"oversize":"x".repeat(64*1024)})).is_err());
    let bytes = std::fs::read(&artifact).unwrap();
    let mut corrupt: Value = serde_json::from_slice(&bytes).unwrap();
    corrupt["value"]["retained"] = json!("tampered");
    std::fs::write(&artifact, serde_json::to_vec(&corrupt).unwrap()).unwrap();
    assert!(run.read("payload").is_err(), "payload hash was not verified");
    corrupt["sha256"] = json!(fingerprint(&corrupt["value"]).unwrap());
    corrupt["tenant"] = json!(TenantId::new());
    std::fs::write(&artifact, serde_json::to_vec(&corrupt).unwrap()).unwrap();
    assert!(run.read("payload").is_err(), "foreign tenant envelope was accepted");
    assert_ne!(identity(tenant, "same", "run"), identity(TenantId::new(), "same", "run"));
}
#[cfg(unix)]
#[test]
fn symlinked_outbox_is_rejected() {
    let root = std::env::temp_dir().join(format!("agf-cms-link-{}", Id::new()));
    std::fs::create_dir(&root).unwrap();
    let other = root.join("other");
    std::fs::create_dir(&other).unwrap();
    std::os::unix::fs::symlink(&other, root.join("cms-outbox")).unwrap();
    assert!(Outbox::open(&root, TenantId::default_tenant()).is_err());
}
