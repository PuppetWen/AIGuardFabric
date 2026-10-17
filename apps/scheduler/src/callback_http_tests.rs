//! Normal loopback HTTP callback delivery exercises permanent admission, start and completion.
use super::*;
use crate::callback_binding::{
    Client,
    test_platform::{Behavior, KEY, Platform},
};
use axum::routing::post;
use serde_json::Value;

struct Delivery {
    platform: Platform,
    registry: Arc<Registry>,
    count: Arc<AtomicU64>,
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Delivery {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Delivery {
    async fn open(behavior: Behavior, failed: bool) -> Self {
        let platform = Platform::open(behavior).await;
        let mut registry = Registry::new();
        registry.execution.cloud = true;
        registry.execution.token = "callback-test-token-32-bytes-long-only".into();
        registry.execution.app_id = "123".into();
        registry.execution.binding = Some(Arc::new(
            Client::literal_loopback(&platform.origin, &tasks::ApiAuth::ApiKey(KEY.into()), platform.data.tenant)
                .unwrap(),
        ));
        let count = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&count);
        let handler: dispatch::Handler = Arc::new(move |_partition| {
            let counter = Arc::clone(&counter);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                assert_eq!(dispatch::EXECUTION_ID.try_with(Clone::clone).unwrap(), "cloud:123:42:execution-42");
                if failed {
                    TaskOutcome::failed("private raw failure must never leave executor")
                } else {
                    TaskOutcome::ok("private handler note must never leave executor")
                }
            })
        });
        for name in ["asset-inventory", "report-generate"] {
            registry.handlers.lock().unwrap().insert(name, Arc::clone(&handler));
        }
        let registry = Arc::new(registry);
        let routes = Arc::clone(&registry);
        let app = Router::new().route(
            "/api/v1/internal/jobs/{kind}",
            post(move |path, headers| callback::invoke(Arc::clone(&routes), path, headers)),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/api/v1/internal/jobs/asset-inventory", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { platform, registry, count, url, task }
    }
    fn request(&self) -> reqwest::RequestBuilder {
        reqwest::Client::new()
            .post(&self.url)
            .bearer_auth(&self.registry.execution.token)
            .header("schedulerx-appId", "123")
            .header("schedulerx-jobId", "42")
            .header("schedulerx-jobExecutionId", "execution-42")
    }
    async fn deliver(&self) -> (StatusCode, Value) {
        let reply = tokio::time::timeout(Duration::from_secs(5), self.request().send()).await.unwrap().unwrap();
        let status = reply.status();
        (status, reply.json().await.unwrap())
    }
    fn counters(&self) -> (u64, u64, u64, u64) {
        let data = &self.platform.data;
        (
            data.claims.load(Ordering::SeqCst),
            data.validates.load(Ordering::SeqCst),
            data.completes.load(Ordering::SeqCst),
            self.count.load(Ordering::SeqCst),
        )
    }
    async fn no_legacy_lane(&self) {
        let id = agf_core::ids::deterministic_id(
            "scheduler-execution",
            &format!("{}:asset-inventory", self.registry.execution.tenant),
        );
        assert!(
            self.registry
                .execution
                .store
                .get::<Value>(self.registry.execution.tenant, "scheduler-execution", id)
                .await
                .unwrap()
                .is_none()
        );
    }
}
#[tokio::test]
async fn http_callback_executes_once_and_rechecks_service_identity() {
    let fixture = Delivery::open(Behavior::Normal, false).await;
    assert_eq!(reqwest::Client::new().post(&fixture.url).send().await.unwrap().status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        fixture.request().header("schedulerx-appId", "124").send().await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    for bad in ["042", "+42", "9223372036854775808"] {
        assert_eq!(
            fixture.request().header("schedulerx-jobId", bad).send().await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    let (status, first) = fixture.deliver().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["receipt"]["state"], "succeeded");
    assert!(first["result"].get("note").is_none());
    assert!(first["result"].get("artifacts").unwrap().as_array().unwrap().is_empty());
    let (status, replay) = fixture.deliver().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay, first);
    assert_eq!(fixture.counters(), (2, 1, 1, 1));
    assert_eq!(
        fixture.request().header("schedulerx-shardingTotal", "0").send().await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    fixture.platform.data.revoked.store(true, Ordering::SeqCst);
    assert_eq!(fixture.deliver().await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(fixture.counters(), (2, 1, 1, 1));
    fixture.no_legacy_lane().await;
}
#[tokio::test]
async fn duplicate_validate_response_never_starts_handler() {
    let fixture = Delivery::open(Behavior::DuplicateStart, false).await;
    assert_eq!(fixture.deliver().await.0, StatusCode::CONFLICT);
    assert_eq!(fixture.deliver().await.0, StatusCode::CONFLICT);
    assert_eq!(fixture.counters(), (2, 1, 0, 0));
    fixture.no_legacy_lane().await;
}
#[tokio::test]
async fn committed_start_with_lost_response_is_only_read_and_never_executed() {
    let fixture = Delivery::open(Behavior::LostStart, false).await;
    let (status, receipt) = fixture.deliver().await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(receipt["receipt"]["state"], "running");
    assert_eq!(receipt["receipt"]["mayExecute"], false);
    assert_eq!(fixture.platform.data.saved.lock().unwrap().as_ref().unwrap()["state"], "running");
    assert_eq!(fixture.platform.data.statuses.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.deliver().await.0, StatusCode::CONFLICT);
    assert_eq!(fixture.counters(), (2, 1, 0, 0));
    fixture.no_legacy_lane().await;
}
#[tokio::test]
async fn lost_claim_reply_does_not_turn_redelivery_into_a_start_grant() {
    let fixture = Delivery::open(Behavior::LostClaim, false).await;
    let (status, receipt) = fixture.deliver().await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(receipt["receipt"]["state"], "admitted");
    assert_eq!(receipt["receipt"]["mayConfirmStart"], false);
    assert_eq!(fixture.platform.data.statuses.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.deliver().await.0, StatusCode::CONFLICT);
    assert_eq!(fixture.counters(), (2, 0, 0, 0));
    fixture.no_legacy_lane().await;
}
#[tokio::test]
async fn known_business_failure_bypasses_legacy_retry_on_every_redelivery() {
    let fixture = Delivery::open(Behavior::Normal, true).await;
    let (status, first) = fixture.deliver().await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(first["receipt"]["state"], "failed");
    assert_eq!(first["result"]["ok"], false);
    for _ in 0..3 {
        let (status, next) = fixture.deliver().await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(next, first);
    }
    assert_eq!(fixture.counters(), (4, 1, 1, 1));
    fixture.no_legacy_lane().await;
}
#[tokio::test]
async fn pending_audit_keeps_known_outcome_without_automatic_completion_or_business_retry() {
    let fixture = Delivery::open(Behavior::PendingCompletion, false).await;
    let (status, receipt) = fixture.deliver().await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(receipt["ok"], false);
    assert_eq!(receipt["receipt"]["outcome"]["ok"], true);
    assert_eq!(fixture.platform.data.saved.lock().unwrap().as_ref().unwrap()["completionState"], "pending_audit");
    assert_eq!(fixture.deliver().await.0, StatusCode::CONFLICT);
    assert_eq!(fixture.counters(), (2, 1, 1, 1));
    fixture.no_legacy_lane().await;
}
#[tokio::test]
async fn conflicting_stored_outcome_cannot_turn_a_failed_complete_into_current_success() {
    let fixture = Delivery::open(Behavior::ConflictingCompletion, false).await;
    assert_eq!(fixture.deliver().await.0, StatusCode::CONFLICT);
    assert_eq!(fixture.platform.data.statuses.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.platform.data.saved.lock().unwrap().as_ref().unwrap()["outcome"]["ok"], false);
    assert_eq!(fixture.counters(), (1, 1, 1, 1));
    fixture.no_legacy_lane().await;
}
#[tokio::test]
async fn runtime_report_aliases_share_the_canonical_permanent_fact() {
    let fixture = Delivery::open(Behavior::Normal, false).await;
    for kind in ["report", "report-generate"] {
        let url = fixture.url.replace("asset-inventory", kind);
        let reply = fixture.request().build().unwrap();
        let mut replacement = reply;
        *replacement.url_mut() = reqwest::Url::parse(&url).unwrap();
        let response = reqwest::Client::new().execute(replacement).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.json::<Value>().await.unwrap()["receipt"]["kind"], "report");
    }
    assert_eq!(fixture.counters(), (2, 1, 1, 1));
}
#[test]
fn callback_headers_and_api_credentials_remain_independent() {
    let tenant = TenantId::default_tenant();
    assert!(Client::new("http://127.0.0.1:1234", &tasks::ApiAuth::Bearer("not-a-service-key".into()), tenant).is_err());
    for origin in [
        "http://user@127.0.0.1:1234",
        "http://127.0.0.1:1234/api",
        "http://127.0.0.1:1234/?key=private",
        "http://127.0.0.1:1234/#private",
    ] {
        assert!(Client::new(origin, &tasks::ApiAuth::ApiKey(KEY.into()), tenant).is_err());
    }
}
#[tokio::test]
async fn caller_cancel_after_known_result_cannot_cancel_its_owned_completion() {
    let fixture = Delivery::open(Behavior::HeldCompletion, false).await;
    let registry = Arc::clone(&fixture.registry);
    let handler = registry.handlers.lock().unwrap()["asset-inventory"].clone();
    let identity = crate::callback_binding::Identity {
        kind: crate::callback_binding::Kind::AssetInventory,
        app: "123".into(),
        job: "42".into(),
        execution: "execution-42".into(),
        partition: Partition::default(),
    };
    let pending = tokio::spawn(binding_execution::run(
        registry,
        identity,
        handler,
        tokio::time::Instant::now() + Duration::from_secs(5),
    ));
    tokio::time::timeout(Duration::from_secs(3), fixture.platform.data.entered.notified()).await.unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    fixture.platform.data.release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if fixture.platform.data.saved.lock().unwrap().as_ref().unwrap()["completionState"] == "complete" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.counters(), (1, 1, 1, 1));
    assert_eq!(fixture.deliver().await.0, StatusCode::OK);
    assert_eq!(fixture.counters(), (2, 1, 1, 1));
    fixture.no_legacy_lane().await;
}
#[tokio::test]
async fn caller_cancel_during_start_confirmation_never_executes_or_completes() {
    let fixture = Delivery::open(Behavior::HeldStart, false).await;
    let registry = Arc::clone(&fixture.registry);
    let handler = registry.handlers.lock().unwrap()["asset-inventory"].clone();
    let identity = crate::callback_binding::Identity {
        kind: crate::callback_binding::Kind::AssetInventory,
        app: "123".into(),
        job: "42".into(),
        execution: "execution-42".into(),
        partition: Partition::default(),
    };
    let pending = tokio::spawn(binding_execution::run(
        registry,
        identity,
        handler,
        tokio::time::Instant::now() + Duration::from_secs(5),
    ));
    tokio::time::timeout(Duration::from_secs(3), fixture.platform.data.entered.notified()).await.unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    fixture.platform.data.release.notify_one();
    assert_eq!(fixture.deliver().await.0, StatusCode::CONFLICT);
    assert_eq!(fixture.counters(), (2, 1, 0, 0));
    fixture.no_legacy_lane().await;
}
