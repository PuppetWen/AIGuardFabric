//! Owned in-process platform protocol fixture. All counters are actual loopback HTTP requests.
use crate::{TenantId, callback_binding::Kind};
use agf_core::{ids::Id, time::Timestamp};
use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

const ROOT: &str = "/api/v1/alicloud/schedulerx3/native/callback-executions";
pub(crate) const KEY: &str = "service-key-only-test";
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Behavior {
    Normal,
    DuplicateStart,
    LostStart,
    LostClaim,
    PendingCompletion,
    HeldStart,
    HeldCompletion,
    ConflictingCompletion,
}
pub(crate) struct Platform {
    pub(crate) origin: String,
    pub(crate) data: Arc<Data>,
    task: tokio::task::JoinHandle<()>,
}
pub(crate) struct Data {
    pub(crate) tenant: TenantId,
    pub(crate) revoked: AtomicBool,
    pub(crate) claims: AtomicU64,
    pub(crate) validates: AtomicU64,
    pub(crate) completes: AtomicU64,
    pub(crate) statuses: AtomicU64,
    pub(crate) source: Value,
    pub(crate) saved: Mutex<Option<Value>>,
    pub(crate) completion_body: Mutex<Option<Value>>,
    pub(crate) entered: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Notify,
    behavior: Behavior,
}
impl Drop for Platform {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Platform {
    pub(crate) async fn open(behavior: Behavior) -> Self {
        let tenant = TenantId::default_tenant();
        let source = json!({"tenant":tenant,"configurationId":Id::new(),"configurationVersion":1,"scopeId":Id::new(),
            "fingerprint":"a".repeat(64),"region":"cn-hangzhou","rpcOrigin":"https://schedulerx3.cn-hangzhou.aliyuncs.com/",
            "configuredAccountId":null,"accountIdentityVerified":false,"clusterId":"owned-cluster","appName":"owned-app","mocked":false,"transportMode":"loopback_test"});
        let data = Arc::new(Data {
            tenant,
            source,
            revoked: AtomicBool::new(false),
            claims: AtomicU64::new(0),
            validates: AtomicU64::new(0),
            completes: AtomicU64::new(0),
            statuses: AtomicU64::new(0),
            saved: Mutex::new(None),
            completion_body: Mutex::new(None),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            behavior,
        });
        let router = Router::new()
            .route("/api/v1/auth/me", get(me))
            .route("/api/v1/alicloud/schedulerx3/native", get(native))
            .route(ROOT, post(claim))
            .route(&format!("{ROOT}/{{fact}}/validate"), post(validate))
            .route(&format!("{ROOT}/{{fact}}/complete"), post(complete))
            .route(&format!("{ROOT}/requests/{{request}}"), get(status))
            .route(&format!("{ROOT}/{{fact}}"), get(status))
            .with_state(Arc::clone(&data));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self { origin, data, task }
    }
}
fn authorized(data: &Data, headers: &HeaderMap) -> bool {
    headers.get("x-agf-key").and_then(|value| value.to_str().ok()) == Some(KEY)
        && headers.get("x-agf-tenant").and_then(|value| value.to_str().ok()) == Some(data.tenant.to_string().as_str())
        && !data.revoked.load(Ordering::SeqCst)
}
async fn me(State(data): State<Arc<Data>>, headers: HeaderMap) -> Response {
    if !authorized(&data, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(json!({"tenant_id":data.tenant})).into_response()
}
async fn native(State(data): State<Arc<Data>>, headers: HeaderMap) -> Response {
    if !authorized(&data, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(native_dto(data.tenant, &data.source)).into_response()
}
pub(crate) fn native_dto(tenant: TenantId, source: &Value) -> Value {
    let items=[Kind::AssetInventory,Kind::LogPull,Kind::RedteamCruise,Kind::RuleHotReload,Kind::Report,Kind::Archive].into_iter()
        .map(|kind|json!({"kind":kind,"jobId":"42","eligibility":"eligible","adoptedProof":{
            "adoptionVersion":1,"sourceTarget":source,"appId":"123","jobId":"42","kind":kind,"httpJob":true,"enabled":true}})).collect::<Vec<_>>();
    json!({"tenantId":tenant,"configured":true,"enabled":true,"sourceTarget":source,"bindings":{
        "version":1,"adoptionVersion":1,"locallyEnabled":true,"sourceCurrent":true,"sourceTarget":source,
        "current":false,"items":items}})
}
fn failure_body() -> Response {
    let chunks = futures::stream::iter([
        Ok(axum::body::Bytes::from_static(b"{\"factId\":")),
        Err(std::io::Error::other("owned truncated reply")),
    ]);
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from_stream(chunks))
        .unwrap()
}
async fn claim(State(data): State<Arc<Data>>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !authorized(&data, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    data.claims.fetch_add(1, Ordering::SeqCst);
    assert!(body.get("callback_token").is_none() && body.get("api_key").is_none());
    let mut saved = data.saved.lock().unwrap();
    if let Some(original) = saved.as_ref() {
        for (request, response) in [
            ("kind", "kind"),
            ("app_id", "appId"),
            ("job_id", "jobId"),
            ("job_execution_id", "jobExecutionId"),
            ("partition_total", "partitionTotal"),
        ] {
            if body[request] != original[response] {
                return StatusCode::CONFLICT.into_response();
            }
        }
        let mut reply = original.clone();
        reply["mayConfirmStart"] = json!(false);
        reply["mayExecute"] = json!(false);
        return Json(reply).into_response();
    }
    let at = Timestamp::now();
    let reply = json!({"factId":Id::new(),"claimId":Id::new(),"requestId":body["request_id"],"tenantId":data.tenant,
        "kind":body["kind"],"appId":body["app_id"],"jobId":body["job_id"],"jobExecutionId":body["job_execution_id"],
        "partitionIndex":body["partition_index"],"partitionTotal":body["partition_total"],"bindingVersion":1,"adoptionVersion":1,
        "originalTarget":data.source,"submittedAt":at,"startLeaseExpiresAt":at.offset_secs(110),"startedAt":null,"executionLeaseExpiresAt":null,"finishedAt":null,
        "state":"admitted","mayConfirmStart":true,"mayExecute":false,"outcome":null,"completionState":"admitted","sourceCurrent":true});
    *saved = Some(reply.clone());
    drop(saved);
    if data.behavior == Behavior::LostClaim { failure_body() } else { Json(reply).into_response() }
}
async fn validate(State(data): State<Arc<Data>>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !authorized(&data, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    data.validates.fetch_add(1, Ordering::SeqCst);
    let response = {
        let mut saved = data.saved.lock().unwrap();
        let reply = saved.as_mut().unwrap();
        assert_eq!(body, json!({"claim_id":reply["claimId"]}));
        let first = reply["startedAt"].is_null();
        let at = Timestamp::now();
        if first {
            reply["startedAt"] = json!(at);
            reply["executionLeaseExpiresAt"] = json!(at.offset_secs(300));
            reply["state"] = json!("running");
        }
        reply["mayConfirmStart"] = json!(false);
        reply["mayExecute"] = json!(false);
        let mut response = reply.clone();
        response["mayExecute"] = json!(first && data.behavior != Behavior::DuplicateStart);
        response
    };
    if data.behavior == Behavior::HeldStart {
        data.entered.notify_one();
        data.release.notified().await;
    }
    if data.behavior == Behavior::LostStart { failure_body() } else { Json(response).into_response() }
}
async fn complete(State(data): State<Arc<Data>>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !authorized(&data, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    data.completes.fetch_add(1, Ordering::SeqCst);
    if data.behavior == Behavior::HeldCompletion {
        data.entered.notify_one();
        data.release.notified().await;
    }
    *data.completion_body.lock().unwrap() = Some(body.clone());
    assert_eq!(body.as_object().unwrap().len(), 2);
    assert_eq!(body["outcome"].as_object().unwrap().len(), 4);
    let mut saved = data.saved.lock().unwrap();
    let reply = saved.as_mut().unwrap();
    assert_eq!(body["claim_id"], reply["claimId"]);
    reply["outcome"] = body["outcome"].clone();
    reply["mayExecute"] = json!(false);
    reply["mayConfirmStart"] = json!(false);
    if data.behavior == Behavior::ConflictingCompletion {
        reply["outcome"]["ok"] = json!(false);
        reply["state"] = json!("failed");
        reply["finishedAt"] = json!(Timestamp::now());
        reply["completionState"] = json!("complete");
        return StatusCode::CONFLICT.into_response();
    }
    if data.behavior == Behavior::PendingCompletion {
        reply["completionState"] = json!("pending_audit");
    } else {
        reply["state"] = json!(if body["outcome"]["ok"] == true { "succeeded" } else { "failed" });
        reply["finishedAt"] = json!(Timestamp::now());
        reply["completionState"] = json!("complete");
    }
    Json(reply.clone()).into_response()
}
async fn status(State(data): State<Arc<Data>>, headers: HeaderMap) -> Response {
    if !authorized(&data, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    data.statuses.fetch_add(1, Ordering::SeqCst);
    let mut reply = data.saved.lock().unwrap().as_ref().unwrap().clone();
    reply["mayConfirmStart"] = json!(false);
    reply["mayExecute"] = json!(false);
    Json(reply).into_response()
}
