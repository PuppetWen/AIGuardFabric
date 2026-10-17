//! Count every received signed RPC on the owned loopback listener.
use crate::common::*;
use agf_core::{error::DomainResult, ids::Id};
use axum::{Json, extract::State, routing::get};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::task::JoinHandle;

pub(crate) const OPERATIONS: &str = "/api/v1/alicloud/connections/alicloud-schedulerx3/operations";
pub(crate) const ACTIONS: [&str; 6] =
    ["CreateJob", "UpdateJob", "OperateEnableJobs", "OperateDisableJobs", "DeleteJobs", "OperateExecuteJob"];

pub(crate) struct Provider {
    endpoint: String,
    received: Arc<AtomicUsize>,
    task: JoinHandle<Result<(), std::io::Error>>,
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Provider {
    pub(crate) async fn new() -> DomainResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let received = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route("/", get(respond).post(respond)).with_state(received.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        Ok(Self { endpoint, received, task })
    }
    pub(crate) fn count(&self) -> usize {
        self.received.load(Ordering::SeqCst)
    }
}
async fn respond(State(received): State<Arc<AtomicUsize>>, headers: HeaderMap) -> Json<Value> {
    received.fetch_add(1, Ordering::SeqCst);
    assert!(headers.get("authorization").is_some());
    Json(json!({"Code":200,"Success":true,"RequestId":"owned-generic-read",
        "Data":{"Records":[],"Total":0,"PageNumber":1,"PageSize":1}}))
}
pub(crate) async fn configured(provider: &Provider, mocked: bool) -> DomainResult<Harness> {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = mocked;
    h.app = build_router(h.state.clone());
    let response = h
        .request(
            "PUT",
            "/api/v1/alicloud/connections/alicloud-schedulerx3",
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true,"mock":mocked,
            "settings":{"endpoint":provider.endpoint,"region_id":"cn-hangzhou",
                "cluster_id":"owned-generic-barrier-cluster","app_name":"owned-generic-barrier-app"},
            "secrets":{"access_key_id":"OWNED-BARRIER-ID","access_key_secret":"OWNED-BARRIER-SOURCE-SECRET"}})),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    Ok(h)
}
pub(crate) fn request(action: &str, request_id: Id) -> Value {
    let mut parameters = json!({"ClusterId":"owned-generic-barrier-cluster","AppName":"owned-generic-barrier-app"});
    match action {
        "CreateJob" => {
            parameters["Name"] = json!("owned-generic-must-not-create");
            parameters["JobType"] = json!("http");
            parameters["TimeType"] = json!(1);
            parameters["TimeExpression"] = json!("0 0/5 * * * ?");
            parameters["Status"] = json!(0);
        }
        "UpdateJob" | "OperateExecuteJob" => parameters["JobId"] = json!(9_007_199_254_741_002_i64),
        "OperateEnableJobs" | "OperateDisableJobs" | "DeleteJobs" => {
            parameters["JobIds"] = json!([9_007_199_254_741_002_i64]);
        }
        "GetJobExecution" => parameters["JobExecutionId"] = json!("9007199254741002"),
        _ => {
            parameters["PageNum"] = json!(1);
            parameters["PageSize"] = json!(1);
        }
    }
    json!({"request_id":request_id,"configuration_version":1,"action":action,
        "parameters":parameters,"confirm_live":true})
}
