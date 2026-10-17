#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Actual router and owned loopback listener; no real cloud or manually fabricated business claim.
mod common;
mod privatelink_provisioning_support;
use agf_core::{enums::AliCloudService, error::DomainResult, ids::Id};
use axum::{Json, extract::State, routing::get};
use common::*;
use std::sync::atomic::{AtomicUsize, Ordering};
struct Provider {
    origin: String,
    received: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Provider {
    async fn open() -> DomainResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let received = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route("/", get(observed).post(observed)).with_state(received.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        Ok(Self { origin, received, task })
    }
}
async fn observed(State(count): State<Arc<AtomicUsize>>) -> Json<Value> {
    count.fetch_add(1, Ordering::SeqCst);
    Json(json!({"Code":"200","RequestId":"owned-unexpected-transport"}))
}
#[tokio::test]
async fn all_managed_actions_are_blocked_before_provider_receipt_or_audit_and_hidden_from_menu() -> DomainResult<()> {
    let provider = Provider::open().await?;
    for service in [AliCloudService::SchedulerX3, AliCloudService::Apig, AliCloudService::Privatelink] {
        let mut h = setup().await;
        Arc::make_mut(&mut h.state.config).mock_mode = false;
        h.app = build_router(h.state.clone());
        let name = service.as_str();
        let config = format!("/api/v1/alicloud/connections/{name}");
        let saved=h.request("PUT",&config,Some(&h.admin),Some(json!({"expected_version":0,"enabled":true,"mock":false,"settings":{"endpoint":provider.origin,"region_id":"cn-hangzhou"},"secrets":{"access_key_id":"OWNED-MANAGED-ID","access_key_secret":"OWNED-MANAGED-SECRET"}}))).await;
        assert_eq!(saved.status, StatusCode::OK);
        let menu = h.get(&config).await;
        assert_eq!(menu.status, StatusCode::OK);
        let menu = menu.json();
        let before = privatelink_provisioning_support::snapshot(&h).await?;
        let actions = agf_alicloud::openapi::contracts(service)?
            .into_iter()
            .filter(|o| match service {
                AliCloudService::Apig => !o.read_only,
                AliCloudService::SchedulerX3 => matches!(
                    o.action.as_str(),
                    "CreateJob"
                        | "UpdateJob"
                        | "OperateEnableJobs"
                        | "OperateDisableJobs"
                        | "DeleteJobs"
                        | "OperateExecuteJob"
                ),
                AliCloudService::Privatelink => {
                    matches!(o.action.as_str(), "CreateVpcEndpoint" | "EnableVpcEndpointConnection")
                }
                _ => false,
            })
            .collect::<Vec<_>>();
        assert!(!actions.is_empty());
        for operation in actions {
            let id = Id::new();
            let url = format!("{config}/operations");
            let response=h.post(&url,json!({"request_id":id,"configuration_version":1,"action":operation.action,"parameters":{},"confirm_live":true})).await;
            assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
            assert_eq!(h.get(&format!("{url}/{id}")).await.status, StatusCode::NOT_FOUND);
            assert!(menu["operations"].as_array().unwrap().iter().all(|o| o["action"] != operation.action));
            assert!(
                privatelink_provisioning_support::snapshot(&h).await? == before,
                "managed generic boundary changed complete local snapshot"
            );
            assert_eq!(provider.received.load(Ordering::SeqCst), 0);
        }
        assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    }
    Ok(())
}
#[tokio::test]
async fn privatelink_managed_writes_are_fenced_even_without_configuration() -> DomainResult<()> {
    let h = setup().await;
    let before = privatelink_provisioning_support::snapshot(&h).await?;
    for action in ["CreateVpcEndpoint", "EnableVpcEndpointConnection"] {
        let response=h.post("/api/v1/alicloud/connections/alicloud-privatelink/operations",json!({"request_id":Id::new(),"configuration_version":1,"action":action,"parameters":{},"confirm_live":true})).await;
        assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
        assert!(
            privatelink_provisioning_support::snapshot(&h).await? == before,
            "missing-source barrier changed complete snapshot"
        );
    }
    Ok(())
}
