//! Raw GetApp can reveal execution credentials and must never enter generic receipt dispatch.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::{cloud_runtime, integration_receipts};
use agf_core::{error::DomainError, ids::Id};
use common::*;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method},
};

const NAME: &str = "alicloud-schedulerx3";
const PATH: &str = "/api/v1/alicloud/connections/alicloud-schedulerx3";

fn request(id: Id, version: u64) -> cloud_runtime::Request {
    cloud_runtime::Request {
        request_id: id,
        configuration_version: version,
        action: "GetApp".into(),
        parameters: json!({"ClusterId":"cluster-owned","AppName":"app-owned"}),
        confirm_live: true,
    }
}

#[tokio::test]
async fn generic_getapp_is_rejected_before_source_loading_or_a_permanent_claim() {
    let h = setup().await;
    for version in [0, 1, 999] {
        let result =
            cloud_runtime::execute(&h.state, h.tenant, NAME, "owned-security-test".into(), request(Id::new(), version))
                .await;
        assert!(matches!(result, Err(DomainError::PreconditionFailed(_))));
        assert!(integration_receipts::history(&h.state, h.tenant, NAME).await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn configured_live_getapp_cannot_leak_a_token_or_send_any_provider_request() {
    let mut h = setup().await;
    std::sync::Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = agf_api::build_router(h.state.clone());
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(header("x-acs-action", "GetApp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Code":200,"Success":true,"RequestId":"owned-read",
            "Data":{"Id":123,"AppName":"app-owned","AccessToken":"PRIVATE-APP-EXECUTION-TOKEN"}
        })))
        .expect(0)
        .mount(&server)
        .await;
    let saved = h.request("PUT", PATH, Some(&h.admin), Some(json!({
        "expected_version":0,"enabled":true,"mock":false,
        "settings":{"endpoint":server.uri(),"region_id":"cn-hangzhou","cluster_id":"cluster-owned","app_name":"app-owned"},
        "secrets":{"access_key_id":"LOCAL-ONLY-AK","access_key_secret":"LOCAL-ONLY-SK"}
    }))).await;
    assert_eq!(saved.status, StatusCode::OK);
    let operation = request(Id::new(), 1);
    let reply = h.post(&format!("{PATH}/operations"), serde_json::to_value(&operation).unwrap()).await;
    assert_eq!(reply.status, StatusCode::PRECONDITION_FAILED);
    assert!(!reply.text.contains("PRIVATE-APP-EXECUTION-TOKEN"));
    assert!(!reply.text.contains("LOCAL-ONLY-SK"));
    assert!(server.received_requests().await.unwrap().is_empty());
    assert!(integration_receipts::history(&h.state, h.tenant, NAME).await.unwrap().is_empty());
}

#[tokio::test]
async fn generic_operation_metadata_hides_native_only_getapp_and_retains_listjobs() {
    let h = setup().await;
    let view = h.get(PATH).await;
    assert_eq!(view.status, StatusCode::OK);
    let body = view.json();
    let actions = body["operations"].as_array().unwrap();
    assert!(actions.iter().all(|operation| operation["action"] != "GetApp"));
    assert!(actions.iter().any(|operation| operation["action"] == "ListJobs"));
    let id = Id::new();
    let blocked = h.post(&format!("{PATH}/operations"), serde_json::to_value(request(id, 0)).unwrap()).await;
    assert_eq!(blocked.status, StatusCode::PRECONDITION_FAILED);
    assert!(h.get(&format!("{PATH}/operations")).await.json()["items"].as_array().unwrap().is_empty());
    assert!(integration_receipts::get(&h.state, h.tenant, NAME, id).await.is_err());
}
