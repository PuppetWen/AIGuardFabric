use super::*;
use crate::{
    credential::CloudCredential,
    test_support::{ScriptedTransport, fixture_config_with_secrets},
};
use serde_json::{Value, json};

async fn adapter(responses: Vec<Value>) -> (ApigAdapter, Arc<ScriptedTransport>) {
    let mut adapter = ApigAdapter::new();
    adapter.init(&fixture_config_with_secrets(AliCloudService::Apig, false)).await.unwrap();
    adapter.core_mut().set_credential(Some(CloudCredential::long_term("ak", "sk")));
    let transport = ScriptedTransport::new(responses);
    adapter.with_recording_transport(transport.clone()).unwrap();
    (adapter, transport)
}

#[tokio::test]
async fn gateways_use_roa_and_public_pagination_instead_of_rpc() {
    let (adapter,transport)=adapter(vec![
        json!({"code":"Ok","data":{"totalSize":2,"items":[{"gatewayId":"gw-1","name":"first","vpc":{"vpcId":"vpc-1"}}]}}),
        json!({"code":"Ok","data":{"totalSize":2,"items":[{"gatewayId":"gw-2","name":"second"}]}}),
    ]).await;
    let gateways = adapter.pull_gateways().await.unwrap();
    assert_eq!(gateways.len(), 2);
    assert_eq!(gateways[0].vpc_id, "vpc-1");
    let requests = transport.requests.lock().unwrap();
    assert!(requests[0].url.ends_with("/v1/gateways"));
    assert_eq!(requests[0].headers.get("x-acs-version").map(String::as_str), Some("2024-03-27"));
    assert!(requests[0].headers["Authorization"].starts_with("ACS3-HMAC-SHA256"));
    assert!(!requests[0].query.contains("Action="));
    assert!(requests[1].query.contains("pageNumber=2"));
}

#[tokio::test]
async fn api_versions_provide_route_parent_and_missing_ids_do_not_disappear() {
    let (adapter, transport) = adapter(vec![
        json!({"data":{"totalSize":1,"items":[{"name":"api","versionedHttpApis":[{"httpApiId":"api-one"}]}]}}),
        json!({"data":{"totalSize":1,"items":[{"routeId":"route-one","name":"chat","match":{"path":{"value":"/chat"}},
            "backend":{"services":[{"serviceId":"model-one"}]}}]}}),
    ])
    .await;
    let routes = adapter.pull_routes(Some("gw-one")).await.unwrap();
    assert_eq!(routes[0].path, "/chat");
    assert_eq!(routes[0].upstream, "model-one");
    assert_eq!(routes[0].gateway_id, "gw-one");
    assert!(transport.requests.lock().unwrap()[1].url.ends_with("/v1/http-apis/api-one/routes"));
    assert!(adapter.push_policy("gw-one", &ApigPolicy::rate_limit("local", 20)).await.is_err());
    assert!(adapter.sync(SyncDirection::Push, &PullRequest::default()).await.is_err());
    assert_eq!(transport.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn wrong_list_shape_does_not_mean_no_gateways() {
    let (adapter, _) = adapter(vec![json!({"code":"Ok","data":{}})]).await;
    assert!(matches!(adapter.pull_gateways().await, Err(DomainError::Parse(_))));
}
