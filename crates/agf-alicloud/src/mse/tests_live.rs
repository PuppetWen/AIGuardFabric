use super::*;
use crate::{
    credential::CloudCredential,
    http::{RpcRequest, RpcResponse, Transport},
};
use serde_json::{Value, json};
use std::{collections::VecDeque, sync::Mutex};

struct Pages {
    responses: Mutex<VecDeque<Value>>,
    requests: Mutex<Vec<RpcRequest>>,
}
impl Transport for Pages {
    fn send(&self, request: &RpcRequest) -> DomainResult<RpcResponse> {
        self.requests.lock().unwrap().push(request.clone());
        let body = self.responses.lock().unwrap().pop_front().expect("unexpected cloud request");
        Ok(RpcResponse { status: 200, raw: body.to_string(), body })
    }
}
async fn adapter(responses: Vec<Value>) -> (MseAdapter, Arc<Pages>) {
    let mut config = crate::test_support::fixture_config_with_secrets(AliCloudService::Mse, false);
    config.settings.insert("instance_id".into(), json!("mse-instance"));
    config.settings.insert("namespace_id".into(), json!("tenant-space"));
    let mut adapter = MseAdapter::new();
    adapter.init(&config).await.unwrap();
    adapter.core_mut().set_credential(Some(CloudCredential::long_term("test-ak", "test-sk")));
    let transport = Arc::new(Pages { responses: Mutex::new(responses.into()), requests: Mutex::new(Vec::new()) });
    adapter.with_recording_transport(transport.clone()).unwrap();
    (adapter, transport)
}

#[tokio::test]
async fn public_service_pages_include_instance_and_preserve_counts() {
    let (adapter, transport) = adapter(vec![
        json!({"Success":true,"TotalCount":2,"Data":[{"Name":"mcp-one","GroupName":"AI","IpCount":2,"HealthyInstanceCount":1}]}),
        json!({"Success":true,"TotalCount":2,"Data":[{"Name":"agent-two","GroupName":"AI","IpCount":1,"HealthyInstanceCount":1}]}),
    ]).await;
    let services = adapter.pull_services().await.unwrap();
    assert_eq!(services.len(), 2);
    assert_eq!(services[0].cluster_id, "mse-instance");
    assert_eq!(services[0].namespace, "tenant-space");
    assert_eq!(services[0].instance_count, 2);
    assert!(!services[0].is_healthy());
    let requests = transport.requests.lock().unwrap();
    assert!(requests[0].query.contains("Action=ListAnsServices"));
    assert!(requests[0].query.contains("Version=2019-05-31"));
    assert!(requests[1].query.contains("PageNum=2"));
    assert!(requests[1].query.contains("InstanceId=mse-instance"));
}

#[tokio::test]
async fn malformed_or_repeated_pages_cannot_become_empty_inventory() {
    for responses in [
        vec![json!({"Success":true})],
        vec![json!({"TotalCount":3,"Data":[{"Name":"same"}]}), json!({"TotalCount":3,"Data":[{"Name":"same"}]})],
    ] {
        let (adapter, _) = adapter(responses).await;
        assert!(matches!(adapter.pull_services().await, Err(DomainError::Parse(_))));
    }
}

#[tokio::test]
async fn config_listing_fetches_content_and_publication_keeps_body_out_of_url() {
    let (adapter, transport) = adapter(vec![
        json!({"TotalCount":1,"Configurations":[{"DataId":"policy.json","Group":"AGF"}]}),
        json!({"Configuration":{"DataId":"policy.json","Group":"AGF","Content":"private-content","Md5":"old-md5"}}),
        json!({"Success":true,"RequestId":"updated"}),
        json!({"Success":true,"Code":"1","RequestId":"created"}),
    ])
    .await;
    let mut configs = adapter.pull_configs().await.unwrap();
    assert_eq!(configs[0].content, "private-content");
    assert_eq!(configs[0].namespace, "tenant-space");
    assert_eq!(adapter.push_config(&configs[0]).await.unwrap(), "updated");
    configs[0].md5.clear();
    assert_eq!(adapter.push_config(&configs[0]).await.unwrap(), "created");
    let requests = transport.requests.lock().unwrap();
    assert!(requests[1].query.contains("Action=GetNacosConfig"));
    assert!(requests[2].query.contains("Action=UpdateNacosConfig"));
    assert!(requests[2].query.contains("Md5=old-md5"));
    assert!(!requests[2].query.contains("Content"));
    assert!(requests[2].body.contains("Content=private-content"));
    assert!(requests[3].query.contains("Action=CreateNacosConfig"));
    assert!(!requests[3].query.contains("Md5="));
}

#[tokio::test]
async fn public_gateway_shape_and_no_implicit_demo_policy_publication() {
    let (adapter,transport)=adapter(vec![json!({"Data":{"TotalSize":1,"Result":[{
        "GatewayUniqueId":"gw-real","Name":"Gateway","GatewayVersion":"2.0","GatewayType":"Ingress","StatusDesc":"Running"
    }]}})]).await;
    let gateways = adapter.pull_gateways().await.unwrap();
    assert_eq!(gateways[0].gateway_id, "gw-real");
    assert_eq!(gateways[0].version, "2.0");
    assert!(adapter.sync(SyncDirection::Push, &PullRequest::default()).await.is_err());
    assert_eq!(transport.requests.lock().unwrap().len(), 1);
}
