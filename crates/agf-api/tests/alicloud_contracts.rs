//! Executable public cloud contracts against loopback receivers, never a real cloud account.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use agf_alicloud::{
    AdapterMode,
    credential::CloudCredential,
    endpoint::{EndpointStyle, resolve},
    http::{ReqwestTransport, RpcClient, RpcClientConfig, SignStyle},
    openapi::{contract, contracts},
};
use agf_core::enums::AliCloudService;
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path, query_param},
};

fn client(service: AliCloudService, url: &str) -> RpcClient {
    let key = agf_alicloud::endpoint::service_key(service).to_string();
    let endpoint =
        resolve(service, "cn-hangzhou", EndpointStyle::Public, &BTreeMap::from([(key, url.into())])).unwrap();
    let transport = Arc::new(ReqwestTransport::new(3).unwrap());
    RpcClient::live(
        AdapterMode::Live,
        RpcClientConfig {
            adapter: service.as_str().into(),
            region: "cn-hangzhou".into(),
            account_id: String::new(),
            style: SignStyle::Rpc,
            timeout_secs: 3,
        },
        Some(CloudCredential::long_term("LOCAL-AK", "LOCAL-SK")),
        endpoint,
        transport.clone(),
    )
    .unwrap()
    .with_async_transport(transport)
    .with_nonce("local-contract-test")
    .with_timestamp(agf_core::time::Timestamp::parse_rfc3339("2026-09-20T00:00:00Z").unwrap())
}
#[tokio::test]
async fn rpc_cms_and_agentteams_use_documented_array_encodings() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(query_param("Action", "PutCustomEvent"))
        .and(query_param("EventInfo.1.EventName", "agf-test"))
        .and(query_param("EventInfo.1.Content", "plus+slash/~equals="))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Code":"200"})))
        .expect(1)
        .mount(&server)
        .await;
    let cms = contract(AliCloudService::Cms, "PutCustomEvent").unwrap();
    cms.call(
        &client(AliCloudService::Cms, &server.uri()),
        &json!({"EventInfo":[{"EventName":"agf-test","Content":"plus+slash/~equals="}]}),
    )
    .await
    .unwrap();
    Mock::given(method("POST"))
        .and(query_param("Action", "UpdateTeam"))
        .and(query_param("TeamMembers", r#"[{"Name":"existing-user"}]"#))
        .and(query_param("InstanceId", "instance-local"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Success":true,"Code":"SUCCESS"})))
        .expect(1)
        .mount(&server)
        .await;
    contract(AliCloudService::AgentTeams, "UpdateTeam")
        .unwrap()
        .call(
            &client(AliCloudService::AgentTeams, &server.uri()),
            &json!({"InstanceId":"instance-local","Name":"team-local","TeamMembers":[{"Name":"existing-user"}]}),
        )
        .await
        .unwrap();
}
#[tokio::test]
async fn mse_and_scheduler_form_data_stays_out_of_the_url() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(query_param("Action", "CreateNacosConfig"))
        .and(query_param("Version", "2019-05-31"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Success":true,"Code":"200"})))
        .expect(1)
        .mount(&server)
        .await;
    contract(AliCloudService::Mse, "CreateNacosConfig")
        .unwrap()
        .call(
            &client(AliCloudService::Mse, &server.uri()),
            &json!({"InstanceId":"mse-local","DataId":"agf.json","Group":"AGF","Content":"token=LOCAL+VALUE&keep=~"}),
        )
        .await
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    assert!(!requests[0].url.as_str().contains("Content="));
    let body = url::form_urlencoded::parse(&requests[0].body).collect::<BTreeMap<_, _>>();
    assert_eq!(body.get("Content").map(std::convert::AsRef::as_ref), Some("token=LOCAL+VALUE&keep=~"));
    let rpc = client(AliCloudService::SchedulerX3, &server.uri());
    let request = contract(AliCloudService::SchedulerX3, "DeleteJobs")
        .unwrap()
        .build(&rpc, &json!({"ClusterId":"cluster-local","AppName":"agf","JobIds":[12,34]}))
        .unwrap();
    let form = url::form_urlencoded::parse(request.body.as_bytes()).collect::<BTreeMap<_, _>>();
    assert_eq!(form.get("JobIds").map(std::convert::AsRef::as_ref), Some("[12,34]"));
    assert!(!request.query.contains("JobIds"));
    let combined = rpc
        .build(
            "DeleteJobs",
            "2024-06-24",
            "POST",
            &[
                ("ClusterId".into(), "cluster-local".into()),
                ("AppName".into(), "agf".into()),
                ("JobIds".into(), "[12,34]".into()),
            ],
        )
        .unwrap();
    let combined_query = url::form_urlencoded::parse(combined.query.as_bytes()).collect::<BTreeMap<_, _>>();
    let split_query = url::form_urlencoded::parse(request.query.as_bytes()).collect::<BTreeMap<_, _>>();
    assert_eq!(split_query.get("Signature"), combined_query.get("Signature"));
}
#[tokio::test]
async fn apig_uses_resource_paths_body_signatures_and_lowercase_business_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/gateways"))
        .and(query_param("pageNumber", "1"))
        .and(header("x-acs-action", "ListGateways"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"code":"Ok","data":{"items":[]}})))
        .expect(1)
        .mount(&server)
        .await;
    let rpc = client(AliCloudService::Apig, &server.uri());
    contract(AliCloudService::Apig, "ListGateways").unwrap().call(&rpc, &json!({"pageNumber":1})).await.unwrap();
    Mock::given(method("PUT"))
        .and(path("/v1/plugin-attachments/pa-local"))
        .and(header("x-acs-action", "UpdatePluginAttachment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"code":"Forbidden","message":"no permission"})))
        .expect(1)
        .mount(&server)
        .await;
    let response = contract(AliCloudService::Apig, "UpdatePluginAttachment")
        .unwrap()
        .call(&rpc, &json!({"pluginAttachmentId":"pa-local","body":{"enable":false}}))
        .await;
    assert!(response.is_err());
    let requests = server.received_requests().await.unwrap();
    let body = &requests[1].body;
    assert_eq!(serde_json::from_slice::<serde_json::Value>(body).unwrap(), json!({"enable":false}));
    assert_eq!(
        requests[1].headers.get("x-acs-content-sha256").unwrap().to_str().unwrap(),
        agf_alicloud::signer::sha256_hex(std::str::from_utf8(body).unwrap(), false)
    );
}
#[test]
fn parameter_validation_rejects_missing_and_unknown_fields_before_io() {
    let operation = contract(AliCloudService::AgentTeams, "ListTeams").unwrap();
    assert!(operation.validate(&json!({})).is_err());
    assert!(operation.validate(&json!({"InstanceId":""})).is_err());
    assert!(operation.validate(&json!({"InstanceId":"i","MaxResults":"10"})).is_err());
    assert!(operation.validate(&json!({"InstanceId":"i","SecurityToken":"secret"})).is_err());
    assert!(operation.validate(&json!({"InstanceId":"i","MaxResults":10})).is_ok());
    let count = AliCloudService::all().iter().map(|service| contracts(*service).unwrap().len()).sum::<usize>();
    assert_eq!(count, 60);
    assert!(contract(AliCloudService::Cms, "PutResourceMetricData").is_err());
    assert!(contract(AliCloudService::Privatelink, "ProbeVpcEndpoint").is_err());
}

#[path = "alicloud_observations/mod.rs"]
mod observations;
#[test]
fn endpoint_rejects_insecure_or_ambiguous_urls_and_unknown_regions() {
    for raw in [
        "http://cloud.example.com",
        "https://user:pass@cloud.example.com",
        "https://cloud.example.com/path",
        "https://cloud.example.com/?token=x",
    ] {
        assert!(
            resolve(
                AliCloudService::Cms,
                "cn-hangzhou",
                EndpointStyle::Public,
                &BTreeMap::from([("cms".into(), raw.into())])
            )
            .is_err()
        );
    }
    assert!(resolve(AliCloudService::AgentTeams, "cn-unlisted", EndpointStyle::Public, &BTreeMap::new()).is_err());
    let endpoint =
        resolve(AliCloudService::AgentTeams, "cn-beijing", EndpointStyle::Private, &BTreeMap::new()).unwrap();
    assert_eq!(endpoint.host, "agentteams-vpc.cn-beijing.aliyuncs.com");
}
