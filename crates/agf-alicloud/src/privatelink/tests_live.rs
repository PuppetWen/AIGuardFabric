use super::*;
use crate::{
    credential::CloudCredential,
    test_support::{ScriptedTransport, fixture_config_with_secrets},
};
use serde_json::{Value, json};

async fn adapter(responses: Vec<Value>, port: Option<u16>) -> (PrivatelinkAdapter, Arc<ScriptedTransport>) {
    let mut config = fixture_config_with_secrets(AliCloudService::Privatelink, false);
    if let Some(port) = port {
        config.settings.insert("probe_port".into(), json!(port));
    }
    let mut adapter = PrivatelinkAdapter::new();
    adapter.init(&config).await.unwrap();
    adapter.core_mut().set_credential(Some(CloudCredential::long_term("ak", "sk")));
    let transport = ScriptedTransport::new(responses);
    adapter.with_recording_transport(transport.clone()).unwrap();
    (adapter, transport)
}

#[tokio::test]
async fn probe_connects_from_runtime_and_reports_closed_port() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let response = json!({"EndpointId":"ep-one","EndpointDomain":"127.0.0.1"});
    let (adapter, transport) = adapter(vec![response.clone(), response], Some(port)).await;
    let result = adapter.probe("ep-one").await.unwrap();
    assert!(result.reachable);
    assert_eq!(result.resolved_ip, "127.0.0.1");
    assert!(result.detail.contains("未验证 TLS"));
    drop(listener);
    assert!(!adapter.probe("ep-one").await.unwrap().reachable);
    assert!(
        transport
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.query.contains("Action=GetVpcEndpointAttribute"))
    );
}

#[tokio::test]
async fn inventory_reads_groups_zones_then_uses_ecs_for_rules() {
    let (adapter,transport)=adapter(vec![
        json!({"Endpoints":[{"EndpointId":"ep-one","EndpointStatus":"Active","ConnectionStatus":"Connected"}]}),
        json!({"SecurityGroups":[{"SecurityGroupId":"sg-one"}],"NextToken":"more"}),
        json!({"SecurityGroups":[{"SecurityGroupId":"sg-two"}],"NextToken":""}),
        json!({"Zones":[{"ZoneId":"cn-hangzhou-a"}]}),
        json!({"Permissions":{"Permission":[{"Policy":"Accept","SourceCidrIp":"0.0.0.0/0"},{"Policy":"Drop","SourceCidrIp":"10.0.0.0/8"}]}}),
        json!({"Permissions":{"Permission":[{"Policy":"Accept","SourceGroupId":"sg-ref"}]}}),
    ],None).await;
    let checks = adapter.check_security_groups().await.unwrap();
    assert_eq!(checks.len(), 2);
    assert_eq!(checks[0].verdict, WhitelistVerdict::PubliclyOpen);
    assert_eq!(checks[1].verdict, WhitelistVerdict::Unknown);
    let requests = transport.requests.lock().unwrap();
    assert!(requests[0].query.contains("RegionId=cn-hangzhou"));
    assert!(requests[2].query.contains("NextToken=more"));
    assert!(requests[4].url.starts_with("https://ecs.cn-hangzhou.aliyuncs.com"));
    assert!(requests[4].query.contains("Action=DescribeSecurityGroupAttribute"));
    assert!(requests[4].query.contains("Version=2014-05-26"));
}

#[tokio::test]
async fn no_probe_port_no_network_and_invalid_cidr_is_unknown() {
    let (adapter, transport) = adapter(Vec::new(), None).await;
    assert!(matches!(adapter.probe("ep-one").await, Err(DomainError::Config(_))));
    assert!(transport.requests.lock().unwrap().is_empty());
    assert_eq!(classify_cidrs(&["10.0.0.0/99".into()]), WhitelistVerdict::Unknown);
    assert_eq!(classify_cidrs(&["broken/24".into()]), WhitelistVerdict::Unknown);
    assert_eq!(classify_cidrs(&["8.8.8.8/32".into()]), WhitelistVerdict::PubliclyOpen);
    assert_eq!(classify_cidrs(&[]), WhitelistVerdict::NoIngress);
}
