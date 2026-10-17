//! 由 `privatelink.rs` 拆分：`health_states` 等 14 个函数（纯搬移，逻辑不变）。
use super::*;

#[tokio::test]
pub(crate) async fn health_states() {
    let adapter = PrivatelinkAdapter::new();
    assert!(adapter.health().await.is_ok_and(|h| h.state == HealthState::Unconfigured));
    let mut mocked = PrivatelinkAdapter::mocked();
    assert!(mocked.init(&fixture_config(AliCloudService::Privatelink, true)).await.is_ok());
    let health = mocked.health().await;
    assert!(health.is_ok());
    if let Ok(health) = health {
        assert_eq!(health.state, HealthState::Degraded);
        assert!(health.message.unwrap_or_default().contains("AGF_MOCK_MODE"));
    }
}

#[tokio::test]
pub(crate) async fn mock_probe_is_deterministic_and_offline() {
    let mut adapter = PrivatelinkAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Privatelink, true)).await.is_ok());
    let ok = adapter.probe("agf-collector-ep").await;
    assert!(ok.is_ok());
    if let Ok(probe) = ok {
        assert!(probe.reachable);
        assert_eq!(probe.latency_ms, 12);
        assert_eq!(probe.endpoint_id, "ep-mock-001");
        assert!(probe.detail.contains("Mock"));
    }
    let bad = adapter.probe("missing-ep").await;
    assert!(bad.is_ok_and(|p| !p.reachable));
    assert_eq!(adapter.transport.call_count().ok(), Some(0));
}

#[tokio::test]
pub(crate) async fn unconfigured_probe_is_unknown_not_down() {
    let probe = PrivatelinkAdapter::unknown_probe("agf-collector-ep");
    assert!(!probe.reachable);
    assert!(probe.detail.contains("未知"), "降级结论必须是「未知」: {}", probe.detail);
}

#[tokio::test]
pub(crate) async fn mock_sync_reports_endpoints_and_risky_whitelists() {
    let mut adapter = PrivatelinkAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Privatelink, true)).await.is_ok());
    let outcome = adapter.sync(SyncDirection::Pull, &PullRequest::default()).await;
    assert!(outcome.is_ok(), "{outcome:?}");
    if let Ok(outcome) = outcome {
        assert!(outcome.mocked && outcome.degraded);
        assert_eq!(outcome.changes.get("vpc_endpoint").copied(), Some(2));
        assert_eq!(outcome.changes.get("endpoint_inactive").copied(), Some(0));
        let risky = outcome.changes.get("whitelist_risky").copied().unwrap_or(0);
        assert!(risky >= 2, "fixtures 必须含过宽白名单: {outcome:?}");
        assert!(outcome.warnings.iter().any(|w| w.contains("安全组")));
    }
    assert_eq!(adapter.transport.call_count().ok(), Some(0));
}

#[tokio::test]
pub(crate) async fn push_direction_is_explicitly_skipped() {
    let mut adapter = PrivatelinkAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Privatelink, true)).await.is_ok());
    let outcome = adapter.sync(SyncDirection::Push, &PullRequest::default()).await;
    assert!(outcome.is_ok());
    if let Ok(outcome) = outcome {
        assert_eq!(outcome.pushed, 0);
        assert_eq!(outcome.skipped, 1);
        assert!(outcome.warnings.iter().any(|w| w.contains("不支持配置下发")));
    }
    let payload = PushPayload {
        entity: "policy".to_string(),
        entity_id: "p".to_string(),
        body: serde_json::json!({}),
        idempotency_key: None,
    };
    assert!(matches!(adapter.push(&payload).await, Err(DomainError::NotImplemented(_))));
}

#[tokio::test]
pub(crate) async fn whitelist_classification() {
    assert_eq!(classify_cidrs(&["10.20.30.0/24".to_string()]), WhitelistVerdict::Minimal);
    assert_eq!(classify_cidrs(&["0.0.0.0/0".to_string()]), WhitelistVerdict::PubliclyOpen);
    assert_eq!(classify_cidrs(&["::/0".to_string()]), WhitelistVerdict::PubliclyOpen);
    assert_eq!(classify_cidrs(&["172.16.0.0/12".to_string()]), WhitelistVerdict::TooBroad);
    assert_eq!(classify_cidrs(&["10.0.0.0/8".to_string()]), WhitelistVerdict::TooBroad);
    assert_eq!(classify_cidrs(&[]), WhitelistVerdict::NoIngress);
    assert!(!WhitelistVerdict::PubliclyOpen.is_acceptable());
    assert!(WhitelistVerdict::Minimal.is_acceptable());
    assert_eq!(WhitelistVerdict::PubliclyOpen.severity(), agf_core::enums::Severity::Critical);
    assert_eq!(WhitelistVerdict::TooBroad.severity(), agf_core::enums::Severity::High);
    assert_eq!(prefix_len("10.0.0.0/8"), Some(8));
    assert_eq!(prefix_len("bogus"), None);
}

#[tokio::test]
pub(crate) async fn security_group_evaluation_covers_all_verdicts() {
    let endpoints = mock::privatelink_endpoints();
    let groups = mock::privatelink_security_groups();
    let checks = evaluate_security_groups(&endpoints, &groups);
    assert!(checks.iter().any(|c| c.verdict == WhitelistVerdict::Minimal));
    assert!(checks.iter().any(|c| c.verdict == WhitelistVerdict::PubliclyOpen));
    assert!(checks.iter().any(|c| c.verdict == WhitelistVerdict::TooBroad));
    let risky = checks.iter().filter(|c| !c.verdict.is_acceptable()).count();
    assert!(risky >= 2, "fixtures 应含至少 2 项风险白名单: {checks:?}");
}

#[tokio::test]
pub(crate) async fn unbound_endpoint_is_flagged() {
    let endpoint = PrivatelinkEndpoint {
        endpoint_id: "ep-unbound".to_string(),
        name: "n".to_string(),
        service_name: "s".to_string(),
        vpc_id: "v".to_string(),
        zone_ids: vec!["z1".to_string()],
        status: "Active".to_string(),
        bandwidth_mbps: 100,
        security_groups: Vec::new(),
        connection_status: "Connected".to_string(),
    };
    let checks = evaluate_security_groups(&[endpoint], &BTreeMap::new());
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].verdict, WhitelistVerdict::Unbound);
    assert!(checks[0].security_group.is_empty());
}

#[tokio::test]
pub(crate) async fn endpoint_helpers() {
    let endpoints = mock::privatelink_endpoints();
    assert!(endpoints.iter().all(PrivatelinkEndpoint::is_active));
    assert!(endpoints[0].is_multi_zone());
    assert!(!endpoints[1].is_multi_zone());
}

#[tokio::test]
pub(crate) async fn pull_resource_routing_and_errors() {
    let mut adapter = PrivatelinkAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Privatelink, true)).await.is_ok());
    for (resource, expected) in [("endpoints", 2), ("security-groups", 4)] {
        let response = adapter.pull(&PullRequest { resource: resource.to_string(), ..PullRequest::default() }).await;
        assert!(response.is_ok(), "{resource}: {response:?}");
        if let Ok(response) = response {
            assert_eq!(response.items.len(), expected, "{resource}");
            assert!(response.origin.contains("mock.rs"));
        }
    }
    let unknown = PullRequest { resource: "configs".to_string(), ..PullRequest::default() };
    assert!(matches!(adapter.pull(&unknown).await, Err(DomainError::Validation(_))));
}

#[tokio::test]
pub(crate) async fn parsers_handle_aliyun_shapes() {
    let endpoints = parse_endpoints(&serde_json::json!({
        "Endpoints": { "Endpoint": [ {
            "EndpointId": "ep-1", "Name": "n", "ServiceName": "svc", "VpcId": "vpc-1",
            "ZoneIds": ["cn-hangzhou-h", "cn-hangzhou-i"], "Status": "Active",
            "Bandwidth": 200, "SecurityGroups": ["sg-1"], "ConnectionStatus": "Connected"
        } ] }
    }));
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].bandwidth_mbps, 200);
    assert_eq!(endpoints[0].zone_ids.len(), 2);
    assert!(endpoints[0].is_active());

    let groups = parse_security_group_rules(&serde_json::json!({
        "SecurityGroupRule": [
            { "SecurityGroupId": "sg-1", "SourceCidrIp": "10.0.0.0/8" },
            { "SecurityGroupId": "sg-1", "SourceCidrIp": "10.20.30.0/24" }
        ]
    }));
    assert_eq!(groups.get("sg-1").map(Vec::len), Some(2));
}

#[tokio::test]
pub(crate) async fn unconfigured_live_probe_is_unknown() {
    let mut adapter = PrivatelinkAdapter::new();
    assert!(adapter.init(&fixture_config(AliCloudService::Privatelink, false)).await.is_ok());
    assert_eq!(adapter.mode(), AdapterMode::Unconfigured);
    let probe = adapter.probe("x").await;
    assert!(probe.is_ok_and(|p| p.detail.contains("未知")));
}

#[tokio::test]
pub(crate) async fn self_check_and_descriptor() {
    let mut adapter = PrivatelinkAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Privatelink, true)).await.is_ok());
    let health = adapter.self_check().await;
    assert!(health.is_ok());
    if let Ok(health) = health {
        assert!(health.message.unwrap_or_default().contains("privatelink:"));
    }
    let descriptor = PrivatelinkAdapter::new().descriptor();
    assert_eq!(descriptor.name, "alicloud-privatelink");
    assert!(descriptor.capabilities.contains(&agf_core::adapter::AdapterCapability::ProbePrivateLink));
    assert!(descriptor.mock_location.ends_with("#mock_privatelink"));
    assert!(descriptor.degradation.contains("未知"));
}
