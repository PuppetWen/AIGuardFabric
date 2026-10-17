//! 由 `apig.rs` 拆分：`health_states_unconfigured_mocked` 等 15 个函数（纯搬移，逻辑不变）。
use super::*;

#[tokio::test]
pub(crate) async fn health_states_unconfigured_mocked() {
    let adapter = ApigAdapter::new();
    assert!(adapter.health().await.is_ok_and(|h| h.state == HealthState::Unconfigured));

    let mut mocked = ApigAdapter::mocked();
    assert!(mocked.init(&fixture_config(AliCloudService::Apig, true)).await.is_ok());
    let health = mocked.health().await;
    assert!(health.is_ok());
    if let Ok(health) = health {
        assert_eq!(health.state, HealthState::Degraded);
        assert!(health.mocked);
        assert!(health.message.unwrap_or_default().contains("AGF_MOCK_MODE"));
    }
}

#[tokio::test]
pub(crate) async fn mock_sync_reports_gateway_route_plugin_counts() {
    let mut adapter = ApigAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Apig, true)).await.is_ok());
    let outcome = adapter.sync(SyncDirection::Both, &PullRequest::default()).await;
    assert!(outcome.is_ok(), "{outcome:?}");
    if let Ok(outcome) = outcome {
        assert!(outcome.mocked && outcome.degraded);
        assert_eq!(outcome.changes.get("gateway").copied(), Some(2));
        assert_eq!(outcome.changes.get("route").copied(), Some(3));
        assert_eq!(outcome.changes.get("plugin").copied(), Some(2));
        assert_eq!(outcome.pulled, 7);
        // 2 个网关 × 4 类策略
        assert_eq!(outcome.pushed, 8, "策略下发计数");
        assert_eq!(outcome.failed, 0);
        assert_eq!(outcome.changes.get("policy").copied(), Some(8));
    }
    assert_eq!(adapter.transport.call_count().ok(), Some(0), "Mock 必须零网络");
}

#[tokio::test]
pub(crate) async fn policy_payload_shapes() {
    let rate = ApigPolicy::rate_limit("agf-rate-limit", 100);
    assert_eq!(rate.kind, ApigPolicyKind::RateLimit);
    assert_eq!(rate.kind.plugin_type(), "ai-rate-limit");
    let params = rate.params("gw-1");
    assert!(params.iter().any(|(k, v)| k == "GatewayId" && v == "gw-1"));
    assert!(params.iter().any(|(k, v)| k == "PluginType" && v == "ai-rate-limit"));
    let config = params.iter().find(|(k, _)| k == "PluginConfig").map(|(_, v)| v.clone()).unwrap_or_default();
    assert!(config.contains("\"qps\":100"), "{config}");
    assert!(config.contains("burst"), "限流必须带 burst，避免边界抖动");

    let quota = ApigPolicy::token_quota("agf-token-quota", 1_000_000, "day");
    assert_eq!(quota.kind.plugin_type(), "ai-token-quota");
    assert!(quota.config.to_string().contains("1000000"));

    let safety = ApigPolicy::content_safety("agf-content-safety", &["prompt_attack"]);
    assert_eq!(safety.kind.plugin_type(), "ai-content-safety");
    assert!(safety.config.to_string().contains("prompt_attack"));
    assert!(safety.config.to_string().contains("agf-ingest"), "内容安全必须回报平台");

    let routing = ApigPolicy::model_routing("agf-model-routing", "qwen-max", "dashscope.aliyuncs.com");
    assert_eq!(routing.kind.plugin_type(), "ai-model-router");
    assert!(routing.enabled);
}

#[tokio::test]
pub(crate) async fn policy_kind_parse_aliases() {
    assert_eq!(ApigPolicyKind::parse("rate_limit"), Ok(ApigPolicyKind::RateLimit));
    assert_eq!(ApigPolicyKind::parse("QUOTA"), Ok(ApigPolicyKind::TokenQuota));
    assert_eq!(ApigPolicyKind::parse("safety"), Ok(ApigPolicyKind::ContentSafety));
    assert_eq!(ApigPolicyKind::parse("routing"), Ok(ApigPolicyKind::ModelRouting));
    assert!(ApigPolicyKind::parse("nope").is_err());
    assert_eq!(ApigPolicyKind::RateLimit.as_str(), "rate-limit");
}

#[tokio::test]
pub(crate) async fn default_policy_set_covers_four_kinds() {
    let policies = ApigAdapter::default_policy_set(200, 500_000);
    assert_eq!(policies.len(), 4);
    let kinds: Vec<ApigPolicyKind> = policies.iter().map(|p| p.kind).collect();
    assert!(kinds.contains(&ApigPolicyKind::RateLimit));
    assert!(kinds.contains(&ApigPolicyKind::TokenQuota));
    assert!(kinds.contains(&ApigPolicyKind::ContentSafety));
    assert!(kinds.contains(&ApigPolicyKind::ModelRouting));
    let names: Vec<&str> = policies.iter().map(|p| p.name.as_str()).collect();
    assert!(names.iter().all(|n| n.starts_with("agf-")), "策略名必须带平台前缀便于回收: {names:?}");
}

#[tokio::test]
pub(crate) async fn mock_pull_routes_filters_by_gateway() {
    let mut adapter = ApigAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Apig, true)).await.is_ok());
    assert_eq!(adapter.pull_routes(None).await.map(|r| r.len()).ok(), Some(3));
    assert_eq!(adapter.pull_routes(Some("gw-mock-002")).await.map(|r| r.len()).ok(), Some(1));
    assert_eq!(adapter.pull_gateways().await.map(|g| g.len()).ok(), Some(2));
    assert_eq!(adapter.pull_plugins().await.map(|p| p.len()).ok(), Some(2));
    assert_eq!(adapter.transport.call_count().ok(), Some(0));
}

#[tokio::test]
pub(crate) async fn mock_push_policy_returns_deterministic_id() {
    let mut adapter = ApigAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Apig, true)).await.is_ok());
    let id = adapter.push_policy("gw-mock-001", &ApigPolicy::rate_limit("agf-rate-limit", 50)).await;
    assert_eq!(id.ok().as_deref(), Some("plugin-mock-rate-limit"));
    assert_eq!(adapter.transport.call_count().ok(), Some(0));
}

#[tokio::test]
pub(crate) async fn mock_access_logs_respect_limit_and_include_blocked() {
    let mut adapter = ApigAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Apig, true)).await.is_ok());
    let logs = adapter.pull_access_logs(&PullRequest::default()).await;
    assert!(logs.is_ok());
    if let Ok(logs) = logs {
        assert_eq!(logs.len(), 2);
        assert!(
            logs.iter().any(|l| l.get("blocked_reason").and_then(serde_json::Value::as_str) == Some("prompt_attack")),
            "Mock 访问日志必须含一条被内容安全阻断的样本"
        );
    }
    let limited = adapter.pull_access_logs(&PullRequest { limit: Some(1), ..PullRequest::default() }).await;
    assert_eq!(limited.map(|l| l.len()).ok(), Some(1));
}

#[tokio::test]
pub(crate) async fn pull_resource_routing_and_errors() {
    let mut adapter = ApigAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Apig, true)).await.is_ok());
    for (resource, expected) in [("gateways", 2), ("routes", 3), ("plugins", 2), ("access-logs", 2)] {
        let response = adapter.pull(&PullRequest { resource: resource.to_string(), ..PullRequest::default() }).await;
        assert!(response.is_ok(), "{resource}: {response:?}");
        if let Ok(response) = response {
            assert_eq!(response.items.len(), expected);
            assert!(response.origin.contains("mock.rs"));
            assert!(response.mocked);
        }
    }
    let unknown = PullRequest { resource: "jobs".to_string(), ..PullRequest::default() };
    assert!(matches!(adapter.pull(&unknown).await, Err(DomainError::Validation(_))));
}

#[tokio::test]
pub(crate) async fn push_rejects_unknown_entity() {
    let mut adapter = ApigAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Apig, true)).await.is_ok());
    let payload = PushPayload {
        entity: "metric".to_string(),
        entity_id: "m".to_string(),
        body: serde_json::json!({}),
        idempotency_key: None,
    };
    assert!(matches!(adapter.push(&payload).await, Err(DomainError::Validation(_))));
    let ok_payload = PushPayload {
        entity: "policy".to_string(),
        entity_id: "agf-rate-limit".to_string(),
        body: serde_json::to_value(ApigPolicy::rate_limit("agf-rate-limit", 10)).unwrap_or_default(),
        idempotency_key: Some("idem-1".to_string()),
    };
    assert!(adapter.push(&ok_payload).await.is_ok());
}

#[tokio::test]
pub(crate) async fn parsers_handle_aliyun_shapes() {
    let body = serde_json::json!({
        "TotalCount": "1",
        "Gateways": { "Gateway": [ { "GatewayId": "gw-1", "Name": "生产网关", "Spec": "small", "Status": "Running", "VpcId": "vpc-1", "Tags": [ {"Key":"env","Value":"prod"} ] } ] }
    });
    let gateways = parse_gateways(&body);
    assert_eq!(gateways.len(), 1);
    assert_eq!(gateways[0].gateway_id, "gw-1");
    assert_eq!(gateways[0].tags, vec!["env:prod".to_string()]);

    let routes = parse_routes(&serde_json::json!({
        "Routes": { "Route": [ { "RouteId": "r-1", "GatewayId": "gw-1", "Path": "/v1", "Upstream": "u:1", "Plugins": ["rate-limit"] } ] }
    }));
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].plugins, vec!["rate-limit".to_string()]);

    let plugins = parse_plugins(&serde_json::json!({
        "Plugin": [ { "PluginId": "p-1", "PluginName": "cs", "PluginType": "ai-content-safety", "Enabled": true, "PluginConfig": {"action":"block"} } ]
    }));
    assert_eq!(plugins.len(), 1);
    assert!(plugins[0].enabled);
    assert_eq!(crate::http::json_i64(&serde_json::json!({"a":"7"}), "a"), Some(7));
}

#[tokio::test]
pub(crate) async fn gateway_resource_mapping_shape() {
    let gateways = mock::apig_gateways();
    let mappings =
        gateways_to_resource_mappings(agf_core::ids::TenantId::default_tenant(), agf_core::ids::Id::new(), &gateways);
    assert_eq!(mappings.len(), 2);
    assert_eq!(mappings[0].resource_kind, "apig-gateway");
    assert_eq!(mappings[0].service, AliCloudService::Apig);
    assert!(!mappings[0].stale);
    assert!(mappings[0].attributes.contains_key("vpc_id"));
}

#[tokio::test]
pub(crate) async fn live_path_builds_create_plugin_request() {
    let transport = Arc::new(RecordingTransport::with_body(
        serde_json::json!({ "code":"Ok", "data":{"pluginAttachmentId":"p-live-1"} }),
    ));
    let mut adapter = ApigAdapter::new();
    let mut config = fixture_config(AliCloudService::Apig, false);
    config.secret_refs.insert("access_key_id".to_string(), agf_core::ids::Id::new());
    config.secret_refs.insert("access_key_secret".to_string(), agf_core::ids::Id::new());
    assert!(adapter.init(&config).await.is_ok());
    adapter.core_mut().set_credential(Some(crate::credential::CloudCredential::long_term("ak", "sk")));
    assert!(adapter.with_recording_transport(transport.clone()).is_ok());
    let mut policy = ApigPolicy::content_safety("agf-cs", &["prompt_attack"]);
    policy.config = serde_json::json!({"plugin_id":"pl-installed","plugin_config":"checkRequest: true"});
    let id = adapter.push_policy("gw-1", &policy).await;
    assert_eq!(id.ok().as_deref(), Some("p-live-1"));
    let last = transport.last_request().ok().flatten();
    assert!(last.is_some());
    if let Some(last) = last {
        assert!(last.url.ends_with("/v1/plugin-attachments"));
        assert_eq!(last.headers.get("x-acs-action").map(String::as_str), Some("CreatePluginAttachment"));
        let body: serde_json::Value = serde_json::from_str(&last.body).unwrap();
        assert_eq!(body["pluginId"], "pl-installed");
        assert_eq!(body["enable"], true);
        assert_eq!(body["attachResourceType"], "Gateway");
        assert_eq!(body["attachResourceIds"], serde_json::json!(["gw-1"]));
        assert_eq!(body["pluginConfig"], "Y2hlY2tSZXF1ZXN0OiB0cnVl");
    }
}

#[tokio::test]
pub(crate) async fn self_check_lists_apig_permissions() {
    let mut adapter = ApigAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Apig, true)).await.is_ok());
    let health = adapter.self_check().await;
    assert!(health.is_ok());
    if let Ok(health) = health {
        let message = health.message.unwrap_or_default();
        assert!(message.contains("apig:"), "自检必须列出 APIG 权限项: {message}");
        assert!(message.contains("Mock"));
    }
}

#[tokio::test]
pub(crate) async fn descriptor_and_capabilities() {
    let descriptor = ApigAdapter::new().descriptor();
    assert_eq!(descriptor.name, "alicloud-apig");
    assert!(descriptor.capabilities.contains(&agf_core::adapter::AdapterCapability::EnforcePolicy));
    assert!(descriptor.capabilities.contains(&agf_core::adapter::AdapterCapability::QueryLogs));
    assert!(descriptor.mock_location.ends_with("#mock_apig"));
}
