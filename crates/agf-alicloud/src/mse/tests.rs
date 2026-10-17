//! 由 `mse.rs` 拆分：`health_states` 等 12 个函数（纯搬移，逻辑不变）。
use super::*;

#[tokio::test]
pub(crate) async fn health_states() {
    let adapter = MseAdapter::new();
    assert!(adapter.health().await.is_ok_and(|h| h.state == HealthState::Unconfigured));
    let mut mocked = MseAdapter::mocked();
    assert!(mocked.init(&fixture_config(AliCloudService::Mse, true)).await.is_ok());
    let health = mocked.health().await;
    assert!(health.is_ok());
    if let Ok(health) = health {
        assert_eq!(health.state, HealthState::Degraded);
        assert!(health.mocked);
        assert!(health.message.unwrap_or_default().contains("AGF_MOCK_MODE"));
    }
}

#[tokio::test]
pub(crate) async fn mock_sync_counts_and_marks_unhealthy() {
    let mut adapter = MseAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Mse, true)).await.is_ok());
    let outcome = adapter.sync(SyncDirection::Both, &PullRequest::default()).await;
    assert!(outcome.is_ok(), "{outcome:?}");
    if let Ok(outcome) = outcome {
        assert!(outcome.mocked && outcome.degraded);
        assert_eq!(outcome.changes.get("mse_cluster").copied(), Some(1));
        assert_eq!(outcome.changes.get("nacos_service").copied(), Some(4));
        assert_eq!(outcome.changes.get("unhealthy_service").copied(), Some(1));
        assert_eq!(outcome.pushed, 2, "两份平台默认配置");
        assert_eq!(outcome.pulled, 5);
    }
    let stale = adapter.stale_marks();
    assert!(stale.is_ok());
    if let Ok(stale) = stale {
        assert_eq!(stale.len(), 1);
        assert!(stale[0].contains("risk-analyst-agent"));
    }
    assert_eq!(adapter.transport.call_count().ok(), Some(0), "Mock 必须零网络");
}

#[tokio::test]
pub(crate) async fn service_metadata_mapping() {
    let services = mock::mse_services();
    let file_server = services.iter().find(|s| s.service_name == "mcp-file-server");
    assert!(file_server.is_some());
    if let Some(service) = file_server {
        assert_eq!(service.asset_kind(), AssetKind::McpServer);
        assert_eq!(service.protocol(), Some(Protocol::McpHttp));
        assert_eq!(service.data_class(), DataClass::Internal);
        assert!(service.is_healthy());
        assert_eq!(service.unique_key(), "public/DEFAULT_GROUP/mcp-file-server");
    }
    let agent = services.iter().find(|s| s.service_name == "risk-analyst-agent");
    assert!(agent.is_some_and(|s| s.asset_kind() == AssetKind::Agent && !s.is_healthy()));
    let model = services.iter().find(|s| s.service_name == "qwen-max-endpoint");
    assert!(model.is_some_and(|s| {
        s.asset_kind() == AssetKind::ModelEndpoint
            && s.protocol() == Some(Protocol::OpenAiCompat)
            && s.data_class() == DataClass::Confidential
    }));
    let db = services.iter().find(|s| s.service_name == "mcp-db-server");
    assert!(db.is_some_and(|s| s.protocol() == Some(Protocol::McpSse)));
}

#[tokio::test]
pub(crate) async fn services_become_assets_and_resource_mappings() {
    let services = mock::mse_services();
    let tenant = TenantId::default_tenant();
    let assets = services_to_assets(tenant, &services);
    assert_eq!(assets.len(), 4);
    let file_server = assets.iter().find(|a| a.name == "mcp-file-server");
    assert!(file_server.is_some());
    if let Some(asset) = file_server {
        assert_eq!(asset.kind, AssetKind::McpServer);
        assert_eq!(asset.endpoint.as_deref(), Some("10.20.30.11:8080"));
        assert_eq!(asset.discovery_source, DiscoverySource::CloudApi);
        assert_eq!(asset.data_class, DataClass::Internal);
        assert!(asset.fingerprint.starts_with("mse://"));
        assert!(asset.tags.iter().any(|t| t == "mse:mse-mock-001"));
    }
    // 同一输入必须产出同一资产 id（可重复 upsert 去重）
    let again = services_to_assets(tenant, &services);
    assert_eq!(assets[0].id, again[0].id);

    let integration_id = Id::new();
    let mappings = services_to_resource_mappings(tenant, integration_id, &services);
    assert_eq!(mappings.len(), 4);
    assert_eq!(mappings[0].resource_kind, "mse-mcp-server");
    assert!(!mappings[0].stale);
    assert!(mappings.iter().any(|m| m.stale), "不健康服务必须标记 stale");
    assert!(mappings.iter().all(|m| m.integration_id == integration_id));
}

#[tokio::test]
pub(crate) async fn mock_push_config_returns_content_bound_md5() {
    let mut adapter = MseAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Mse, true)).await.is_ok());
    let a = adapter
        .push_config(&MseConfig {
            data_id: "agf-policy.json".to_string(),
            group_name: "AGF".to_string(),
            namespace: "public".to_string(),
            content: "{\"v\":1}".to_string(),
            md5: String::new(),
        })
        .await;
    let b = adapter
        .push_config(&MseConfig {
            data_id: "agf-policy.json".to_string(),
            group_name: "AGF".to_string(),
            namespace: "public".to_string(),
            content: "{\"v\":2}".to_string(),
            md5: String::new(),
        })
        .await;
    assert!(a.is_ok() && b.is_ok());
    assert_ne!(a.ok(), b.ok(), "内容不同必须返回不同 md5");
    assert_eq!(adapter.transport.call_count().ok(), Some(0));
}

#[tokio::test]
pub(crate) async fn pull_resource_routing() {
    let mut adapter = MseAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Mse, true)).await.is_ok());
    for (resource, expected) in [("services", 4), ("clusters", 1), ("configs", 2), ("gateways", 1)] {
        let response = adapter.pull(&PullRequest { resource: resource.to_string(), ..PullRequest::default() }).await;
        assert!(response.is_ok(), "{resource}: {response:?}");
        if let Ok(response) = response {
            assert_eq!(response.items.len(), expected, "{resource}");
            assert!(response.origin.contains("mock.rs"));
        }
    }
    let unknown = PullRequest { resource: "teams".to_string(), ..PullRequest::default() };
    assert!(matches!(adapter.pull(&unknown).await, Err(DomainError::Validation(_))));
}

#[tokio::test]
pub(crate) async fn push_payload_routing() {
    let mut adapter = MseAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Mse, true)).await.is_ok());
    let ok = PushPayload {
        entity: "config".to_string(),
        entity_id: "agf-policy.json".to_string(),
        body: serde_json::to_value(platform_default_configs()[0].clone()).unwrap_or_default(),
        idempotency_key: Some("k".to_string()),
    };
    assert!(adapter.push(&ok).await.is_ok());
    let bad = PushPayload {
        entity: "policy".to_string(),
        entity_id: "p".to_string(),
        body: serde_json::json!({}),
        idempotency_key: None,
    };
    assert!(matches!(adapter.push(&bad).await, Err(DomainError::Validation(_))));
}

#[tokio::test]
pub(crate) async fn platform_default_configs_are_two() {
    let configs = platform_default_configs();
    assert_eq!(configs.len(), 2);
    assert!(configs.iter().all(|c| c.group_name == "AGF"));
    assert!(configs.iter().all(|c| !c.md5.is_empty()));
}

#[tokio::test]
pub(crate) async fn parsers_handle_aliyun_shapes() {
    let clusters = parse_clusters(&serde_json::json!({
        "Clusters": { "Cluster": [ { "ClusterId": "c-1", "Name": "nacos", "ClusterType": "Nacos", "Version": "2.3.2", "InstanceCount": "3", "VpcId": "vpc-1", "Status": "Running" } ] }
    }));
    assert_eq!(clusters.len(), 1);
    assert_eq!(clusters[0].instance_count, 3, "字符串数字必须能解析");

    let services = parse_services(&serde_json::json!({
        "Service": [ { "NamespaceId": "public", "GroupName": "DEFAULT_GROUP", "ServiceName": "mcp-x", "ClusterId": "c-1", "InstanceCount": 2, "HealthyInstanceCount": 1, "Metadata": { "kind": "mcp-server", "protocol": "mcp-http" } } ]
    }));
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].asset_kind(), AssetKind::McpServer);
    assert!(!services[0].is_healthy());

    let configs = parse_configs(&serde_json::json!({
        "Configs": { "Config": [ { "DataId": "d", "Group": "G", "NamespaceId": "public", "Content": "{}", "Md5": "abc" } ] }
    }));
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0].md5, "abc");
}

#[tokio::test]
pub(crate) async fn live_push_config_builds_publish_request() {
    let transport = Arc::new(RecordingTransport::with_body(serde_json::json!({ "RequestId": "live-request" })));
    let mut adapter = MseAdapter::new();
    let mut config = fixture_config(AliCloudService::Mse, false);
    config.settings.insert("instance_id".into(), serde_json::json!("mse-test"));
    config.secret_refs.insert("access_key_id".to_string(), Id::new());
    config.secret_refs.insert("access_key_secret".to_string(), Id::new());
    assert!(adapter.init(&config).await.is_ok());
    adapter.core_mut().set_credential(Some(crate::credential::CloudCredential::long_term("ak", "sk")));
    assert!(adapter.with_recording_transport(transport.clone()).is_ok());
    let md5 = adapter.push_config(&platform_default_configs()[0]).await;
    assert_eq!(md5.ok().as_deref(), Some("live-request"));
    let last = transport.last_request().ok().flatten();
    assert!(last.is_some());
    if let Some(last) = last {
        assert!(last.query.contains("Action=UpdateNacosConfig"));
        assert!(last.query.contains("DataId="));
    }
}

#[tokio::test]
pub(crate) async fn self_check_lists_mse_permissions() {
    let mut adapter = MseAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::Mse, true)).await.is_ok());
    let health = adapter.self_check().await;
    assert!(health.is_ok());
    if let Ok(health) = health {
        assert!(health.message.unwrap_or_default().contains("mse:"));
    }
}

#[tokio::test]
pub(crate) async fn descriptor_is_complete() {
    let descriptor = MseAdapter::new().descriptor();
    assert_eq!(descriptor.name, "alicloud-mse");
    assert!(descriptor.capabilities.contains(&agf_core::adapter::AdapterCapability::PullInventory));
    assert!(descriptor.capabilities.contains(&agf_core::adapter::AdapterCapability::PushConfig));
    assert!(descriptor.mock_location.ends_with("#mock_mse"));
    assert!(descriptor.degradation.contains("stale"));
}
