//! 由 `registry.rs` 拆分：`mock_only_registry_has_six_services` 等 14 个函数（纯搬移，逻辑不变）。
use super::*;

#[test]
pub(crate) fn mock_only_registry_has_six_services() {
    let registry = AliCloudRegistry::mock_only();
    assert_eq!(registry.records().len(), 6);
    assert_eq!(registry.names().len(), 6);
    assert_eq!(registry.descriptors().len(), 6);
    assert_eq!(registry.all().len(), 6);
    for service in AliCloudService::all() {
        let record = registry.record(service);
        assert!(record.is_some(), "{} 必须有记录", service.as_str());
        if let Some(record) = record {
            assert_eq!(record.mode, AdapterMode::Mocked);
            assert!(record.enabled);
            assert!(!record.is_serving(), "Mock 不承载真实流量");
            assert!(!record.descriptor.degradation.is_empty());
            assert!(
                record.descriptor.mock_location.ends_with(&format!("#{}", mock::mock_constructor_name(service))),
                "{} 的 mock_location 必须指向其 Mock 构造器",
                service.as_str()
            );
        }
        assert!(registry.get(service.as_str()).is_some());
    }
    assert_eq!(registry.degraded_services().len(), 6);
}

#[test]
pub(crate) fn every_descriptor_is_complete_and_unique() {
    let registry = AliCloudRegistry::mock_only();
    let mut names: Vec<String> = registry.descriptors().iter().map(|d| d.name.clone()).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 6, "描述符名必须唯一");
    for descriptor in registry.descriptors() {
        assert_eq!(descriptor.category, "alicloud");
        assert!(!descriptor.required_secrets.is_empty());
        assert!(!descriptor.capabilities.is_empty());
        assert!(!descriptor.degradation.trim().is_empty(), "{} 缺降级说明", descriptor.name);
        assert!(!descriptor.mock_location.trim().is_empty(), "{} 缺 Mock 位置", descriptor.name);
        assert!(descriptor.real_implementation);
    }
}

#[tokio::test]
pub(crate) async fn health_all_reports_degraded_mock_for_every_service() {
    let registry = AliCloudRegistry::mock_only();
    let health = registry.health_all().await;
    assert!(health.is_ok(), "{health:?}");
    if let Ok(health) = health {
        assert_eq!(health.len(), 6);
        for (name, report) in health {
            assert_eq!(report.state, agf_core::enums::HealthState::Degraded, "{name}");
            assert!(report.mocked);
            assert!(report.message.unwrap_or_default().contains("AGF_MOCK_MODE"), "{name}");
        }
    }
}

#[tokio::test]
pub(crate) async fn from_configs_with_mock_flags_builds_all_six() {
    let configs: Vec<AdapterConfig> = AliCloudService::all().iter().map(|s| fixture_config(*s, true)).collect();
    let registry = AliCloudRegistry::from_configs(&configs).await;
    assert!(registry.is_ok(), "{registry:?}");
    if let Ok(registry) = registry {
        assert_eq!(registry.records().len(), 6);
        for record in registry.records() {
            assert_eq!(record.mode, AdapterMode::Mocked);
            assert!(record.config_id.is_some(), "配置驱动的记录必须带配置 id");
            assert!(record.configured);
        }
    }
}

#[tokio::test]
pub(crate) async fn from_configs_without_credentials_degrades_not_fails() {
    let configs: Vec<AdapterConfig> = AliCloudService::all().iter().map(|s| fixture_config(*s, false)).collect();
    let registry = AliCloudRegistry::from_configs(&configs).await;
    assert!(registry.is_ok(), "未配置不得导致构建失败: {registry:?}");
    if let Ok(registry) = registry {
        for record in registry.records() {
            assert_eq!(record.mode, AdapterMode::Unconfigured);
            assert!(!record.configured);
            assert!(!record.is_serving());
        }
    }
}

#[tokio::test]
pub(crate) async fn from_configs_rejects_invalid_region() {
    let mut config = fixture_config(AliCloudService::Cms, true);
    config.settings.insert("region_id".to_string(), serde_json::Value::from("bad region"));
    let result = AliCloudRegistry::from_configs(&[config]).await;
    assert!(matches!(result, Err(DomainError::Config(_))), "非法配置必须报错: {result:?}");
}

#[tokio::test]
pub(crate) async fn missing_config_falls_back_to_mock() {
    let configs = vec![fixture_config(AliCloudService::Cms, true)];
    let registry = AliCloudRegistry::from_configs(&configs).await;
    assert!(registry.is_ok());
    if let Ok(registry) = registry {
        assert_eq!(registry.record(AliCloudService::Cms).map(|r| r.mode), Some(AdapterMode::Mocked));
        let apig = registry.record(AliCloudService::Apig);
        assert!(apig.is_some_and(|r| r.mode == AdapterMode::Mocked && r.config_id.is_none()));
    }
}

#[test]
pub(crate) fn self_check_suite_covers_all_services_with_ram_policy() {
    let registry = AliCloudRegistry::mock_only();
    let suite = registry.self_check_suite();
    assert_eq!(suite.reports.len(), 6);
    assert_eq!(suite.overall(), agf_core::enums::HealthState::Degraded);
    assert!(suite.blocking_failures().is_empty(), "Mock 模式无阻断项");
    let policy = suite.ram_policy_json();
    assert!(policy.is_ok());
    if let Ok(policy) = policy {
        assert!(policy.contains("cms:DescribeAlertHistoryList"));
        assert!(!policy.contains("agentteams:"), "不得编造未公布的 RAM Action");
        assert!(!policy.contains("cms:ListAlarmHistories"), "可选权限不应进入策略");
    }
    let markdown = suite.to_markdown();
    for service in AliCloudService::all() {
        assert!(markdown.contains(service.as_str()), "总览必须包含 {}", service.as_str());
    }
}

#[test]
pub(crate) fn console_row_contains_required_console_fields() {
    let registry = AliCloudRegistry::mock_only();
    let rows: Vec<BTreeMap<String, String>> = registry.records().iter().map(console_row).collect();
    assert_eq!(rows.len(), 6);
    for row in rows {
        assert!(row.contains_key("mode"));
        assert!(row.contains_key("capabilities"));
        assert!(!row.get("degradation").unwrap_or(&String::new()).is_empty());
        assert!(row.get("mock_location").unwrap_or(&String::new()).contains("mock.rs"));
        assert!(row.get("doc_anchor").unwrap_or(&String::new()).starts_with("docs/"));
    }
}

#[test]
pub(crate) fn index_configs_detects_duplicates() {
    let config = fixture_config(AliCloudService::Cms, true);
    let indexed = index_configs(std::slice::from_ref(&config));
    assert!(indexed.is_ok());
    if let Ok(map) = &indexed {
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("alicloud-cms"));
    }
    let dup = index_configs(&[config.clone(), config]);
    assert!(matches!(dup, Err(DomainError::Conflict(_))));
}

#[test]
pub(crate) fn typed_accessors_return_matching_adapters() {
    let registry = AliCloudRegistry::mock_only();
    assert_eq!(registry.cms().name(), "alicloud-cms");
    assert_eq!(registry.apig().name(), "alicloud-apig");
    assert_eq!(registry.mse().name(), "alicloud-mse");
    assert_eq!(registry.privatelink().name(), "alicloud-privatelink");
    assert_eq!(registry.schedulerx3().name(), "alicloud-schedulerx3");
    assert_eq!(registry.agentteams().name(), "alicloud-agentteams");
    assert_eq!(registry.get("nope").map(|a| a.name().to_string()), None);
    assert_eq!(registry.get_service(AliCloudService::Mse).name(), "alicloud-mse");
}

#[tokio::test]
pub(crate) async fn registry_shares_tenant_with_adapters() {
    let configs: Vec<AdapterConfig> = AliCloudService::all().iter().map(|s| fixture_config(*s, true)).collect();
    let registry = AliCloudRegistry::from_configs(&configs).await;
    assert!(registry.is_ok());
    if let Ok(registry) = registry {
        assert_eq!(registry.tenant_id(), TenantId::default_tenant());
        assert_eq!(registry.cms().core().tenant_id, TenantId::default_tenant());
    }
}

#[tokio::test]
pub(crate) async fn mock_only_smoke_sync_works_through_registry() {
    let registry = AliCloudRegistry::mock_only();
    let outcome = registry
        .agentteams()
        .sync(agf_core::adapter::SyncDirection::Pull, &agf_core::adapter::PullRequest::default())
        .await;
    assert!(outcome.is_ok(), "{outcome:?}");
    if let Ok(outcome) = outcome {
        assert!(outcome.mocked);
        assert_eq!(outcome.changes.get("team").copied(), Some(3));
    }
}

#[test]
pub(crate) fn default_registry_is_mock_only() {
    let registry = AliCloudRegistry::default();
    assert!(registry.records().iter().all(|record| record.mode == AdapterMode::Mocked));
    assert!(!registry.names().is_empty());
}
