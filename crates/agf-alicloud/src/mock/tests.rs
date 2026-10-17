//! 由 `mock.rs` 拆分：`cloud_integration_fixture_is_deterministic` 等 18 个函数（纯搬移，逻辑不变）。
use super::*;

#[test]
pub(crate) fn cloud_integration_fixture_is_deterministic() {
    let a = fixture_cloud_integration();
    let b = fixture_cloud_integration();
    assert_eq!(a.id, b.id, "fixture 集成 id 必须稳定");
    assert_eq!(a.account_id, FIXTURE_ACCOUNT_ID);
    assert_eq!(a.region_id, FIXTURE_REGION);
}

#[test]
pub(crate) fn every_service_has_capabilities_degradation_and_mock_location() {
    for service in AliCloudService::all() {
        let descriptor = descriptor_of(service);
        assert_eq!(descriptor.name, service.as_str());
        assert_eq!(descriptor.category, "alicloud");
        assert!(!descriptor.capabilities.is_empty(), "{} 必须有能力声明", service.as_str());
        assert!(descriptor.capabilities.contains(&AdapterCapability::SelfCheck));
        assert_eq!(descriptor.required_secrets.len(), 2);
        assert!(!descriptor.degradation.trim().is_empty(), "{} 必须写明降级行为", service.as_str());
        assert!(descriptor.mock_location.starts_with("crates/agf-alicloud/src/mock.rs#"));
        assert!(descriptor.real_implementation);
        assert!(descriptor.doc_anchor.contains("adapter-spec.md"));
    }
}

#[test]
pub(crate) fn degradation_texts_are_distinct_per_service() {
    let mut texts: Vec<&str> = AliCloudService::all().iter().map(|s| degradation_of(*s)).collect();
    texts.sort_unstable();
    texts.dedup();
    assert_eq!(texts.len(), 6, "每个服务的降级说明必须各自独立");
}

#[test]
pub(crate) fn mock_locations_are_unique() {
    let mut locations: Vec<String> = AliCloudService::all().iter().map(|s| mock_location(*s)).collect();
    locations.sort();
    locations.dedup();
    assert_eq!(locations.len(), 6);
    assert!(mock_location(AliCloudService::AgentTeams).ends_with("#mock_agentteams"));
    assert_eq!(mock_constructor_name(AliCloudService::SchedulerX3), "mock_schedulerx3");
}

#[test]
pub(crate) fn capabilities_match_spec_table() {
    assert!(capabilities_of(AliCloudService::Cms).contains(&AdapterCapability::PushMetrics));
    assert!(capabilities_of(AliCloudService::Apig).contains(&AdapterCapability::EnforcePolicy));
    assert!(capabilities_of(AliCloudService::Apig).contains(&AdapterCapability::QueryLogs));
    assert!(!capabilities_of(AliCloudService::Apig).contains(&AdapterCapability::SubscribeEvents));
    assert!(capabilities_of(AliCloudService::Mse).contains(&AdapterCapability::PullInventory));
    assert!(capabilities_of(AliCloudService::Privatelink).contains(&AdapterCapability::ProbePrivateLink));
    assert!(capabilities_of(AliCloudService::SchedulerX3).contains(&AdapterCapability::ScheduleTask));
    assert!(capabilities_of(AliCloudService::AgentTeams).contains(&AdapterCapability::SubscribeEvents));
}

#[test]
pub(crate) fn core_mode_transitions_and_shutdown() {
    let mut core = AdapterCore::new(AliCloudService::Cms);
    assert_eq!(core.mode(), AdapterMode::Unconfigured);
    assert_eq!(core.health_of().state, HealthState::Unconfigured);
    core.mode = AdapterMode::Mocked;
    assert!(core.is_mock());
    assert!(core.health_of().message.unwrap_or_default().contains("AGF_MOCK_MODE"));
    core.shutdown_common();
    assert_eq!(core.mode(), AdapterMode::Unconfigured);
    assert!(core.credential.is_none());
}

#[test]
pub(crate) fn fixtures_cover_all_three_onboarding_modes() {
    let teams = agentteams_teams();
    assert_eq!(teams.len(), 3);
    let modes: Vec<OnboardingMode> = teams.iter().map(|t| t.onboarding).collect();
    assert!(modes.contains(&OnboardingMode::Sidecar));
    assert!(modes.contains(&OnboardingMode::SdkInjection));
    assert!(modes.contains(&OnboardingMode::ObserveOnly));
    assert!((teams[0].managed_ratio() - 1.0).abs() < 1e-6);
    assert!((teams[1].managed_ratio() - 0.5).abs() < 1e-6);
    assert_eq!(teams[2].managed_ratio(), 0.0);
}

#[test]
pub(crate) fn fixtures_are_stable_across_calls() {
    let a = agentteams_teams();
    let b = agentteams_teams();
    assert_eq!(a[0].id, b[0].id);
    assert_eq!(a[0].agents[0].asset_id, b[0].agents[0].asset_id);
    let alarms = cms_alarm_histories(&PullRequest::default());
    assert_eq!(alarms.len(), 3);
    assert_eq!(alarms[0].alarm_id, "alarm-mock-001");
}

#[test]
pub(crate) fn alarm_fixture_respects_limit() {
    let req = PullRequest { limit: Some(1), ..PullRequest::default() };
    assert_eq!(cms_alarm_histories(&req).len(), 1);
}

#[test]
pub(crate) fn scheduler_fixture_has_six_platform_jobs() {
    assert_eq!(schedulerx3_jobs(TenantId::default_tenant()).len(), 6);
}

#[test]
pub(crate) fn security_group_fixture_contains_wide_open_entry() {
    let groups = privatelink_security_groups();
    assert!(groups.values().any(|rules| rules.iter().any(|r| r == "0.0.0.0/0")));
    assert!(groups.values().any(|rules| rules == &vec!["10.20.30.0/24".to_string()]));
}

#[test]
pub(crate) fn cross_call_fixture_includes_blocked_and_cross_account() {
    let calls = agentteams_cross_calls();
    assert_eq!(calls.len(), 3);
    assert!(calls.iter().any(|c| c.blocked));
    assert!(calls.iter().any(|c| c.cross_account));
}

#[test]
pub(crate) fn audit_event_fixture_marks_verdicts() {
    let events = agentteams_audit_events();
    assert_eq!(events.len(), 3);
    assert!(events.iter().any(|e| e.get("verdict").and_then(serde_json::Value::as_str) == Some("malicious")));
}

#[tokio::test]
pub(crate) async fn smoke_test_all_returns_six_degraded_services() {
    let result = smoke_test_all().await;
    assert!(result.is_ok(), "{result:?}");
    if let Ok(rows) = result {
        assert_eq!(rows.len(), 6);
        for (service, pulled, state) in rows {
            assert!(pulled > 0, "{} 的 Mock 拉取必须有数据", service.as_str());
            assert_eq!(state, HealthState::Degraded, "{} 在 Mock 下应为 Degraded", service.as_str());
        }
    }
}

#[test]
pub(crate) fn null_transport_never_records_calls() {
    assert_eq!(null_transport().call_count().ok(), Some(0));
}

#[test]
pub(crate) fn quota_fixture_has_conflict_dimensions() {
    let fixture = agentteams_quota_fixture();
    assert_eq!(fixture.len(), 4);
    assert!(fixture.iter().any(|(_, platform, cloud)| platform != cloud), "必须含冲突维度");
    assert!(fixture.iter().any(|(_, platform, cloud)| platform == cloud), "必须含一致维度");
}

#[test]
pub(crate) fn log_init_covers_all_modes_without_panic() {
    for mode in [AdapterMode::Mocked, AdapterMode::Unconfigured, AdapterMode::Live] {
        log_init(AliCloudService::Cms, mode);
    }
}

#[test]
pub(crate) fn error_helpers_are_dependency_unavailable() {
    assert!(matches!(unavailable(AliCloudService::Cms, "x"), DomainError::DependencyUnavailable { .. }));
    let err = mock_blocked(AliCloudService::Mse);
    assert!(err.to_string().contains("AGF_MOCK_MODE"));
    assert!(err.is_degradable());
}
