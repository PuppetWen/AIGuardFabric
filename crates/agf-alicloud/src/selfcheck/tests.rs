//! 由 `selfcheck.rs` 拆分：`core` 等 19 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn core(service: AliCloudService, mode: AdapterMode) -> AdapterCore {
    let mut core = AdapterCore::new(service);
    core.mode = mode;
    if mode == AdapterMode::Mocked {
        core.unconfigured_reason = None;
    }
    core
}

pub(crate) fn live_core(service: AliCloudService) -> AdapterCore {
    let mut core = AdapterCore::new(service);
    core.mode = AdapterMode::Live;
    core.region = "cn-hangzhou".to_string();
    core.endpoint = Some(
        crate::endpoint::resolve(service, "cn-hangzhou", crate::endpoint::EndpointStyle::Public, &BTreeMap::new())
            .unwrap_or_else(|_| crate::endpoint::ResolvedEndpoint {
                service,
                region: "cn-hangzhou".to_string(),
                host: "example.aliyuncs.com".to_string(),
                scheme: "https",
                style: crate::endpoint::EndpointStyle::Public,
                origin: "public",
            }),
    );
    core.set_credential(Some(crate::credential::CloudCredential::long_term("ak", "sk")));
    core
}

#[test]
pub(crate) fn required_permissions_cover_spec_examples() {
    assert!(required_permissions(AliCloudService::Cms).contains(&"cms:DescribeAlertHistoryList"));
    assert!(required_permissions(AliCloudService::Apig).contains(&"apig:ListGateways"));
    assert!(required_permissions(AliCloudService::Mse).contains(&"mse:ListClusters"));
    assert!(required_permissions(AliCloudService::Privatelink).contains(&"privatelink:ListVpcEndpoints"));
    assert!(required_permissions(AliCloudService::SchedulerX3).contains(&"schedulerx3:ListJobs"));
    assert!(required_permissions(AliCloudService::AgentTeams).is_empty());
    for service in AliCloudService::all().into_iter().filter(|s| *s != AliCloudService::AgentTeams) {
        assert!(!required_permissions(service).is_empty(), "{} 必须有必需权限", service.as_str());
        assert!(!optional_permissions(service).is_empty());
        for action in required_permissions(service) {
            assert!(action.contains(':'), "Action 必须是 service:Operation 形式: {action}");
        }
    }
}

#[test]
pub(crate) fn mock_mode_marks_checks_as_not_really_verified() {
    let checks = service_checks(AliCloudService::Cms, &core(AliCloudService::Cms, AdapterMode::Mocked), None);
    assert!(!checks.is_empty());
    for check in checks.iter().filter(|c| c.required) {
        assert!(!check.passed, "Mock 不应显示真实权限通过");
        assert!(check.note.contains("Mock 模式：未真实校验"), "必须明确未真实校验: {}", check.note);
        assert!(check.is_blocking());
    }
}

#[test]
pub(crate) fn unconfigured_mode_blocks_required_checks() {
    let checks = service_checks(AliCloudService::Mse, &core(AliCloudService::Mse, AdapterMode::Unconfigured), None);
    let blocking: Vec<&PermissionCheck> = checks.iter().filter(|c| c.is_blocking()).collect();
    assert!(!blocking.is_empty(), "未配置时必需权限应标红");
    assert!(blocking.iter().all(|c| c.note.contains("未配置")));
}

#[test]
pub(crate) fn live_mode_requires_credential_to_pass() {
    let with_cred = service_checks(AliCloudService::Cms, &live_core(AliCloudService::Cms), None);
    assert!(with_cred.iter().filter(|c| c.required).all(|c| !c.passed));

    let mut no_cred = live_core(AliCloudService::Cms);
    no_cred.set_credential(None);
    let checks = service_checks(AliCloudService::Cms, &no_cred, None);
    assert!(checks.iter().any(PermissionCheck::is_blocking), "Live 但无凭据必须阻断");
}

#[test]
pub(crate) fn connectivity_conclusions_per_mode() {
    let (ok, message, _) = connectivity_of(&core(AliCloudService::Cms, AdapterMode::Unconfigured));
    assert!(!ok);
    assert!(message.contains("降级"));

    let (ok, message, latency) = connectivity_of(&core(AliCloudService::Cms, AdapterMode::Mocked));
    assert!(!ok);
    assert!(message.contains("Mock"));
    assert_eq!(latency, None);

    let (ok, message, _) = connectivity_of(&live_core(AliCloudService::Apig));
    assert!(!ok);
    assert!(message.contains("endpoint"));

    let mut no_cred = live_core(AliCloudService::Apig);
    no_cred.set_credential(None);
    let (ok, message, _) = connectivity_of(&no_cred);
    assert!(!ok);
    assert!(message.contains("凭据未就绪"));
}

#[test]
pub(crate) fn overall_state_matrix() {
    let mock_checks = service_checks(AliCloudService::Cms, &core(AliCloudService::Cms, AdapterMode::Mocked), None);
    let quotas = quota_headroom(AliCloudService::Cms, Timestamp::now());
    assert_eq!(overall_state(AdapterMode::Mocked, &mock_checks, &quotas), HealthState::Degraded);
    assert_eq!(overall_state(AdapterMode::Unconfigured, &mock_checks, &quotas), HealthState::Unconfigured);

    let live_checks = service_checks(AliCloudService::Cms, &live_core(AliCloudService::Cms), None);
    assert_eq!(overall_state(AdapterMode::Live, &live_checks, &quotas), HealthState::Unhealthy);

    let mut exhausted = quota_headroom(AliCloudService::SchedulerX3, Timestamp::now());
    exhausted[0].used = exhausted[0].limit;
    assert_eq!(
        overall_state(AdapterMode::Live, &live_checks, &exhausted),
        HealthState::Unhealthy,
        "配额耗尽必须判不健康"
    );
}

#[test]
pub(crate) fn quota_headroom_math_and_levels() {
    let quotas = quota_headroom(AliCloudService::SchedulerX3, Timestamp::now());
    assert_eq!(quotas.len(), 1);
    let quota = &quotas[0];
    assert_eq!(quota.remaining(), 200_000 - quota.used);
    assert!(quota.is_near_exhaustion(), "SchedulerX3 的 fixtures 应接近耗尽（用于验证告警）");
    assert_eq!(quota.severity(), Severity::High);

    let mut full = quota.clone();
    full.used = full.limit;
    assert_eq!(full.remaining(), 0);
    assert_eq!(full.severity(), Severity::Critical);

    let mut over = quota.clone();
    over.used = over.limit * 2;
    assert_eq!(over.remaining(), 0, "剩余量不得为负");
    assert_eq!(over.used_ratio(), 1.0, "占比必须截断到 1.0");

    let mut light = quota.clone();
    light.used = 1;
    light.limit = 1_000_000;
    assert_eq!(light.severity(), Severity::Info);
    assert!(!light.is_near_exhaustion());
    let zero_limit = QuotaHeadroom { limit: 0, used: 5, ..quota.clone() };
    assert_eq!(zero_limit.used_ratio(), 0.0);
}

#[test]
pub(crate) fn service_quota_definitions_cover_all_services() {
    for service in AliCloudService::all() {
        assert!(!quota_definitions(service).is_empty(), "{} 必须有配额定义", service.as_str());
    }
}

#[test]
pub(crate) fn report_blocking_failures_and_markdown() {
    let report = build_report(&core(AliCloudService::Privatelink, AdapterMode::Unconfigured), Some(Id::new()));
    assert_eq!(report.state, HealthState::Unconfigured);
    let blockers = report.blocking_failures();
    assert!(!blockers.is_empty(), "未配置时应有阻断项");
    assert!(blockers.iter().all(|b| b.contains("privatelink:")));
    let markdown = report.to_markdown();
    assert!(markdown.starts_with("# 阿里云环境自检 — alicloud-privatelink"));
    assert!(markdown.contains("## 最小权限"));
    assert!(markdown.contains("## 配额余量"));
    assert!(markdown.contains("## 阻断性问题"));
    assert!(markdown.contains("privatelink:ListVpcEndpoints"));
    assert!(markdown.contains("unconfigured"));
    assert!(report.summary().contains("未配置"));
}

#[test]
pub(crate) fn mock_report_has_no_blocking_failures_and_marks_mock() {
    let report = build_report(&core(AliCloudService::AgentTeams, AdapterMode::Mocked), None);
    assert_eq!(report.state, HealthState::Degraded);
    assert!(report.blocking_failures().is_empty(), "Mock 模式不应有阻断项");
    assert!(!report.connectivity_ok);
    let markdown = report.to_markdown();
    assert!(markdown.contains("Mock 模式：未真实校验"));
    assert_eq!(report.summary(), "降级：Mock 模式或凭据非最优（未真实校验）");
    assert!(report.integration_id.is_none());
}

#[test]
pub(crate) fn healthy_report_summary() {
    let report = build_report(&live_core(AliCloudService::Mse), None);
    assert_eq!(report.state, HealthState::Degraded);
    assert!(report.summary().contains("未真实校验"));
    assert!(report.to_markdown().contains("未真实校验"));
}

#[test]
pub(crate) fn ram_policy_json_contains_required_actions_only() {
    let report = build_report(&core(AliCloudService::Cms, AdapterMode::Mocked), None);
    let policy = report.ram_policy_json();
    assert!(policy.is_ok());
    if let Ok(policy) = policy {
        let parsed: serde_json::Value = serde_json::from_str(&policy).unwrap_or(serde_json::Value::Null);
        let actions = parsed
            .get("Statement")
            .and_then(|s| s.get(0))
            .and_then(|s| s.get("Action"))
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let names: Vec<&str> = actions.iter().filter_map(serde_json::Value::as_str).collect();
        assert!(names.contains(&"cms:DescribeAlertHistoryList"));
        assert!(!names.contains(&"cms:ListAlarmHistories"), "可选权限不应进入策略");
        assert!(policy.contains("\"Version\""));
    }
}

#[test]
pub(crate) fn suite_aggregates_worst_state_and_failures() {
    let suite = CloudSelfCheckSuite {
        reports: vec![
            build_report(&core(AliCloudService::Cms, AdapterMode::Mocked), None),
            build_report(&core(AliCloudService::Mse, AdapterMode::Unconfigured), None),
        ],
    };
    // 只要有一个服务处于 Mock（Degraded），总览就不能报 Healthy/Unconfigured
    assert_eq!(suite.overall(), HealthState::Degraded, "Mock 服务使总览降级");
    let blockers = suite.blocking_failures();
    assert!(blockers.iter().any(|b| b.starts_with("[alicloud-mse]")));
    assert!(!blockers.iter().any(|b| b.starts_with("[alicloud-cms]")), "Mock 模式不产生阻断项");
    let markdown = suite.to_markdown();
    assert!(markdown.contains("云环境自检总览"));
    assert!(markdown.contains("alicloud-cms"));
    let policy = suite.ram_policy_json();
    assert!(policy.is_ok_and(|p| p.contains("mse:ListClusters")));
}

#[test]
pub(crate) fn suite_with_only_unconfigured_services_reports_unconfigured() {
    let suite = CloudSelfCheckSuite {
        reports: vec![
            build_report(&core(AliCloudService::Cms, AdapterMode::Unconfigured), None),
            build_report(&core(AliCloudService::Mse, AdapterMode::Unconfigured), None),
        ],
    };
    assert_eq!(suite.overall(), HealthState::Unconfigured);
    let blockers = suite.blocking_failures();
    let mse_blockers = blockers.iter().filter(|blocker| blocker.starts_with("[alicloud-mse]")).count();
    let cms_blockers = blockers.iter().filter(|blocker| blocker.starts_with("[alicloud-cms]")).count();
    assert_eq!(mse_blockers, required_permissions(AliCloudService::Mse).len());
    assert_eq!(cms_blockers, required_permissions(AliCloudService::Cms).len());
    assert!(blockers.iter().all(|blocker| blocker.contains("未配置")));
}

#[test]
pub(crate) fn suite_overall_prefers_unhealthy_then_unconfigured() {
    let unhealthy =
        CloudSelfCheckSuite { reports: vec![build_report(&core(AliCloudService::Cms, AdapterMode::Live), None)] };
    // Live 但无凭据 → Unhealthy
    assert_eq!(unhealthy.overall(), HealthState::Unhealthy);
    let empty = CloudSelfCheckSuite { reports: Vec::new() };
    assert_eq!(empty.overall(), HealthState::Unconfigured);
    let all_unconfigured = CloudSelfCheckSuite {
        reports: vec![
            build_report(&core(AliCloudService::Cms, AdapterMode::Unconfigured), None),
            build_report(&core(AliCloudService::Mse, AdapterMode::Unconfigured), None),
        ],
    };
    assert_eq!(all_unconfigured.overall(), HealthState::Unconfigured);
    assert!(all_unconfigured.quota_warnings().is_empty(), "未配置时配额无告警");
}

#[test]
pub(crate) fn quota_warnings_surface_near_exhaustion() {
    let suite = CloudSelfCheckSuite { reports: vec![build_report(&live_core(AliCloudService::SchedulerX3), None)] };
    let warnings = suite.quota_warnings();
    assert!(warnings.is_empty(), "没有实际云配额时不得显示演示值");
}

#[test]
pub(crate) fn summarize_checks_mentions_actions_and_mode() {
    let checks = service_checks(AliCloudService::Apig, &core(AliCloudService::Apig, AdapterMode::Mocked), None);
    let summary = summarize_checks(&checks, AdapterMode::Mocked);
    assert!(summary.contains("apig:ListGateways"));
    assert!(summary.contains("Mock 模式"));
    let live = summarize_checks(&checks, AdapterMode::Live);
    assert!(!live.contains("Mock 模式"));
}
