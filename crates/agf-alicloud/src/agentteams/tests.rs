//! 由 `agentteams.rs` 拆分：`member` 等 21 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn member(name: &str, models: &[&str], tools: &[&str], managed: bool) -> AgentTeamMember {
    AgentTeamMember {
        cloud_agent_id: format!("agent-{name}"),
        name: name.to_string(),
        models: models.iter().map(ToString::to_string).collect(),
        tools: tools.iter().map(ToString::to_string).collect(),
        role_names: Vec::new(),
        asset_id: managed.then(Id::new),
        status: "running".to_string(),
    }
}

#[tokio::test]
pub(crate) async fn health_states() {
    let adapter = AgentTeamsAdapter::new();
    assert!(adapter.health().await.is_ok_and(|h| h.state == HealthState::Unconfigured));
    let mut mocked = AgentTeamsAdapter::mocked();
    assert!(mocked.init(&fixture_config(AliCloudService::AgentTeams, true)).await.is_ok());
    let health = mocked.health().await;
    assert!(health.is_ok());
    if let Ok(health) = health {
        assert_eq!(health.state, HealthState::Degraded);
        assert!(health.mocked);
        assert!(health.message.unwrap_or_default().contains("AGF_MOCK_MODE"));
    }
}

#[tokio::test]
pub(crate) async fn pull_teams_returns_full_definitions() {
    let mut adapter = AgentTeamsAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::AgentTeams, true)).await.is_ok());
    let teams = adapter.pull_teams().await;
    assert!(teams.is_ok());
    if let Ok(teams) = teams {
        assert_eq!(teams.len(), 3);
        let risk = teams.iter().find(|team| team.cloud_team_id == "team-risk");
        assert!(risk.is_some());
        if let Some(team) = risk {
            assert_eq!(team.name, "风险分析团队");
            assert_eq!(team.agents.len(), 2);
            assert_eq!(team.roles.len(), 2, "Role 定义必须拉取");
            assert_eq!(team.orchestration.len(), 2, "任务编排定义必须拉取");
            assert!(team.orchestration.iter().any(OrchestrationNode::is_scheduled));
            assert_eq!(team.onboarding, OnboardingMode::Sidecar);
        }
    }
    assert_eq!(adapter.transport.call_count().ok(), Some(0));
}

#[tokio::test]
pub(crate) async fn managed_ratio_computation() {
    let teams = mock::agentteams_teams();
    let (managed, total, ratio) = managed_summary(&teams);
    assert_eq!(total, 6);
    assert_eq!(managed, 3, "2 + 1 + 0 个已纳管 Agent");
    assert!((ratio - 0.5).abs() < 1e-6, "整体纳管率应为 0.5，实际 {ratio}");
    assert!((teams[0].managed_ratio() - 1.0).abs() < 1e-6);
    assert!((teams[1].managed_ratio() - 0.5).abs() < 1e-6);
    assert_eq!(teams[2].managed_ratio(), 0.0);
}

#[tokio::test]
pub(crate) async fn onboarding_selection_matrix() {
    let adapter = AgentTeamsAdapter::mocked();
    assert_eq!(
        adapter.select_onboarding(&member("a", &["qwen-max"], &[], true)).ok(),
        Some(OnboardingMode::Sidecar),
        "已纳管保持侧车"
    );
    assert_eq!(
        adapter.select_onboarding(&member("a", &["qwen-max"], &[], false)).ok(),
        Some(OnboardingMode::GatewayRegistration),
        "只调模型走网关注册"
    );
    assert_eq!(
        adapter.select_onboarding(&member("a", &[], &["mcp:file-read"], false)).ok(),
        Some(OnboardingMode::Sidecar),
        "MCP 工具走侧车"
    );
    assert_eq!(
        adapter.select_onboarding(&member("a", &[], &["internal-tool"], false)).ok(),
        Some(OnboardingMode::SdkInjection),
        "自研工具走 SDK 注入"
    );
    assert_eq!(
        adapter.select_onboarding(&member("a", &[], &[], false)).ok(),
        Some(OnboardingMode::ObserveOnly),
        "无工具无模型只能旁路观测"
    );
    assert_eq!(select_onboarding_mode(&member("a", &[], &["internal-tool"], false)), OnboardingMode::SdkInjection);
}

#[tokio::test]
pub(crate) async fn unmanaged_member_listing() {
    let teams = mock::agentteams_teams();
    let unmanaged = unmanaged_members(&teams);
    assert_eq!(unmanaged.len(), 3, "3 个未纳管 Agent");
    assert!(unmanaged.iter().any(|(team, _, _)| team == "team-ops"));
    assert!(unmanaged.iter().all(|(team, agent, _)| !team.is_empty() && !agent.is_empty()));
}

#[tokio::test]
pub(crate) async fn member_asset_id_is_deterministic() {
    let teams = mock::agentteams_teams();
    let team = &teams[0];
    let agent = &team.agents[0];
    let first = member_asset_id(&team.cloud_team_id, agent);
    let second = member_asset_id(&team.cloud_team_id, agent);
    assert_eq!(first, second, "同一成员必须产出同一资产 id（可重复纳管去重）");
    assert!(member_fingerprint(&team.cloud_team_id, agent).starts_with("agentteams://team-risk/"));
}

#[tokio::test]
pub(crate) async fn ide_agent_detection() {
    assert!(looks_like_ide_agent(&member("Cursor Agent", &[], &[], false)));
    assert!(looks_like_ide_agent(&member("claude-code", &[], &[], false)));
    assert!(!looks_like_ide_agent(&member("内部研报助手", &[], &[], false)));
}

#[tokio::test]
pub(crate) async fn cross_team_calls_and_time_filter() {
    let mut adapter = AgentTeamsAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::AgentTeams, true)).await.is_ok());
    let calls = adapter.pull_cross_team_calls(None).await;
    assert!(calls.is_ok());
    if let Ok(calls) = calls {
        assert_eq!(calls.len(), 3);
        assert!(calls.iter().any(|call| call.blocked), "必须能看出被策略阻断的调用");
        assert!(calls.iter().any(|call| call.cross_account), "必须能看出跨账号调用");
        assert!(calls.iter().all(|call| !call.from_team_id.is_empty() && !call.to_team_id.is_empty()));
    }
    let since = Timestamp::now().offset_secs(-100);
    let recent = adapter.pull_cross_team_calls(Some(since)).await;
    assert!(recent.is_ok_and(|calls| calls.len() == 2), "时间过滤应生效（-120s 一条被排除）");
}

#[tokio::test]
pub(crate) async fn quota_sync_prefers_platform_and_alerts_once() {
    let mut adapter = AgentTeamsAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::AgentTeams, true)).await.is_ok());
    let integration_id = Id::new();
    let platform = AgentTeamsAdapter::platform_quota_defaults();

    let first = adapter.sync_quotas(integration_id, &platform).await;
    assert!(first.is_ok(), "{first:?}");
    if let Ok(report) = first {
        assert!(report.has_conflict(), "fixtures 必须触发冲突告警");
        assert_eq!(report.conflict_count(), 2, "Tokens 与 Concurrency 冲突");
        assert_eq!(report.effective.get("tokens").copied(), Some(1_000_000), "以平台为准");
        assert_eq!(report.effective.get("concurrency").copied(), Some(32));
        assert_eq!(report.effective.get("requests").copied(), Some(50_000));
        assert!(report.conflict_alerts.iter().any(|alert| alert.contains("平台为准")));
    }

    let second = adapter.sync_quotas(integration_id, &platform).await;
    assert!(second.is_ok());
    if let Ok(report) = second {
        assert!(!report.has_conflict(), "同一冲突不应重复告警: {report:?}");
        assert_eq!(report.conflict_count(), 2, "冲突状态仍为 true");
    }
    assert_eq!(adapter.transport.call_count().ok(), Some(0));
}

#[tokio::test]
pub(crate) async fn quota_sync_validates_input() {
    let adapter = AgentTeamsAdapter::mocked();
    let empty = adapter.sync_quotas(Id::new(), &[]).await;
    assert!(matches!(empty, Err(DomainError::Validation(_))));
}

#[tokio::test]
pub(crate) async fn sync_teams_merges_with_platform_priority() {
    let adapter = AgentTeamsAdapter::mocked();
    // 平台侧已有 team-risk 但 Agent 更少（内容与远端不同）→ 冲突：平台为准并告警；
    // 另外两个团队内容一致 → 计数为 skipped（用内容签名判定，不受时间戳精度干扰）
    let mut local = mock::agentteams_teams();
    if let Some(team) = local.first_mut() {
        team.cloud_updated_at = Some(Timestamp::now().offset_secs(-1));
        team.agents.truncate(1);
    }
    let report = adapter.sync_teams(&local, SyncDirection::Both).await;
    assert!(report.is_ok(), "{report:?}");
    if let Ok(report) = report {
        assert_eq!(report.pulled, 3);
        assert_eq!(report.total_agents, 6);
        assert_eq!(report.managed_agents, 3);
        assert!((report.managed_ratio() - 0.5).abs() < 1e-6);
        assert_eq!(report.conflicts, 1, "只有一个团队内容不一致: {report:?}");
        assert_eq!(report.skipped, 2, "内容一致的两个团队必须判为无变化");
        assert!(report.warnings.iter().any(|warning| warning.contains("平台为准")));
        assert_eq!(report.updated + report.created + report.skipped, 3);
    }
}

#[tokio::test]
pub(crate) async fn team_content_signature_detects_real_changes() {
    let teams = mock::agentteams_teams();
    let base = &teams[0];
    assert_eq!(team_content_signature(base), team_content_signature(&teams[0]));
    let mut changed = base.clone();
    changed.agents.truncate(1);
    assert_ne!(team_content_signature(base), team_content_signature(&changed));
    let mut renamed = base.clone();
    renamed.name = "改名了".to_string();
    assert_ne!(team_content_signature(base), team_content_signature(&renamed));
}

#[tokio::test]
pub(crate) async fn pull_only_sync_does_not_report_conflicts() {
    let adapter = AgentTeamsAdapter::mocked();
    let local = mock::agentteams_teams();
    let report = adapter.sync_teams(&local, SyncDirection::Pull).await;
    assert!(report.is_ok());
    if let Ok(report) = report {
        assert_eq!(report.conflicts, 0, "仅拉取方向不做冲突判定");
        assert_eq!(report.pulled, 3);
    }
}

#[tokio::test]
pub(crate) async fn role_mapping_uses_declared_then_infers() {
    let roles = vec![
        AgentTeamRole {
            name: "分析员".to_string(),
            description: String::new(),
            allowed_tools: vec!["mcp:file-read".to_string()],
            mapped_platform_role: Some("analyst".to_string()),
        },
        AgentTeamRole {
            name: "运维".to_string(),
            description: String::new(),
            allowed_tools: vec!["mcp:shell-exec".to_string()],
            mapped_platform_role: None,
        },
        AgentTeamRole {
            name: "只读".to_string(),
            description: String::new(),
            allowed_tools: vec!["mcp:web-search".to_string()],
            mapped_platform_role: None,
        },
        AgentTeamRole {
            name: "审计".to_string(),
            description: String::new(),
            allowed_tools: Vec::new(),
            mapped_platform_role: None,
        },
    ];
    let mapped = map_roles_to_platform(&roles);
    assert_eq!(mapped.len(), 4);
    assert_eq!(mapped[0], ("分析员".to_string(), "analyst".to_string()), "显式声明的优先");
    assert_eq!(mapped[1].1, "operator", "含执行类工具 → operator");
    assert_eq!(mapped[2].1, "viewer");
    assert_eq!(mapped[3].1, "auditor");
}

#[tokio::test]
pub(crate) async fn audit_events_are_ingest_ready() {
    let mut adapter = AgentTeamsAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::AgentTeams, true)).await.is_ok());
    let events = adapter.pull_audit_events(None).await;
    assert!(events.is_ok());
    if let Ok(events) = events {
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|event| event.get("event_id").is_some() && event.get("at").is_some()));
        assert!(
            events
                .iter()
                .any(|event| { event.get("verdict").and_then(serde_json::Value::as_str) == Some("malicious") })
        );
    }
    let limited = adapter.pull_audit_events(Some(2)).await;
    assert_eq!(limited.map(|events| events.len()).ok(), Some(2));
}

#[tokio::test]
pub(crate) async fn mock_sync_reports_all_change_kinds() {
    let mut adapter = AgentTeamsAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::AgentTeams, true)).await.is_ok());
    let outcome = adapter.sync(SyncDirection::Both, &PullRequest::default()).await;
    assert!(outcome.is_ok(), "{outcome:?}");
    if let Ok(outcome) = outcome {
        assert!(outcome.mocked && outcome.degraded);
        assert_eq!(outcome.changes.get("team").copied(), Some(3));
        assert_eq!(outcome.changes.get("agent").copied(), Some(6));
        assert_eq!(outcome.changes.get("managed_agent").copied(), Some(3));
        assert_eq!(outcome.changes.get("cross_team_call").copied(), Some(3));
        assert_eq!(outcome.changes.get("cross_team_blocked").copied(), Some(1));
        assert_eq!(outcome.changes.get("cross_team_cross_account").copied(), Some(1));
        assert_eq!(outcome.changes.get("audit_event").copied(), Some(3));
        assert_eq!(outcome.changes.get("quota_conflict").copied(), Some(2));
        assert_eq!(outcome.changes.get("quota_synced").copied(), Some(4));
        // fixtures 的 3 个未纳管 Agent：2 个带 MCP 工具 → 侧车；1 个只调模型 → 网关注册
        assert_eq!(
            outcome.changes.get("onboarding:sidecar").copied(),
            Some(2),
            "带 MCP 工具的未纳管 Agent 走侧车: {outcome:?}"
        );
        assert_eq!(outcome.changes.get("onboarding:gateway-registration").copied(), Some(1));
        assert!(outcome.warnings.iter().any(|warning| warning.contains("平台为准")));
    }
    assert_eq!(adapter.transport.call_count().ok(), Some(0), "Mock 必须零网络");
}

#[tokio::test]
pub(crate) async fn onboarding_flow_covers_all_four_modes() {
    // 侧车 / SDK 注入 / 网关注册 / 旁路观测四种模式在纳管流程中都可被选中
    let teams = mock::agentteams_teams();
    let mut modes: Vec<OnboardingMode> = Vec::new();
    for team in &teams {
        for agent in &team.agents {
            if agent.asset_id.is_none() {
                modes.push(select_onboarding_mode(agent));
            }
        }
    }
    assert!(modes.contains(&OnboardingMode::Sidecar));
    assert!(modes.contains(&OnboardingMode::GatewayRegistration));
    assert_eq!(modes.len(), 3);
    // SDK 注入与旁路观测由纯函数矩阵覆盖（见 onboarding_selection_matrix）
    let custom = member("自研", &[], &["internal-tool"], false);
    assert_eq!(select_onboarding_mode(&custom), OnboardingMode::SdkInjection);
    let bare = member("空壳", &[], &[], false);
    assert_eq!(select_onboarding_mode(&bare), OnboardingMode::ObserveOnly);
}

#[tokio::test]
pub(crate) async fn pull_resource_routing() {
    let mut adapter = AgentTeamsAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::AgentTeams, true)).await.is_ok());
    for (resource, expected) in [("teams", 3), ("cross-team-calls", 3), ("audit-events", 3)] {
        let response = adapter.pull(&PullRequest { resource: resource.to_string(), ..PullRequest::default() }).await;
        assert!(response.is_ok(), "{resource}: {response:?}");
        if let Ok(response) = response {
            assert_eq!(response.items.len(), expected, "{resource}");
            assert!(response.origin.contains("mock.rs"));
        }
    }
    let unknown = PullRequest { resource: "jobs".to_string(), ..PullRequest::default() };
    assert!(matches!(adapter.pull(&unknown).await, Err(DomainError::Validation(_))));
}

#[tokio::test]
pub(crate) async fn push_quota_and_role_mapping() {
    let mut adapter = AgentTeamsAdapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::AgentTeams, true)).await.is_ok());
    let quota = PushPayload {
        entity: "quota".to_string(),
        entity_id: "tokens".to_string(),
        body: serde_json::json!({ "dimension": "tokens", "value": 2_000_000 }),
        idempotency_key: Some("q1".to_string()),
    };
    assert!(adapter.push(&quota).await.is_ok());
    let roles = PushPayload {
        entity: "role-mapping".to_string(),
        entity_id: "roles".to_string(),
        body: serde_json::json!([{ "name": "分析员", "allowed_tools": [] }]),
        idempotency_key: None,
    };
    assert!(adapter.push(&roles).await.is_ok());
    let bad = PushPayload {
        entity: "event".to_string(),
        entity_id: "e".to_string(),
        body: serde_json::json!({}),
        idempotency_key: None,
    };
    assert!(matches!(adapter.push(&bad).await, Err(DomainError::Validation(_))));
}

#[tokio::test]
pub(crate) async fn parsers_handle_aliyun_shapes() {
    let teams = parse_teams(
        &serde_json::json!({
            "Teams": { "Team": [ {
                "TeamId": "t-1", "Name": "风险分析", "Description": "d",
                "Agents": [ { "AgentId": "a-1", "Name": "分析员", "Models": ["qwen-max"], "Tools": ["mcp:file-read"], "Roles": ["分析员"], "Status": "running" } ],
                "Roles": [ { "Name": "分析员", "AllowedTools": ["mcp:file-read"], "MappedPlatformRole": "analyst" } ],
                "Orchestration": [ { "NodeId": "n1", "Name": "采集", "AgentIds": ["a-1"], "DependsOn": [], "Trigger": "cron", "Cron": "0 2 * * *" } ],
                "UpdatedAt": 1_700_000_000_000_i64
            } ] }
        }),
        TenantId::default_tenant(),
    );
    assert_eq!(teams.len(), 1);
    assert_eq!(teams[0].cloud_team_id, "t-1");
    assert_eq!(teams[0].agents.len(), 1);
    assert_eq!(teams[0].roles.len(), 1);
    assert_eq!(teams[0].orchestration.len(), 1);
    assert!(teams[0].orchestration[0].is_scheduled());
    assert!(teams[0].cloud_updated_at.is_some());

    let calls = parse_cross_team_calls(
        &serde_json::json!({
            "Calls": { "Call": [ { "FromTeamId": "t-1", "FromAgentId": "a-1", "ToTeamId": "t-2", "ToAgentId": "a-2", "CallKind": "mcp", "CrossAccount": true, "Blocked": true, "LatencyMs": "250", "Timestamp": 1_700_000_000_000_i64 } ] }
        }),
        TenantId::default_tenant(),
    );
    assert_eq!(calls.len(), 1);
    assert!(calls[0].blocked && calls[0].cross_account);
    assert_eq!(calls[0].latency_ms, 250);
}
