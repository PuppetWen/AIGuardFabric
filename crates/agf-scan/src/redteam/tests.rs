//! 由 `redteam.rs` 拆分：`case` 等 17 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn case(
    key: &str,
    category: AttackCategory,
    signals: &[&str],
    tools: &[&str],
    mode: ExecutionMode,
) -> RedteamCase {
    RedteamCase {
        key: key.to_string(),
        title: format!("用例 {key}"),
        category,
        severity: Severity::High,
        mode,
        turns: vec![AttackTurn { role: "user".into(), content: format!("payload for {key}"), expect: vec![] }],
        applies_to: vec![],
        success_signals: signals.iter().map(|s| (*s).to_string()).collect(),
        required_tools: tools.iter().map(|s| (*s).to_string()).collect(),
        tags: vec!["LLM01".into()],
        references: vec![],
        public_poc: false,
        remediation: format!("修复 {key}"),
        author: "test".into(),
        version: 1,
    }
}

pub(crate) fn library() -> CaseLibrary {
    CaseLibrary::from_cases(vec![
        case("RT-JB-001", AttackCategory::Jailbreak, &["marker_echo"], &[], ExecutionMode::SingleTurn),
        case(
            "RT-TA-001",
            AttackCategory::ToolAbuse,
            &["unauthorized_tool_call"],
            &["execute_shell"],
            ExecutionMode::ToolSequence,
        ),
        case(
            "RT-DE-001",
            AttackCategory::DataExfiltration,
            &["data_exfil_url_requested"],
            &["read_file", "http_request"],
            ExecutionMode::ToolSequence,
        ),
    ])
}

#[test]
pub(crate) fn library_stats_and_selection() {
    let lib = library();
    assert_eq!(lib.stats().total, 3);
    assert_eq!(lib.stats().count_category(AttackCategory::Jailbreak), 1);
    assert!(lib.stats().is_healthy());
    assert!(!lib.stats().meets_target(200), "3 条不满足 200+ 目标");
    assert_eq!(lib.by_category(AttackCategory::ToolAbuse).len(), 1);
    assert_eq!(lib.by_keys(&["RT-JB-001".to_string()]).len(), 1);
    assert_eq!(lib.by_tags(&["LLM01".to_string()]).len(), 3);
    assert_eq!(lib.by_tags(&["NOPE".to_string()]).len(), 0);
}

#[test]
pub(crate) fn select_filters_by_capability() {
    let mut lib = library();
    // 显式定位到目标用例，避免依赖排序细节
    let idx = lib.cases.iter().position(|c| c.key == "RT-JB-001").unwrap_or_else(|| unreachable!());
    lib.cases[idx].applies_to = vec!["prompt".into()];
    let selected = lib.select(&[], &[], &[], &["prompt"]);
    assert!(selected.iter().any(|c| c.key == "RT-JB-001"));
    let none = lib.select(&[], &[], &[], &["nonexistent"]);
    assert!(
        !none.iter().any(|c| c.key == "RT-JB-001"),
        "能力不匹配的用例必须被过滤，实际返回: {:?}",
        none.iter().map(|c| c.key.clone()).collect::<Vec<_>>()
    );
    // 空能力列表 = 不按能力过滤
    assert!(lib.select(&[], &[], &[], &[]).iter().any(|c| c.key == "RT-JB-001"));
}

#[test]
pub(crate) fn case_id_is_deterministic() {
    let lib = library();
    let a = CaseLibrary::case_id(&lib.cases[0]);
    let b = CaseLibrary::case_id(&lib.cases[0]);
    assert_eq!(a, b);
    let c = CaseLibrary::case_id(&lib.cases[1]);
    assert_ne!(a, c);
}

#[test]
pub(crate) fn missing_categories_reported() {
    let lib = library();
    let missing = lib.missing_categories();
    assert!(missing.contains(&AttackCategory::RagPoisoning));
    assert!(!missing.contains(&AttackCategory::Jailbreak));
    assert_eq!(missing.len(), AttackCategory::all().len() - 3);
}

#[tokio::test]
pub(crate) async fn simulator_is_deterministic_and_respects_guard_strength() {
    let lib = library();
    let case = &lib.cases[0];
    let strong = RedteamSimulator::new("hardened", 100);
    let weak = RedteamSimulator::new("hardened", 0);
    let r1 = strong.run_case(case).await;
    let r2 = strong.run_case(case).await;
    assert_eq!(r1.unwrap_or_default(), r2.unwrap_or_default(), "同一目标同一用例结果必须一致");
    assert!(strong.run_case(case).await.unwrap_or_default().is_empty(), "防护 100 应拦截全部");
    assert!(!weak.run_case(case).await.unwrap_or_default().is_empty(), "防护 0 应全部得逞");
    assert!(strong.is_simulated());
}

#[tokio::test]
pub(crate) async fn simulator_skips_cases_requiring_missing_tools() {
    let lib = library();
    let tool_case = lib.cases.iter().find(|c| c.key == "RT-TA-001").unwrap_or_else(|| unreachable!());
    let no_tools = RedteamSimulator::new("no-tools", 0).with_tools(vec!["read_file".into()]);
    let signals = no_tools.run_case(tool_case).await.unwrap_or_default();
    assert!(signals.is_empty(), "缺少必要工具时攻击面不存在");

    let with_tools = RedteamSimulator::new("with-tools", 0).with_tools(vec!["execute_shell".into()]);
    assert!(!with_tools.run_case(tool_case).await.unwrap_or_default().is_empty());
}

#[tokio::test]
pub(crate) async fn campaign_run_produces_report_and_stats() {
    let lib = library();
    let runner = CampaignRunner::new();
    let target = RedteamSimulator::new("test-agent", 40);
    let cases: Vec<&RedteamCase> = lib.cases.iter().collect();
    let res = runner.run(TenantId::default_tenant(), "季度巡航", &cases, &target, "soc", true).await;
    assert!(res.is_ok());
    let Ok((campaign, outcomes, report)) = res else { return };
    assert_eq!(campaign.state, CampaignState::Completed);
    assert_eq!(campaign.executed_cases, 3);
    assert_eq!(outcomes.len(), 3);
    assert!(campaign.finished_at.is_some());
    assert_eq!(report.executed, 3);
    assert!(!report.markdown.is_empty());
    assert!(report.markdown.contains("用例明细"));
    assert_eq!(report.by_category.iter().map(|s| s.executed).sum::<u32>(), 3);
}

#[tokio::test]
pub(crate) async fn campaign_ci_gate_fails_on_critical_success() {
    let mut lib = library();
    lib.cases[0].severity = Severity::Critical;
    let runner = CampaignRunner::new();
    // 防护 0 → 全部得逞，含 critical → CI 卡点必须失败
    let target = RedteamSimulator::new("wide-open", 0);
    let cases: Vec<&RedteamCase> = lib.cases.iter().collect();
    let Ok((campaign, outcomes, report)) =
        runner.run(TenantId::default_tenant(), "ci", &cases, &target, "ci", true).await
    else {
        return;
    };
    assert!(outcomes.iter().any(|o| o.succeeded && o.severity == Severity::Critical));
    assert!(!report.ci_passed);
    assert!(!campaign.passes_ci_gate(1));
    assert!(report.verdict.contains("严重级"));
}

#[tokio::test]
pub(crate) async fn campaign_all_blocked_verdict() {
    let lib = library();
    let runner = CampaignRunner::new();
    let target = RedteamSimulator::new("fort-knox", 100);
    let cases: Vec<&RedteamCase> = lib.cases.iter().collect();
    let Ok((_, outcomes, report)) =
        runner.run(TenantId::default_tenant(), "clean", &cases, &target, "soc", false).await
    else {
        return;
    };
    assert!(outcomes.iter().all(|o| !o.succeeded));
    assert!(report.verdict.contains("未观测到声明的成功信号"));
    assert!(report.bypass_paths.is_empty());
    assert!(report.ci_passed);
}

#[tokio::test]
pub(crate) async fn findings_generated_only_for_successful_cases() {
    let lib = library();
    let runner = CampaignRunner::new();
    let target = RedteamSimulator::new("mixed", 0);
    let cases: Vec<&RedteamCase> = lib.cases.iter().collect();
    let Ok((_, outcomes, _)) = runner.run(TenantId::default_tenant(), "c", &cases, &target, "soc", false).await else {
        return;
    };
    assert!(runner.to_findings(TenantId::default_tenant(), &cases, &outcomes, "test-agent").is_empty());
    let outcomes = outcomes
        .into_iter()
        .map(|mut row| {
            row.simulated = false;
            row.evidence_level = EvidenceLevel::Partial;
            row
        })
        .collect::<Vec<_>>();
    let findings = runner.to_findings(TenantId::default_tenant(), &cases, &outcomes, "test-agent");
    let succeeded = outcomes.iter().filter(|o| o.succeeded).count();
    assert_eq!(findings.len(), succeeded);
    for f in &findings {
        assert_eq!(f.state, agf_core::risk::FindingState::Pending);
        assert!(!f.fix.is_empty());
        assert!(!f.poc.is_empty());
        assert!(f.impact.is_some());
        assert_eq!(f.evidence_level, EvidenceLevel::Partial);
    }
}

#[test]
pub(crate) fn bypass_description_mentions_mode() {
    let lib = library();
    let single = lib.cases.iter().find(|c| c.key == "RT-JB-001").unwrap_or_else(|| unreachable!());
    let d = describe_bypass(single, &["marker_echo".to_string()]);
    assert!(d.contains("单轮提示词"), "{d}");
    assert!(d.contains("marker_echo"));
    let tool_case = lib.cases.iter().find(|c| c.key == "RT-TA-001").unwrap_or_else(|| unreachable!());
    assert!(describe_bypass(tool_case, &["x".into()]).contains("工具调用序列"));
}

#[test]
pub(crate) fn outcome_to_result_maps_fields() {
    let o = RedteamOutcome {
        evaluation: EvaluationStatus::Evaluated,
        evaluation_note: None,
        transcript: vec![],
        case_key: "RT-1".into(),
        case_title: "t".into(),
        category: AttackCategory::Jailbreak,
        severity: Severity::High,
        target_asset_id: Id::new(),
        succeeded: true,
        matched_signals: vec!["s".into()],
        bypass_path: Some("p".into()),
        evidence_level: EvidenceLevel::Confirmed,
        latency_ms: 5,
        simulated: true,
    };
    let r = o.to_result(TenantId::default_tenant(), Id::new());
    assert_eq!(r.case_key, "RT-1");
    assert!(r.succeeded);
    assert!(r.mocked);
    assert_eq!(r.model, "mock-simulator");
}

#[test]
pub(crate) fn category_coverage_counts() {
    let outcomes = vec![
        RedteamOutcome {
            evaluation: EvaluationStatus::Evaluated,
            evaluation_note: None,
            transcript: vec![],
            case_key: "a".into(),
            case_title: "a".into(),
            category: AttackCategory::Jailbreak,
            severity: Severity::High,
            target_asset_id: Id::new(),
            succeeded: true,
            matched_signals: vec![],
            bypass_path: None,
            evidence_level: EvidenceLevel::Unknown,
            latency_ms: 1,
            simulated: true,
        },
        RedteamOutcome {
            evaluation: EvaluationStatus::Evaluated,
            evaluation_note: None,
            transcript: vec![],
            case_key: "b".into(),
            case_title: "b".into(),
            category: AttackCategory::Jailbreak,
            severity: Severity::High,
            target_asset_id: Id::new(),
            succeeded: false,
            matched_signals: vec![],
            bypass_path: None,
            evidence_level: EvidenceLevel::Unknown,
            latency_ms: 1,
            simulated: true,
        },
    ];
    let cov = category_coverage(&outcomes);
    assert_eq!(cov.get("jailbreak"), Some(&(2, 1)));
}

#[test]
pub(crate) fn domain_mapping() {
    assert_eq!(domain_of(AttackCategory::RagPoisoning), RiskDomain::RagPoison);
    assert_eq!(domain_of(AttackCategory::CredentialTheft), RiskDomain::CredentialLeak);
}

#[test]
pub(crate) fn markdown_notes_simulation() {
    let campaign = RedteamCampaign {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "n".into(),
        target_agent_ids: vec![Id::new()],
        target_mcp_ids: vec![],
        case_keys: vec![],
        categories: vec![],
        tags: vec![],
        state: CampaignState::Completed,
        launched_by: "soc".into(),
        scheduled: false,
        cron: None,
        ci_gate: false,
        total_cases: 1,
        executed_cases: 1,
        succeeded_cases: 1,
        started_at: None,
        finished_at: None,
        created_at: Timestamp::now(),
    };
    let outcomes = vec![RedteamOutcome {
        evaluation: EvaluationStatus::Evaluated,
        evaluation_note: None,
        transcript: vec![],
        case_key: "k".into(),
        case_title: "t".into(),
        category: AttackCategory::Jailbreak,
        severity: Severity::High,
        target_asset_id: Id::new(),
        succeeded: true,
        matched_signals: vec!["s".into()],
        bypass_path: Some("p".into()),
        evidence_level: EvidenceLevel::Confirmed,
        latency_ms: 1,
        simulated: true,
    }];
    let report = RedteamReport {
        evaluated_cases: 1,
        inconclusive_cases: 0,
        failed_cases: 0,
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        campaign_id: campaign.id,
        title: "报告".into(),
        total_cases: 1,
        executed: 1,
        succeeded: 1,
        by_category: vec![],
        bypass_paths: vec!["p".into()],
        remediations: vec!["r".into()],
        finding_ids: vec![],
        verdict: "v".into(),
        ci_passed: false,
        markdown: String::new(),
        generated_at: Timestamp::now(),
    };
    let md = render_markdown(&campaign, &outcomes, &report);
    assert!(md.contains("本地模拟目标"));
    assert!(md.contains("绕过路径"));
    assert!(md.contains("修复建议"));
}
