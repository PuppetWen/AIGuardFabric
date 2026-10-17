//! 灌库单元测试（上）：测试 helper 与前 7 个用例（自 seed.rs 拆出，断言未改）。

#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines))]

use super::*;

use agf_core::enums::EvidenceLevel;
use agf_core::redteam::{AttackCategory, AttackTurn, CampaignState, ExecutionMode, RedteamCase};
use serde_json::json;

/// 仓库根目录（`crates/agf-api` → 上溯两级）。
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// 数据集目录（真实 fixtures）。
pub(super) fn fixtures_dir() -> PathBuf {
    repo_root().join("data").join("seed")
}

/// 小型确定性用例库（测试不依赖 `redteam/*.yaml` 的内容规模）。
pub(super) fn sample_library() -> CaseLibrary {
    let make = |key: &str, title: &str, category: AttackCategory, mode: ExecutionMode| RedteamCase {
        key: key.to_string(),
        title: title.to_string(),
        category,
        severity: Severity::High,
        mode,
        turns: vec![AttackTurn {
            role: "user".to_string(),
            content: format!("{{{{marker}}}} {title}"),
            expect: vec!["marker_echo".to_string()],
        }],
        applies_to: vec!["prompt".to_string()],
        success_signals: vec!["marker_echo".to_string()],
        required_tools: Vec::new(),
        tags: vec!["demo".to_string()],
        references: Vec::new(),
        public_poc: false,
        remediation: "启用输出侧策略校验".to_string(),
        author: "test".to_string(),
        version: 1,
    };
    CaseLibrary::from_cases(vec![
        make("RT-JB-001", "角色扮演越狱", AttackCategory::Jailbreak, ExecutionMode::SingleTurn),
        make("RT-TA-001", "工具滥用", AttackCategory::ToolAbuse, ExecutionMode::SingleTurn),
    ])
}

pub(super) fn tenant() -> TenantId {
    TenantId::default_tenant()
}

/// 灌一次并断言无失败（happy path 的公共前置）。
pub(super) fn seed_once(store: &ApiStore, root: &Path) -> SeedReport {
    let report = seed_demo_data(store, root, tenant(), &QuotaDefaults::default(), &sample_library()).expect("灌库失败");
    assert_eq!(report.total_errors(), 0, "happy path 不应有失败条数：{:?}", report.warnings);
    report
}

fn ids_of<T: Copy + Ord>(items: &[T]) -> Vec<T> {
    let mut ids: Vec<T> = items.to_vec();
    ids.sort();
    ids
}

#[test]
fn flag_parsing_is_strict() {
    for on in ["1", "true", "TRUE", " yes ", "On"] {
        assert!(seed_flag_enabled(Some(on)), "{on} 应视为开启");
    }
    for off in ["", "0", "false", "no", "off", "  "] {
        assert!(!seed_flag_enabled(Some(off)), "{off} 应视为关闭");
    }
    assert!(!seed_flag_enabled(None), "未设置 = 默认关闭（生产安全）");
}

#[test]
fn mapping_helpers_are_total_and_documented() {
    assert_eq!(map_asset_kind("model"), Ok(AssetKind::ModelEndpoint));
    assert_eq!(map_asset_kind("mcp"), Ok(AssetKind::McpServer));
    assert_eq!(map_asset_kind("datasource"), Ok(AssetKind::DataSource));
    assert_eq!(map_asset_kind("agent"), Ok(AssetKind::Agent));
    assert!(map_asset_kind("不存在的类型").is_err());

    assert_eq!(map_risk_domain("runtime", "prompt-injection"), Ok(RiskDomain::PromptAttack));
    assert_eq!(map_risk_domain("runtime", "tool-abuse"), Ok(RiskDomain::ToolAbuse));
    assert_eq!(map_risk_domain("identity", "credential-leak"), Ok(RiskDomain::CredentialLeak));
    assert_eq!(map_risk_domain("data", "rag-poison"), Ok(RiskDomain::RagPoison));
    assert_eq!(map_risk_domain("data", "model-data"), Ok(RiskDomain::ModelData));
    assert_eq!(map_risk_domain("asset", "exposure"), Ok(RiskDomain::ToolAbuse));
    assert_eq!(map_risk_domain("prompt-attack", ""), Ok(RiskDomain::PromptAttack));
    assert!(map_risk_domain("", "").is_err());

    assert_eq!(map_lifecycle(Some("active")), Ok(LifecycleState::Production));
    assert_eq!(map_lifecycle(Some("onboarding")), Ok(LifecycleState::Trial));
    assert!(map_lifecycle(Some("bogus")).is_err());
    assert_eq!(map_data_class(Some("confidential")), Ok(DataClass::Confidential));
    assert_eq!(map_policy_action("require-approval"), Ok(PolicyAction::Approval));
    assert_eq!(map_case_state(Some("contained")), Ok(CaseState::Containing));
    assert_eq!(map_alert_state(Some("acknowledged")), Ok(AlertState::Acknowledged));
}

#[test]
fn malformed_item_is_rejected_without_panic() {
    // 字段缺失必须走 Err（调用方据 Err 计数并跳过），不能 panic
    assert!(asset_from_item(&json!({}), tenant()).is_err());
    assert!(asset_from_item(&json!({ "id": "ast-x", "name": "x" }), tenant()).is_err(), "缺少 kind");
    let refs = CrossRefs::default();
    let mut stat = DatasetReport::default();
    assert!(finding_from_item(&json!({ "id": "fnd-x" }), tenant(), &refs, &mut stat).is_err(), "缺少 severity");
    assert!(policy_from_item(&json!({ "id": "pol-x" }), tenant()).is_err(), "缺少 name");
}

#[test]
fn contract_counts_and_kind_projection_match_fixtures() {
    let store = ApiStore::offline();
    let report = seed_once(&store, &fixtures_dir());

    // 条数契约（与 data/seed/index.json 的清单一致）
    assert_eq!(report.inserted(DS_ASSETS), 8);
    assert_eq!(report.inserted(DS_FINDINGS), 6);
    assert_eq!(report.inserted(DS_ALERTS), 4);
    assert_eq!(report.inserted(DS_CASES), 2);
    assert_eq!(report.inserted(DS_POLICIES), 3);
    assert_eq!(report.inserted(DS_SCANS), 2);
    assert_eq!(report.inserted(DS_REPORTS), 2);
    assert_eq!(report.inserted(DS_CAMPAIGNS), 1);
    assert_eq!(report.inserted(DS_QUOTAS), 4);
    // redteam-cases.json 无存储面：如实记 skipped 而不是 inserted
    assert_eq!(report.inserted(DS_REDTEAM_CASES), 0);
    assert_eq!(report.datasets.get(DS_REDTEAM_CASES).map(|d| d.skipped), Some(3));

    // 存储侧条数契约
    let assets = store.asset_list_all(tenant()).unwrap();
    assert_eq!(assets.len(), 8);
    assert_eq!(store.finding_list_all(tenant()).unwrap().len(), 6);
    assert_eq!(store.alert_list(tenant(), None, None).unwrap().len(), 4);
    assert_eq!(store.case_list(tenant()).unwrap().len(), 2);
    assert_eq!(store.policy_list(tenant()).unwrap().len(), 3);
    assert_eq!(store.scan_list(tenant()).unwrap().len(), 2);
    assert_eq!(store.report_list(tenant()).unwrap().len(), 2);
    assert_eq!(store.campaign_list(tenant()).unwrap().len(), 1);
    assert_eq!(store.quota_list(tenant()).unwrap().len(), 4);

    // kind 投影契约：agents 3 / mcps 1 / skills 1 / models/endpoints 1
    let count = |kind: AssetKind| assets.iter().filter(|a| a.kind == kind).count();
    assert_eq!(count(AssetKind::Agent), 3);
    assert_eq!(count(AssetKind::McpServer), 1);
    assert_eq!(count(AssetKind::Skill), 1);
    assert_eq!(count(AssetKind::ModelEndpoint), 1);
    assert_eq!(count(AssetKind::Credential), 1);
    assert_eq!(count(AssetKind::DataSource), 1);

    // 状态投影契约
    let cases = store.case_list(tenant()).unwrap();
    assert!(cases.iter().any(|c| c.state == CaseState::Investigating));
    assert!(cases.iter().any(|c| c.state == CaseState::Containing));
    let alerts = store.alert_list(tenant(), None, None).unwrap();
    assert!(alerts.iter().any(|a| a.state == AlertState::Acknowledged));
    let scans = store.scan_list(tenant()).unwrap();
    assert!(scans.iter().any(|s| s.state == ScanJobState::Succeeded));
    assert!(scans.iter().any(|s| s.state == ScanJobState::Running));
    let campaigns = store.campaign_list(tenant()).unwrap();
    assert_eq!(campaigns.first().map(|c| c.state), Some(CampaignState::Completed));

    // 发现必须带证据（报表/复核链路依赖）
    assert!(store.finding_list_all(tenant()).unwrap().iter().all(|f| !f.evidence.is_empty()));
    assert!(store.finding_list_all(tenant()).unwrap().iter().all(|f| f.evidence_level >= EvidenceLevel::Partial));
}

#[test]
fn deterministic_ids_are_stable_across_runs() {
    let root = fixtures_dir();
    let first = ApiStore::offline();
    let second = ApiStore::offline();
    seed_once(&first, &root);
    seed_once(&second, &root);

    // 业务键 → 确定性 UUID（同一份 fixtures 两次灌库完全一致）
    let agent = first.asset_get(tenant(), deterministic_id(NS_ASSET, "ast-agent-0001")).unwrap();
    assert_eq!(agent.map(|a| a.name), Some("客服智能助手 Copilot".to_string()));
    assert!(first.asset_get(tenant(), deterministic_id(NS_ASSET, "ast-unknown")).unwrap().is_none());

    assert_eq!(
        ids_of(&first.asset_list_all(tenant()).unwrap().iter().map(|a| a.id).collect::<Vec<_>>()),
        ids_of(&second.asset_list_all(tenant()).unwrap().iter().map(|a| a.id).collect::<Vec<_>>())
    );
    assert_eq!(
        ids_of(&first.finding_list_all(tenant()).unwrap().iter().map(|f| f.id).collect::<Vec<_>>()),
        ids_of(&second.finding_list_all(tenant()).unwrap().iter().map(|f| f.id).collect::<Vec<_>>())
    );
    assert_eq!(
        ids_of(&first.policy_list(tenant()).unwrap().iter().map(|p| p.id).collect::<Vec<_>>()),
        ids_of(&second.policy_list(tenant()).unwrap().iter().map(|p| p.id).collect::<Vec<_>>())
    );
    assert_eq!(
        ids_of(&first.scan_list(tenant()).unwrap().iter().map(|s| s.id).collect::<Vec<_>>()),
        ids_of(&second.scan_list(tenant()).unwrap().iter().map(|s| s.id).collect::<Vec<_>>())
    );
    assert_eq!(
        ids_of(&first.report_list(tenant()).unwrap().iter().map(|r| r.id).collect::<Vec<_>>()),
        ids_of(&second.report_list(tenant()).unwrap().iter().map(|r| r.id).collect::<Vec<_>>())
    );
    assert_eq!(
        ids_of(&first.campaign_list(tenant()).unwrap().iter().map(|c| c.id).collect::<Vec<_>>()),
        ids_of(&second.campaign_list(tenant()).unwrap().iter().map(|c| c.id).collect::<Vec<_>>())
    );

    // 告警/案件的 UUID 由 ApiStore 内部 Id::new() 生成（store 无注入 id 的写入路径），
    // 其绝对值不保证跨进程稳定；但"业务键 → 去重键/标题"的映射与引用关系必须一致。
    let alert_keys = |store: &ApiStore| -> Vec<String> {
        let mut keys: Vec<String> =
            store.alert_list(tenant(), None, None).unwrap().into_iter().map(|a| a.dedup_key).collect();
        keys.sort();
        keys
    };
    assert_eq!(alert_keys(&first), alert_keys(&second));
    let case_titles = |store: &ApiStore| -> Vec<String> {
        let mut titles: Vec<String> = store.case_list(tenant()).unwrap().into_iter().map(|c| c.title).collect();
        titles.sort();
        titles
    };
    assert_eq!(case_titles(&first), case_titles(&second));
}

#[test]
fn cross_table_references_resolve() {
    let store = ApiStore::offline();
    seed_once(&store, &fixtures_dir());

    // finding → asset
    let findings = store.finding_list_all(tenant()).unwrap();
    assert!(findings.iter().all(|f| f.asset_id.is_some()), "每条发现都应解析到资产");
    for finding in &findings {
        let asset_id = finding.asset_id.unwrap();
        assert!(store.asset_get(tenant(), asset_id).unwrap().is_some(), "发现引用的资产必须存在");
    }

    // alert → finding / asset
    for alert in store.alert_list(tenant(), None, None).unwrap() {
        assert!(!alert.finding_ids.is_empty(), "告警应关联发现：{}", alert.title);
        for id in &alert.finding_ids {
            assert!(store.finding_get(tenant(), *id).unwrap().is_some());
        }
        for id in &alert.asset_ids {
            assert!(store.asset_get(tenant(), *id).unwrap().is_some());
        }
        assert!(alert.domain.is_some(), "告警安全域应跟随来源发现");
    }

    // case → alert / finding
    for case in store.case_list(tenant()).unwrap() {
        assert!(!case.finding_ids.is_empty(), "案件应关联发现：{}", case.title);
        assert!(!case.alert_ids.is_empty(), "案件应关联告警：{}", case.title);
        for id in &case.finding_ids {
            assert!(store.finding_get(tenant(), *id).unwrap().is_some());
        }
        for id in &case.alert_ids {
            assert!(store.alert_get(tenant(), *id).unwrap().is_some());
        }
    }

    // campaign → 结果 / 报告 / 目标资产
    let campaign = store.campaign_list(tenant()).unwrap().remove(0);
    assert!(!campaign.target_agent_ids.is_empty());
    for id in &campaign.target_agent_ids {
        assert!(store.asset_get(tenant(), *id).unwrap().is_some());
    }
    let results = store.campaign_results(tenant(), campaign.id).unwrap();
    assert_eq!(results.len(), campaign.executed_cases as usize);
    assert!(results.iter().all(|r| r.campaign_id == campaign.id));
    for result in &results {
        assert!(store.asset_get(tenant(), result.target_asset_id).unwrap().is_some());
    }
    let detail = store.campaign_report(tenant(), campaign.id).unwrap().expect("战役报告应存在");
    assert_eq!(detail.campaign_id, campaign.id);
    assert!(!detail.markdown.is_empty(), "战役报告应有 Markdown 正文");
}

#[test]
fn seeding_twice_is_idempotent() {
    let store = ApiStore::offline();
    let root = fixtures_dir();
    seed_once(&store, &root);
    let before = {
        let campaign_id = store.campaign_list(tenant()).unwrap().remove(0).id;
        (
            store.asset_list_all(tenant()).unwrap().len(),
            store.finding_list_all(tenant()).unwrap().len(),
            store.alert_list(tenant(), None, None).unwrap().len(),
            store.case_list(tenant()).unwrap().len(),
            store.policy_list(tenant()).unwrap().len(),
            store.scan_list(tenant()).unwrap().len(),
            store.report_list(tenant()).unwrap().len(),
            store.campaign_results(tenant(), campaign_id).unwrap().len(),
        )
    };

    let second =
        seed_demo_data(&store, &root, tenant(), &QuotaDefaults::default(), &sample_library()).expect("二次灌库失败");
    assert_eq!(second.total_errors(), 0);
    for (dataset, stat) in &second.datasets {
        assert_eq!(stat.inserted, 0, "{dataset} 二次灌库不应新增（幂等）");
    }
    let campaign_id = store.campaign_list(tenant()).unwrap().remove(0).id;
    let after = (
        store.asset_list_all(tenant()).unwrap().len(),
        store.finding_list_all(tenant()).unwrap().len(),
        store.alert_list(tenant(), None, None).unwrap().len(),
        store.case_list(tenant()).unwrap().len(),
        store.policy_list(tenant()).unwrap().len(),
        store.scan_list(tenant()).unwrap().len(),
        store.report_list(tenant()).unwrap().len(),
        store.campaign_results(tenant(), campaign_id).unwrap().len(),
    );
    assert_eq!(before, after, "二次灌库后各表条数必须不变");
}
