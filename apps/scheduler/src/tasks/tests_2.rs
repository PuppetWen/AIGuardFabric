//! 由 `tasks.rs` 拆分：`render_report_includes_real_numbers` 等 6 个函数（纯搬移，逻辑不变）。
use super::*;

#[test]
pub(crate) fn render_report_includes_real_numbers() {
    let input = ReportInput {
        generated_at: "2024-01-01T00:00:00Z".to_string(),
        rules_dir: "/rules".to_string(),
        rules_count: Some(12),
        rules_fingerprint: Some("deadbeef".to_string()),
        redteam_cases: Some(4),
        redteam_reports: vec!["redteam-cruise-c1.md".to_string()],
        asset_summary: Some("资产台账：总量 42".to_string()),
        log_pull_summary: Some("日志拉取：源 1/1 成功".to_string()),
        archive: Some(ArchiveManifest {
            files: 3,
            bytes: 512,
            backend: "s3".to_string(),
            manifest_sha256: "abc".to_string(),
            ..ArchiveManifest::default()
        }),
        cms_note: Some("CMS 指标 4/4 条已上报，Mock 模式".to_string()),
        tasks: vec![snapshot("rules-regression", 5, 0, 12)],
    };
    let markdown = render_report(&input);
    assert!(markdown.contains("deadbeef") && markdown.contains("12"));
    assert!(markdown.contains("redteam-cruise-c1.md"));
    assert!(markdown.contains("资产台账：总量 42"));
    assert!(markdown.contains("| rules-regression | 5 | 0 | 12 |"));
    assert!(!markdown.contains(NO_DATA), "有数据时不得出现无数据占位");
}

#[test]
pub(crate) fn latest_file_and_list_matching_pick_newest_first() {
    let dir = temp_dir("latest");
    std::fs::write(dir.join("redteam-cruise-a.md"), b"a").expect("写文件");
    std::fs::write(dir.join("redteam-cruise-b.md"), b"b").expect("写文件");
    std::fs::write(dir.join("other.md"), b"c").expect("写文件");
    let latest = latest_file(&dir, "redteam-cruise-", ".md").expect("取到最新");
    assert_eq!(latest.file_name().and_then(|n| n.to_str()), Some("redteam-cruise-b.md"));
    let listed = list_matching(&dir, "redteam-cruise-", ".md", 5);
    assert_eq!(listed, vec!["redteam-cruise-b.md".to_string(), "redteam-cruise-a.md".to_string()]);
    assert!(latest_file(&dir, "missing-", ".json").is_none());
    assert_eq!(list_matching(&dir, "redteam-cruise-", ".md", 1).len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
pub(crate) fn report_generate_writes_markdown_even_without_data() {
    let dir = temp_dir("report");
    let empty_rules = dir.join("rules");
    let empty_redteam = dir.join("redteam");
    let tasks = vec![snapshot("rules-regression", 1, 0, 3)];
    let outcome = run_report_generate(&empty_rules, &empty_redteam, &dir, tasks, None);
    assert!(outcome.ok, "无数据也必须生成报表：{}", outcome.note);
    let path = latest_file(&dir, "report-", ".md").expect("报表文件必须存在");
    let body = std::fs::read_to_string(&path).expect("读报表");
    assert!(body.contains("| rules-regression | 1 | 0 | 3 |"));
    assert!(body.contains("本期无数据"));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- alicloud-cms-push ----

#[test]
pub(crate) fn cms_metrics_map_local_stats_to_metric_values() {
    let tasks = vec![snapshot("a", 3, 1, 5), snapshot("b", 4, 0, 6)];
    let metrics = cms_metrics(&tasks, Some(12), Some(0.75));
    let get = |name: &str| metrics.iter().find(|(k, _)| k == name).map(|(_, v)| *v).expect("指标必须存在");
    assert_eq!(get("agf_scheduler_task_runs"), 7.0);
    assert_eq!(get("agf_scheduler_task_failures"), 1.0);
    assert_eq!(get("agf_rules_total"), 12.0);
    assert_eq!(get("agf_redteam_success_rate"), 75.0);
    let empty = cms_metrics(&[], None, None);
    assert_eq!(empty.len(), 2, "未观测规则量和真实红队成功率不应上报伪造的零");
    assert!(empty.iter().all(|(_, v)| *v == 0.0));
}

#[tokio::test]
pub(crate) async fn cms_push_explicit_mock_is_degraded_and_not_failed() {
    let adapter = CmsAdapter::mocked();
    let metrics = cms_metrics(&[snapshot("rules-regression", 2, 0, 7)], Some(3), Some(0.5));
    let outcome = run_cms_push_with(&adapter, &metrics, "", "").await;
    assert!(outcome.ok, "Mock 不算失败：{}", outcome.note);
    assert!(outcome.degraded, "Mock 必须保留降级标识");
    assert_eq!(outcome.status_label(), "degraded");
    assert!(outcome.note.contains("Mock") || outcome.note.contains("mocked"), "必须标注 mocked：{}", outcome.note);
    assert!(outcome.note.contains("4/4"), "Mock 也必须返回指标名：{}", outcome.note);
    assert!(outcome.note.contains("失败 0 条"));
    assert_eq!(adapter.transport().call_count().unwrap(), 0, "显式 Mock 不得触发传输");
}

#[test]
pub(crate) fn cms_live_config_requests_env_credential_source() {
    let config = live_cms_config("cn-hangzhou");
    assert_eq!(config.adapter, "alicloud-cms");
    assert_eq!(config.get_str("region_id"), Some("cn-hangzhou"));
    assert_eq!(config.get_str("credential_source"), Some("env"));
    assert!(!config.mock, "真实模式配置不得自带 mock 标志");
}
