//! 由 `drift.rs` 拆分：`asset` 等 17 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn asset(kind: AssetKind, name: &str) -> Asset {
    Asset::new(TenantId::default_tenant(), kind, name, format!("fp-{name}"))
}

#[test]
pub(crate) fn added_mcp_is_flagged_risky() {
    let scanner = DriftScanner::new();
    let mcp = asset(AssetKind::McpServer, "new-mcp");
    let changes = scanner.diff(&[], &[mcp]);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].change_kind, ChangeKind::Added);
    assert!(changes[0].risky, "新增未评审 MCP 应标记高风险");
    assert!(changes[0].risk_note.is_some());
}

#[test]
pub(crate) fn added_production_asset_is_not_flagged() {
    let scanner = DriftScanner::new();
    let mut mcp = asset(AssetKind::McpServer, "known-mcp");
    mcp.lifecycle = LifecycleState::Production;
    let changes = scanner.diff(&[], &[mcp]);
    assert_eq!(changes.len(), 1);
    assert!(!changes[0].risky);
}

#[test]
pub(crate) fn removed_archived_asset_is_not_flagged() {
    let scanner = DriftScanner::new();
    let mut old = asset(AssetKind::McpServer, "old");
    old.lifecycle = LifecycleState::Archived;
    let changes = scanner.diff(&[old], &[]);
    assert_eq!(changes.len(), 1);
    assert!(!changes[0].risky, "归档资产消失不算异常");
}

#[test]
pub(crate) fn endpoint_change_is_risky_but_dataclass_is_not_in_default_scanner() {
    let scanner = DriftScanner::new();
    let mut before = asset(AssetKind::McpServer, "m");
    before.endpoint = Some("https://mcp.corp.local/mcp".into());
    let mut after = before.clone();
    after.endpoint = Some("https://evil.example.com/mcp".into());
    let changes = scanner.diff_one(&before, &after, Timestamp::now());
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].field.as_deref(), Some("endpoint"));
    assert!(changes[0].risky);
}

#[test]
pub(crate) fn non_risky_field_change_recorded_without_flag() {
    let scanner = DriftScanner::new();
    let before = asset(AssetKind::Agent, "a");
    let mut after = before.clone();
    after.lifecycle = LifecycleState::Production;
    let changes = scanner.diff_one(&before, &after, Timestamp::now());
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].field.as_deref(), Some("lifecycle"));
    assert!(!changes[0].risky);
}

#[test]
pub(crate) fn dependent_change_detected() {
    let scanner = DriftScanner::new();
    let before = asset(AssetKind::Agent, "a");
    let mut after = before.clone();
    after.dependencies = vec![Id::new()];
    let changes = scanner.diff_one(&before, &after, Timestamp::now());
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].field.as_deref(), Some("dependencies"));
}

#[test]
pub(crate) fn identical_assets_produce_no_changes() {
    let scanner = DriftScanner::new();
    let a = asset(AssetKind::McpServer, "m");
    let before = vec![a.clone()];
    assert!(scanner.diff(&before, &[a]).is_empty());
}

#[test]
pub(crate) fn version_change_is_risky() {
    let scanner = DriftScanner::new();
    let mut before = asset(AssetKind::McpServer, "m");
    before.version = Some("1.0.0".into());
    let mut after = before.clone();
    after.version = Some("2.0.0".into());
    let changes = scanner.diff_one(&before, &after, Timestamp::now());
    assert!(changes.iter().any(|c| c.field.as_deref() == Some("version") && c.risky));
}

#[test]
pub(crate) fn custom_risky_fields_respected() {
    let scanner = DriftScanner::new().with_risky_fields(&["exposure_score"]);
    let mut before = asset(AssetKind::McpServer, "m");
    before.exposure_score = 10;
    let mut after = before.clone();
    after.exposure_score = 90;
    let changes = scanner.diff_one(&before, &after, Timestamp::now());
    assert!(changes.iter().any(|c| c.field.as_deref() == Some("exposure_score") && c.risky));
    // 默认高风险字段此时反而不标记
    let mut b2 = asset(AssetKind::McpServer, "m2");
    b2.endpoint = Some("https://a/mcp".into());
    let mut a2 = b2.clone();
    a2.endpoint = Some("https://b/mcp".into());
    assert!(scanner.diff_one(&b2, &a2, Timestamp::now()).iter().all(|c| !c.risky));
}

#[test]
pub(crate) fn hash_diff_classifies_correctly() {
    let a = Id::new();
    let b = Id::new();
    let c = Id::new();
    let before: BTreeMap<Id, String> = [(a, "h1".to_string()), (b, "h2".to_string())].into_iter().collect();
    let after: BTreeMap<Id, String> =
        [(a, "h1".to_string()), (b, "h2-changed".to_string()), (c, "h3".to_string())].into_iter().collect();
    let (added, removed, modified) = DriftScanner::hash_diff(&before, &after);
    assert_eq!(added, vec![c]);
    assert!(removed.is_empty());
    assert_eq!(modified, vec![b]);
}

#[test]
pub(crate) fn content_hash_changes_on_security_relevant_fields() {
    let a = asset(AssetKind::McpServer, "m");
    let h1 = DriftScanner::content_hash(&a);
    let mut b = a.clone();
    b.endpoint = Some("https://x/mcp".into());
    b.protocol = Some(Protocol::McpHttp);
    let h2 = DriftScanner::content_hash(&b);
    assert_ne!(h1, h2);
    let mut c = a.clone();
    c.data_class = DataClass::Restricted;
    assert_ne!(h1, DriftScanner::content_hash(&c));
    let mut d = a.clone();
    d.lifecycle = LifecycleState::Production;
    assert_ne!(h1, DriftScanner::content_hash(&d));
}

#[test]
pub(crate) fn summary_counts_and_severity() {
    let scanner = DriftScanner::new();
    let mcp = asset(AssetKind::McpServer, "new");
    let mut known = asset(AssetKind::McpServer, "known");
    known.lifecycle = LifecycleState::Production;
    let changes = scanner.diff(
        &[known],
        &[mcp, {
            let mut k = asset(AssetKind::McpServer, "known");
            k.lifecycle = LifecycleState::Production;
            k
        }],
    );
    let summary = DriftScanner::summarize(&changes);
    assert_eq!(summary.total, changes.len());
    assert!(summary.needs_attention());
    assert_eq!(summary.severity, Severity::High);
    assert!(!summary.risky_assets.is_empty());
}

#[test]
pub(crate) fn summary_of_clean_diff_is_info() {
    let summary = DriftScanner::summarize(&[]);
    assert_eq!(summary.total, 0);
    assert_eq!(summary.severity, Severity::Info);
    assert!(!summary.needs_attention());
}

#[test]
pub(crate) fn report_markdown_contains_key_sections() {
    let scanner = DriftScanner::new();
    let mcp = asset(AssetKind::McpServer, "new-mcp");
    let changes = scanner.diff(&[], &[mcp]);
    let report = DriftReport::new(TenantId::default_tenant(), "2026-03-01", "2026-03-02", changes);
    let md = report.to_markdown();
    assert!(md.contains("# 资产漂移报告（2026-03-01 → 2026-03-02）"));
    assert!(md.contains("需人工确认"));
    assert!(md.contains("## 明细"));
    assert_eq!(report.summary.total, 1);
}

#[test]
pub(crate) fn report_markdown_without_risk_skips_section() {
    let report = DriftReport::new(TenantId::default_tenant(), "a", "b", Vec::new());
    let md = report.to_markdown();
    assert!(!md.contains("需人工确认"));
    assert!(md.contains("## 明细"));
}

#[test]
pub(crate) fn discovery_source_included_in_content_hash() {
    let mut a = asset(AssetKind::McpServer, "m");
    a.discovery_source = DiscoverySource::Manual;
    let h1 = DriftScanner::content_hash(&a);
    a.discovery_source = DiscoverySource::NetworkScan;
    assert_ne!(h1, DriftScanner::content_hash(&a));
}
