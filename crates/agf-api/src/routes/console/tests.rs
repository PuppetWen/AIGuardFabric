//! 控制台只读端点的单元测试（断言与原文件逐字一致）。

use super::*;

pub(super) fn asset(kind: AssetKind, name: &str) -> Asset {
    Asset::new(TenantId::default_tenant(), kind, name, format!("fp-{name}"))
}

#[test]
fn risk_domain_mapping_covers_all_backend_domains() {
    use agf_core::enums::RiskDomain;
    for domain in RiskDomain::all() {
        let mapped = risk_domain_frontend(domain);
        assert!(FRONTEND_DOMAINS.contains(&mapped), "{domain:?} → {mapped} 不在前端词表内");
    }
}

#[test]
fn asset_view_maps_kind_lifecycle_and_exposure() {
    let mut a = asset(AssetKind::McpServer, "order-mcp");
    a.lifecycle = LifecycleState::Trial;
    a.network_zone = Some("public".to_string());
    a.data_class = DataClass::Confidential;
    a.risk_score = Some(88);
    let view = asset_view(&a, Some(3));
    assert_eq!(view.kind, "mcp");
    assert_eq!(view.lifecycle, "onboarding");
    assert_eq!(view.exposure, "public-internet");
    assert_eq!(view.classification, "confidential");
    assert_eq!(view.risk_score, Some(88));
    assert_eq!(view.open_findings, Some(3));
}

#[test]
fn absent_assessments_and_activity_are_not_inferred_from_exposure_or_updates() {
    let mut a = asset(AssetKind::Skill, "unassessed");
    a.exposure_score = 99;
    a.last_seen_at = None;
    let view = asset_view(&a, Some(0));
    assert_eq!(view.risk_score, None);
    assert_eq!(view.exposure, "unknown");
    assert!(view.last_seen_at.is_empty());
    a.risk_score = Some(0);
    assert_eq!(asset_view(&a, Some(0)).risk_score, Some(0));
}

#[test]
fn topology_edge_kind_and_node_type() {
    assert_eq!(topology_node_type(AssetKind::Agent), Some("agent"));
    assert_eq!(topology_node_type(AssetKind::Credential), None);
    assert_eq!(topology_edge_kind("agent", "mcp"), "invokes");
    assert_eq!(topology_edge_kind("mcp", "tool"), "exposes");
    assert_eq!(topology_edge_kind("tool", "datasource"), "reads");
    assert_eq!(topology_edge_kind("agent", "model"), "invokes");
}

#[test]
fn blacklist_view_skips_kinds_absent_from_frontend_enum() {
    let deny = RuleRule::deny(
        "cmd.mkfs",
        RuleKind::Command,
        "mkfs",
        "格式化文件系统",
        agf_core::enums::RiskDomain::ToolAbuse,
        Severity::Critical,
    );
    let view = blacklist_view(&deny, "2026-01-01T00:00:00.000Z").expect("command 规则必须可见");
    assert_eq!(view.kind, "command");
    assert_eq!(view.action, "deny");
    assert_eq!(view.scope, "tenant");
    let path = RuleRule::deny(
        "path.etc-shadow",
        RuleKind::Path,
        "/etc/shadow",
        "口令文件",
        agf_core::enums::RiskDomain::CredentialLeak,
        Severity::High,
    );
    assert!(blacklist_view(&path, "2026-01-01T00:00:00.000Z").is_none(), "path 类无前端取值，应跳过");
}

#[test]
fn intercept_point_rows_always_cover_frontend_enum() {
    let rows = intercept_point_rows(
        &[InterceptPoint::McpProxy, InterceptPoint::AiGateway],
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
    );
    let points: Vec<&str> = rows.iter().map(|row| row.point.as_str()).collect();
    assert_eq!(points, vec!["mcp-proxy", "ai-gateway", "process-hook", "egress-proxy"]);
    assert!(rows.iter().all(|row| !row.enabled), "API 进程内没有拦截点代理，必须如实标 false");
    assert!(rows.iter().all(|row| row.throughput_per_min == 0), "无流量时吞吐必须为 0: {rows:?}");
    assert!(rows.iter().all(|row| row.p95_latency_ms == 0), "无样本时时延必须为 0（不编造）: {rows:?}");
}

#[test]
fn intercept_point_rows_project_real_throughput() {
    let mut throughput: BTreeMap<String, u64> = BTreeMap::new();
    throughput.insert("mcp-proxy".to_string(), 7);
    let rows = intercept_point_rows(&[InterceptPoint::McpProxy], &BTreeMap::new(), &throughput, &BTreeMap::new());
    let mcp = rows.iter().find(|row| row.point == "mcp-proxy").expect("必须有 mcp-proxy 行");
    assert_eq!(mcp.throughput_per_min, 7, "吞吐必须来自链上聚合: {rows:?}");
    // 链上没有记录的拦截点仍为 0（不编造）
    let hook = rows.iter().find(|row| row.point == "process-hook").expect("必须有 process-hook 行");
    assert_eq!(hook.throughput_per_min, 0, "{rows:?}");
}

#[test]
fn intercept_point_rows_project_real_p95_latency() {
    let mut p95: BTreeMap<String, i64> = BTreeMap::new();
    p95.insert("process-hook".to_string(), 12);
    let rows = intercept_point_rows(&[InterceptPoint::ProcessHook], &BTreeMap::new(), &BTreeMap::new(), &p95);
    let hook = rows.iter().find(|row| row.point == "process-hook").expect("必须有 process-hook 行");
    assert_eq!(hook.p95_latency_ms, 12, "p95 必须来自链上耗时样本聚合: {rows:?}");
    // 没有样本的点位（含占位行 egress-proxy）如实为 0
    let mcp = rows.iter().find(|row| row.point == "mcp-proxy").expect("必须有 mcp-proxy 行");
    assert_eq!(mcp.p95_latency_ms, 0, "{rows:?}");
    let egress = rows.iter().find(|row| row.point == "egress-proxy").expect("必须有 egress-proxy 行");
    assert_eq!(egress.p95_latency_ms, 0, "占位行永远是 0: {rows:?}");
}

#[test]
fn endpoint_specs_use_absolute_paths_and_are_counted() {
    let specs = endpoint_specs();
    assert_eq!(specs.len(), 16, "控制台端点应为 16 条");
    for spec in &specs {
        // 路径统一为**完整路径**（与 `platform::endpoint_specs()` 的既有条目一致）：
        // `EndpointSpec.path` 是 `&'static str`，运行期无法拼前缀，
        // 而 `/overview` 与 `/healthz` 同为绝对形状、无法靠形状区分是否要加前缀。
        assert!(spec.path.starts_with("/api/v1/"), "清单路径必须是完整路径（与 platform 一致）: {}", spec.path);
        assert!(!spec.path.ends_with('/'), "路径不应以斜杠结尾: {}", spec.path);
        assert!(!spec.id.is_empty() && !spec.summary.is_empty() && !spec.tag.is_empty(), "{}", spec.path);
    }
    assert_eq!(specs.iter().filter(|spec| spec.implemented).count(), 16, "16 条控制台端点全部已实现");
    assert!(specs.iter().any(|spec| spec.id == "consoleCreateUser"));
    assert!(specs.iter().any(|spec| spec.id == "consoleUpdateUser"));
    assert!(specs.iter().any(|spec| spec.id == "consoleIngestReplay"));
    assert!(specs.iter().any(|spec| spec.id == "consoleIngestReplayExecute"));
    let not_implemented: Vec<&str> = specs.iter().filter(|s| !s.implemented).map(|s| s.path).collect();
    assert!(not_implemented.is_empty(), "不应再有未实现端点: {not_implemented:?}");
}
