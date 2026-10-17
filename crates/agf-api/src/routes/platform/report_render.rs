//! Report data rendering.
use super::*;
pub async fn render_report(
    state: &AppState,
    tenant: agf_core::ids::TenantId,
    kind: ReportKind,
    range: &TimeRange,
) -> agf_core::error::DomainResult<String> {
    let inventory = state.store.asset_stats_durable(tenant).await?;
    let findings: Vec<_> = state
        .store
        .finding_list_all_durable(tenant)
        .await?
        .into_iter()
        .filter(|r| r.first_seen_at >= range.from && r.first_seen_at < range.to)
        .collect();
    let alerts: Vec<_> = state
        .store
        .alert_list_durable(tenant, None, None)
        .await?
        .into_iter()
        .filter(|r| r.first_seen_at >= range.from && r.first_seen_at < range.to)
        .collect();
    let cases: Vec<_> = state
        .store
        .case_list_durable(tenant)
        .await?
        .into_iter()
        .filter(|r| r.created_at >= range.from && r.created_at < range.to)
        .collect();
    let policies = crate::policy_store::list(state, tenant).await?;
    let platform = state.store.platform_snapshot_durable(tenant).await?;
    let (audit_entries, audit_tail) = state.store.audit_stats_durable(tenant).await?;

    let mut out = String::new();
    out.push_str(&format!("# {} 报表\n\n", kind.as_str()));
    out.push_str(&format!("- 生成时间：{}\n", Timestamp::now().to_rfc3339()));
    out.push_str(&format!("- 统计窗口：{} ~ {}\n", range.from.to_rfc3339(), range.to.to_rfc3339()));
    out.push_str(&format!("- 租户：{tenant}\n"));
    out.push_str(&format!("- 运行模式：{}（mock_mode={}）\n\n", state.mode.as_str(), state.config.force_mock()));

    out.push_str("## 1. 平台概览（生成时快照）\n\n");
    out.push_str(&format!(
        "| 指标 | 数值 |\n|---|---|\n| 资产总数 | {} |\n| 生产资产 | {} |\n| 未评审 MCP | {} |\n| 待处置发现 | {} |\n| 严重发现 | {} |\n| 活动告警 | {} |\n| 未关闭案件 | {} |\n| 策略数 | {} |\n| 扫描任务 | {} |\n\n",
        platform.assets,
        platform.assets_production,
        platform.shadow_mcps,
        platform.findings_open,
        platform.findings_critical,
        state.store.alert_list_durable(tenant, None, None).await?.iter().filter(|alert| alert.is_active()).count(),
        platform.cases_open,
        platform.policies,
        platform.scans
    ));

    out.push_str("## 2. 资产盘点（生成时快照）\n\n");
    out.push_str(&format!("- 资产总数：{}\n", inventory.total));
    out.push_str(&format!("- 影子资产：{}\n", inventory.shadow));
    out.push_str(&format!("- 高暴露资产（≥70）：{}\n", inventory.high_exposure));
    out.push_str(&format!("- 含明文凭据资产：{}\n\n", inventory.with_plaintext_secret));
    out.push_str("| 资产类型 | 数量 |\n|---|---|\n");
    for (key, value) in &inventory.by_kind {
        out.push_str(&format!("| {key} | {value} |\n"));
    }
    out.push('\n');

    out.push_str("## 3. 窗口内首次发现的风险\n\n");
    out.push_str(&format!("- 发现总数：{}\n", findings.len()));
    let critical = findings.iter().filter(|f| f.severity.as_str() == "critical").count();
    let verified = findings.iter().filter(|f| f.state.as_str() == "verified").count();
    out.push_str(&format!("- 严重：{critical}\n- 已验证：{verified}\n\n"));
    out.push_str("| 域 | 数量 |\n|---|---|\n");
    for domain in agf_core::enums::RiskDomain::all() {
        let count = findings.iter().filter(|f| f.domain == domain).count();
        out.push_str(&format!("| {} | {} |\n", domain.display_zh(), count));
    }
    out.push('\n');

    out.push_str("## 4. 窗口内新告警与案件\n\n");
    out.push_str(&format!("- 告警总数：{}\n", alerts.len()));
    out.push_str(&format!("- 活动告警：{}\n", alerts.iter().filter(|a| a.is_active()).count()));
    out.push_str(&format!("- 案件总数：{}\n", cases.len()));
    out.push_str(&format!("- 未关闭案件：{}\n\n", cases.iter().filter(|c| !c.is_closed()).count()));

    out.push_str("## 5. 策略与拦截（生成时快照）\n\n");
    out.push_str(&format!("- 策略总数：{}\n", policies.len()));
    out.push_str(&format!("- 启用策略：{}\n", policies.iter().filter(|p| p.enabled).count()));
    out.push_str(&format!("- 观察模式（dry-run）策略：{}\n\n", policies.iter().filter(|p| p.dry_run).count()));

    out.push_str("## 6. 审计链健康\n\n");
    out.push_str(&format!("- 审计条目：{audit_entries}\n- 链尾哈希：{audit_tail}\n"));
    let verification = state.store.audit_verify_durable(tenant).await?;
    out.push_str(&format!(
        "- 链校验：{}（检查 {} 条，违例 {} 条）\n\n",
        if verification.passed { "通过" } else { "失败" },
        verification.checked,
        verification.violations.len()
    ));

    super::report_details::append(state, tenant, kind, range, &mut out).await?;
    out.push_str("## 8. 运行说明\n\n");
    for note in state.notes.iter() {
        out.push_str(&format!("- {note}\n"));
    }
    Ok(out)
}

/// 解析报表类型。
///
/// # Errors
/// 未知类型。
pub fn parse_report_kind(raw: &str) -> Result<ReportKind, ApiError> {
    let wanted = raw.trim().to_ascii_lowercase().replace('_', "-");
    ReportKind::all()
        .into_iter()
        .find(|k| k.as_str() == wanted)
        .ok_or_else(|| ApiError::new(DomainError::Validation(format!("未知报表类型: {raw}"))))
}
