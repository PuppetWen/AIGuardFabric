//! 控制台总览端点（`/overview`）与 KPI / 趋势 / 适配器健康投影。

use super::*;

// ===========================================================================
// 总览
// ===========================================================================

/// 控制台总览（`GET /api/v1/overview`）。
///
/// # Errors
/// 权限不足（`assets:read`）或存储错误。
pub(super) async fn overview(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<DashboardOverviewView>> {
    principal.require(&state, "assets", "read")?;
    let tenant = principal.tenant;
    let allowed = |resource| principal.require(&state, resource, "read").is_ok();
    let access: BTreeMap<String, bool> = ["findings", "alerts", "models", "redteam", "alicloud"]
        .into_iter()
        .map(|resource| (resource.into(), allowed(resource)))
        .collect();
    let assets = state.store.asset_list_all_durable(tenant).await?;
    let findings = if allowed("findings") { state.store.finding_list_all_durable(tenant).await? } else { vec![] };
    let alerts = if allowed("alerts") { state.store.alert_list_durable(tenant, None, None).await? } else { vec![] };
    let redteam = if allowed("redteam") { state.store.campaign_live_success_rate(tenant).await? } else { None };
    let usage = if allowed("models") { crate::gateway_quota::usage(&state, tenant).await? } else { vec![] };

    // 资产 → 未关闭发现数（与 platform_snapshot 的 `findings_open` 同口径）。
    let mut open_by_asset: BTreeMap<Id, i64> = BTreeMap::new();
    for finding in &findings {
        if is_closed_finding(finding.state) {
            continue;
        }
        if let Some(asset_id) = finding.asset_id {
            *open_by_asset.entry(asset_id).or_insert(0) += 1;
        }
    }

    // 未授权或尚未观测的指标保留 null，不与实际零值混淆。
    let token_spend = model_cost_cny(&usage);
    let kpis = vec![
        kpi("assets", "unit.assets", Some(assets.len() as f64)),
        kpi(
            "openAlerts",
            "unit.findings",
            allowed("alerts").then(|| alerts.iter().filter(|alert| alert.is_active()).count() as f64),
        ),
        kpi(
            "criticalFindings",
            "unit.findings",
            allowed("findings").then(|| {
                findings.iter().filter(|f| f.severity == Severity::Critical && !is_closed_finding(f.state)).count()
                    as f64
            }),
        ),
        kpi("redteamSuccessRate", "common.unit.percent", redteam),
        kpi("tokenSpend", "common.unit.cny", token_spend),
    ];

    // 仅在有发现读取权限时采样，禁止把无权读取误记为零。
    let high_open = findings
        .iter()
        .filter(|f| !is_closed_finding(f.state) && matches!(f.severity, Severity::Critical | Severity::High))
        .count();
    let now = Timestamp::now();
    if allowed("findings") {
        state.risk_history.record(tenant, now, high_open as f64);
    }
    let risk_trend = state
        .risk_history
        .points(tenant)
        .into_iter()
        .filter(|_| allowed("findings"))
        .map(|sample| SeriesPointView { ts: sample.at.to_rfc3339(), value: sample.value })
        .collect();

    // 域分布：资产按 kind 归域（与 demo 的 domainOfAsset 同口径），发现按 domain 归域。
    let mut asset_domain: BTreeMap<&'static str, i64> = BTreeMap::new();
    for asset in &assets {
        *asset_domain.entry(asset_domain_of_kind(asset.kind)).or_insert(0) += 1;
    }
    let mut finding_domain: BTreeMap<&'static str, (i64, i64)> = BTreeMap::new();
    for finding in &findings {
        let entry = finding_domain.entry(risk_domain_frontend(finding.domain)).or_insert((0, 0));
        entry.0 += 1;
        if finding.severity == Severity::Critical {
            entry.1 += 1;
        }
    }
    let domain_distribution = FRONTEND_DOMAINS
        .iter()
        .map(|domain| {
            let assets = asset_domain.get(domain).copied().unwrap_or(0);
            let (findings, critical) = finding_domain.get(domain).copied().unwrap_or((0, 0));
            DomainDistributionView {
                domain: (*domain).to_string(),
                assets,
                findings: allowed("findings").then_some(findings),
                critical: allowed("findings").then_some(critical),
            }
        })
        .collect();

    // TOP 风险资产：按风险分倒序取前 8。
    let mut ranked: Vec<&Asset> = assets.iter().collect();
    ranked.sort_by_key(|asset| std::cmp::Reverse(asset_risk_score(asset)));
    let top_risk_assets = ranked
        .into_iter()
        .take(8)
        .map(|asset| asset_view(asset, allowed("findings").then(|| open_by_asset.get(&asset.id).copied().unwrap_or(0))))
        .collect();

    // 最近告警：按 last_seen_at 倒序取前 6（资产名反查台账）。
    let names: BTreeMap<Id, String> = assets.iter().map(|a| (a.id, a.name.clone())).collect();
    let mut recent: Vec<&agf_core::alert::Alert> = alerts.iter().collect();
    recent.sort_by_key(|alert| std::cmp::Reverse(alert.last_seen_at));
    let recent_alerts = recent
        .into_iter()
        .take(6)
        .map(|alert| RecentAlertView {
            id: alert.id.to_string(),
            title: alert.title.clone(),
            severity: alert.severity.as_str().to_string(),
            domain: alert.domain.map_or("runtime", risk_domain_frontend).to_string(),
            asset_name: alert.asset_ids.first().and_then(|id| names.get(id)).cloned().unwrap_or_default(),
            occurred_at: alert.last_seen_at.to_rfc3339(),
            status: alert_state_frontend(alert.state).to_string(),
        })
        .collect();

    Ok(Json(DashboardOverviewView {
        kpis,
        risk_trend,
        domain_distribution,
        top_risk_assets,
        recent_alerts,
        adapter_health: if allowed("alicloud") { adapter_health(&state) } else { vec![] },
        access,
        generated_at: now.to_rfc3339(),
    }))
}

/// 没有可比的历史窗口时，不构造变化率和趋势。
pub(super) fn kpi(key: &str, unit: &str, value: Option<f64>) -> DashboardKpiView {
    DashboardKpiView {
        key: key.to_string(),
        label: key.to_string(),
        value,
        unit: unit.to_string(),
        delta: None,
        sparkline: Vec::new(),
    }
}

/// Retained live model calls, converted from micro-CNY.
fn model_cost_cny(usage: &[agf_core::model::UsageRecord]) -> Option<f64> {
    let mut actual = usage.iter().filter(|row| !row.mocked).peekable();
    actual.peek()?;
    Some(actual.map(|row| u128::from(row.cost_micro)).sum::<u128>() as f64 / 1_000_000.0)
}

/// 适配器健康条：来自阿里云适配器注册表（健康度与可用率是占位，见模块文档）。
pub(super) fn adapter_health(state: &AppState) -> Vec<AdapterHealthBarView> {
    state
        .alicloud
        .records()
        .into_iter()
        .map(|record| AdapterHealthBarView {
            id: record.service.as_str().to_string(),
            name: record.descriptor.display_name.clone(),
            category: adapter_category(&record.descriptor.category),
            health: "unknown".to_string(),
            uptime_percent: None,
            mock: record.mode.is_mock(),
        })
        .collect()
}

/// 适配器类别：命中前端 `AdapterCategory` 就原样保留，否则归 `cloud`。
fn adapter_category(raw: &str) -> String {
    const KNOWN: [&str; 9] = ["llm-provider", "edr", "siem", "soar", "iam", "cloud", "dlp", "notify", "storage"];
    let normalized = raw.trim().to_ascii_lowercase().replace('_', "-");
    if KNOWN.contains(&normalized.as_str()) { normalized } else { "cloud".to_string() }
}
