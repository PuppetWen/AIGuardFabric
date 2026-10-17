//! 运行时只读端点：黑名单视图 / 事件 / 拦截点 / 配额。

use super::*;

// ===========================================================================
// 运行时：黑名单 / 事件 / 拦截点 / 配额
// ===========================================================================

/// 运行时黑名单（`GET /api/v1/runtime/blacklists`）：**裸数组**。
///
/// 数据源是 `agf_runtime::blocklist::default_rules()`（内置分级黑名单），只输出 domain.ts 支持
/// 的 `command`/`domain` 两类（见模块文档）。
///
/// # Errors
/// 权限不足（`policies:read`）或拦截链读取错误。
pub(super) async fn list_blacklists(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<Vec<BlacklistEntryView>>> {
    // 权限先判，再读运行时状态。
    principal.require(&state, "policies", "read")?;
    let rows = crate::runtime_rules::load(&state, principal.tenant).await?;
    let since = Timestamp::now().offset_secs(-86400);
    let records = crate::runtime_audit::list(&state, principal.tenant).await?;
    Ok(Json(
        rows.rules
            .into_iter()
            .filter_map(|row| {
                let mut view = blacklist_view(&row.rule, &row.updated_at.to_rfc3339())?;
                view.enabled = row.enabled;
                view.version = row.version;
                view.hits_24h = records
                    .iter()
                    .filter(|record| record.at >= since && record.blocklist_rules.contains(&row.rule.id))
                    .count() as i64;
                Some(view)
            })
            .collect(),
    ))
}

/// 黑名单规则 → 视图；前端不支持的类别返回 `None`（不篡改类别）。
pub(super) fn blacklist_view(rule: &RuleRule, updated_at: &str) -> Option<BlacklistEntryView> {
    let kind = match rule.kind {
        RuleKind::Command => "command",
        RuleKind::Domain => "domain",
        RuleKind::Path | RuleKind::Tool | RuleKind::Hash => return None,
    };
    Some(BlacklistEntryView {
        id: rule.id.clone(),
        kind: kind.to_string(),
        pattern: rule.pattern.clone(),
        action: match rule.action {
            RuleAction::Deny => "deny",
            RuleAction::Allow => "allow",
            // 黑名单的 `audit` 语义是"放行但记录"，前端 `PolicyAction` 用 `alert` 表达。
            RuleAction::Audit => "alert",
        }
        .to_string(),
        // 内置规则是平台级闸门；domain.ts 的 `QuotaScope` 没有 platform 取值，故记 tenant。
        scope: "tenant".to_string(),
        enabled: true,
        version: 0,
        // 无统计读取接口（TODO(api-console-blacklist-stats)）。
        hits_24h: 0,
        note: rule.reason.clone(),
        updated_at: updated_at.to_string(),
    })
}

/// 拦截事件流（`GET /api/v1/runtime/events`）：**裸数组**，来自运行时拦截审计链。
///
/// # Errors
/// 权限不足（`policies:read`）或存储错误。
pub(super) async fn list_runtime_events(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<Vec<InterceptEventView>>> {
    principal.require(&state, "policies", "read")?;
    let names: BTreeMap<Id, String> = state
        .store
        .asset_list_all_durable(principal.tenant)
        .await?
        .into_iter()
        .map(|a| (a.id, a.name.clone()))
        .collect();
    let mut records = crate::runtime_audit::list(&state, principal.tenant).await?;
    records.sort_by_key(|record| std::cmp::Reverse(record.at));
    Ok(Json(
        records
            .into_iter()
            .map(|record| InterceptEventView {
                id: record.id.to_string(),
                ts: record.at.to_rfc3339(),
                point: record.intercept_point.as_str().to_string(),
                agent_name: record.agent_id.and_then(|id| names.get(&id).cloned()).unwrap_or_else(|| "-".to_string()),
                // 拦截链只有工具名，没有 MCP 名。
                mcp_name: None,
                tool_name: record.tool_name.clone(),
                action: policy_action_frontend(record.action).to_string(),
                policy_name: record.policy_name.clone().unwrap_or_else(|| "-".to_string()),
                reason: record.reason.clone(),
                payload_digest: record.entry_hash.clone(),
                // 审计链存微秒；事件流按毫秒展示同一次拦截的实测耗时。
                latency_ms: record.latency_micros as f64 / 1000.0,
                severity: record.severity.unwrap_or(Severity::Info).as_str().to_string(),
            })
            .collect(),
    ))
}

/// 拦截点状态（`GET /api/v1/runtime/intercept-points`）：**裸数组**。
///
/// # Errors
/// 权限不足（`policies:read`）。
pub(super) async fn list_intercept_points(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<Vec<InterceptPointStatusView>>> {
    principal.require(&state, "policies", "read")?;
    let required = state.runtime.config().required_intercept_points();
    // 阻断计数与吞吐**同源**：同一份拦截审计链（真实；无流量时为 0）。
    let records = crate::runtime_audit::list(&state, principal.tenant).await?;
    let blocked: BTreeMap<&'static str, i64> = {
        let mut map: BTreeMap<&'static str, i64> = BTreeMap::new();
        for record in &records {
            if record.verdict.is_blocking() && record.at >= Timestamp::now().offset_secs(-86400) {
                *map.entry(record.intercept_point.as_str()).or_insert(0) += 1;
            }
        }
        map
    };
    // 吞吐 = 最近 60 秒落在该拦截点上的链上条目数（即"条/分钟"，滚动窗口，非累计）。
    // `now` 只取一次：两条口径必须落在同一时间基准上。
    let now = Timestamp::now();
    let throughput = crate::metrics::interception_snapshot(&records, now, THROUGHPUT_WINDOW_SECS).by_point;
    // p95 时延：同一份链、更宽的窗口（分位数需要足够样本），微秒样本向上取整到毫秒。
    let latency_p95 =
        crate::metrics::interception_latency_p95_ms(&records, now, crate::metrics::INTERCEPTION_P95_WINDOW_SECS);
    let mut rows = intercept_point_rows(&required, &blocked, &throughput, &latency_p95);
    for row in &mut rows {
        if matches!(row.point.as_str(), "mcp-proxy" | "ai-gateway") {
            row.enabled = true;
            row.mode = "enforce".into();
            row.health = "healthy".into();
            row.last_error = None;
        }
    }
    Ok(Json(rows))
}

/// 拦截点行：**恒 4 行**，顺序与前端 `InterceptPoint` 枚举一致。
///
/// - `mcp-proxy`/`ai-gateway`/`process-hook`：来自引擎的 `required_intercept_points()`（真实配置）；
/// - `egress-proxy`：**占位行**——`agf-runtime` 没有独立的出网代理拦截点（出网管控由
///   mcp-proxy / ai-gateway 上的域名黑名单与策略承担），但控制台枚举里有这一项，
///   因此给一行 `enabled=false` + 明确说明，而不是把后端的 `collector`（南向采集网关）
///   冒充成 `egress-proxy`。
///
/// 数值来源（逐项如实标注）：
///
/// - `blocked_24h`：拦截审计链上判定为阻断的条数（真实，与 `/runtime/events` 同源）；
/// - `throughput_per_min`：**最近 60 秒**落在该拦截点上的链上条目数（真实，滚动窗口；
///   无流量即 0，见 [`THROUGHPUT_WINDOW_SECS`]）；
/// - `p95_latency_ms`：**最近 [`crate::metrics::INTERCEPTION_P95_WINDOW_SECS`] 秒**内该点位的
///   链上耗时样本（`InterceptionRecord::latency_micros`，由拦截入口真实测量）的
///   **最近秩法 p95**，微秒样本**向上取整**到毫秒（见
///   [`crate::metrics::interception_latency_p95_ms`]）。窗口内**没有样本的点位如实为 0**；
///   链上条目若来自旧版本（无该字段，反序列化为 0）或测试手工构造，则按 0µs 参与统计
///   ——那是真实取值，不做剔除。
///
/// `enabled` 恒 `false`：agf-api 进程内没有承载这些拦截点的代理/钩子服务（引擎已装配、无流量入口）。
pub(super) fn intercept_point_rows(
    required: &[InterceptPoint],
    blocked: &BTreeMap<&'static str, i64>,
    throughput: &BTreeMap<String, u64>,
    latency_p95_ms: &BTreeMap<String, i64>,
) -> Vec<InterceptPointStatusView> {
    const FRONTEND_POINTS: [&str; 4] = ["mcp-proxy", "ai-gateway", "process-hook", "egress-proxy"];
    FRONTEND_POINTS
        .iter()
        .map(|point| {
            let configured = required.iter().any(|candidate| candidate.as_str() == *point);
            let last_error = if *point == "egress-proxy" {
                "agf-runtime 无独立出网代理拦截点（占位行）：出网管控由 mcp-proxy / ai-gateway 的域名黑名单与策略承担".to_string()
            } else if configured {
                format!(
                    "引擎已装配该拦截点（required_intercept_points），但 agf-api 进程内没有承载它的代理/钩子服务：实际拦截由独立部署的 {point} 组件承担"
                )
            } else {
                format!("该拦截点未在 EngineConfig 中声明（当前 required 拦截点仅 {} 个）", required.len())
            };
            InterceptPointStatusView {
                point: (*point).to_string(),
                enabled: false,
                mode: "bypass".to_string(),
                health: "unknown".to_string(),
                throughput_per_min: throughput.get(*point).copied().unwrap_or(0) as i64,
                blocked_24h: blocked.get(point).copied().unwrap_or(0),
                p95_latency_ms: latency_p95_ms.get(*point).copied().unwrap_or(0),
                version: crate::VERSION.to_string(),
                last_error: Some(last_error),
            }
        })
        .collect()
}

/// 运行时配额（`GET /api/v1/runtime/quotas`）：**裸数组**，与 `GET /quotas/snapshot` 同源。
///
/// # Errors
/// 权限不足（`quotas:read`）或存储错误。
pub(super) async fn list_runtime_quotas(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<Vec<QuotaUsageView>>> {
    principal.require(&state, "quotas", "read")?;
    let tenant = principal.tenant;
    let usage = crate::runtime_quota::usage(&state, tenant).await?;
    let quotas = crate::quota_definitions::list(&state, tenant).await?;
    let names: BTreeMap<Id, String> =
        state.store.asset_list_all_durable(tenant).await?.into_iter().map(|a| (a.id, a.name.clone())).collect();
    let now = Timestamp::now();
    Ok(Json(
        quotas
            .iter()
            .map(|quota| {
                let used = usage.get(&quota.id).copied().unwrap_or(0);
                QuotaUsageView {
                    scope: quota.scope.as_str().to_string(),
                    scope_id: quota.target_id.map_or_else(|| tenant.to_string(), |id| id.to_string()),
                    scope_name: quota
                        .target_id
                        .and_then(|id| names.get(&id).cloned())
                        .unwrap_or_else(|| quota.name.clone()),
                    unit: quota_unit(quota.dimension).to_string(),
                    used,
                    limit: quota.limit,
                    window_start: quota_window_start(quota, now).to_rfc3339(),
                    window_end: now.to_rfc3339(),
                    throttled: quota.is_exceeded(used),
                }
            })
            .collect(),
    ))
}

/// 配额维度 → 前端单位（domain.ts 的 `unit` 没有金额取值，`cost` 按 `calls` 呈现）。
pub(super) const fn quota_unit(dimension: QuotaDimension) -> &'static str {
    match dimension {
        QuotaDimension::Tokens => "tokens",
        QuotaDimension::Concurrency => "sessions",
        QuotaDimension::Requests | QuotaDimension::Cost => "calls",
    }
}

/// 窗口起点：按配额窗口精度回推；`session`/`total` 不滚动，取配额创建时间。
fn quota_window_start(quota: &Quota, now: Timestamp) -> Timestamp {
    let at = now.as_datetime();
    match quota.window {
        QuotaWindow::Minute => now.offset_secs(-60),
        QuotaWindow::Hour => now.offset_secs(-3_600),
        QuotaWindow::Day => day_start(at).unwrap_or_else(|| now.offset_secs(-86_400)),
        QuotaWindow::Month => month_start(at).unwrap_or_else(|| now.offset_secs(-2_592_000)),
        QuotaWindow::Session | QuotaWindow::Total => quota.created_at,
    }
}

/// 当日 00:00:00Z。
fn day_start(at: chrono::DateTime<chrono::Utc>) -> Option<Timestamp> {
    at.date_naive().and_hms_opt(0, 0, 0).map(|naive| Timestamp::from_datetime(naive.and_utc()))
}

/// 当月 1 日 00:00:00Z。
fn month_start(at: chrono::DateTime<chrono::Utc>) -> Option<Timestamp> {
    use chrono::Datelike;
    at.date_naive().with_day(1)?.and_hms_opt(0, 0, 0).map(|naive| Timestamp::from_datetime(naive.and_utc()))
}
