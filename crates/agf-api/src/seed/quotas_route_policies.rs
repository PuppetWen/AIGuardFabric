//! 配额与模型路由策略灌入（自 seed.rs 拆出，逻辑未变）。

use super::*;

// ===========================================================================
// 配额
// ===========================================================================

/// 确保租户默认配额存在（[`ApiStore::quota_ensure_defaults`] 幂等），并如实记录本次新增条数。
pub(super) fn seed_quotas(
    store: &ApiStore,
    tenant: TenantId,
    quota: &QuotaDefaults,
    report: &mut SeedReport,
) -> DomainResult<()> {
    let before = store.quota_list(tenant)?.len();
    let stat = report.stat(DS_QUOTAS, SYNTHETIC_SOURCE);
    settle(store.quota_ensure_defaults(tenant, quota), DS_QUOTAS, "quota_ensure_defaults", stat)?;
    let after = store.quota_list(tenant)?.len();
    let stat = report.stat(DS_QUOTAS, SYNTHETIC_SOURCE);
    // ensure_defaults 是"缺什么补什么"，用前后差值给出真实新增数（首次 4 条，重复调用 0 条）
    stat.inserted = after.saturating_sub(before);
    stat.skipped = before;
    stat.note = format!("租户默认配额（tenant 级 4 维）；当前共 {after} 条");
    info!(dataset = DS_QUOTAS, total = after, "演示配额已就绪");
    Ok(())
}

// ===========================================================================
// 模型路由策略（演示记录：agf-aigw 没有策略实体）
// ===========================================================================

/// 演示模型路由策略规格：`(确定性键, 名称, 策略, 日预算美元)`。
const DEMO_ROUTE_SPECS: [(&str, &str, &str, f64); 2] = [
    ("route:demo-cost-first", "演示-成本优先路由（合成）", "cost-first", 20.0),
    ("route:demo-latency-first", "演示-延迟优先路由（合成）", "latency-first", 5.0),
];

/// 灌模型路由策略（**演示记录**，`agf-aigw` 没有策略实体可读）。
///
/// 主端点取台账里真实存在的 `ModelEndpoint` 资产（`ast-model-0001`）；**降级链一律为空**——
/// fixtures 只登记了 1 个模型端点，编造未登记的 endpoint id 会让控制台点开就是 404。
///
/// # 降级
/// 台账没有该资产（fixtures 缺失/降级）时只 `warn` + 记 `warnings`，不写任何策略。
pub(super) fn seed_route_policies(
    store: &ApiStore,
    tenant: TenantId,
    refs: &CrossRefs,
    report: &mut SeedReport,
) -> DomainResult<()> {
    let Some(endpoint_id) = refs.asset("ast-model-0001") else {
        warn!(dataset = DS_ROUTE_POLICIES, "台账没有模型端点资产，跳过演示路由策略（不伪造端点引用）");
        report.warnings.push(format!("{DS_ROUTE_POLICIES}：台账没有模型端点资产，跳过演示路由策略"));
        let stat = report.stat(DS_ROUTE_POLICIES, SYNTHETIC_SOURCE);
        stat.skipped += 1;
        stat.note = "无模型端点资产（fixtures 未灌入）".to_string();
        return Ok(());
    };
    for (key, name, strategy, budget) in DEMO_ROUTE_SPECS {
        let id = deterministic_id(NS_RUNTIME, key);
        if store.route_policy_get(tenant, id)?.is_some() {
            report.stat(DS_ROUTE_POLICIES, SYNTHETIC_SOURCE).skipped += 1;
            continue;
        }
        let policy = ModelRoutePolicy {
            version: 0,
            id,
            tenant_id: tenant,
            name: name.to_string(),
            primary_endpoint_id: endpoint_id.to_string(),
            // 台账只有 1 个模型端点：降级链为空（不编造）
            fallback_endpoint_ids: Vec::new(),
            strategy: strategy.to_string(),
            weights: BTreeMap::new(),
            budget_cny_per_day: budget,
            enabled: true,
        };
        let stat = report.stat(DS_ROUTE_POLICIES, SYNTHETIC_SOURCE);
        settle(store.route_policy_upsert(&policy), DS_ROUTE_POLICIES, "route_policy_upsert", stat)?;
    }
    let stat = report.stat(DS_ROUTE_POLICIES, SYNTHETIC_SOURCE);
    stat.note = format!(
        "演示记录（agf-aigw 无策略实体）：{} 条，主端点 {}；降级链为空（台账仅 1 个模型端点）",
        DEMO_ROUTE_SPECS.len(),
        endpoint_id
    );
    Ok(())
}
