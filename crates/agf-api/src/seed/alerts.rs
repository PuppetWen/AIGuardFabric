//! 告警（alerts）映射与灌入（自 seed.rs 拆出，逻辑未变）。

use super::*;

// ===========================================================================
// 告警
// ===========================================================================

/// 映射告警状态。
pub(super) fn map_alert_state(raw: Option<&str>) -> Result<AlertState, String> {
    match raw.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        None | Some("open") => Ok(AlertState::Open),
        Some("acknowledged") => Ok(AlertState::Acknowledged),
        Some("suppressed") => Ok(AlertState::Suppressed),
        Some("escalated") => Ok(AlertState::Escalated),
        Some("closed") => Ok(AlertState::Closed),
        Some(other) => Err(format!("未知告警状态: {other}")),
    }
}

/// 灌告警。
///
/// 幂等策略：先按**标题**查已存在告警（[`ApiStore::alert_list`]），命中即跳过 ——
/// 既不产生重复行，也不会因为重复调用而累加 `dedup_count`。
pub(super) fn seed_alerts(
    store: &ApiStore,
    root: &Path,
    tenant: TenantId,
    report: &mut SeedReport,
    refs: &mut CrossRefs,
) -> DomainResult<()> {
    let file = "alerts.json";
    let items = match load_items(root, file) {
        Ok((items, note)) => {
            if let Some(note) = note {
                report.warnings.push(format!("{DS_ALERTS}：{note}"));
            }
            items
        }
        Err(reason) => {
            mark_dataset_unavailable(report, DS_ALERTS, file, &reason);
            return Ok(());
        }
    };
    let existing: BTreeMap<String, Id> =
        store.alert_list(tenant, None, None)?.into_iter().map(|a| (a.title, a.id)).collect();
    for item in &items {
        let business_key = match req_str(item, "id") {
            Ok(key) => key,
            Err(error) => {
                warn!(dataset = DS_ALERTS, error = %error, "演示告警字段非法，已跳过该条（降级）");
                report.stat(DS_ALERTS, file).errors += 1;
                continue;
            }
        };
        if let Some(existing_id) = existing.get(&req_str(item, "title").unwrap_or_default()).copied() {
            report.stat(DS_ALERTS, file).skipped += 1;
            refs.alerts.insert(business_key, existing_id);
            continue;
        }
        let mapped = alert_from_item(store, item, tenant, refs, report);
        match mapped {
            Ok(alert_id) => {
                refs.alerts.insert(business_key, alert_id);
            }
            Err(error) => {
                warn!(dataset = DS_ALERTS, alert = %business_key, error = %error, "演示告警写入失败，已跳过（降级）");
                report.stat(DS_ALERTS, file).errors += 1;
            }
        }
    }
    Ok(())
}

/// 写入单条告警，返回其 ID（状态非 `open` 时补一次状态流转）。
fn alert_from_item(
    store: &ApiStore,
    item: &Value,
    tenant: TenantId,
    refs: &CrossRefs,
    report: &mut SeedReport,
) -> DomainResult<Id> {
    const FILE: &str = "alerts.json";
    let title = req_str(item, "title").map_err(DomainError::Validation)?;
    let severity = Severity::parse(&req_str(item, "severity").map_err(DomainError::Validation)?)
        .map_err(DomainError::Validation)?;
    let state = map_alert_state(opt_str(item, "status").as_deref()).map_err(DomainError::Validation)?;

    let asset_id = opt_str(item, "asset").as_deref().and_then(|name| refs.asset_by_name(name));
    if asset_id.is_none() && opt_str(item, "asset").is_some() {
        warn!(dataset = DS_ALERTS, alert = %title, "告警引用的资产未解析到（该引用置空）");
        report.stat(DS_ALERTS, FILE).errors += 1;
    }
    let finding_id = opt_str(item, "finding_id").as_deref().and_then(|key| refs.findings.get(key).copied());
    if finding_id.is_none() && opt_str(item, "finding_id").is_some() {
        warn!(dataset = DS_ALERTS, alert = %title, "告警引用的发现未解析到（该引用置空）");
        report.stat(DS_ALERTS, FILE).errors += 1;
    }
    // 告警的安全域跟随其来源发现，保持与发现口径一致
    let domain = finding_domain(store, tenant, finding_id)?;
    let count = opt_u64(item, "count").unwrap_or(1);
    let description = format!(
        "演示告警（合成）：来源 {}，发生 {count} 次；关联资产 {}",
        opt_str(item, "source").unwrap_or_else(|| "-".to_string()),
        opt_str(item, "asset").unwrap_or_else(|| "-".to_string())
    );
    let asset_ids: Vec<Id> = asset_id.into_iter().collect();
    let finding_ids: Vec<Id> = finding_id.into_iter().collect();
    let dedup_key = agf_core::alert::Alert::compute_dedup_key(tenant, domain, asset_ids.first(), &title);

    let (alert_id, created) = store.alert_upsert_dedup(
        tenant,
        &dedup_key,
        &title,
        &description,
        severity,
        domain,
        &asset_ids,
        &finding_ids,
    )?;
    {
        let stat = report.stat(DS_ALERTS, FILE);
        if created {
            stat.inserted += 1;
        } else {
            stat.skipped += 1;
        }
    }
    if created && state != AlertState::Open {
        let stat = report.stat(DS_ALERTS, FILE);
        tolerate(store.alert_set_state(tenant, alert_id, state, None), DS_ALERTS, "alert_set_state", stat)?;
    }
    Ok(alert_id)
}

/// 读取发现所属安全域（找不到时返回 `None`，`alert_upsert_dedup` 允许无域）。
fn finding_domain(store: &ApiStore, tenant: TenantId, finding_id: Option<Id>) -> DomainResult<Option<RiskDomain>> {
    let Some(id) = finding_id else {
        return Ok(None);
    };
    Ok(store.finding_get(tenant, id)?.map(|f| f.domain))
}
