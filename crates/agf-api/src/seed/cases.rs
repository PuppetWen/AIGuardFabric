//! 案件（cases）映射、灌入与跨表引用解析（自 seed.rs 拆出，逻辑未变）。

use super::*;

// ===========================================================================
// 案件
// ===========================================================================

/// 映射案件状态（fixtures 的 `contained` → 领域模型的"处置中"）。
pub(super) fn map_case_state(raw: Option<&str>) -> Result<CaseState, String> {
    match raw.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        None | Some("new") => Ok(CaseState::New),
        Some("investigating") => Ok(CaseState::Investigating),
        Some("contained" | "containing") => Ok(CaseState::Containing),
        Some("resolved") => Ok(CaseState::Resolved),
        Some("closed") => Ok(CaseState::Closed),
        Some(other) => Err(format!("未知案件状态: {other}")),
    }
}

/// 目标状态 → 合法流转路径（[`agf_core::case::Case::can_transition_to`] 只允许逐级推进）。
fn case_transition_path(target: CaseState) -> &'static [CaseState] {
    match target {
        CaseState::New => &[],
        CaseState::Investigating => &[CaseState::Investigating],
        CaseState::Containing => &[CaseState::Investigating, CaseState::Containing],
        CaseState::Resolved => &[CaseState::Investigating, CaseState::Resolved],
        CaseState::Closed => &[CaseState::Investigating, CaseState::Resolved, CaseState::Closed],
    }
}

/// 灌案件（按标题判重；`case_create` 的 ID 由 store 生成，见模块文档的"幂等性"说明）。
pub(super) fn seed_cases(
    store: &ApiStore,
    root: &Path,
    tenant: TenantId,
    report: &mut SeedReport,
    refs: &mut CrossRefs,
) -> DomainResult<()> {
    let file = "cases.json";
    let items = match load_items(root, file) {
        Ok((items, note)) => {
            if let Some(note) = note {
                report.warnings.push(format!("{DS_CASES}：{note}"));
            }
            items
        }
        Err(reason) => {
            mark_dataset_unavailable(report, DS_CASES, file, &reason);
            return Ok(());
        }
    };
    let existing: BTreeMap<String, Id> = store.case_list(tenant)?.into_iter().map(|c| (c.title, c.id)).collect();
    for item in &items {
        let business_key = match req_str(item, "id") {
            Ok(key) => key,
            Err(error) => {
                warn!(dataset = DS_CASES, error = %error, "演示案件字段非法，已跳过该条（降级）");
                report.stat(DS_CASES, file).errors += 1;
                continue;
            }
        };
        let title = req_str(item, "title").unwrap_or_else(|_| business_key.clone());
        if let Some(existing_id) = existing.get(&title).copied() {
            report.stat(DS_CASES, file).skipped += 1;
            refs.cases.insert(business_key, existing_id);
            continue;
        }
        match case_from_item(store, item, tenant, &title, refs, report) {
            Ok(case_id) => {
                refs.cases.insert(business_key, case_id);
            }
            Err(error) => {
                warn!(dataset = DS_CASES, case = %business_key, error = %error, "演示案件写入失败，已跳过（降级）");
                report.stat(DS_CASES, file).errors += 1;
            }
        }
    }
    Ok(())
}

/// 写入单条案件（含状态流转与时间线），返回其 ID。
fn case_from_item(
    store: &ApiStore,
    item: &Value,
    tenant: TenantId,
    title: &str,
    refs: &CrossRefs,
    report: &mut SeedReport,
) -> DomainResult<Id> {
    const FILE: &str = "cases.json";
    let severity = Severity::parse(&req_str(item, "severity").map_err(DomainError::Validation)?)
        .map_err(DomainError::Validation)?;
    let target_state = map_case_state(opt_str(item, "status").as_deref()).map_err(DomainError::Validation)?;

    let finding_ids = resolve_refs(item, "finding_ids", &refs.findings, "案件引用的发现", title, report);
    let alert_ids = resolve_refs(item, "alert_ids", &refs.alerts, "案件引用的告警", title, report);
    let asset_ids: Vec<Id> = finding_ids
        .iter()
        .filter_map(|id| store.finding_get(tenant, *id).ok().flatten())
        .filter_map(|f| f.asset_id)
        .collect();

    let summary = opt_str(item, "summary").unwrap_or_else(|| format!("演示案件（合成）：{title}"));
    let owner = opt_str(item, "owner");
    let case =
        store.case_create(tenant, title, &summary, severity, &alert_ids, &finding_ids, &asset_ids, owner.as_deref())?;
    report.stat(DS_CASES, FILE).inserted += 1;
    for step in case_transition_path(target_state) {
        let stat = report.stat(DS_CASES, FILE);
        tolerate(store.case_set_state(tenant, case.id, *step, None), DS_CASES, "case_set_state", stat)?;
    }
    let stat = report.stat(DS_CASES, FILE);
    tolerate(
        store.case_add_event(
            tenant,
            case.id,
            agf_core::case::CaseEventKind::Comment,
            DEMO_ACTOR,
            "演示数据灌库生成（合成，非真实处置记录）",
        ),
        DS_CASES,
        "case_add_event",
        stat,
    )?;
    Ok(case.id)
}

/// 解析一组业务键引用；不可解析的引用计入 `errors` 并跳过该键。
fn resolve_refs(
    item: &Value,
    key: &str,
    table: &BTreeMap<String, Id>,
    what: &str,
    owner: &str,
    report: &mut SeedReport,
) -> Vec<Id> {
    let mut resolved = Vec::new();
    for business_key in str_list(item, key) {
        match table.get(&business_key).copied() {
            Some(id) => resolved.push(id),
            None => {
                warn!(dataset = DS_CASES, owner = %owner, reference = %business_key, what, "跨表引用未解析到（忽略该引用）");
                report.stat(DS_CASES, "cases.json").errors += 1;
            }
        }
    }
    resolved
}
