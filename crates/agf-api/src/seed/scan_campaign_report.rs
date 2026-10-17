//! 扫描任务、红队战役与报表的合成灌入（自 seed.rs 拆出，逻辑未变）。

use super::*;

// ===========================================================================
// 红队用例索引（无存储面，仅校验）
// ===========================================================================

/// 校验 `redteam-cases.json`：解析 + 检查 `policy_id` 是否指向本次灌入的策略。
///
/// 该数据集**没有对应的内存表**（红队用例库来自 `redteam/*.yaml`），因此条数如实记入
/// [`DatasetReport::skipped`] 而非 `inserted`，不伪造存储面。
pub(super) fn check_redteam_case_index(root: &Path, report: &mut SeedReport, refs: &CrossRefs) {
    let file = "redteam-cases.json";
    let items = match load_items(root, file) {
        Ok((items, note)) => {
            if let Some(note) = note {
                report.warnings.push(format!("{DS_REDTEAM_CASES}：{note}"));
            }
            items
        }
        Err(reason) => {
            mark_dataset_unavailable(report, DS_REDTEAM_CASES, file, &reason);
            return;
        }
    };
    let mut unresolved = 0_usize;
    for item in &items {
        let Ok(business_key) = req_str(item, "id") else {
            warn!(dataset = DS_REDTEAM_CASES, "红队用例索引条目缺少 id，已跳过");
            report.stat(DS_REDTEAM_CASES, file).errors += 1;
            continue;
        };
        if let Some(policy_key) = opt_str(item, "policy_id") {
            if !refs.policies.contains_key(&policy_key) {
                warn!(dataset = DS_REDTEAM_CASES, case = %business_key, policy = %policy_key, "索引引用的策略未解析到");
                unresolved += 1;
            }
        }
        report.stat(DS_REDTEAM_CASES, file).skipped += 1;
    }
    let stat = report.stat(DS_REDTEAM_CASES, file);
    stat.errors += unresolved;
    stat.note = format!(
        "无对应存储面（红队用例库来自 redteam/*.yaml 的 CaseLibrary）：仅解析校验 {} 条，其中策略引用未解析 {unresolved} 条",
        items.len()
    );
}

// ===========================================================================
// 合成运行时对象：扫描任务
// ===========================================================================

/// 灌 2 个扫描任务（**合成，仅为演示**）：1 个终态 `succeeded`、1 个 `running`。
pub(super) fn seed_scans(store: &ApiStore, tenant: TenantId, report: &mut SeedReport) -> DomainResult<()> {
    let now = Timestamp::now();
    let jobs = vec![
        ScanJob {
            id: deterministic_id(NS_RUNTIME, "scan:demo-inventory"),
            tenant_id: tenant,
            name: "演示-资产盘点扫描（合成）".to_string(),
            state: ScanJobState::Succeeded,
            targets: 8,
            domains: vec!["asset".to_string(), "runtime".to_string()],
            progress: 100,
            use_llm_judge: false,
            rule_hits: BTreeMap::from([("AGF-ASSET-021".to_string(), 1_usize), ("AGF-PROMPT-001".to_string(), 1)]),
            finding_count: 6,
            risk_score: Some(92),
            finding_ids: Vec::new(),
            llm_mocked: None,
            judgement_count: 0,
            judgement_failures: 0,
            max_severity: Severity::Critical.as_str().to_string(),
            summary: "演示扫描已完成（合成）：8 个 AI 资产、6 条发现".to_string(),
            elapsed_ms: 12_480,
            error: None,
            requested_by: DEMO_ACTOR.to_string(),
            created_at: now.offset_secs(-3_600),
            started_at: Some(now.offset_secs(-3_590)),
            finished_at: Some(now.offset_secs(-3_478)),
        },
        ScanJob {
            id: deterministic_id(NS_RUNTIME, "scan:demo-prompt-regression"),
            tenant_id: tenant,
            name: "演示-提示词注入回归（合成）".to_string(),
            state: ScanJobState::Running,
            targets: 3,
            domains: vec!["prompt-attack".to_string()],
            progress: 42,
            use_llm_judge: true,
            rule_hits: BTreeMap::from([("AGF-PROMPT-001".to_string(), 2_usize)]),
            finding_count: 0,
            risk_score: None,
            finding_ids: Vec::new(),
            llm_mocked: None,
            judgement_count: 0,
            judgement_failures: 0,
            max_severity: Severity::Info.as_str().to_string(),
            summary: "演示扫描执行中（合成）：3 个目标，进度 42%".to_string(),
            elapsed_ms: 1_230,
            error: None,
            requested_by: DEMO_ACTOR.to_string(),
            created_at: now.offset_secs(-120),
            started_at: Some(now.offset_secs(-110)),
            finished_at: None,
        },
    ];
    for job in jobs {
        let stat = report.stat(DS_SCANS, SYNTHETIC_SOURCE);
        if store.scan_get(tenant, job.id)?.is_some() {
            stat.skipped += 1;
        } else {
            settle(store.scan_insert(job), DS_SCANS, "scan_insert", stat)?;
        }
    }
    report.stat(DS_SCANS, SYNTHETIC_SOURCE).note = "合成，仅为演示：1 个终态 succeeded + 1 个 running".to_string();
    Ok(())
}

// ===========================================================================
// 合成运行时对象：红队战役（真实用例库 + 离线模拟目标）
// ===========================================================================

/// 灌 1 个已完成的红队战役（**合成，仅为演示**）+ 逐用例结果 + Markdown 报告。
///
/// 用真实用例库 [`CaseLibrary`]（`redteam/*.yaml`）在 [`RedteamSimulator`] 离线目标上跑
/// [`CampaignRunner::run`]，与 `apps/scheduler` 的 `redteam-cruise` 任务同源。
/// 用例库为空（目录缺失等降级场景）时跳过并如实记录，不影响其余数据集。
pub(super) fn seed_campaign(
    store: &ApiStore,
    tenant: TenantId,
    library: &CaseLibrary,
    refs: &CrossRefs,
    report: &mut SeedReport,
) -> DomainResult<()> {
    let campaign_id = deterministic_id(NS_RUNTIME, "redteam-campaign:demo-cruise");
    if library.cases().is_empty() {
        mark_campaign_skipped(report, "红队用例库为空（redteam/*.yaml 未加载），跳过合成战役");
        return Ok(());
    }
    if store.campaign_get(tenant, campaign_id)?.is_some() {
        let stat = report.stat(DS_CAMPAIGNS, SYNTHETIC_SOURCE);
        stat.skipped += 1;
        stat.note = "合成战役已存在（幂等跳过）".to_string();
        return Ok(());
    }
    let cases: Vec<&agf_core::redteam::RedteamCase> = library.cases().iter().collect();
    // 离线模拟目标：防护强度 35（与 agf-scheduler 的巡航任务同口径）
    let target = RedteamSimulator::new("demo-offline-agent", 35);
    let runner = CampaignRunner::new();
    // `CampaignRunner::run` 是 async，但离线模拟目标内部不真正挂起；`now_or_never`
    // 单次轮询即可拿到结果，避免在同步的 `AppState::build` 里引入运行时依赖。
    let Some(outcome) = runner.run(tenant, CAMPAIGN_NAME, &cases, &target, DEMO_ACTOR, false).now_or_never() else {
        mark_campaign_skipped(report, "红队战役在未来的一次轮询内未就绪，跳过合成战役");
        return Ok(());
    };
    let (mut campaign, outcomes, mut detail) = match outcome {
        Ok(value) => value,
        Err(error) => {
            warn!(error = %error, "合成红队战役执行失败，已跳过（降级）");
            let stat = report.stat(DS_CAMPAIGNS, SYNTHETIC_SOURCE);
            stat.errors += 1;
            stat.note = format!("战役执行失败：{error}");
            return Ok(());
        }
    };

    let target_asset = refs.asset("ast-agent-0001");
    campaign.id = campaign_id;
    campaign.name = CAMPAIGN_NAME.to_string();
    campaign.launched_by = DEMO_ACTOR.to_string();
    if let Some(agent) = target_asset {
        campaign.target_agent_ids = vec![agent];
    }
    let results: Vec<RedteamResult> = outcomes
        .iter()
        .map(|outcome| {
            let mut result = outcome.to_result(tenant, campaign_id);
            result.id = deterministic_id(NS_RUNTIME, &format!("redteam-result:{}", outcome.case_key));
            if let Some(agent) = target_asset {
                result.target_asset_id = agent;
            }
            result
        })
        .collect();
    detail.id = deterministic_id(NS_RUNTIME, "redteam-report:demo-cruise");
    detail.campaign_id = campaign_id;
    detail.title = format!("{CAMPAIGN_NAME}报告");
    let markdown = render_markdown(&campaign, &outcomes, &detail);
    detail.markdown = markdown;

    let stat = report.stat(DS_CAMPAIGNS, SYNTHETIC_SOURCE);
    settle(store.campaign_insert(campaign), DS_CAMPAIGNS, "campaign_insert", stat)?;
    let stat = report.stat(DS_CAMPAIGNS, SYNTHETIC_SOURCE);
    tolerate(
        store.campaign_store_outcome(tenant, campaign_id, results, detail),
        DS_CAMPAIGNS,
        "campaign_store_outcome",
        stat,
    )?;
    let stat = report.stat(DS_CAMPAIGNS, SYNTHETIC_SOURCE);
    stat.note = format!("合成，仅为演示：真实用例库 {} 条用例在离线模拟目标上跑一轮，含逐用例结果与报告", cases.len());
    Ok(())
}

/// 记录一次"合成战役被跳过"。
fn mark_campaign_skipped(report: &mut SeedReport, reason: &str) {
    warn!(reason, "合成红队战役已跳过（降级）");
    report.warnings.push(format!("{DS_CAMPAIGNS}：{reason}"));
    let stat = report.stat(DS_CAMPAIGNS, SYNTHETIC_SOURCE);
    stat.skipped += 1;
    stat.note = reason.to_string();
}

// ===========================================================================
// 合成运行时对象：报表
// ===========================================================================

/// 灌 2 份报表（**合成，仅为演示**）：1 份 Markdown 态势总览、1 份 JSON 明细。
pub(super) fn seed_reports(
    store: &ApiStore,
    tenant: TenantId,
    refs: &CrossRefs,
    report: &mut SeedReport,
) -> DomainResult<()> {
    let markdown_id = deterministic_id(NS_RUNTIME, "report:demo-posture");
    let json_id = deterministic_id(NS_RUNTIME, "report:demo-findings");
    let counts = serde_json::json!({
        "assets": refs.assets_by_business.len(),
        "findings": refs.findings.len(),
        "alerts": refs.alerts.len(),
        "cases": refs.cases.len(),
        "policies": refs.policies.len(),
    });

    let markdown_body = format!(
        "# 演示环境安全态势总览（合成）\n\n\
         > 本报表由 `agf-api` 演示数据灌库（`AGF_SEED_FIXTURES=1`）合成，**不是真实业务数据**。\n\n\
         | 指标 | 数量 |\n|---|---|\n\
         | AI 资产 | {} |\n| 风险发现 | {} |\n| 告警 | {} |\n| 案件 | {} |\n| 策略 | {} |\n\n\
         生成时间：{}\n",
        refs.assets_by_business.len(),
        refs.findings.len(),
        refs.alerts.len(),
        refs.cases.len(),
        refs.policies.len(),
        Timestamp::now().to_rfc3339(),
    );
    let mut markdown_report = crate::store::new_report(
        tenant,
        ReportKind::Posture,
        "演示-安全态势总览（合成）",
        TimeRange::last_day(),
        markdown_body,
        None,
    );
    markdown_report.id = markdown_id;

    let json_body = serde_json::to_string_pretty(&serde_json::json!({
        "synthetic": true,
        "note": "演示报表（合成），由 AGF_SEED_FIXTURES 灌库生成",
        "generated_at": Timestamp::now().to_rfc3339(),
        "counts": counts,
        "assets": refs.assets_by_business.keys().cloned().collect::<Vec<_>>(),
        "findings": refs.findings.keys().cloned().collect::<Vec<_>>(),
    }))
    .unwrap_or_else(|_| "{}".to_string());
    let mut json_report = crate::store::new_report(
        tenant,
        ReportKind::Findings,
        "演示-风险发现明细（合成）",
        TimeRange::last_day(),
        json_body,
        None,
    );
    json_report.id = json_id;
    json_report.format = ReportFormat::Json;

    for item in [markdown_report, json_report] {
        let stat = report.stat(DS_REPORTS, SYNTHETIC_SOURCE);
        if store.report_get(tenant, item.id)?.is_some() {
            stat.skipped += 1;
        } else {
            settle(store.report_insert(item), DS_REPORTS, "report_insert", stat)?;
        }
    }
    report.stat(DS_REPORTS, SYNTHETIC_SOURCE).note = "合成，仅为演示：1 份 Markdown + 1 份 JSON".to_string();
    Ok(())
}
