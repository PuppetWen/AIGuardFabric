//! 由 `tasks.rs` 拆分：`collect_report_input` 等 6 个函数（纯搬移，逻辑不变）。
use super::*;

/// 从磁盘真实读取报表输入（缺文件/缺目录 → 对应字段 `None`，不编数字）。
#[must_use]
pub(crate) fn collect_report_input(
    rules_dir: &Path,
    redteam_dir: &Path,
    report_dir: &Path,
    tasks: Vec<TaskSnapshot>,
    cms_note: Option<String>,
) -> ReportInput {
    let mut input = ReportInput {
        generated_at: chrono::Utc::now().to_rfc3339(),
        rules_dir: rules_dir.display().to_string(),
        tasks,
        cms_note,
        ..ReportInput::default()
    };

    if let Ok(pack) = RulePackLoader::strict().load_dir(&RulesDir::new(rules_dir.to_path_buf())) {
        input.rules_count = Some(pack.len());
        input.rules_fingerprint = Some(pack.report.pack_fingerprint.clone());
    }
    if let Ok(library) = CaseLibrary::load_dir(redteam_dir) {
        input.redteam_cases = Some(library.cases().len());
    }
    input.redteam_reports = list_matching(report_dir, "redteam-cruise-", ".md", 5);
    if let Some(path) = latest_file(report_dir, "asset-inventory-", ".json") {
        if let Ok(raw) = std::fs::read_to_string(&path) {
            input.asset_summary = summarize_asset_stats(&raw).map(|(summary, _)| asset_summary_text(&summary));
        }
    }
    if let Some(path) = latest_file(report_dir, "log-pull-", ".json") {
        if let Ok(raw) = std::fs::read_to_string(&path) {
            input.log_pull_summary = serde_json::from_str::<LogPullStats>(&raw).ok().map(|stats| log_pull_text(&stats));
        }
    }
    if let Some(path) = latest_file(report_dir, "archive-", ".json") {
        if let Ok(raw) = std::fs::read_to_string(&path) {
            input.archive = serde_json::from_str::<ArchiveManifest>(&raw).ok();
        }
    }
    input
}

/// 任务：周期报表生成（无数据时也生成，并写明"本期无数据"）。
pub(crate) fn run_report_generate(
    rules_dir: &Path,
    redteam_dir: &Path,
    report_dir: &Path,
    tasks: Vec<TaskSnapshot>,
    cms_note: Option<String>,
) -> TaskOutcome {
    let input = collect_report_input(rules_dir, redteam_dir, report_dir, tasks, cms_note);
    let markdown = render_report(&input);
    let path = report_dir.join(format!("report-{}.md", now_slug()));
    match std::fs::write(&path, &markdown) {
        Ok(()) => {
            let has_data = input.rules_count.is_some() || input.redteam_cases.is_some() || !input.tasks.is_empty();
            let note = if has_data {
                format!("报表已生成（{} 字节，任务表 {} 行）", markdown.len(), input.tasks.len())
            } else {
                format!("报表已生成（{} 字节），本期无数据", markdown.len())
            };
            TaskOutcome::ok(note).with_artifact(path.display().to_string())
        }
        Err(e) => TaskOutcome::failed(format!("报表落盘失败（{}）：{e}", path.display())),
    }
}

// ---------------------------------------------------------------------------
// alicloud-cms-push
// ---------------------------------------------------------------------------

/// 本地统计 → CMS 自定义指标（纯映射，测试直接断言数值）。
#[must_use]
pub(crate) fn cms_metrics(
    tasks: &[TaskSnapshot],
    rules_count: Option<usize>,
    redteam_success_rate: Option<f64>,
) -> Vec<(String, f64)> {
    let runs: u64 = tasks.iter().map(|t| t.runs).sum();
    let failures: u64 = tasks.iter().map(|t| t.failures).sum();
    let mut metrics = vec![
        ("agf_scheduler_task_runs".to_string(), runs as f64),
        ("agf_scheduler_task_failures".to_string(), failures as f64),
    ];
    if let Some(count) = rules_count {
        metrics.push(("agf_rules_total".into(), count as f64));
    }
    if let Some(rate) = redteam_success_rate {
        metrics.push(("agf_redteam_success_rate".into(), rate * 100.0));
    }
    metrics
}

/// 真实模式用的适配器配置（凭据走 `AGF_ALIYUN_*` 环境变量解析器）。
#[must_use]
#[cfg(test)]
pub(crate) fn live_cms_config(region: &str) -> AdapterConfig {
    let mut settings = BTreeMap::new();
    settings.insert("region_id".to_string(), serde_json::Value::String(region.to_string()));
    settings.insert("credential_source".to_string(), serde_json::Value::String("env".to_string()));
    AdapterConfig {
        id: Id::nil(),
        tenant_id: TenantId::default_tenant(),
        adapter: "alicloud-cms".to_string(),
        display_name: "agf-scheduler CMS 指标上报".to_string(),
        enabled: true,
        settings,
        secret_refs: BTreeMap::new(),
        circuit_breaker: CircuitBreakerConfig::default(),
        retry: RetryConfig::default(),
        timeout_secs: 15,
        mock: false,
        is_default: false,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    }
}

/// 适配器边界测试专用；生产周期任务只能通过持久队列。
#[cfg(test)]
pub(crate) async fn run_cms_push_with(
    adapter: &CmsAdapter,
    metrics: &[(String, f64)],
    group_id: &str,
    note_prefix: &str,
) -> TaskOutcome {
    let mocked = adapter.core().is_mock();
    if !mocked && group_id.trim().is_empty() {
        return TaskOutcome::failed("CMS 自定义指标需要 AGF_CMS_GROUP_ID，请填写云监控应用分组 ID");
    }
    let mut pushed = Vec::new();
    let mut errors = Vec::new();
    for (name, value) in metrics {
        let mut metric = CmsMetric::new(name.clone(), *value);
        metric.group_id = group_id.trim().into();
        metric.dimensions.insert("service".to_string(), "agf-scheduler".to_string());
        match adapter.put_metric(&metric).await {
            Ok(request_id) => pushed.push(format!("{name}={value}（{request_id}）")),
            Err(e) => {
                tracing::warn!(metric = %name, error = %e, "CMS 指标上报失败");
                errors.push(format!("{name}: {e}"));
            }
        }
    }
    cms_push_outcome(mocked, metrics.len(), &pushed, &errors, note_prefix)
}

/// 任一上传失败都不能成为成功回执；同时保留真实成功数量和 Mock 降级标识。
#[cfg(test)]
pub(crate) fn cms_push_outcome(
    mocked: bool,
    total: usize,
    pushed: &[String],
    errors: &[String],
    note_prefix: &str,
) -> TaskOutcome {
    let mode = if mocked { "Mock 模式（未真实触达云监控，标注 mocked）" } else { "真实模式" };
    let note = format!(
        "{note_prefix}CMS 指标 {}/{} 条已上报，失败 {} 条，{mode}；指标：{}",
        pushed.len(),
        total,
        errors.len(),
        pushed.join(", ")
    );
    if !errors.is_empty() {
        let mut outcome = TaskOutcome::failed(format!("{note}；失败指标：{}", errors.join("；")));
        outcome.degraded = mocked;
        return outcome;
    }
    if mocked {
        // 无凭据走 Mock → 不算失败，但显式降级标注。
        return TaskOutcome::degraded(note);
    }
    TaskOutcome::ok(note)
}
