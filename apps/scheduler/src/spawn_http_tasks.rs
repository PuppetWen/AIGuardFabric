//! 由 `main.rs` 拆分：`spawn_http_tasks` 等 11 个函数（纯搬移，逻辑不变）。
use super::*;

/// Red-team scheduling shares the platform's case versions, history and cancellation state.
pub(crate) fn spawn_redteam_task(
    registry: Arc<Registry>,
    client: &reqwest::Client,
    config: tasks::CruiseConfig,
    interval_secs: u64,
) {
    let client = client.clone();
    spawn_periodic(
        registry,
        "redteam-cruise",
        task_enabled("redteam-cruise"),
        task_period("redteam-cruise", interval_secs),
        move |partition| {
            let config = config.clone();
            let client = client.clone();
            async move { tasks::run_redteam_cruise(&client, &config, partition).await }
        },
    );
}

/// 三个需要 `AGF_SERVER_URL` / 拉取源的周期任务。
pub(crate) fn spawn_http_tasks(
    registry: Arc<Registry>,
    client: &reqwest::Client,
    config: HttpTaskConfig,
    interval_secs: u64,
) {
    let asset = config.clone();
    let client_asset = client.clone();
    spawn_periodic(
        Arc::clone(&registry),
        "asset-inventory",
        task_enabled("asset-inventory"),
        task_period("asset-inventory", interval_secs),
        move |partition| {
            let config = asset.clone();
            let client = client_asset.clone();
            async move {
                if !partition.first() {
                    return TaskOutcome::skipped("汇总统计由分片 0 执行");
                }
                let cloud_note = if config.agentteams_sync {
                    let sync = tasks::run_agentteams_sync(
                        &client,
                        &config.server_url,
                        config.auth.as_ref(),
                        config.agentteams_confirm_live,
                    )
                    .await;
                    if !sync.ok {
                        return sync;
                    }
                    Some(sync.note)
                } else {
                    None
                };
                let mut stats =
                    tasks::run_asset_inventory(&client, &config.server_url, config.auth.as_ref(), &config.report_dir)
                        .await;
                if let Some(note) = cloud_note {
                    stats.note = format!("{note}；{}", stats.note);
                }
                stats
            }
        },
    );

    let pull = config.clone();
    let client_pull = client.clone();
    spawn_periodic(
        Arc::clone(&registry),
        "log-pull",
        task_enabled("log-pull"),
        task_period("log-pull", interval_secs),
        move |partition| {
            let config = pull.clone();
            let client = client_pull.clone();
            async move {
                if config.pull_urls.trim().is_empty() {
                    tasks::run_configured_pull(&client, &config.server_url, config.auth.as_ref(), partition).await
                } else {
                    let urls = tasks::parse_pull_urls(&config.pull_urls)
                        .into_iter()
                        .filter(|url| partition.owns(url))
                        .collect::<Vec<_>>()
                        .join(",");
                    tasks::run_log_pull(&client, &urls, None, &config.report_dir).await
                }
            }
        },
    );

    let reload = config.clone();
    let client_reload = client.clone();
    spawn_periodic(
        Arc::clone(&registry),
        "rule-hot-reload",
        task_enabled("rule-hot-reload"),
        task_period("rule-hot-reload", interval_secs),
        move |partition| {
            let config = reload.clone();
            let client = client_reload.clone();
            async move {
                if !partition.first() {
                    return TaskOutcome::skipped("规则重载由分片 0 执行");
                }
                tasks::run_rule_hot_reload(&client, &config.server_url, config.auth.as_ref(), &config.rules_dir).await
            }
        },
    );
}

/// 冷归档周期任务。
pub(crate) fn spawn_archive_task(registry: Arc<Registry>, config: ArchiveTaskConfig, interval_secs: u64) {
    spawn_periodic(
        registry,
        "cold-archive",
        task_enabled("cold-archive"),
        task_period("cold-archive", interval_secs),
        move |partition| {
            let job = config.job.clone();
            async move { tasks::run_cold_archive(job, partition).await }
        },
    );
}

/// 周期报表任务。
pub(crate) fn spawn_report_task(registry: Arc<Registry>, config: ReportTaskConfig, interval_secs: u64) {
    let source = Arc::clone(&registry);
    spawn_periodic(
        registry,
        "report-generate",
        task_enabled("report-generate"),
        task_period("report-generate", interval_secs),
        move |partition| {
            let config = config.clone();
            let registry = Arc::clone(&source);
            async move {
                if !partition.first() {
                    return TaskOutcome::skipped("汇总报表由分片 0 执行");
                }
                let cms_note = tasks::note_get(&registry.notes, "alicloud-cms-push");
                tasks::run_report_generate(
                    &config.rules,
                    &config.redteam,
                    &config.output,
                    registry.snapshot(),
                    cms_note,
                )
            }
        },
    );
}

/// CMS 指标先保存不可变 payload，再通过平台持久队列交付。
pub(crate) fn spawn_cms_task(registry: Arc<Registry>, config: CmsTaskConfig, interval_secs: u64) {
    let source = Arc::clone(&registry);
    spawn_periodic(
        registry,
        "alicloud-cms-push",
        task_enabled("alicloud-cms-push"),
        task_period("alicloud-cms-push", interval_secs),
        move |partition| {
            let config = config.clone();
            let registry = Arc::clone(&source);
            async move {
                if !partition.first() {
                    return TaskOutcome::skipped("CMS 指标由分片 0 执行");
                }
                let snapshot = registry.snapshot();
                let rules = registry.rules_count().map(|count| count as usize);
                let rate = registry.redteam_rate();
                tasks::run_cms_queue(&config, snapshot, rules, rate).await
            }
        },
    );
}

/// 毫秒耗时。
pub(crate) fn millis(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// 存活检查。
pub(crate) async fn healthz() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "agf-scheduler",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// 就绪检查：任务注册表摘要。
pub(crate) async fn readyz(registry: Arc<Registry>) -> impl IntoResponse {
    let failures: BTreeMap<&str, u64> = registry
        .tasks
        .iter()
        .map(|(name, state)| (*name, state.failures.load(Ordering::Relaxed)))
        .filter(|(_, failures)| *failures > 0)
        .collect();
    axum::Json(serde_json::json!({
        "status": "ready",
        // 8 个周期任务全部已实现 → 不再是"因缺实现而降级"；仅当失败计数上升时需要关注。
        "degraded": !failures.is_empty(),
        "reason": if failures.is_empty() {
            "8 个周期任务全部已实现；无失败计数"
        } else {
            "存在失败计数的任务（外部依赖不可达时属预期，见 /tasks），不阻断就绪"
        },
        "implemented_tasks": registry.tasks.len(),
        "todo_tasks": 0,
        "task_failures": failures,
    }))
}

/// 任务清单 JSON（同步纯函数，便于单测）。
///
/// 每项含：`name` / `status`（恒为 `implemented`）/ `note`（最近一次真实执行结论）/
/// `requirement`（生效所需的配置）/ `runs` / `failures` / `last_millis`。
/// **不含 `todo` 字段**（8 个任务均已实现）。
pub(crate) fn tasks_value(registry: &Registry) -> serde_json::Value {
    let items: Vec<serde_json::Value> = tasks::catalog()
        .into_iter()
        .map(|descriptor| {
            let state = registry.state(descriptor.name);
            let runs = state.map_or(0, |s| s.runs.load(Ordering::Relaxed));
            let failures = state.map_or(0, |s| s.failures.load(Ordering::Relaxed));
            let last_millis = state.map_or(0, |s| s.last_millis.load(Ordering::Relaxed));
            let note = tasks::note_get(&registry.notes, descriptor.name)
                .unwrap_or_else(|| format!("尚未执行（等待首个周期）：{}", descriptor.note));
            serde_json::json!({
                "name": descriptor.name,
                "status": "implemented",
                "note": note,
                "requirement": descriptor.note,
                "runs": runs,
                "failures": failures,
                "last_millis": last_millis,
            })
        })
        .collect();
    serde_json::json!({
        "backend": if registry.execution.cloud { "schedulerx3" } else { "local-cron" },
        "receipts_persistent": registry.execution.persistent,
        "tenant_id": registry.execution.tenant,
        "interval_secs": env_or("AGF_SCHEDULER_INTERVAL_SECS", "3600"),
        "implemented": tasks::TASK_NAMES.len(),
        "todo": 0,
        "tasks": items,
    })
}

/// 任务清单（实现态 + 最近一次执行结论）。
pub(crate) async fn tasks_json(registry: Arc<Registry>) -> impl IntoResponse {
    axum::Json(tasks_value(&registry))
}

/// Prometheus 文本指标（覆盖全部 8 个任务的 runs / failures / last_millis）。
pub(crate) fn metrics_text(registry: Arc<Registry>) -> (StatusCode, [(String, String); 1], String) {
    let mut body = String::from(
        "# HELP agf_scheduler_task_runs_total 任务执行次数\n\
         # TYPE agf_scheduler_task_runs_total counter\n",
    );
    for (name, state) in &registry.tasks {
        let runs = state.runs.load(Ordering::Relaxed);
        body.push_str(&format!("agf_scheduler_task_runs_total{{task=\"{name}\"}} {runs}\n"));
    }
    body.push_str(
        "# HELP agf_scheduler_task_failures_total 任务失败次数\n\
         # TYPE agf_scheduler_task_failures_total counter\n",
    );
    for (name, state) in &registry.tasks {
        let failures = state.failures.load(Ordering::Relaxed);
        body.push_str(&format!("agf_scheduler_task_failures_total{{task=\"{name}\"}} {failures}\n"));
    }
    body.push_str(
        "# HELP agf_scheduler_task_last_millis 任务最近一次耗时（毫秒）\n\
         # TYPE agf_scheduler_task_last_millis gauge\n",
    );
    for (name, state) in &registry.tasks {
        let last = state.last_millis.load(Ordering::Relaxed);
        body.push_str(&format!("agf_scheduler_task_last_millis{{task=\"{name}\"}} {last}\n"));
    }
    (StatusCode::OK, [("content-type".to_string(), "text/plain; version=0.0.4".to_string())], body)
}

/// Ctrl-C / SIGTERM 优雅关闭。
pub(crate) async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %e, "无法监听 Ctrl-C");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => tracing::warn!(error = %e, "无法监听 SIGTERM"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("收到关闭信号，等待在途任务结束…");
}
