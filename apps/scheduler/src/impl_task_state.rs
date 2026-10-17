//! 由 `main.rs` 拆分：`impl_TaskState`/`impl_Registry` 等 14 项（纯搬移，逻辑不变）。
use super::*;

impl TaskState {
    pub(crate) fn record(&self, ok: bool, millis: u64) {
        self.runs.fetch_add(1, Ordering::Relaxed);
        if !ok {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }
        self.last_millis.store(millis, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self, name: &str) -> TaskSnapshot {
        TaskSnapshot {
            name: name.to_string(),
            runs: self.runs.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            last_millis: self.last_millis.load(Ordering::Relaxed),
        }
    }
}

impl Registry {
    pub(crate) fn new() -> Self {
        let tasks = tasks::catalog().into_iter().map(|d| (d.name, TaskState::default())).collect();
        Self {
            execution: dispatch::Execution::offline(),
            handlers: Mutex::new(BTreeMap::new()),
            tasks,
            notes: tasks::new_note_store(),
            redteam_rate: Mutex::new(None),
            rules_count: AtomicU64::new(0),
        }
    }

    pub(crate) fn state(&self, name: &str) -> Option<&TaskState> {
        self.tasks.iter().find(|(task, _)| *task == name).map(|(_, state)| state)
    }

    /// 记录一次执行（任务不在册则静默忽略，由目录测试保证不会发生）。
    pub(crate) fn record(&self, name: &str, ok: bool, millis: u64) {
        if let Some(state) = self.state(name) {
            state.record(ok, millis);
        }
    }

    pub(crate) fn snapshot(&self) -> Vec<TaskSnapshot> {
        self.tasks.iter().map(|(name, state)| state.snapshot(name)).collect()
    }

    #[cfg(test)]
    pub(crate) fn set_redteam_rate(&self, rate: f64) {
        if let Ok(mut guard) = self.redteam_rate.lock() {
            *guard = Some(rate);
        }
    }

    pub(crate) fn redteam_rate(&self) -> Option<f64> {
        self.redteam_rate.lock().ok().and_then(|guard| *guard)
    }

    pub(crate) fn set_rules_count(&self, count: u64) {
        self.rules_count.store(count, Ordering::Relaxed);
    }

    pub(crate) fn rules_count(&self) -> Option<u64> {
        match self.rules_count.load(Ordering::Relaxed) {
            0 => None,
            count => Some(count),
        }
    }
}

/// 探测 `/healthz`。
pub(crate) async fn healthcheck(url: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(3)).build().context("构造 HTTP 客户端失败")?;
    match client.get(url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let _ = writeln!(std::io::stdout(), "OK {}", resp.status().as_u16());
            Ok(())
        }
        Ok(resp) => {
            let _ = writeln!(std::io::stderr(), "FAIL {} {}", url, resp.status().as_u16());
            std::process::exit(1);
        }
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "FAIL {url} {e}");
            std::process::exit(1);
        }
    }
}

/// 读取环境变量（空值视为未设置）。
pub(crate) fn env_or(key: &str, default: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => default.to_string(),
    }
}

/// 依次尝试多个环境变量，取第一个非空值。
pub(crate) fn optional_env(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        let value = env_or(key, "");
        if value.is_empty() { None } else { Some(value) }
    })
}

/// 解析路径：环境变量优先；容器里默认 `/app/<name>`，本机默认 `<项目根>/<name>`。
pub(crate) fn resolve_dir(key: &str, name: &str, fallback_root: &Path) -> PathBuf {
    let value = std::env::var(key).unwrap_or_default();
    if !value.trim().is_empty() {
        return PathBuf::from(value.trim());
    }
    let container = PathBuf::from(format!("/app/{name}"));
    if container.is_dir() {
        return container;
    }
    fallback_root.join(name)
}

/// 任务级环境变量前缀：`cold-archive` → `COLD_ARCHIVE`。
pub(crate) fn task_env_prefix(name: &str) -> String {
    name.replace('-', "_").to_ascii_uppercase()
}

/// 逐任务开关（`AGF_SCHEDULER_<TASK>_ENABLED`，缺省启用）。
pub(crate) fn task_enabled(name: &str) -> bool {
    let key = format!("AGF_SCHEDULER_{}_ENABLED", task_env_prefix(name));
    tasks::env_flag(std::env::var(key).ok().as_deref(), true)
}

/// 逐任务间隔（`AGF_SCHEDULER_<TASK>_INTERVAL_SECS`，缺省取全局间隔）。
pub(crate) fn task_period(name: &str, default_secs: u64) -> Duration {
    let key = format!("AGF_SCHEDULER_{}_INTERVAL_SECS", task_env_prefix(name));
    let secs: u64 = env_or(&key, &default_secs.to_string()).parse().unwrap_or(default_secs);
    Duration::from_secs(secs.max(5))
}

/// 启动调度。
pub(crate) async fn serve() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    let filter = env_or("RUST_LOG", "info");
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_target(false)
        .try_init();

    let host = env_or("AGF_SCHEDULER_HOST", "0.0.0.0");
    let port = env_or("AGF_SCHEDULER_PORT", "9101");
    let backend = env_or("AGF_SCHEDULER_BACKEND", "local-cron");
    let interval_secs: u64 = env_or("AGF_SCHEDULER_INTERVAL_SECS", "3600").parse().unwrap_or(3_600);
    let guard_strength: u8 = env_or("AGF_SCHEDULER_REDTEAM_GUARD", "30").parse().context("红队模拟强度必须为 0–100")?;
    anyhow::ensure!(guard_strength <= 100, "红队模拟强度必须为 0–100");
    let server_url = env_or("AGF_SERVER_URL", "http://127.0.0.1:9100");
    // 调 agf-api 的凭据：**API Key 优先**（服务账号拿不到 JWT），否则用外部注入的 JWT。
    // 两者互斥（API 侧同时收到会优先校验 X-AGF-Key 而直接 401），见 tasks::ApiAuth 文档。
    let api_key = optional_env(&["AGF_SCHEDULER_API_KEY", "AGF_API_KEY"]);
    let api_token = optional_env(&["AGF_SCHEDULER_API_TOKEN", "AGF_API_TOKEN"]);
    let api_auth = tasks::ApiAuth::from_values(api_key, api_token);
    let pull_urls = env_or("AGF_SCHEDULER_PULL_URLS", "");
    let agentteams_sync =
        tasks::env_flag(std::env::var("AGF_SCHEDULER_AGENTTEAMS_SYNC_ENABLED").ok().as_deref(), false);
    let agentteams_confirm_live =
        tasks::env_flag(std::env::var("AGF_SCHEDULER_AGENTTEAMS_CONFIRM_LIVE").ok().as_deref(), false);
    let archive_after_days: u64 = env_or("AGF_SCHEDULER_ARCHIVE_AFTER_DAYS", "7").parse().unwrap_or(7);
    let archive_delete_local =
        tasks::env_flag(std::env::var("AGF_SCHEDULER_ARCHIVE_DELETE_LOCAL").ok().as_deref(), false);
    let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let rules_dir = resolve_dir("AGF_RULES_DIR", "rules", &root);
    let redteam_dir = resolve_dir("AGF_REDTEAM_DIR", "redteam", &root);
    let tenant: TenantId = env_or("AGF_SCHEDULER_TENANT_ID", &TenantId::default_tenant().to_string())
        .parse()
        .map_err(|_| anyhow::anyhow!("调度租户 UUID 无效"))?;
    let scope_dir =
        |path: PathBuf| if tenant == TenantId::default_tenant() { path } else { path.join(tenant.to_string()) };
    let report_dir = scope_dir(PathBuf::from(env_or("AGF_REPORT_DIR", "data/reports")));
    let archive_dir = scope_dir(PathBuf::from(env_or("AGF_SCHEDULER_ARCHIVE_DIR", "data/archive")));
    if let Err(e) = std::fs::create_dir_all(&report_dir) {
        tracing::warn!(dir = %report_dir.display(), error = %e, "报表目录创建失败（报告将只落日志）");
    }

    tracing::info!(
        "调度后端={backend}；间隔={interval_secs}s；规则目录={}；红队目录={}；报告目录={}；归档目录={}",
        rules_dir.display(),
        redteam_dir.display(),
        report_dir.display(),
        archive_dir.display()
    );
    tracing::info!(
        server_url = %server_url,
        api_auth = %api_auth.as_ref().map_or("未配置（调用 agf-api 必然 401，见 /tasks 的 requirement）", |a| match a { tasks::ApiAuth::ApiKey(_) => "API Key（X-AGF-Key）", tasks::ApiAuth::Bearer(_) => "Bearer JWT" }),
        pull_sources = tasks::parse_pull_urls(&pull_urls).len(),
        archive_after_days,
        archive_delete_local,
        "周期任务外部依赖配置"
    );

    // 对象存储句柄（冷归档用）：S3 优先，失败/未配置 → build_object_store 自带降级，note 如实说明。
    let storage_cfg = storage_config();
    let (store, store_note) = agf_storage::build_object_store(&storage_cfg).await;
    tracing::info!(
        backend = store.backend(),
        note = store_note.as_deref().unwrap_or("对象存储就绪（真实后端）"),
        "冷归档对象存储已初始化"
    );

    let execution = callback::configure(
        &backend,
        &storage_cfg,
        Arc::clone(&store),
        &server_url,
        api_auth.as_ref(),
        vec![report_dir.clone(), archive_dir.clone()],
    )
    .await?;
    let mut registered = Registry::new();
    registered.execution = execution;
    let registry = Arc::new(registered);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .context("构造周期任务 HTTP 客户端失败")?;

    spawn_builtin_tasks(Arc::clone(&registry), &rules_dir, interval_secs);
    spawn_redteam_task(
        Arc::clone(&registry),
        &client,
        tasks::CruiseConfig {
            server: server_url.clone(),
            auth: api_auth.clone(),
            tenant,
            output: report_dir.clone(),
            guard: guard_strength,
        },
        interval_secs,
    );
    spawn_http_tasks(
        Arc::clone(&registry),
        &client,
        HttpTaskConfig {
            server_url: server_url.clone(),
            auth: api_auth.clone(),
            report_dir: report_dir.clone(),
            rules_dir: rules_dir.clone(),
            pull_urls: pull_urls.clone(),
            agentteams_sync,
            agentteams_confirm_live,
        },
        interval_secs,
    );
    spawn_archive_task(
        Arc::clone(&registry),
        ArchiveTaskConfig {
            job: tasks::ArchiveJob {
                report_dir: report_dir.clone(),
                archive_dir: archive_dir.clone(),
                store,
                store_note,
                after_days: archive_after_days,
                delete_local: archive_delete_local,
            },
        },
        interval_secs,
    );
    spawn_report_task(
        Arc::clone(&registry),
        ReportTaskConfig { rules: rules_dir.clone(), redteam: redteam_dir.clone(), output: report_dir.clone() },
        interval_secs,
    );
    spawn_cms_task(
        Arc::clone(&registry),
        CmsTaskConfig {
            server: server_url,
            auth: api_auth,
            tenant,
            output: report_dir,
            confirm_live: env_or("AGF_SCHEDULER_CMS_CONFIRM_LIVE", "false") == "true",
        },
        interval_secs,
    );

    let readyz_registry = Arc::clone(&registry);
    let tasks_registry = Arc::clone(&registry);
    let metrics_registry = Arc::clone(&registry);
    let callback_registry = Arc::clone(&registry);
    let app: Router = Router::new()
        .route(
            "/api/v1/internal/jobs/{kind}",
            axum::routing::post(move |path, headers| callback::invoke(Arc::clone(&callback_registry), path, headers)),
        )
        .route("/healthz", get(healthz))
        .route("/readyz", get(move || readyz(Arc::clone(&readyz_registry))))
        .route("/tasks", get(move || tasks_json(Arc::clone(&tasks_registry))))
        .route(
            "/metrics",
            get(move || {
                // 包一层 async 块：`metrics_text` 是同步纯函数，而 axum 的 Handler 要求返回 Future。
                let registry = Arc::clone(&metrics_registry);
                async move { metrics_text(registry) }
            }),
        )
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let addr = format!("{host}:{port}");
    let listener = TcpListener::bind(&addr).await.with_context(|| format!("HTTP 监听 {addr} 失败"))?;
    tracing::info!("调度服务监听 http://{addr}（/healthz /readyz /tasks /metrics；8 个周期任务全部已实现）");

    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await.context("HTTP 服务异常退出")?;
    Ok(())
}

/// 从环境变量构造存储配置（`AGF_S3_*` 等）；解析失败退回默认值并 warn。
pub(crate) fn storage_config() -> agf_storage::StorageConfig {
    let env_map: BTreeMap<String, String> = std::env::vars().collect();
    let mut config = match agf_core::config::from_env_map(&env_map) {
        Ok(app) => agf_storage::StorageConfig::from(&app),
        Err(e) => {
            tracing::warn!(error = %e, "解析 AppConfig 失败，冷归档改用 StorageConfig 默认值");
            agf_storage::StorageConfig::default()
        }
    };
    config.data_dir = PathBuf::from(env_or("AGF_DATA_DIR", "data"));
    config
}

/// 周期任务调度：统一"记录 runs/failures/last_millis + 失败只 warn"的口径。
///
/// 失败仅记 warn（外部依赖不可达属预期），绝不 panic、绝不退避重试死循环：
/// 下一轮由 ticker 自然触发。
pub(crate) fn spawn_periodic<F, Fut>(
    registry: Arc<Registry>,
    name: &'static str,
    enabled: bool,
    period: Duration,
    run: F,
) where
    F: Fn(Partition) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = TaskOutcome> + Send + 'static,
{
    if !enabled {
        tasks::note_set(&registry.notes, name, "任务已禁用，不接受周期或云回调触发");
        return;
    }
    let handler: dispatch::Handler = Arc::new(move |partition| Box::pin(run(partition)));
    if let Ok(mut handlers) = registry.handlers.lock() {
        handlers.insert(name, Arc::clone(&handler));
    }
    if registry.execution.cloud && callback::cloud_task(name) {
        tasks::note_set(&registry.notes, name, "等待经过认证的 SchedulerX3 HTTP 回调；本地周期已关闭");
        return;
    }
    tokio::spawn(async move {
        let timer = match calendar::Timer::from_env(name, period) {
            Ok(timer) => timer,
            Err(error) => {
                tasks::note_set(&registry.notes, name, format!("日历配置无效，任务未启动：{error}"));
                return;
            }
        };
        let mut completed = None;
        let mut ticker = tokio::time::interval(timer.poll_period());
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let now = agf_core::time::Timestamp::now();
            let Some(bucket) = timer.bucket(now) else { continue };
            if completed == Some(bucket) {
                continue;
            }
            let execution_id = format!("local:{name}:{bucket}");
            match dependencies::run(&registry, name, &execution_id, Arc::clone(&handler), Partition::default()).await {
                Ok(result) => {
                    if result.ok {
                        completed = Some(bucket);
                    }
                    tracing::info!(task = name, "{}", result.note);
                }
                Err(error) => {
                    tasks::note_set(&registry.notes, name, error.to_string());
                    tracing::warn!(task = name, error = %error, "任务未执行或执行失败");
                }
            }
        }
    });
}

/// 本地规则回归任务。
pub(crate) fn spawn_builtin_tasks(registry: Arc<Registry>, rules_dir: &Path, interval_secs: u64) {
    let rules_path = rules_dir.to_path_buf();
    let rules_registry = Arc::clone(&registry);
    spawn_periodic(
        Arc::clone(&registry),
        "rules-regression",
        task_enabled("rules-regression"),
        task_period("rules-regression", interval_secs),
        move |partition| {
            let path = rules_path.clone();
            let registry = Arc::clone(&rules_registry);
            async move {
                if !partition.first() {
                    return TaskOutcome::skipped("全局规则回归由分片 0 执行");
                }
                let dir = RulesDir::new(path.clone());
                if !dir.exists() {
                    return TaskOutcome::failed(format!("规则目录不存在（{}），跳过本轮回归", path.display()));
                }
                match RulePackLoader::strict()
                    .load_dir(&dir)
                    .and_then(|pack| SampleRegression::new().run_pack(&pack).map(|report| (pack.len(), report)))
                {
                    Ok((rules, report)) => {
                        registry.set_rules_count(rules as u64);
                        let note = format!(
                            "规则包回归完成：规则 {rules} 条，通过 {}，失败 {}（正样本 {} / 负样本 {}）",
                            report.passed, report.failed, report.positive_total, report.negative_total
                        );
                        if report.failed == 0 { TaskOutcome::ok(note) } else { TaskOutcome::failed(note) }
                    }
                    Err(e) => TaskOutcome::failed(format!("规则库回归失败（规则文件或模板有问题）：{e}")),
                }
            }
        },
    );
}
