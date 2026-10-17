//! # agf-server — AIGuardFabric 主服务入口
//!
//! ## 职责
//!
//! 1. `dotenvy` 载入 `.env` → `agf_core::config::from_process_env()` 解析配置；
//! 2. `tracing-subscriber` 初始化（pretty / json）+ **OTLP span 导出**（由 `AGF_OTLP_ENDPOINT`
//!    门控；未设置时不建导出器、行为与接线前一致；导出失败只记日志、不影响请求）；
//! 3. 有数据库凭据时连接 PostgreSQL 并执行 `MIGRATOR`；否则**离线内存模式**继续服务；
//! 4. 首启创建引导管理员（`must_change_password=true`，口令不打印，随机口令写入
//!    `<AGF_DATA_DIR>/seed/bootstrap-admin.txt`）；
//! 5. 装配 `/ws` 事件面（`AGF_NATS_ENABLED=1` 时接 NATS，连不上只 `warn` + 退回进程内广播）；
//! 6. 挂载 `agf-api` 路由，Ctrl-C / SIGTERM 优雅关闭并等待在途请求（退出前冲刷 OTLP 批次）。
//!
//! ## 子命令（compose 的 healthcheck 依赖第一个）
//!
//! ```text
//! agf-server                               # 默认：启动服务
//! agf-server healthcheck --url <URL>       # 探测 /healthz，退出码 0/1
//! agf-server migrate                       # 只执行数据库迁移
//! agf-server bootstrap-admin               # 只创建/检查引导管理员
//! ```

#![forbid(unsafe_code)]
// 二进制入口用 eprintln/println 之外的方式输出；这里放开 assert 类宏的 clippy 限制。
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agf_api::{AppState, BootstrapOutcome};
mod listeners;
use agf_core::config::{AppConfig, LogFormat};
use agf_core::ids::TenantId;
use clap::{Parser, Subcommand};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// 命令行。
#[derive(Debug, Parser)]
#[command(name = "agf-server", version, about = "AIGuardFabric 主服务（HTTP API / 迁移 / 健康检查）")]
struct Cli {
    /// 子命令；缺省即启动服务。
    #[command(subcommand)]
    command: Option<Command>,
}

/// 子命令。
#[derive(Debug, Subcommand)]
enum Command {
    /// 探测本机 `/healthz`（退出码 0 = 健康，1 = 不健康）。
    Healthcheck {
        /// 探测地址。
        #[arg(long, default_value = "http://127.0.0.1:8080/healthz")]
        url: String,
        /// 超时（秒）。
        #[arg(long, default_value_t = 5)]
        timeout_secs: u64,
    },
    /// 只执行数据库迁移（幂等）。
    Migrate,
    /// 只创建/检查引导管理员。
    BootstrapAdmin {
        /// 登录名（缺省取 `AGF_BOOTSTRAP_ADMIN_USER`）。
        #[arg(long)]
        username: Option<String>,
        /// 邮箱（缺省取 `AGF_BOOTSTRAP_ADMIN_EMAIL`）。
        #[arg(long)]
        email: Option<String>,
        /// 初始口令（缺省随机生成并写入文件；不会打印到日志）。
        #[arg(long)]
        password: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let code = match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            error!(error = %e, "启动失败");
            1
        }
    };
    std::process::exit(code);
}

async fn run(cli: Cli) -> anyhow::Result<i32> {
    // 1) 载入 .env（不存在时静默跳过，环境变量仍然是唯一配置来源）
    let loaded = dotenvy::dotenv();
    if let Err(e) = &loaded {
        if !matches!(e, dotenvy::Error::Io(_)) {
            warn!(error = %e, "dotenvy 载入 .env 失败（继续使用进程环境）");
        }
    }

    // healthcheck 子命令不需要配置与日志初始化，先短路，保证探针在配置损坏时也能给出结论
    if let Some(Command::Healthcheck { url, timeout_secs }) = cli.command {
        return Ok(healthcheck(&url, timeout_secs).await);
    }

    let config = agf_core::config::from_process_env()?;
    // OTLP 由 `AGF_OTLP_ENDPOINT`（或 `AGF_OTEL_ENABLED=1` + `AGF_OTEL_ENDPOINT`）门控：
    // 未配置时返回 None，`tracing` 初始化与接线前**逐行一致**（零开销、无副作用）。
    let otel = init_tracing(&config);
    let code = run_configured(cli, &config).await;
    // `std::process::exit` 不会跑析构，必须在退出前显式冲刷 OTLP 批次。
    if let Some(keepalive) = &otel {
        info!("OTLP 导出器关闭（冲刷未发送的 span）");
        keepalive.shutdown();
    }
    code
}

/// 服务主体（日志与 OTLP 已就绪后执行）。
async fn run_configured(cli: Cli, config: &AppConfig) -> anyhow::Result<i32> {
    info!(version = agf_api::VERSION, "agf-server 启动中");
    let safety = config.enforce_safety()?;
    for warning in &safety {
        warn!(warning = %warning, "配置安全基线告警");
    }

    match cli.command {
        Some(Command::Migrate) => {
            migrate_only(config).await?;
            return Ok(0);
        }
        Some(Command::BootstrapAdmin { username, email, password }) => {
            let state = build_state(config).await?;
            bootstrap_admin(&state, config, username.as_deref(), email.as_deref(), password.as_deref()).await?;
            return Ok(0);
        }
        _ => {}
    }

    // 2) 组装状态
    let state = build_state(config).await?;
    for note in state.notes.iter() {
        warn!(note = %note, "运行说明");
    }
    if state.mode.is_offline() {
        info!("以离线内存模式启动：未配置数据库连接，平台功能全部可用但数据不持久");
    }

    // 3) 首启创建引导管理员
    bootstrap_admin(&state, config, None, None, None).await?;

    // Restore authoritative committed totals before HTTP; expiry is one bounded local worker.
    let gateway_maintenance = agf_api::start_gateway_maintenance(state.clone()).await;

    // 4) 启动 HTTP 服务
    let notification_worker = tokio::spawn(agf_api::notification_outbox::run_loop(state.clone()));
    let escalation_worker = tokio::spawn(agf_api::alert_escalation::run_loop(state.clone()));
    let report_worker = tokio::spawn(agf_api::report_service::run_loop(state.clone()));
    let source_worker = tokio::spawn(agf_api::source_worker::run_loop(state.clone()));
    let event_delivery = tokio::spawn(agf_api::event_delivery::run_loop(state.clone()));
    let event_analysis = tokio::spawn(agf_api::event_analysis::run_loop(state.clone()));
    let soar_worker = tokio::spawn(agf_api::soar_workflow::run_loop(state.clone()));
    let inventory_worker = tokio::spawn(agf_api::asset_inventory::run_loop(state.clone()));
    let audit_anchor_worker = tokio::spawn(agf_api::audit_anchor::run_loop(state.clone()));
    let app = agf_api::build_router(state.clone());
    let addr: SocketAddr = config.server.bind_addr().parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(
        %addr,
        api_prefix = %config.server.api_prefix,
        mode = state.mode.as_str(),
        event_plane = state.event_plane_name(),
        nats_enabled = config.nats.enabled,
        "HTTP 服务已就绪"
    );
    listeners::serve(state, listener, app).await?;
    gateway_maintenance.shutdown().await;
    notification_worker.abort();
    escalation_worker.abort();
    report_worker.abort();
    source_worker.abort();
    event_delivery.abort();
    event_analysis.abort();
    soar_worker.abort();
    inventory_worker.abort();
    audit_anchor_worker.abort();
    info!("agf-server 已退出");
    Ok(0)
}

/// 初始化 tracing；返回 OTLP 保活句柄（`None` = 未启用 OTLP）。
///
/// **门控**：`AGF_OTLP_ENDPOINT` 非空即启用；未设置时，仅当 `AGF_OTEL_ENABLED=1` 且
/// `AGF_OTEL_ENDPOINT` 非空才启用。**未启用时不构建任何导出器**：没有后台导出线程、
/// 没有 HTTP 客户端、不发任何网络请求，`tracing` 的初始化路径与接线前完全一致。
///
/// **降级**：端点非法或导出器构建失败只写 stderr（此时订阅者尚未安装，`warn!` 会丢失）
/// 并继续以本地输出启动——**绝不因为 collector 不可用而让服务起不来**；
/// 运行期导出失败由 OTLP SDK 的批处理线程吞掉，不影响任何请求路径。
fn init_tracing(config: &AppConfig) -> Option<agf_api::metrics::otel::OtlpKeepAlive> {
    let filter = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| EnvFilter::try_new(v).ok())
        .or_else(|| EnvFilter::try_new(&config.log_level).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));
    let registry = tracing_subscriber::registry().with(filter);
    if let Some(endpoint) = agf_api::metrics::otel::resolve_otlp_endpoint(config) {
        let service = config.observability.otel_service_name.clone();
        // 层要挂到"已带 EnvFilter 的 registry"上，类型参数必须与之完全一致。
        let built = agf_api::metrics::otel::build::<agf_api::metrics::otel::FilteredRegistry>(&endpoint, &service);
        match built {
            Ok((layer, keepalive)) => {
                let result = match config.log_format {
                    LogFormat::Json => registry.with(layer).with(tracing_subscriber::fmt::layer().json()).try_init(),
                    LogFormat::Pretty => registry.with(layer).with(tracing_subscriber::fmt::layer()).try_init(),
                };
                report_init(&result);
                info!(%endpoint, %service, "OTLP span 导出已启用（AGF_OTLP_ENDPOINT）");
                return Some(keepalive);
            }
            Err(error) => {
                let _ = writeln!(std::io::stderr(), "OTLP 导出器装配失败（降级为本地 tracing 输出）: {error}");
            }
        }
    }
    let result = match config.log_format {
        LogFormat::Json => registry.with(tracing_subscriber::fmt::layer().json()).try_init(),
        LogFormat::Pretty => registry.with(tracing_subscriber::fmt::layer()).try_init(),
    };
    report_init(&result);
    None
}

/// 报告 tracing 初始化结果（日志系统已初始化——例如测试中重复调用——不是致命错误）。
fn report_init<E: std::fmt::Display>(result: &Result<(), E>) {
    if let Err(e) = result {
        let _ = writeln!(std::io::stderr(), "tracing 初始化跳过: {e}");
    }
}

/// 按配置构造 `AppState`（有数据库凭据时先连库并迁移，失败则降级离线）。
///
/// 装配完成后立即接 `/ws` 的**事件面**（`AGF_NATS_ENABLED`）：
/// NATS 可达 → 事件经 `agf.ws.<tenant>.<kind>` 跨副本分发；不可达或未启用 → 退回进程内广播
/// （只 `warn` + 写 `notes`，见 `AppState::attach_nats_events`，**不阻断启动**）。
async fn build_state(config: &AppConfig) -> anyhow::Result<AppState> {
    let store = match try_connect_store(config).await? {
        Some((store, notes)) => {
            for note in &notes {
                warn!(note = %note, "存储层降级说明");
            }
            Some(store)
        }
        None => None,
    };
    let state = AppState::build(config.clone(), store)?;
    if state.store.has_database() && agf_api::seed::seed_enabled() {
        if let Err(error) = state.seed_replay_samples().await {
            warn!(error = %error, "演示原始日志灌入失败，服务继续启动；请检查回放样例");
        }
        match state.seed_durable_demo_tasks().await {
            Ok((scans, campaigns)) => info!(scans, campaigns, "演示终态任务已提交到控制台使用的 PostgreSQL 列表"),
            Err(error) => warn!(error = %error, "演示任务落库失败，服务继续启动；请检查扫描和战役列表"),
        }
    }
    Ok(state.attach_nats_events().await)
}

/// 尝试连接 PostgreSQL + 对象存储；返回 `None` 表示走离线内存模式。
async fn try_connect_store(config: &AppConfig) -> anyhow::Result<Option<(Arc<agf_storage::Store>, Vec<String>)>> {
    let dsn_configured = std::env::var("DATABASE_URL").is_ok_and(|v| !v.trim().is_empty());
    if config.database.password.is_empty() && !dsn_configured {
        info!("未配置 AGF_PG_PASSWORD / DATABASE_URL：跳过数据库连接");
        return Ok(None);
    }
    let storage = agf_storage::StorageConfig::from(config);
    match agf_storage::build_store(&storage).await {
        Ok((store, notes)) => {
            info!(dsn = %config.database.masked_dsn(), "PostgreSQL 连接成功");
            store.db().migrate().await?;
            info!("数据库迁移已执行（幂等）");
            Ok(Some((Arc::new(store), notes)))
        }
        Err(e) => Err(anyhow::anyhow!("已配置的数据库不可用，拒绝启动空白内存后端: {e}")),
    }
}

/// `agf-server migrate`。
async fn migrate_only(config: &AppConfig) -> anyhow::Result<()> {
    let storage = agf_storage::StorageConfig::from(config);
    let db = agf_storage::Database::connect(&storage).await?;
    db.migrate().await?;
    info!(dsn = %config.database.masked_dsn(), "迁移完成");
    Ok(())
}

/// 首启创建引导管理员（幂等）。
async fn bootstrap_admin(
    state: &AppState,
    config: &AppConfig,
    username: Option<&str>,
    email: Option<&str>,
    password: Option<&str>,
) -> anyhow::Result<()> {
    let tenant = TenantId::default_tenant();
    let user = username.unwrap_or(&config.security.bootstrap_admin_user);
    let mail = email.unwrap_or(&config.security.bootstrap_admin_email);
    let explicit =
        password.map(ToString::to_string).unwrap_or_else(|| config.security.bootstrap_admin_password.clone());
    let explicit = if explicit.is_empty() { None } else { Some(explicit) };
    if explicit.is_some() {
        warn!("AGF_BOOTSTRAP_ADMIN_PASSWORD 已显式设置：生产环境建议留空以随机生成（避免口令进入 .env/镜像层）");
    }
    let outcome = state
        .ensure_bootstrap_admin(tenant, user, mail, explicit.as_deref(), config.security.force_password_change)
        .await?;
    match outcome {
        BootstrapOutcome::AlreadyExists { user } => {
            info!(username = %user.username, "引导管理员已存在（幂等启动，口令未改动）");
        }
        BootstrapOutcome::Created { user, generated_password } => {
            info!(
                username = %user.username,
                must_change_password = user.must_change_password,
                "引导管理员已创建：**首登必须改密**（口令不打印）"
            );
            if let Some(secret) = generated_password {
                match write_seed_password(config, &secret) {
                    Ok(path) => info!(
                        path = %path,
                        "初始口令已写入该文件（仅首启生成一次）；请首次登录后立即改密并删除文件"
                    ),
                    Err(e) => {
                        warn!(error = %e, "初始口令写入文件失败，请用 agf-server bootstrap-admin --password 重新设置");
                    }
                }
            }
        }
    }
    Ok(())
}

/// 把随机生成的初始口令写入 `<data_dir>/seed/bootstrap-admin.txt`（**不打印口令**）。
fn write_seed_password(config: &AppConfig, password: &str) -> anyhow::Result<String> {
    let dir = PathBuf::from(&config.data_dir).join("seed");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("bootstrap-admin.txt");
    let mut file = std::fs::File::create(&path)?;
    writeln!(file, "{password}")?;
    file.sync_all()?;
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path.to_string_lossy().replace('\\', "/"))
}

/// 健康探测：返回进程退出码。
async fn healthcheck(url: &str, timeout_secs: u64) -> i32 {
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(timeout_secs.max(1))).build() {
        Ok(client) => client,
        Err(e) => {
            error!(error = %e, "HTTP 客户端构造失败");
            return 1;
        }
    };
    match client.get(url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let _ = writeln!(std::io::stdout(), "OK {} {url}", resp.status());
            0
        }
        Ok(resp) => {
            let _ = writeln!(std::io::stderr(), "FAIL {} {url}", resp.status());
            1
        }
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "FAIL {url}: {e}");
            1
        }
    }
}

/// 优雅关闭：Ctrl-C（全平台）+ SIGTERM（Unix）。
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!(error = %e, "无法监听 Ctrl-C");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                warn!(error = %e, "无法监听 SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => info!("收到 Ctrl-C"),
        () = terminate => info!("收到 SIGTERM"),
    }
    info!("开始优雅关闭：等待在途请求完成（stop_grace_period 30s）");
}
