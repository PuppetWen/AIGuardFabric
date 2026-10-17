#![forbid(unsafe_code)]
// CLI 的产物就是"打到终端/文件"的文本，因此显式放行 print_*（库代码仍受 workspace lints 约束）。
#![allow(clippy::print_stdout, clippy::print_stderr)]
//! `agf-agent` 命令行入口：采集 → 输出（或按 `--json` 输出上行信封）。
//!
//! ```text
//! agf-agent capabilities                 # 打印本机采集能力矩阵（真实现 / 仅接口）
//! agf-agent collect --json               # 采集并输出上行信封 JSON（不联网）
//! agf-agent collect --home <dir> --json  # 对指定用户目录采集（联调/取证复现）
//! agf-agent tls-check [--json]           # 只读校验 mTLS 配置（不联网；不健康时退出码 1）
//! agf-agent check-update --manifest m.json [--current 0.1.0]
//! ```
//!
//! 本入口的 `collect` / `capabilities` / `tls-check` / `check-update` **都不发网络请求**：
//! 真实上行由 [`agf_agent::AgentClient`] 负责（mTLS 已实现，见 `client::tls`）。

use std::path::PathBuf;
use std::process::ExitCode;

use agf_agent::{
    AgentIdentity, ClientConfig, CollectContext, Envelope, PayloadKind, ReleaseManifest, UpdatePlan, collect_all,
    collector_roster, plan_update, platform,
};
use clap::{Args, Parser, Subcommand};
mod mcp_proxy;
mod process_cli;
mod run;
mod update_cli;

/// AIGuardFabric 终端 Agent（智御矩阵）。
#[derive(Debug, Parser)]
#[command(name = "agf-agent", version, about = "AIGuardFabric 终端采集器：AI 资产 / MCP / 凭据", long_about = None)]
struct Cli {
    /// 子命令。
    #[command(subcommand)]
    command: Command,
}

/// 子命令。
#[derive(Debug, Subcommand)]
enum Command {
    /// 以 stdio 包装原 MCP 进程，执行双向策略与脱敏。
    McpProxy(mcp_proxy::ProxyArgs),
    /// 显式启动有限时长的系统进程观察；不宣称已执行阻断。
    ProcessObserve(process_cli::ObserveArgs),
    /// 平台已审计放行后启动明确的本机 PE/ELF；其它动作默认拒绝。
    ProcessRun(process_cli::RunArgs),
    /// 持续采集并真实上报，支持断线补传；--once 只发送一次。
    Run(run::RunArgs),
    /// 采集本终端事实并输出（默认人读摘要，`--json` 输出上行信封）。
    Collect(CollectArgs),
    /// 打印采集能力矩阵（哪些是真实现、哪些只是接口）。
    Capabilities,
    /// 只读校验 mTLS / TLS 配置（读盘 + 门禁判定，**不联网、不打印任何凭据**）。
    TlsCheck(TlsCheckArgs),
    /// 预览未验签更新计划（比较版本并读取资产信息；不下载、不安装）。
    CheckUpdate(UpdateArgs),
    /// 显式外部 helper：验签、HTTPS 下载、安装和 60 秒启动健康回滚。
    ApplyUpdate(update_cli::ApplyArgs),
    /// 只恢复原更新事务；不下载、不重复安装、不终止无归属进程。
    RecoverUpdate(update_cli::RecoverArgs),
}

/// `tls-check` 参数。
#[derive(Debug, Args)]
struct TlsCheckArgs {
    /// 以 JSON 输出（供脚本/端到端验证断言）。
    #[arg(long, default_value_t = false)]
    json: bool,
}

/// `collect` 参数。
#[derive(Debug, Args)]
struct CollectArgs {
    /// 用户主目录（默认取当前用户；联调/取证复现可指定）。
    #[arg(long)]
    home: Option<PathBuf>,
    /// Agent 数据目录（默认 `<data_dir>/aiguardfabric`）。
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// 输出上行信封 JSON（可直接对照服务端契约）。
    #[arg(long, default_value_t = false)]
    json: bool,
    /// 关闭进程与端口采集（低开销/最小权限模式）。
    #[arg(long, default_value_t = false)]
    no_system_probes: bool,
    /// 打印各采集器状态（人读摘要模式）。
    #[arg(long, default_value_t = true)]
    status: bool,
}

/// `check-update` 参数。
#[derive(Debug, Args)]
struct UpdateArgs {
    /// 发布清单 JSON 文件路径。
    #[arg(long)]
    manifest: PathBuf,
    /// 当前版本（默认取本二进制版本）。
    #[arg(long)]
    current: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).with_writer(std::io::stderr).init();
    match Cli::parse().run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("错误: {error}");
            ExitCode::FAILURE
        }
    }
}

impl Cli {
    /// 执行所选子命令；只有显式联网命令访问平台。
    ///
    /// # Errors
    /// 读文件、构造身份或序列化失败时返回错误（均带上下文说明）。
    async fn run(self) -> anyhow::Result<()> {
        match self.command {
            Command::McpProxy(args) => mcp_proxy::run(args).await,
            Command::ProcessObserve(args) => process_cli::observe_command(args).await,
            Command::ProcessRun(args) => process_cli::run_command(args).await,
            Command::Run(args) => run::run(args).await,
            Command::Capabilities => {
                print_capabilities();
                Ok(())
            }
            Command::Collect(args) => collect_command(&args),
            Command::TlsCheck(args) => tls_check(&args),
            Command::CheckUpdate(args) => check_update(&args),
            Command::ApplyUpdate(args) => update_cli::apply(args).await,
            Command::RecoverUpdate(args) => update_cli::recover(args),
        }
    }
}

/// 只读校验 mTLS / TLS 配置（不联网）。
///
/// 退出码：配置健康 = 0；配置错误（缺证书、不成对、未授权的跳过校验、明文配了客户端证书）= 1。
/// 输出**绝不包含证书/私钥内容**，只给模式、开关与分类。
///
/// # Errors
/// JSON 序列化失败。
fn tls_check(args: &TlsCheckArgs) -> anyhow::Result<()> {
    let config = ClientConfig::from_env();
    let health = config.tls_health();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&health)?);
    } else {
        println!("上行地址: {}", config.server_url.as_deref().unwrap_or("<未配置 AGF_AGENT_SERVER_URL>"));
        println!("TLS 模式: {}（{}）", health.mode.as_str(), health.detail);
        println!(
            "客户端证书={} 私钥={} 自定义CA={} 跳过校验={}（已授权={}）环境={}",
            health.client_cert_configured,
            health.client_key_configured,
            health.ca_configured,
            health.insecure_skip_verify,
            health.insecure_allowed,
            health.env_name.as_deref().unwrap_or("<未设置 AGF_ENV>")
        );
        match health.error_kind {
            Some(kind) => println!("结论: **配置错误**（分类 {}）", kind.as_str()),
            None => println!("结论: 配置自洽（不代表对端一定接受）"),
        }
    }
    if health.is_healthy() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "TLS 配置不健康（{}）：{}",
            health.error_kind.map_or("unknown", |kind| kind.as_str()),
            health.detail
        ))
    }
}

/// 打印采集能力矩阵。
fn print_capabilities() {
    println!("agf-agent {} @ {}/{}", agf_agent::VERSION, platform::current(), platform::current_arch());
    println!("{:<18} {:<15} {:<16} 说明", "采集器", "支持级别", "TODO 锚点");
    for descriptor in collector_roster() {
        println!(
            "{:<18} {:<15} {:<16} {}",
            descriptor.name,
            descriptor.level.as_str(),
            descriptor.todo_anchor.unwrap_or("-"),
            descriptor.display_name
        );
    }
}

/// 采集并输出。
fn collect_command(args: &CollectArgs) -> anyhow::Result<()> {
    let mut ctx = CollectContext::for_current_user();
    if let Some(home) = &args.home {
        ctx = ctx.with_home(home);
    }
    if let Some(data_dir) = &args.data_dir {
        ctx = ctx.with_data_dir(data_dir);
    }
    if args.no_system_probes {
        ctx = ctx.without_system_probes();
    }
    let identity = AgentIdentity::from_env(&ctx.data_dir)?;
    let snapshot = collect_all(&identity, &ctx);
    let envelope = Envelope::new(&identity, PayloadKind::Snapshot, snapshot.payload.clone())?;

    if args.json {
        println!("{}", envelope.to_json()?);
    } else {
        println!("采集器: {}（host={} os={}）", identity.agent_id, identity.hostname, identity.os);
        println!(
            "Agent={} MCP={} 凭据命中={} 模型端点={} Skill={} 进程={} 监听端口={}",
            snapshot.payload.report.agents.len(),
            snapshot.payload.report.mcp_configs.len(),
            snapshot.payload.report.credential_hits.len(),
            snapshot.payload.extras.model_endpoints.len(),
            snapshot.payload.extras.skills.len(),
            snapshot.payload.extras.processes.len(),
            snapshot.payload.extras.listening_ports.len()
        );
        println!("幂等键: {}", envelope.idempotency_key);
        if args.status {
            println!("{:<18} {:<15} {:>6} {:>8}  错误", "采集器", "级别", "条目", "耗时ms");
            for status in &snapshot.statuses {
                println!(
                    "{:<18} {:<15} {:>6} {:>8}  {}",
                    status.name,
                    status.level,
                    status.items,
                    status.elapsed_ms,
                    status.error.clone().unwrap_or_else(|| "-".to_string())
                );
            }
        }
    }
    let failed = snapshot.failed_collectors();
    if !failed.is_empty() {
        eprintln!("注意：以下采集器未完成（其余结果照常上报）：{failed:?}");
    }
    eprintln!(
        "提示：上行需配置 AGF_AGENT_SERVER_URL；mTLS 由 AGF_AGENT_TLS_CERT/_KEY/_CA 配置（agf-agent tls-check 可只读校验）"
    );
    Ok(())
}

/// 检查更新（不下载）。
fn check_update(args: &UpdateArgs) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(&args.manifest)
        .map_err(|e| anyhow::anyhow!("读取 manifest 失败 {}: {e}", args.manifest.display()))?;
    let manifest: ReleaseManifest =
        serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("manifest 非法 JSON: {e}"))?;
    let current = args.current.clone().unwrap_or_else(|| agf_agent::VERSION.to_string());
    let plan = plan_update(&current, &manifest, platform::current(), platform::current_arch());
    match plan {
        Ok(Some(plan)) => print!("{}", UpdateReport { current: &current, plan: Some(plan) }.to_text()),
        Ok(None) => println!("当前 {current}：已是最新，或该平台/架构暂无发布资产"),
        Err(error) => {
            eprintln!("版本号非法: {error}");
            return Err(anyhow::anyhow!("版本号非法: {error}"));
        }
    }
    if manifest.signature.is_none() {
        eprintln!("注意：manifest 未签名；apply-update 必须使用独立可信公钥完成验签");
    }
    Ok(())
}

/// 升级检查结果（仅展示，不执行）。
#[derive(Debug)]
struct UpdateReport<'a> {
    current: &'a str,
    plan: Option<UpdatePlan>,
}

impl UpdateReport<'_> {
    /// 人读文本。
    fn to_text(&self) -> String {
        match &self.plan {
            Some(plan) => format!(
                "当前 {} → 目标 {}\n下载地址: {}\nSHA-256: {}\n大小: {} 字节\n未验签预览需人工核对: {}\n显式安装请使用 apply-update 与独立可信公钥；此预览不能直接安装\n",
                self.current, plan.target, plan.url, plan.sha256, plan.size, plan.requires_manual_approval
            ),
            None => format!("当前 {}：已是最新\n", self.current),
        }
    }
}
