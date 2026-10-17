//! agf-scheduler 服务入口（§4.6 定时关联/巡航、§5.2 SchedulerX3 双模）。
//!
//! ## 职责
//!
//! 按日历/间隔执行平台级周期任务，并把"哪些任务在跑、各自成功/失败多少次、
//! 最近一次做了什么、产出了什么"暴露成 `GET /tasks`（控制台"调度"页与运维排障直接消费）。
//!
//! ## 任务清单（8 个全部已实现，实现在 [`tasks`] 模块）
//!
//! | 任务 | 说明 | 外部依赖不可达时 |
//! |---|---|---|
//! | `rules-regression` | 严格加载 `<rules>/` 并对全部规则跑正负样本回归 | 记失败 |
//! | `redteam-cruise` | 调用平台持久战役 API，按执行编号去重并下载 JSON 证据/Markdown 报告 | 记失败 |
//! | `asset-inventory` | 可选 AgentTeams 真实盘点，再汇总资产台账并落 JSON | warn + 记失败 |
//! | `log-pull` | 调用控制台配置的 HTTP Pull 源，持久游标并入事件库 | 未配置源 → **如实 skip**（不算失败） |
//! | `rule-hot-reload` | 严格加载 `<rules>/` 后 `POST {AGF_SERVER_URL}/api/v1/policies/reload` | warn + 记失败 |
//! | `cold-archive` | 把 `<AGF_REPORT_DIR>` 下超龄文件 gzip 上传对象存储 | **降级为本地 gzip**（日志/结果明确标注） |
//! | `report-generate` | 汇总真实读取的统计生成 Markdown 报表 | 无数据也生成，写明"本期无数据" |
//! | `alicloud-cms-push` | 先保存指标并接入平台 CMS 持久队列 | 离线保留 payload，Mock 回执明确降级 |
//!
//! ## 双模
//!
//! `AGF_SCHEDULER_BACKEND=local-cron` 使用五段 UTC 日历，支持显式 interval 兼容模式。
//! `=schedulerx3` 使用经过认证的 HTTP 回调，关闭对应本地周期；平台永久 SQL 事实与一次性启动校验负责跨实例防重跑。
//! 日志源、红队用例、归档文件按稳定哈希分片；汇总任务只由分片 0 执行。云依赖由平台原批次领取核验。
//! 配置和验收步骤见 `docs/scheduler-guide.md`。
//!
//! ## 配置
//!
//! 全局：`AGF_SCHEDULER_HOST` / `AGF_SCHEDULER_PORT` / `AGF_SCHEDULER_INTERVAL_SECS` /
//! `AGF_SCHEDULER_BACKEND` / `AGF_RULES_DIR` / `AGF_REDTEAM_DIR` / `AGF_REPORT_DIR`。
//!
//! 逐任务：`AGF_SCHEDULER_<TASK_UPPER>_ENABLED`（开关）与
//! `AGF_SCHEDULER_<TASK_UPPER>_INTERVAL_SECS`（间隔），`<TASK_UPPER>` 由任务名的 `-` 换 `_` 大写得到
//! （如 `AGF_SCHEDULER_COLD_ARCHIVE_ENABLED`）。
//!
//! ## 子命令
//!
//! `agf-scheduler`（默认启动）· `agf-scheduler healthcheck --url <url>`（compose 健康检查，退出码 0/1）

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::io::Write;

pub(crate) use std::path::Path;
pub(crate) use std::path::PathBuf;

pub(crate) use std::sync::atomic::AtomicU64;
pub(crate) use std::sync::atomic::Ordering;

pub(crate) use std::sync::Arc;
pub(crate) use std::sync::Mutex;

pub(crate) use std::time::Duration;

use anyhow::Context as _;

pub(crate) use axum::Router;

pub(crate) use axum::http::StatusCode;

pub(crate) use axum::response::IntoResponse;

pub(crate) use axum::routing::get;

pub(crate) use clap::Parser;
pub(crate) use clap::Subcommand;

pub(crate) use tokio::net::TcpListener;

pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_scan::loader::RulePackLoader;
pub(crate) use agf_scan::loader::RulesDir;

pub(crate) use agf_scan::samples::SampleRegression;

pub(crate) use tasks::NoteStore;
pub(crate) use tasks::TaskOutcome;
pub(crate) use tasks::TaskSnapshot;

#[allow(unused_imports)]
pub(crate) use impl_task_state::*;
#[allow(unused_imports)]
pub(crate) use spawn_http_tasks::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

mod calendar;
mod dependencies;
mod partition;
pub(crate) use partition::Partition;
mod binding_execution;
mod callback;
mod callback_binding;
#[cfg(test)]
mod callback_business_tests;
#[cfg(test)]
mod callback_http_tests;
mod dispatch;
mod tasks;

/// 单个任务的运行态。
#[derive(Debug, Default)]
struct TaskState {
    /// 已执行次数。
    runs: AtomicU64,
    /// 失败次数。
    failures: AtomicU64,
    /// 最近一次耗时（毫秒）。
    last_millis: AtomicU64,
}

/// 任务注册表：8 个任务的运行态 + 动态 note + 跨任务共享的少量真实统计。
///
/// 条目由 [`tasks::catalog`] 派生，因此 `/tasks`、`/metrics` 与执行体不可能出现
/// "表里有 8 个、实际只跑 2 个"的漂移。
struct Registry {
    execution: dispatch::Execution,
    handlers: Mutex<BTreeMap<&'static str, dispatch::Handler>>,
    tasks: Vec<(&'static str, TaskState)>,
    notes: NoteStore,
    /// 最近一次红队巡航成功率（供 CMS 指标使用，真实值）。
    redteam_rate: Mutex<Option<f64>>,
    /// 最近一次严格加载的规则条数（供报表/CMS 使用，真实值）。
    rules_count: AtomicU64,
}

/// 命令行。
#[derive(Debug, Parser)]
#[command(name = "agf-scheduler", version, about = "AIGuardFabric 调度服务")]
struct Cli {
    /// 子命令（缺省 = 启动调度）。
    #[command(subcommand)]
    command: Option<Command>,
}

/// 子命令。
#[derive(Debug, Subcommand)]
enum Command {
    /// 健康检查：探测 `/healthz`，成功退出码 0，失败 1（compose healthcheck 用）。
    Healthcheck {
        /// 目标 URL。
        #[arg(long, default_value = "http://127.0.0.1:9101/healthz")]
        url: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Healthcheck { url }) => healthcheck(&url).await,
        None => serve().await,
    }
}

/// HTTP 依赖任务（asset-inventory / log-pull / rule-hot-reload）的配置。
#[derive(Debug, Clone)]
struct HttpTaskConfig {
    server_url: String,
    auth: Option<tasks::ApiAuth>,
    report_dir: PathBuf,
    rules_dir: PathBuf,
    pull_urls: String,
    agentteams_sync: bool,
    agentteams_confirm_live: bool,
}

/// 冷归档配置。
#[derive(Debug, Clone)]
struct ArchiveTaskConfig {
    job: tasks::ArchiveJob,
}

/// 报表任务配置。
#[derive(Debug, Clone)]
struct ReportTaskConfig {
    rules: PathBuf,
    redteam: PathBuf,
    output: PathBuf,
}

/// CMS 上报任务配置。
type CmsTaskConfig = tasks::CmsQueueConfig;

mod impl_task_state;
mod spawn_http_tasks;
#[cfg(test)]
mod tests;
