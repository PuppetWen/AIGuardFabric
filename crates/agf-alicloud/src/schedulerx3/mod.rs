//! SchedulerX3（分布式任务调度）适配器：任务注册、分片、重试、依赖编排、日历调度、执行历史（§5.2）。
//!
//! ## 六个平台任务
//!
//! §5.2 要求把六类周期工作注册为云任务；本模块的 [`SchedulerX3Job::platform_defaults`] 是
//! **唯一权威定义**，`agf-runtime` 的本地 tokio-cron 后端复用同一份定义（双模）。
//!
//! | `job_kind` | 任务 | 默认 cron | 分片 | 重试 | 依赖 |
//! |---|---|---|---|---|---|
//! | `asset-inventory` | 资产盘点 | `0 2 * * *`（每日 02:00） | 4 | 3 | — |
//! | `log-pull` | 日志拉取 | `*/10 * * * *`（每 10 分钟） | 8 | 5 | asset-inventory |
//! | `redteam-cruise` | 红队巡航 | `0 3 * * 1`（每周一 03:00） | 2 | 2 | asset-inventory |
//! | `rule-hot-reload` | 规则热更新 | `*/5 * * * *`（每 5 分钟） | 1 | 2 | — |
//! | `report` | 报表 | `0 7 * * *`（每日 07:00） | 1 | 3 | asset-inventory, log-pull |
//! | `archive` | 归档 | `0 4 1 * *`（每月 1 日 04:00） | 2 | 1 | report |
//!
//! ## 降级
//!
//! 未配置时全部任务回退 [`ScheduleBackend::fallback`]（`SchedulerX3 → LocalCron`），
//! 无云环境零配置可用；分片在本地后端退化为单实例串行。

pub mod managed_jobs;

pub mod native_observation;

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Arc;

pub(crate) use agf_core::adapter::Adapter;
pub(crate) use agf_core::adapter::AdapterConfig;
pub(crate) use agf_core::adapter::AdapterDescriptor;
pub(crate) use agf_core::adapter::AdapterHealth;
pub(crate) use agf_core::adapter::PullRequest;
pub(crate) use agf_core::adapter::PullResponse;
pub(crate) use agf_core::adapter::PushPayload;
pub(crate) use agf_core::adapter::SyncDirection;
pub(crate) use agf_core::adapter::SyncOutcome;

pub(crate) use agf_core::cloud::ScheduleBackend;
pub(crate) use agf_core::cloud::ScheduleRegistration;

pub(crate) use agf_core::enums::AliCloudService;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;
pub(crate) use agf_core::ids::deterministic_id;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use async_trait::async_trait;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use crate::AdapterMode;

pub(crate) use crate::http::RpcClient;
pub(crate) use crate::http::json_array;
pub(crate) use crate::http::json_i64;
pub(crate) use crate::http::json_str;

pub(crate) use crate::mock;
pub(crate) use crate::mock::AdapterCore;
pub(crate) use crate::mock::NS_SCHEDULE;
pub(crate) use crate::mock::null_transport;

#[cfg(test)]
pub(crate) use crate::http::RecordingTransport;

#[cfg(test)]
pub(crate) use crate::test_support::fixture_config;

#[cfg(test)]
pub(crate) use agf_core::enums::HealthState;

#[allow(unused_imports)]
pub use impl_scheduler_x3_adapter::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// SchedulerX3 API 版本。
pub const SCHEDULERX3_API_VERSION: &str = "2024-06-24";

/// 平台六个任务的定义（`job_kind` 数组，顺序即依赖顺序）。
pub const PLATFORM_JOB_KINDS: [&str; 6] =
    ["asset-inventory", "log-pull", "redteam-cruise", "rule-hot-reload", "report", "archive"];

/// 云侧任务定义（可下发的形态）。
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct SchedulerX3Job {
    /// Preserved public CreateJob/UpdateJob fields (Script, Parameters, Calendar, etc.).
    #[serde(default)]
    pub cloud_parameters: BTreeMap<String, serde_json::Value>,
    /// 平台任务 id（确定性生成，本地/云双模一致）。
    pub id: Id,
    /// 任务名。
    pub name: String,
    /// 任务类型。
    pub job_kind: String,
    /// cron 表达式。
    pub cron: String,
    /// 分片数。
    pub shard_count: u32,
    /// 失败重试次数。
    pub max_retries: u32,
    /// 依赖的上游任务 id。
    pub depends_on: Vec<Id>,
    /// 是否启用。
    pub enabled: bool,
    /// 执行后端。
    pub backend: ScheduleBackend,
    /// 云侧 job id（注册后回填）。
    pub cloud_job_id: Option<String>,
    /// 执行入口（云侧调用的 HTTP/函数入口）。
    pub handler: String,
}

/// 一次执行历史。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchedulerX3Execution {
    /// 任务 id（云侧）。
    pub job_id: String,
    /// 执行 id。
    pub execution_id: String,
    /// 分片序号。
    pub shard_index: Option<u32>,
    /// 状态（`SUCCESS` / `FAILED` / `RUNNING`）。
    pub status: String,
    /// 执行时间。
    pub at: Option<Timestamp>,
    /// Cloud timestamps without a timezone are retained as received instead of guessing UTC.
    #[serde(default)]
    pub scheduled_at_raw: Option<String>,
    /// 耗时（毫秒）。
    pub duration_ms: Option<u64>,
    /// Native Duration has no documented unit; it must not be labelled milliseconds.
    #[serde(default)]
    pub duration_native: Option<u64>,
    /// 结果摘要。
    pub result: String,
}

/// 注册结果。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRegistrationReport {
    /// Per-job failures; failed publication is never reported as an offline enqueue.
    #[serde(default)]
    pub errors: BTreeMap<String, String>,
    /// 新建任务数。
    pub created: usize,
    /// 更新任务数。
    pub updated: usize,
    /// 跳过数。
    pub skipped: usize,
    /// 失败数。
    pub failed: usize,
    /// `job_kind → 云侧 job id`。
    pub cloud_job_ids: BTreeMap<String, String>,
}

/// SchedulerX3 服务能力契约。
#[async_trait]
pub trait SchedulerX3Api: Send + Sync {
    /// 列出任务。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn pull_jobs(&self) -> DomainResult<Vec<SchedulerX3Job>>;

    /// 创建或更新任务，返回云侧 job id。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn create_job(&self, job: &SchedulerX3Job, namespace: &str) -> DomainResult<String>;

    /// 删除任务。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn delete_job(&self, cloud_job_id: &str, namespace: &str) -> DomainResult<()>;

    /// 查询执行历史。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn pull_executions(&self, job_id: Option<&str>) -> DomainResult<Vec<SchedulerX3Execution>>;

    /// 批量注册平台六个任务（依赖编排按序下发）。
    ///
    /// # Errors
    /// 单个任务失败不返回错误，而是计入 [`JobRegistrationReport::failed`]。
    async fn register_platform_jobs(&self, tenant_id: TenantId) -> DomainResult<JobRegistrationReport>;
}

/// SchedulerX3 适配器。Mock 与真实实现是同一类型的两种模式。
pub struct SchedulerX3Adapter {
    core: AdapterCore,
    client: Option<Arc<RpcClient>>,
    transport: Arc<crate::http::RecordingTransport>,
    /// 云侧命名空间（SchedulerX3 隔离单位）。
    namespace: String,
    cluster_id: String,
    registration_jobs: Vec<SchedulerX3Job>,
}

mod impl_scheduler_x3_adapter;
mod impl_scheduler_x3_job;
mod live;
mod registration;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_live;
