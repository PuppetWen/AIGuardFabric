//! 调度周期任务的实现体（§5.2 SchedulerX3 双模下的六个平台级任务）。
//!
//! ## 设计约定
//!
//! - **离线可跑**：外部依赖（`AGF_SERVER_URL` / 对象存储 / 云监控）不可达时只
//!   `warn!` + 记失败，**绝不 panic、绝不无限重试**；
//! - **如实跳过**：前置条件未配置（如 `log-pull` 没有拉取源）时返回 [`TaskOutcome::skipped`]，
//!   计一次 run 但**不计失败**，日志写明"为什么跳过"；
//! - **纯逻辑可测**：时间窗口筛选、归档清单与 sha256、gzip 往返、报表渲染、拉取源解析、
//!   指标映射全部是纯函数，单元测试直接覆盖；**测试里绝不真发外部 HTTP**。
//!
//! ## 落盘产物
//!
//! | 任务 | 产物 |
//! |---|---|
//! | `asset-inventory` | `<AGF_REPORT_DIR>/asset-inventory-<ts>.json` |
//! | `log-pull` | `<AGF_REPORT_DIR>/log-pull-<ts>.json` |
//! | `cold-archive` | `<AGF_REPORT_DIR>/archive-<ts>.json` + 对象存储 `<name>.gz`（降级时 `<archive_dir>/<name>.gz`） |
//! | `report-generate` | `<AGF_REPORT_DIR>/report-<ts>.md` |

pub(crate) use std::collections::BTreeMap;

use std::fmt::Write as _;

pub(crate) use std::path::Path;
pub(crate) use std::path::PathBuf;

pub(crate) use std::sync::Arc;
pub(crate) use std::sync::Mutex;

pub(crate) use std::time::SystemTime;

#[cfg(test)]
pub(crate) use agf_alicloud::cms::{CmsAdapter, CmsApi, CmsMetric};

#[cfg(test)]
pub(crate) use agf_core::adapter::{Adapter, AdapterConfig, CircuitBreakerConfig, RetryConfig};

pub(crate) use agf_core::enums::IngestProtocol;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use agf_ingest::registry::ParserRegistry;

pub(crate) use agf_scan::loader::RulePackLoader;
pub(crate) use agf_scan::loader::RulesDir;

pub(crate) use agf_scan::redteam::CaseLibrary;

pub(crate) use agf_storage::ObjectStore;

pub(crate) use agf_storage::objectstore::content_hash;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

#[allow(unused_imports)]
pub(crate) use catalog::*;
#[allow(unused_imports)]
pub(crate) use collect_report_input::*;
pub(crate) use configured_pull::run_configured_pull;
#[allow(unused_imports)]
pub(crate) use run_log_pull::*;
mod cloud_inventory;
mod configured_pull;
pub(crate) use cloud_inventory::run_agentteams_sync;
mod redteam_cruise;
pub(crate) use redteam_cruise::{CruiseConfig, run_redteam_cruise};
mod cms_queue_client;
mod cms_queue_delivery;
mod cms_queue_outbox;
mod cms_queue_task;
pub(crate) use cms_queue_task::{CmsQueueConfig, run_cms_queue};
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests_2::*;

/// 8 个周期任务的固定顺序（`/tasks`、`/metrics`、注册表齐全性测试共用）。
pub(crate) const TASK_NAMES: [&str; 8] = [
    "rules-regression",
    "redteam-cruise",
    "asset-inventory",
    "log-pull",
    "rule-hot-reload",
    "cold-archive",
    "report-generate",
    "alicloud-cms-push",
];

/// 无数据占位（报表里如实写"本期无数据"，不编数字）。
pub(crate) const NO_DATA: &str = "本期无数据";

/// 任务静态描述（名称 + 说明 + 需要的配置）。
#[derive(Debug, Clone, Copy)]
pub(crate) struct TaskDescriptor {
    /// 任务名（与 `/metrics` 的 `task=` 标签一致）。
    pub(crate) name: &'static str,
    /// 静态说明（`/tasks` 的 `note`；运行时另有动态 note 时以动态为准）。
    pub(crate) note: &'static str,
}

/// 运行时可变的 note 覆盖（如 CMS 是否 mocked、归档是否降级）。
pub(crate) type NoteStore = Arc<Mutex<BTreeMap<&'static str, String>>>;

/// 任务执行结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TaskOutcome {
    /// 是否成功（skip / 降级都算成功：它们不是错误）。
    pub(crate) ok: bool,
    /// 本轮是否因未配置而如实跳过。
    pub(crate) skipped: bool,
    /// 是否走了降级路径（本地归档 / Mock 云指标）。
    pub(crate) degraded: bool,
    /// 人类可读结论（进日志与 `/tasks` 的动态 note）。
    pub(crate) note: String,
    /// 本轮落盘的产物路径。
    pub(crate) artifacts: Vec<String>,
}

/// 调用 agf-api 的凭据。
///
/// 平台 API 的认证中间件**只接受两种**凭据（见 `crates/agf-api/src/middleware.rs`）：
/// `X-AGF-Key: <API Key>` 或 `Authorization: Bearer <JWT>`；且**两者同时出现时优先校验
/// `X-AGF-Key`**（验不过就直接 401），因此必须二选一，不能都发。
///
/// 为什么需要它：调度器是**服务账号**，它没有交互式登录能力，也就拿不到 JWT——
/// 只能靠运维为它签发一把 API Key。此前只实现了 Bearer，导致 `asset-inventory` 与
/// `rule-hot-reload` 在容器里稳定 401（实测），这把缺口补上。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApiAuth {
    /// API Key（`X-AGF-Key`），服务账号推荐方式。
    ApiKey(String),
    /// 服务 JWT（`Authorization: Bearer`），由外部注入/轮换。
    Bearer(String),
}

// ---------------------------------------------------------------------------
// asset-inventory
// ---------------------------------------------------------------------------

/// 资产台账统计摘要（由 `GET /api/v1/assets/stats` 的真实响应派生，不编数字）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AssetStatsSummary {
    /// `inventory` 对象的字段数。
    pub(crate) inventory_fields: usize,
    /// 显式总量字段（`total` / `count` / `total_assets`）之一，缺失为 0。
    pub(crate) total: u64,
    /// 是否存在 `inventory` 对象。
    pub(crate) has_inventory: bool,
    /// 原始 JSON 文本字节数。
    pub(crate) raw_bytes: usize,
}

/// 单条拉取源的统计。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct SourceStat {
    /// 拉取地址。
    pub(crate) url: String,
    /// 是否拉取成功。
    pub(crate) ok: bool,
    /// 响应字节数。
    pub(crate) bytes: usize,
    /// 非空行数。
    pub(crate) lines: usize,
    /// 解析命中条数。
    pub(crate) parsed: usize,
    /// 解析未命中条数。
    pub(crate) failed: usize,
    /// 失败原因。
    pub(crate) error: Option<String>,
}

/// 日志拉取统计（落 `<AGF_REPORT_DIR>/log-pull-<ts>.json`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct LogPullStats {
    /// 配置的源数量。
    pub(crate) sources: usize,
    /// 拉取成功的源数量。
    pub(crate) fetched: usize,
    /// 非空行总数。
    pub(crate) lines: usize,
    /// 解析命中总数。
    pub(crate) parsed: usize,
    /// 解析未命中总数。
    pub(crate) failed: usize,
    /// 逐源明细。
    pub(crate) per_source: Vec<SourceStat>,
}

// ---------------------------------------------------------------------------
// cold-archive
// ---------------------------------------------------------------------------

/// 待归档候选（真实读盘：大小、mtime、sha256）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchiveCandidate {
    /// 文件绝对/相对路径。
    pub(crate) path: PathBuf,
    /// 文件名。
    pub(crate) name: String,
    /// 字节数。
    pub(crate) bytes: u64,
    /// 最后修改时间。
    pub(crate) modified: SystemTime,
    /// 距 now 的整天数（向下取整）。
    pub(crate) age_days: u64,
    /// 内容 SHA-256（hex）。
    pub(crate) sha256: String,
}

/// 归档清单条目（落 JSON 的稳定结构）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct ArchiveEntry {
    /// 原文件名。
    pub(crate) name: String,
    /// 原始字节数。
    pub(crate) bytes: u64,
    /// 原始内容 SHA-256。
    pub(crate) sha256: String,
    /// 归档时的年龄（天）。
    pub(crate) age_days: u64,
}

/// 归档清单（落 `<AGF_REPORT_DIR>/archive-<ts>.json`，也是报表"上次归档"的数据源）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct ArchiveManifest {
    /// 生成时间。
    pub(crate) at: String,
    /// 扫描目录。
    pub(crate) source_dir: String,
    /// 归档阈值（天）。
    pub(crate) archive_after_days: u64,
    /// 实际后端（`s3` / `local` / `memory`）。
    pub(crate) backend: String,
    /// 是否降级为本地归档。
    pub(crate) degraded_local: bool,
    /// 降级原因（如未配置 AGF_S3_*）。
    pub(crate) degrade_reason: Option<String>,
    /// 文件数。
    pub(crate) files: usize,
    /// 原始字节总数。
    pub(crate) bytes: u64,
    /// 清单哈希（对 entries 的 `name:sha256` 串联取 SHA-256）。
    pub(crate) manifest_sha256: String,
    /// 条目明细。
    pub(crate) entries: Vec<ArchiveEntry>,
    /// 上传成功的对象键。
    pub(crate) uploaded: Vec<String>,
    /// 本地归档产物路径（降级或兜底）。
    pub(crate) local_archives: Vec<String>,
    /// 已删除的本地原文件。
    pub(crate) deleted_locals: Vec<String>,
    /// 逐文件错误（失败只记录，不 panic）。
    pub(crate) errors: Vec<String>,
}

/// 归档作业配置（owned，便于在周期任务闭包里 clone）。
#[derive(Debug, Clone)]
pub(crate) struct ArchiveJob {
    /// 扫描目录（默认 `AGF_REPORT_DIR`）。
    pub(crate) report_dir: PathBuf,
    /// 本地归档目录（降级目标）。
    pub(crate) archive_dir: PathBuf,
    /// 对象存储句柄（`build_object_store`）。
    pub(crate) store: Arc<dyn ObjectStore>,
    /// `build_object_store` 的降级说明；`Some` = 当前不是真实对象存储。
    pub(crate) store_note: Option<String>,
    /// 归档阈值（天，严格超过才归档）。
    pub(crate) after_days: u64,
    /// 上传成功后是否删除本地原文件（默认 false）。
    pub(crate) delete_local: bool,
}

// ---------------------------------------------------------------------------
// report-generate
// ---------------------------------------------------------------------------

/// 任务执行态快照（来自 `Registry` 的真实计数）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct TaskSnapshot {
    /// 任务名。
    pub(crate) name: String,
    /// 已执行次数。
    pub(crate) runs: u64,
    /// 失败次数。
    pub(crate) failures: u64,
    /// 最近耗时（毫秒）。
    pub(crate) last_millis: u64,
}

/// 报表输入（全部字段来自真实读取，缺数据写 [`NO_DATA`]）。
#[derive(Debug, Clone, Default)]
pub(crate) struct ReportInput {
    /// 生成时间（RFC3339）。
    pub(crate) generated_at: String,
    /// 规则目录。
    pub(crate) rules_dir: String,
    /// 规则包条数。
    pub(crate) rules_count: Option<usize>,
    /// 规则包指纹。
    pub(crate) rules_fingerprint: Option<String>,
    /// 红队用例数。
    pub(crate) redteam_cases: Option<usize>,
    /// 最近的战役报告文件名（新的在前）。
    pub(crate) redteam_reports: Vec<String>,
    /// 资产盘点摘要。
    pub(crate) asset_summary: Option<String>,
    /// 日志拉取摘要。
    pub(crate) log_pull_summary: Option<String>,
    /// 上次归档清单。
    pub(crate) archive: Option<ArchiveManifest>,
    /// 云指标上报摘要。
    pub(crate) cms_note: Option<String>,
    /// 任务执行表。
    pub(crate) tasks: Vec<TaskSnapshot>,
}

/// [`ApiAuth`] 的选择逻辑单测（纯函数，不发任何请求）。
#[cfg(test)]
mod api_auth_tests {
    use super::ApiAuth;

    #[test]
    fn api_key_takes_precedence_over_bearer() {
        let auth = ApiAuth::from_values(Some("agf_live_key".into()), Some("eyJhbGciOi.jwt".into()));
        assert_eq!(auth, Some(ApiAuth::ApiKey("agf_live_key".into())));
    }

    #[test]
    fn bearer_is_used_when_no_api_key() {
        let auth = ApiAuth::from_values(None, Some("eyJhbGciOi.jwt".into()));
        assert_eq!(auth, Some(ApiAuth::Bearer("eyJhbGciOi.jwt".into())));
    }

    #[test]
    fn blank_or_missing_values_mean_unconfigured() {
        assert_eq!(ApiAuth::from_values(None, None), None);
        assert_eq!(ApiAuth::from_values(Some("   ".into()), Some(String::new())), None);
        // 只有 API Key 为空、JWT 有值 → 回落到 JWT（而不是把空 API Key 当成凭据）
        let auth = ApiAuth::from_values(Some("  ".into()), Some(" jwt ".into()));
        assert_eq!(auth, Some(ApiAuth::Bearer("jwt".into())));
    }

    #[test]
    fn values_are_trimmed() {
        let auth = ApiAuth::from_values(Some("  key-1  ".into()), None);
        assert_eq!(auth, Some(ApiAuth::ApiKey("key-1".into())));
    }
}

// ---------------------------------------------------------------------------
// 测试（纯逻辑；外部 HTTP 一律不真发）
// ---------------------------------------------------------------------------

mod catalog;
#[cfg(test)]
mod cms_push_tests;
mod collect_report_input;
mod run_log_pull;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_2;
