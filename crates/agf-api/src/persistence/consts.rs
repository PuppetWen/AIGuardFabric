//! 持久化覆盖面常量（队列上限、水合上限、已落库 / 仅内存资源清单）。

pub const MAX_PENDING_WRITES: usize = 4096;

/// 最近错误保留条数（`PersistenceReport::recent_errors`）。
pub const MAX_RECENT_ERRORS: usize = 16;

/// 水合单资源上限（防止超大库把启动拖死；超出部分如实记进报告）。
pub const HYDRATE_LIMIT: i64 = 100_000;

/// 发现分页水合的页大小（`agf_core::pagination::MAX_PAGE_SIZE` 上限 200）。
pub(super) const FINDING_PAGE_SIZE: u32 = 200;

/// 发现分页水合的页数上限（200 × 200 = 40 000 条，超出部分记进报告）。
pub(super) const MAX_FINDING_PAGES: u32 = 200;

/// 丢弃日志的采样间隔（每 1000 条丢弃记一条日志，避免日志自身成为放大器）。
pub(super) const DROP_LOG_INTERVAL: u64 = 1_000;

/// 已落 PG 的资源（与 [`PersistenceReport::durable`] 同源）。
pub const DURABLE_RESOURCES: &[&str] = &[
    "assets",
    "assets.changes",
    "assets.snapshots",
    "findings",
    "policies",
    "alerts",
    "cases",
    "cases.events",
    "audit_logs",
    "api_keys",
    "scan_jobs",
    "redteam_campaigns",
    "redteam_reports",
];

/// **仅**内存的资源：`agf_storage::repository` 没有对应仓储方法（不是忘了接）。
pub const MEMORY_ONLY_RESOURCES: &[&str] = &[
    "quotas",
    "quota_usage",
    "reports",
    "report_schedules",
    "model_route_policies",
    "soar_runs",
    "auth_users(内存后端 InMemoryAuthBackend)",
    "runtime_interceptions(agf_runtime 进程内哈希链)",
    "risk_history(进程内趋势采样)",
    "ingest_raw_logs(InMemorySink)",
];
