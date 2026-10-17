//! SQL 拉取结果与指标：`SqlPullReport`、`SqlPullMetrics`（按方言登记）与 `pull_prometheus`。

use super::*;

/// 单轮拉取结果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlPullReport {
    /// 本批行数。
    pub rows: usize,
    /// 落库事件数。
    pub persisted: usize,
    /// 行 JSON 解析失败（丢弃）数。
    pub malformed: usize,
}

/// SQL 拉取专属指标（拉取条数 / 丢弃 / 每轮批次数 / 查询失败数 / 游标推进次数）。
///
/// 与 [`ReceiverCounters`] 的分工：后者是**所有接收器统一口径**的四族计数（协议层收到 /
/// 命中 / 未命中 / 丢弃），本结构是 SQL 拉取**特有的**观测面——"这一轮到底从数据库拉了几行、
/// 有几行被丢弃、游标推进了几次、查询失败了几次"。两者都如实给出，不互相推算。
#[derive(Debug, Default)]
pub struct SqlPullMetrics {
    rows_pulled: AtomicU64,
    rows_dropped: AtomicU64,
    batches: AtomicU64,
    errors: AtomicU64,
    cursor_advanced: AtomicU64,
}

/// [`SqlPullMetrics`] 的只读快照。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlPullMetricsSnapshot {
    /// 累计从数据库拉取的行数。
    pub rows_pulled: u64,
    /// 累计丢弃行数（行 JSON 缺游标列 / 未落库）。
    pub rows_dropped: u64,
    /// 累计拉取轮次。
    pub batches: u64,
    /// 累计查询失败轮次。
    pub errors: u64,
    /// 累计游标推进次数。
    pub cursor_advanced: u64,
}

impl SqlPullMetrics {
    /// 新建（全零）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(super) fn record_pulled(&self, rows: usize) {
        self.rows_pulled.fetch_add(u64::try_from(rows).unwrap_or(u64::MAX), Ordering::Relaxed);
        self.batches.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn record_dropped(&self, rows: usize) {
        self.rows_dropped.fetch_add(u64::try_from(rows).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub(super) fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn record_cursor_advanced(&self) {
        self.cursor_advanced.fetch_add(1, Ordering::Relaxed);
    }

    /// 快照。
    #[must_use]
    pub fn snapshot(&self) -> SqlPullMetricsSnapshot {
        SqlPullMetricsSnapshot {
            rows_pulled: self.rows_pulled.load(Ordering::Relaxed),
            rows_dropped: self.rows_dropped.load(Ordering::Relaxed),
            batches: self.batches.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            cursor_advanced: self.cursor_advanced.load(Ordering::Relaxed),
        }
    }

    /// Prometheus 文本（与统一四族计数器同格式，可直接拼进 `/metrics`）。
    #[must_use]
    pub fn prometheus(&self, dialect: SqlDialect, receiver: &str) -> String {
        let snapshot = self.snapshot();
        let labels = format!("receiver=\"{receiver}\",dialect=\"{}\"", dialect.as_str());
        let mut out = String::new();
        for (name, help, value) in [
            ("agf_ingest_jdbc_rows_pulled_total", "SQL 拉取累计行数", snapshot.rows_pulled),
            ("agf_ingest_jdbc_rows_dropped_total", "SQL 拉取累计丢弃行数", snapshot.rows_dropped),
            ("agf_ingest_jdbc_batches_total", "SQL 拉取累计轮次", snapshot.batches),
            ("agf_ingest_jdbc_errors_total", "SQL 拉取累计查询失败轮次", snapshot.errors),
            ("agf_ingest_jdbc_cursor_advanced_total", "SQL 拉取累计游标推进次数", snapshot.cursor_advanced),
        ] {
            out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n{name}{{{labels}}} {value}\n"));
        }
        out
    }
}

/// 进程级 SQL 拉取指标槽位（`/metrics` 用，详见 [`pull_prometheus`]）。
static PROCESS_PULL_METRICS: Mutex<Option<(Arc<SqlPullMetrics>, SqlDialect)>> = Mutex::new(None);

/// 登记进程级 SQL 拉取指标（接收器构造时调用；锁中毒 ⇒ 照常写入，绝不影响接收器）。
pub(super) fn register_process_pull_metrics(metrics: &Arc<SqlPullMetrics>, dialect: SqlDialect) {
    let mut slot = match PROCESS_PULL_METRICS.lock() {
        Ok(slot) => slot,
        Err(poisoned) => poisoned.into_inner(),
    };
    *slot = Some((Arc::clone(metrics), dialect));
}

/// 渲染进程级 SQL 拉取指标的 Prometheus 文本（挂在 `/metrics`）。
///
/// 与 [`crate::mqtt::link_prometheus`] 同一套路：接收器构造时把自己的指标句柄登记进
/// [`PROCESS_PULL_METRICS`]（进程内只有一个 SQL 拉取接收器，重复构造时后登记的生效）。
/// **未登记时渲染全零序列**（方言标签取默认 `postgres`）——未配置 SQL 拉取时这一族指标
/// 仍然存在，而不是"有数据才出现"。
#[must_use]
pub fn pull_prometheus() -> String {
    // 先取出句柄再渲染：渲染过程不持有槽位锁（与 `snmp::usm_prometheus` 一致）。
    let registered = {
        let slot = match PROCESS_PULL_METRICS.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        slot.clone()
    };
    match registered {
        Some((metrics, dialect)) => metrics.prometheus(dialect, "jdbc"),
        None => SqlPullMetrics::new().prometheus(SqlDialect::default(), "jdbc"),
    }
}
