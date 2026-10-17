//! 冷归档指标：编码成功/回落/失败计数与只读快照（进程级单例，`/metrics` 用）。

use super::*;

/// 冷归档进程级指标（对象数 / 字节数 / 事件数 / 回落次数 / Parquet 对象数 / 回灌计数）。
#[derive(Debug, Default)]
pub struct ColdArchiveMetrics {
    objects: AtomicU64,
    bytes: AtomicU64,
    events: AtomicU64,
    fallbacks: AtomicU64,
    parquet_objects: AtomicU64,
    replay_objects: AtomicU64,
    replay_events: AtomicU64,
    replay_duplicates: AtomicU64,
    replay_filtered: AtomicU64,
}

/// [`ColdArchiveMetrics`] 的只读快照。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdArchiveMetricsSnapshot {
    /// 归档对象数。
    pub objects: u64,
    /// 归档字节数（**压缩后**实际写入对象存储的字节数）。
    pub bytes: u64,
    /// 归档事件数。
    pub events: u64,
    /// Parquet 失败回落 gzip 的次数。
    pub fallbacks: u64,
    /// Parquet 格式的对象数。
    pub parquet_objects: u64,
    /// 回灌过的归档对象数。
    pub replay_objects: u64,
    /// 回灌写入 sink 的事件数。
    pub replay_events: u64,
    /// 回灌时因**账本命中（重复）**跳过的事件数。
    pub replay_duplicates: u64,
    /// 回灌时被时间/租户过滤掉的事件数。
    pub replay_filtered: u64,
}

impl ColdArchiveMetrics {
    /// 常量构造（用于进程级 `static`）。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            objects: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            events: AtomicU64::new(0),
            fallbacks: AtomicU64::new(0),
            parquet_objects: AtomicU64::new(0),
            replay_objects: AtomicU64::new(0),
            replay_events: AtomicU64::new(0),
            replay_duplicates: AtomicU64::new(0),
            replay_filtered: AtomicU64::new(0),
        }
    }

    pub(super) fn record(&self, format: ColdFormat, bytes: usize, events: usize) {
        self.objects.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
        self.events.fetch_add(u64::try_from(events).unwrap_or(u64::MAX), Ordering::Relaxed);
        if format == ColdFormat::Parquet {
            self.parquet_objects.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn record_fallback(&self) {
        self.fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    /// 记账一次回灌（对象数 +1；入库/重复/过滤按事件数累加）。
    pub(super) fn record_replay(&self, _format: ColdFormat, replayed: usize, duplicates: usize, filtered: usize) {
        self.replay_objects.fetch_add(1, Ordering::Relaxed);
        self.replay_events.fetch_add(u64::try_from(replayed).unwrap_or(u64::MAX), Ordering::Relaxed);
        self.replay_duplicates.fetch_add(u64::try_from(duplicates).unwrap_or(u64::MAX), Ordering::Relaxed);
        self.replay_filtered.fetch_add(u64::try_from(filtered).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// 快照。
    #[must_use]
    pub fn snapshot(&self) -> ColdArchiveMetricsSnapshot {
        ColdArchiveMetricsSnapshot {
            objects: self.objects.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            events: self.events.load(Ordering::Relaxed),
            fallbacks: self.fallbacks.load(Ordering::Relaxed),
            parquet_objects: self.parquet_objects.load(Ordering::Relaxed),
            replay_objects: self.replay_objects.load(Ordering::Relaxed),
            replay_events: self.replay_events.load(Ordering::Relaxed),
            replay_duplicates: self.replay_duplicates.load(Ordering::Relaxed),
            replay_filtered: self.replay_filtered.load(Ordering::Relaxed),
        }
    }

    /// Prometheus 文本。
    #[must_use]
    pub fn prometheus(&self) -> String {
        let snapshot = self.snapshot();
        let mut out = String::new();
        for (name, help, value) in [
            ("agf_ingest_coldarchive_objects_total", "冷归档对象数", snapshot.objects),
            ("agf_ingest_coldarchive_bytes_total", "冷归档写入字节数（压缩后）", snapshot.bytes),
            ("agf_ingest_coldarchive_events_total", "冷归档事件数", snapshot.events),
            ("agf_ingest_coldarchive_fallbacks_total", "Parquet 编码失败回落 gzip 次数", snapshot.fallbacks),
            ("agf_ingest_coldarchive_parquet_objects_total", "Parquet 格式归档对象数", snapshot.parquet_objects),
            (
                "agf_ingest_coldarchive_replay_objects_total",
                "回灌的归档对象数（arrow 列式读回）",
                snapshot.replay_objects,
            ),
            ("agf_ingest_coldarchive_replay_events_total", "回灌写入 sink 的事件数", snapshot.replay_events),
            (
                "agf_ingest_coldarchive_replay_duplicates_total",
                "回灌因 raw_hash 账本命中而跳过的事件数（幂等）",
                snapshot.replay_duplicates,
            ),
            ("agf_ingest_coldarchive_replay_filtered_total", "回灌被时间/租户过滤掉的事件数", snapshot.replay_filtered),
        ] {
            out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"));
        }
        out
    }
}

/// 进程级归档指标（`/metrics` 可直接拼接 [`ColdArchiveMetrics::prometheus`]）。
static ARCHIVE_METRICS: ColdArchiveMetrics = ColdArchiveMetrics::new();

/// 取进程级归档指标。
#[must_use]
pub const fn archive_metrics() -> &'static ColdArchiveMetrics {
    &ARCHIVE_METRICS
}

// ---------------------------------------------------------------------------
// Parquet 列式 schema
// ---------------------------------------------------------------------------
