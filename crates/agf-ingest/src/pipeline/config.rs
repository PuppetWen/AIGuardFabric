//! 流水线配置、统计与限流：`IngestConfig`、`PipelineStats`、内部计数器与令牌桶（EPS 背压）。

use super::*;

// ---------------------------------------------------------------------------
// 配置与统计
// ---------------------------------------------------------------------------

/// 流水线配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestConfig {
    /// 脱敏模式（默认仅凭据；PII 是否脱敏属租户策略）。
    pub redaction: RedactionMode,
    /// 去重窗口（秒）；`0` 表示关闭去重。
    pub dedup_window_secs: i64,
    /// 是否投递事件总线。
    pub emit_to_bus: bool,
    /// 单批最大条数（`ingest_batch` 的背压点）。
    pub batch_limit: usize,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self { redaction: RedactionMode::CredentialsOnly, dedup_window_secs: 300, emit_to_bus: true, batch_limit: 512 }
    }
}

/// 流水线统计（原子累加，随时可读）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PipelineStats {
    /// 接收报文数（含被拒）。
    pub received: u64,
    /// 成功持久化事件数。
    pub persisted: u64,
    /// 去重丢弃数。
    pub deduped: u64,
    /// 超长报文拒绝数。
    pub oversized: u64,
    /// 限流拒绝数。
    pub rate_limited: u64,
    /// 未命中模板数。
    pub unmatched: u64,
    /// 命中模板数（严格趟 + 放宽趟 + 样本打分 + AI 推断 + 显式指定）。
    pub matched: u64,
    /// 其中**放宽趟**（忽略协议白名单）命中的条数——新接入协议（OTLP/MQTT/JDBC/Pulsar/
    /// SNMP Trap）缺模板声明时的兜底命中，单列出来以便"命中率变高"可解释、可告警。
    pub matched_relaxed: u64,
    /// 命中数**按匹配趟次全量分解**（键 = `MatchMode::as_str`：`explicit` / `protocol` /
    /// `protocol-relaxed` / `sample-score` / `ai-inferred`）。
    ///
    /// `matched` 是总量、`matched_relaxed` 是其中一格；本字段给**每一格**，
    /// 使"命中率变化"能逐趟解释（`/stats` 直读；`/metrics` 的同名分项见
    /// `agf_ingest_matched_by_total`）。
    #[serde(default)]
    pub matched_by: BTreeMap<String, u64>,
    /// 发生脱敏的事件数。
    pub redacted: u64,
    /// 总线投递失败数。
    pub bus_failed: u64,
}

#[derive(Debug, Default)]
pub(super) struct Counters {
    pub(super) received: AtomicU64,
    pub(super) persisted: AtomicU64,
    pub(super) deduped: AtomicU64,
    pub(super) oversized: AtomicU64,
    pub(super) rate_limited: AtomicU64,
    pub(super) unmatched: AtomicU64,
    pub(super) matched: AtomicU64,
    pub(super) matched_relaxed: AtomicU64,
    /// 按匹配趟次分解的命中数（原子量不够用：键集合来自 `MatchMode`，且只在命中时写 5 个取值）。
    pub(super) matched_by_mode: Mutex<BTreeMap<String, u64>>,
    pub(super) redacted: AtomicU64,
    pub(super) bus_failed: AtomicU64,
}

impl Counters {
    /// 记一格匹配趟次（锁中毒时**跳过**而不是 panic：指标不能反过来把接入流程搞挂）。
    pub(super) fn record_mode(&self, mode: MatchMode) {
        if let Ok(mut counts) = self.matched_by_mode.lock() {
            *counts.entry(mode.as_str().to_string()).or_insert(0) += 1;
        }
    }

    pub(super) fn snapshot(&self) -> PipelineStats {
        let matched_by =
            self.matched_by_mode.lock().map_or_else(|poisoned| poisoned.into_inner().clone(), |c| c.clone());
        PipelineStats {
            received: self.received.load(Ordering::Relaxed),
            persisted: self.persisted.load(Ordering::Relaxed),
            deduped: self.deduped.load(Ordering::Relaxed),
            oversized: self.oversized.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            unmatched: self.unmatched.load(Ordering::Relaxed),
            matched: self.matched.load(Ordering::Relaxed),
            matched_relaxed: self.matched_relaxed.load(Ordering::Relaxed),
            matched_by,
            redacted: self.redacted.load(Ordering::Relaxed),
            bus_failed: self.bus_failed.load(Ordering::Relaxed),
        }
    }
}

/// 令牌桶（每日志源一个）。
#[derive(Debug)]
pub(super) struct TokenBucket {
    pub(super) tokens: f64,
    pub(super) capacity: f64,
    pub(super) refill_per_sec: f64,
    pub(super) last: Instant,
}

impl TokenBucket {
    pub(super) fn new(max_eps: u32) -> Self {
        let capacity = f64::from(max_eps.max(1));
        Self { tokens: capacity, capacity, refill_per_sec: capacity, last: Instant::now() }
    }

    pub(super) fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
    }

    pub(super) fn try_acquire(&mut self) -> bool {
        self.try_acquire_many(1)
    }

    pub(super) fn set_rate(&mut self, max_eps: u32) {
        self.refill();
        self.capacity = f64::from(max_eps.max(1));
        self.refill_per_sec = self.capacity;
        self.tokens = self.tokens.min(self.capacity);
    }

    pub(super) fn try_acquire_many(&mut self, count: u32) -> bool {
        self.refill();
        let needed = f64::from(count);
        if self.tokens >= needed {
            self.tokens -= needed;
            true
        } else {
            false
        }
    }
}

/// 接入结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestOutcome {
    /// 原始日志 id。
    pub raw_id: Id,
    /// 事件 id（去重丢弃时为 `None`）。
    pub event_id: Option<Id>,
    /// 命中的解析器 key。
    pub parser_key: Option<String>,
    /// **命中趟次**（`explicit` / `protocol` / `protocol-relaxed` / `sample-score` / `ai-inferred`）。
    ///
    /// 逐条透出（来自 `ParseOutcome::matched_by`）：只给 `parser_key` 时"命中了，但凭什么命中"
    /// 不可观测——严格趟与放宽趟、样本打分、AI 兜底的**可信度不同**，运维与看板必须能区分。
    /// 未命中时为 `None`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_by: Option<String>,
    /// 是否命中模板。
    pub matched: bool,
    /// 是否**已落库**（原始日志 + 事件）。批量上限拒绝 / 前置校验失败为 `false`。
    ///
    /// 与 [`Self::matched`] **正交**：未命中模板的载荷仍会保真落库
    /// （`persisted = true, matched = false`），这是"保真优先"策略的体现；
    /// 而"接入条数"必须按本字段统计，否则"未命中"会被误报成"接入失败"。
    #[serde(default)]
    pub persisted: bool,
    /// 是否被判为重复丢弃。
    pub deduped: bool,
    /// 是否发生脱敏。
    pub redacted: bool,
    /// 载荷字节数。
    pub bytes: usize,
    /// 端到端耗时（微秒）。
    pub elapsed_micros: u64,
    /// 来源描述。
    pub origin: String,
    /// 处理失败原因（批量模式下不中断整批）。
    pub error: Option<String>,
}
