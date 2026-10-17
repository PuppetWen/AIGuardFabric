//! 接收器统计与 Prometheus 指标渲染：`KafkaStats` / `KafkaSeries` / `kafka_prometheus`（offset、lag、失败与重连）。

use super::*;

/// 分区级指标登记（与 [`ReceiverCounters`] 的四族计数互补）。
#[derive(Debug, Default)]
pub struct KafkaStats {
    partitions: Mutex<BTreeMap<i32, KafkaPartitionState>>,
    reconnects: AtomicU64,
    reconnect_backoff_ms: AtomicU64,
    records_consumed: AtomicU64,
    deduped: AtomicU64,
    skipped: AtomicU64,
    /// 最近一次多副本分配决策（`None` = 尚未做过分配，按单副本全分区渲染）。
    ownership: Mutex<Option<PartitionOwnership>>,
    /// 每个分区被**本副本接管**的累计次数（多副本接管的可观测证据）。
    takeovers: Mutex<BTreeMap<i32, u64>>,
}

/// 一条 Prometheus 指标序列（`/metrics` 聚合渲染用）。
#[derive(Debug, Clone)]
pub struct KafkaSeries {
    /// `receiver` 标签（`kafka` / `pulsar`）。
    pub receiver: String,
    /// `topic` 标签。
    pub topic: String,
    /// 指标来源。
    pub stats: Arc<KafkaStats>,
}

impl KafkaStats {
    /// 新建（全零）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录一次成功的分区取数（含空批次：空批次也要回写高水位，lag 才可观测）。
    pub fn record_batch(&self, partition: i32, next_offset: i64, high_watermark: i64, records: u64) {
        let mut map = match self.partitions.lock() {
            Ok(map) => map,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry =
            map.entry(partition).or_insert_with(|| KafkaPartitionState { partition, ..KafkaPartitionState::default() });
        entry.owned = true;
        entry.next_offset = next_offset;
        entry.high_watermark = high_watermark;
        entry.lag = high_watermark.saturating_sub(next_offset).max(0);
        entry.records = records;
        entry.records_total = entry.records_total.saturating_add(records);
        entry.last_success_ms = Some(now_millis());
        if entry.consecutive_failures != 0 {
            debug!(partition, previous_failures = entry.consecutive_failures, "Kafka 分区已恢复");
        }
        entry.consecutive_failures = 0;
        drop(map);
        self.records_consumed.fetch_add(records, Ordering::Relaxed);
    }

    /// 记录一次分区失败（原因脱敏并截断）。
    pub fn record_failure(&self, partition: i32, error: &str) {
        let mut map = match self.partitions.lock() {
            Ok(map) => map,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry =
            map.entry(partition).or_insert_with(|| KafkaPartitionState { partition, ..KafkaPartitionState::default() });
        entry.owned = true;
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.failures_total = entry.failures_total.saturating_add(1);
        entry.last_error = Some(sanitize_error(error));
    }

    /// 记录一次退避重连。
    pub fn record_reconnect(&self, delay: Duration) {
        self.reconnects.fetch_add(1, Ordering::Relaxed);
        self.reconnect_backoff_ms.store(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// 累加去重（重放）记录数。
    pub fn add_deduped(&self, n: u64) {
        self.deduped.fetch_add(n, Ordering::Relaxed);
    }

    /// 累加协议层跳过（墓碑/空值）记录数。
    pub fn add_skipped(&self, n: u64) {
        self.skipped.fetch_add(n, Ordering::Relaxed);
    }

    /// 登记本轮的多副本分配决策（每轮消费前调用；同时把**不由本副本负责**的分区
    /// 以 `owned=false` 占位写入快照——它们的 offset/lag 渲染为 `-1`（未知））。
    ///
    /// 接管计数：本轮 `taken_over_partitions` 里每个分区各计一次。
    pub fn set_ownership(&self, view: PartitionOwnership) {
        if !view.taken_over_partitions.is_empty() {
            let mut takeovers = match self.takeovers.lock() {
                Ok(map) => map,
                Err(poisoned) => poisoned.into_inner(),
            };
            for partition in &view.taken_over_partitions {
                let counter = takeovers.entry(*partition).or_insert(0);
                *counter = counter.saturating_add(1);
            }
        }
        let owners = view.owners.clone();
        let live = view.live_instances.clone();
        {
            let mut map = match self.partitions.lock() {
                Ok(map) => map,
                Err(poisoned) => poisoned.into_inner(),
            };
            for partition in &view.partitions {
                let owner = owners.get(partition).copied().unwrap_or(view.instance_id);
                let entry = map
                    .entry(*partition)
                    .or_insert_with(|| KafkaPartitionState { partition: *partition, ..KafkaPartitionState::default() });
                entry.owner_instance = owner;
                entry.live_instances.clone_from(&live);
                if owner != view.instance_id {
                    // 不由本副本负责：只保留归属信息，数值渲染为未知（-1），并且**不消费、不推进游标**
                    entry.owned = false;
                    entry.next_offset = -1;
                    entry.high_watermark = -1;
                    entry.lag = -1;
                }
            }
        }
        let mut slot = match self.ownership.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        *slot = Some(view);
    }

    /// 最近一次分配决策（`None` = 未启用多副本分配/尚未决策）。
    #[must_use]
    pub fn ownership(&self) -> Option<PartitionOwnership> {
        match self.ownership.lock() {
            Ok(slot) => slot.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// 每分区被本副本接管的累计次数快照。
    #[must_use]
    pub fn takeover_snapshot(&self) -> BTreeMap<i32, u64> {
        match self.takeovers.lock() {
            Ok(map) => map.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// 分区连续失败次数（用于"只 warn 一次"的日志降噪）。
    #[must_use]
    pub fn consecutive_failures(&self, partition: i32) -> u32 {
        match self.partitions.lock() {
            Ok(map) => map.get(&partition).map_or(0, |state| state.consecutive_failures),
            Err(poisoned) => poisoned.into_inner().get(&partition).map_or(0, |state| state.consecutive_failures),
        }
    }

    /// 累计去重记录数。
    #[must_use]
    pub fn deduped_total(&self) -> u64 {
        self.deduped.load(Ordering::Relaxed)
    }

    /// 累计跳过记录数。
    #[must_use]
    pub fn skipped_total(&self) -> u64 {
        self.skipped.load(Ordering::Relaxed)
    }

    /// 累计消费记录数。
    #[must_use]
    pub fn records_consumed_total(&self) -> u64 {
        self.records_consumed.load(Ordering::Relaxed)
    }

    /// 累计重连次数。
    #[must_use]
    pub fn reconnects_total(&self) -> u64 {
        self.reconnects.load(Ordering::Relaxed)
    }

    /// 当前退避间隔。
    #[must_use]
    pub fn reconnect_backoff(&self) -> Duration {
        Duration::from_millis(self.reconnect_backoff_ms.load(Ordering::Relaxed))
    }

    /// 总滞后（**只累加本副本负责的分区**，便于一条曲线看背压）。
    #[must_use]
    pub fn lag_total(&self) -> i64 {
        let map = match self.partitions.lock() {
            Ok(map) => map,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.values().filter(|state| state.owned).map(|state| state.lag.max(0)).sum()
    }

    /// 分区状态快照（key = 分区号文本，输出稳定）。
    ///
    /// 归属字段（`owned` / `owner_instance` / `live_instances`）来自最近一次
    /// [`Self::set_ownership`]；未启用多副本分配时按"单副本消费全部分区"渲染
    /// （`owned=true`、`live_instances=[instance_id]`）。
    #[must_use]
    pub fn snapshot(&self) -> BTreeMap<String, KafkaPartitionState> {
        let view = self.ownership();
        let map = match self.partitions.lock() {
            Ok(map) => map,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.iter()
            .map(|(partition, state)| {
                let mut state = state.clone();
                match &view {
                    Some(view) => {
                        state.owned = view.owns(state.partition);
                        state.owner_instance = view.owner_of(state.partition).unwrap_or(view.instance_id);
                        state.live_instances.clone_from(&view.live_instances);
                    }
                    None => {
                        state.owned = true;
                        state.live_instances = vec![state.owner_instance];
                    }
                }
                (partition.to_string(), state)
            })
            .collect()
    }
}

/// 当前时间（epoch 毫秒）。
pub(super) fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// 错误文本脱敏：截断 + 去掉可能的控制字符（错误只来自 broker 侧，本模块从不把凭据拼进去）。
pub(super) fn sanitize_error(error: &str) -> String {
    let cleaned: String = error.chars().filter(|c| !c.is_control()).take(200).collect();
    cleaned
}

/// 从游标键 `"{topic}/{partition}"` 反解分区号（键前缀必须与当前 topic 完全一致）。
pub(super) fn cursor_partition_of(key: &str, topic: &str) -> Option<i32> {
    key.strip_prefix(topic)?.strip_prefix('/')?.parse().ok()
}

/// 渲染 Kafka 分区指标（`/metrics` 用；HELP/TYPE 每族只出一次，多个接收器共用）。
#[must_use]
pub fn kafka_prometheus(series: &[KafkaSeries]) -> String {
    let mut out = String::new();
    let families: [(&str, &str, &str); 11] = [
        ("agf_ingest_kafka_offset", "每个分区本地游标（下一个待消费 offset；处理成功后才推进）", "gauge"),
        ("agf_ingest_kafka_lag", "每个分区滞后（broker 高水位 − 本地游标；-1 = 该分区不由本副本负责）", "gauge"),
        ("agf_ingest_kafka_fetch_failures_total", "每个分区定位/拉取失败累计次数", "counter"),
        ("agf_ingest_kafka_records_consumed_total", "已消费（游标已推进）记录数", "counter"),
        ("agf_ingest_kafka_deduped_total", "流水线去重命中的记录数（崩溃重放的可见证据）", "counter"),
        ("agf_ingest_kafka_skipped_records_total", "协议层跳过的记录数（墓碑/空值）", "counter"),
        ("agf_ingest_kafka_reconnects_total", "退避重连次数（broker 不可达）", "counter"),
        ("agf_ingest_kafka_reconnect_backoff_seconds", "当前退避间隔（秒）", "gauge"),
        (
            "agf_ingest_kafka_partition_owned",
            "本副本是否负责该分区（1=负责；0=由 owner_instance 负责，本副本不消费、不推进游标）",
            "gauge",
        ),
        (
            "agf_ingest_kafka_partition_takeovers_total",
            "该分区被**本副本**接管的累计次数（原负责副本租约判死后重分片到本副本）",
            "counter",
        ),
        (
            "agf_ingest_kafka_instance_info",
            "多副本分配身份（instance_id/instance_count=静态分片；live_instances=租约判活结果）",
            "gauge",
        ),
    ];
    for (name, help, kind) in families {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
        for item in series {
            let receiver = escape_label(&item.receiver);
            let topic = escape_label(&item.topic);
            match name {
                "agf_ingest_kafka_offset" | "agf_ingest_kafka_lag" | "agf_ingest_kafka_fetch_failures_total" => {
                    for state in item.stats.snapshot().values() {
                        let value = match name {
                            "agf_ingest_kafka_offset" => state.next_offset,
                            "agf_ingest_kafka_lag" => state.lag,
                            _ => i64::try_from(state.failures_total).unwrap_or(i64::MAX),
                        };
                        out.push_str(&format!(
                            "{name}{{receiver=\"{receiver}\",topic=\"{topic}\",partition=\"{}\"}} {value}\n",
                            state.partition
                        ));
                    }
                }
                "agf_ingest_kafka_records_consumed_total" => out.push_str(&format!(
                    "{name}{{receiver=\"{receiver}\",topic=\"{topic}\"}} {}\n",
                    item.stats.records_consumed_total()
                )),
                "agf_ingest_kafka_deduped_total" => out.push_str(&format!(
                    "{name}{{receiver=\"{receiver}\",topic=\"{topic}\"}} {}\n",
                    item.stats.deduped_total()
                )),
                "agf_ingest_kafka_skipped_records_total" => out.push_str(&format!(
                    "{name}{{receiver=\"{receiver}\",topic=\"{topic}\"}} {}\n",
                    item.stats.skipped_total()
                )),
                "agf_ingest_kafka_reconnects_total" => out.push_str(&format!(
                    "{name}{{receiver=\"{receiver}\",topic=\"{topic}\"}} {}\n",
                    item.stats.reconnects_total()
                )),
                // 多副本分配：每分区一行，`owner_instance` 明示归属，`owned` 明示本副本是否消费它
                "agf_ingest_kafka_partition_owned" => {
                    for state in item.stats.snapshot().values() {
                        let owned = u8::from(state.owned);
                        out.push_str(&format!(
                            "{name}{{receiver=\"{receiver}\",topic=\"{topic}\",partition=\"{}\",owner_instance=\"{}\"}} {owned}\n",
                            state.partition, state.owner_instance
                        ));
                    }
                }
                // 接管计数：每分区一行（0 也出，避免"零接管 = 指标消失"的观测空洞）
                "agf_ingest_kafka_partition_takeovers_total" => {
                    let takeovers = item.stats.takeover_snapshot();
                    for state in item.stats.snapshot().values() {
                        let count = takeovers.get(&state.partition).copied().unwrap_or(0);
                        out.push_str(&format!(
                            "{name}{{receiver=\"{receiver}\",topic=\"{topic}\",partition=\"{}\"}} {count}\n",
                            state.partition
                        ));
                    }
                }
                // 身份：未启用多副本分配时如实渲染"单副本消费全部分区"（instance_id=0/instance_count=1）
                "agf_ingest_kafka_instance_info" => {
                    let (id, count, live, leased, degraded, settling, ttl) = match item.stats.ownership() {
                        Some(view) => (
                            view.instance_id,
                            view.instance_count,
                            view.live_instances.iter().map(u32::to_string).collect::<Vec<_>>().join(","),
                            view.leased,
                            view.degraded,
                            view.settling,
                            view.lease_ttl_ms,
                        ),
                        None => (0, 1, "0".to_string(), false, false, false, 0),
                    };
                    out.push_str(&format!(
                        "{name}{{receiver=\"{receiver}\",topic=\"{topic}\",instance_id=\"{id}\",\
                         instance_count=\"{count}\",live_instances=\"{live}\",leased=\"{}\",degraded=\"{}\",\
                         settling=\"{}\",lease_ttl_ms=\"{ttl}\"}} 1\n",
                        u8::from(leased),
                        u8::from(degraded),
                        u8::from(settling)
                    ));
                }
                _ => {
                    let secs = item.stats.reconnect_backoff().as_secs_f64();
                    out.push_str(&format!("{name}{{receiver=\"{receiver}\",topic=\"{topic}\"}} {secs}\n"));
                }
            }
        }
    }
    out
}

/// Prometheus 标签值转义（`\` `"` 换行）。
fn escape_label(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

// ---------------------------------------------------------------------------
// 单轮消费结果
// ---------------------------------------------------------------------------
