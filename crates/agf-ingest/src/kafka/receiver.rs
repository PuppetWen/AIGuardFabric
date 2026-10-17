//! Kafka 接收器：结构体、构造器与游标/归属维护（拉取循环与 `Receiver` 实现在 `receiver_pull` 子模块）。

use super::*;

/// 单轮消费结果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KafkaPullReport {
    /// 消费到的记录数。
    pub records: usize,
    /// 拆出的日志条数（一条记录可含多行）。
    pub lines: usize,
    /// 落库事件数。
    pub persisted: usize,
    /// 拉取失败的分区数。
    pub failed_partitions: usize,
    /// 协议层跳过的记录数（墓碑/空值）。
    pub skipped: usize,
}

// ---------------------------------------------------------------------------
// 停机信号
// ---------------------------------------------------------------------------

/// 停机信号：`apps/ingest` 在 SIGINT/SIGTERM 时触发，接收器随即刷新游标并退出。
#[derive(Debug, Clone)]
pub struct KafkaShutdown {
    tx: watch::Sender<bool>,
}

impl KafkaShutdown {
    /// 新建（未触发）。
    #[must_use]
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        Self { tx }
    }

    /// 取一个接收端句柄（交给接收器）。
    #[must_use]
    pub fn handle(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }

    /// 触发停机（幂等）。
    pub fn trigger(&self) {
        let _ = self.tx.send(true);
    }

    /// 是否已触发。
    #[must_use]
    pub fn triggered(&self) -> bool {
        *self.tx.borrow()
    }
}

impl Default for KafkaShutdown {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// 接收器
// ---------------------------------------------------------------------------

/// Kafka 消费接收器（多分区 + 本地游标 + SASL/TLS + 退避重连 + 优雅停机）。
///
/// 字段为 `pub(super)`：拉取循环与 `Receiver` 实现拆在 `receiver_pull` 子模块，仍需访问这些字段
/// （对 `kafka` 之外的可见性不变 ⇒ 公开 API 未扩大）。
#[derive(Debug)]
pub struct KafkaReceiver {
    pub(super) source: Arc<dyn KafkaSource>,
    pub(super) config: KafkaPullConfig,
    pub(super) cursor: Mutex<KafkaCursor>,
    pub(super) counters: Arc<ReceiverCounters>,
    pub(super) stats: Arc<KafkaStats>,
    pub(super) shutdown: Option<watch::Receiver<bool>>,
    pub(super) stopped: AtomicBool,
    /// 已见分区（用于"新增分区自动纳入"只打一次日志）。
    pub(super) known_partitions: Mutex<Vec<i32>>,
    /// 本接收器构造时刻（多副本分配的**启动静默期**基准；见 [`KafkaPullConfig::assign_settle_ms`]）。
    pub(super) started_at: std::time::Instant,
}

impl KafkaReceiver {
    /// 构造（游标从 `config.cursor_path` 恢复；多副本模式下从**分区分片游标目录**合并恢复）。
    #[must_use]
    pub fn new(source: Arc<dyn KafkaSource>, config: KafkaPullConfig) -> Self {
        let mut cursor = match (&config.lease_dir, &config.cursor_path) {
            // 多副本：每个分区一个游标文件（归属交接时新 owner 读原 owner 的进度 ⇒ 接管不丢）
            (Some(dir), _) => KafkaCursor::load_sharded(dir, &config.cursor_shard_prefix()),
            (None, Some(path)) => KafkaCursor::load(path),
            (None, None) => KafkaCursor { version: 1, namespace: None, offsets: BTreeMap::new() },
        };
        if cursor.version == 0 {
            cursor.version = 1;
        }
        match (&cursor.namespace, &config.namespace) {
            (Some(found), Some(expected)) if found != expected => warn!(
                cursor_namespace = %found,
                config_namespace = %expected,
                "Kafka 游标命名空间与当前配置不一致（可能指向了别的订阅/消费者组）——继续使用游标，请确认是否串号"
            ),
            (None, Some(expected)) => cursor.namespace = Some(expected.clone()),
            _ => {}
        }
        if !cursor.offsets.is_empty() {
            info!(
                partitions = cursor.offsets.len(),
                namespace = cursor.namespace.as_deref().unwrap_or("-"),
                "Kafka 游标已恢复（进程重启不重复消费）"
            );
        }
        Self {
            source,
            config,
            cursor: Mutex::new(cursor),
            counters: Arc::new(ReceiverCounters::new()),
            stats: Arc::new(KafkaStats::new()),
            shutdown: None,
            stopped: AtomicBool::new(false),
            known_partitions: Mutex::new(Vec::new()),
            started_at: std::time::Instant::now(),
        }
    }

    /// 注入共享计数器。
    #[must_use]
    pub fn with_counters(mut self, counters: Arc<ReceiverCounters>) -> Self {
        self.counters = counters;
        self
    }

    /// 注入分区指标登记（`/metrics` 与 `/stats` 共享）。
    #[must_use]
    pub fn with_stats(mut self, stats: Arc<KafkaStats>) -> Self {
        self.stats = stats;
        self
    }

    /// 注入停机信号（SIGINT/SIGTERM 时刷新游标并退出）。
    #[must_use]
    pub fn with_shutdown(mut self, shutdown: watch::Receiver<bool>) -> Self {
        self.shutdown = Some(shutdown);
        self
    }

    /// 配置。
    #[must_use]
    pub const fn config(&self) -> &KafkaPullConfig {
        &self.config
    }

    /// 计数器。
    #[must_use]
    pub fn counters(&self) -> &Arc<ReceiverCounters> {
        &self.counters
    }

    /// 分区指标。
    #[must_use]
    pub fn stats(&self) -> &Arc<KafkaStats> {
        &self.stats
    }

    /// 游标快照。
    #[must_use]
    pub fn cursor_snapshot(&self) -> KafkaCursor {
        match self.cursor.lock() {
            Ok(cursor) => cursor.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// 游标刷新落盘（**停机路径显式调用**；正常路径每批成功后也已落盘）。
    ///
    /// # Errors
    /// 写盘失败。
    pub fn flush_cursor(&self) -> DomainResult<()> {
        let cursor = self.cursor_snapshot();
        if let Some(dir) = &self.config.lease_dir {
            // 多副本：每个分区各写自己的分片文件（只有该分区的 owner 会写它）
            let prefix = self.config.cursor_shard_prefix();
            let topic = self.config.topic.clone();
            for (key, next_offset) in &cursor.offsets {
                let Some(partition) = cursor_partition_of(key, &topic) else {
                    continue;
                };
                cursor.save_shard(dir, &prefix, &topic, partition, *next_offset)?;
            }
        } else {
            let Some(path) = self.config.cursor_path.clone() else {
                return Ok(());
            };
            cursor.save(&path)?;
        }
        info!(
            directory = %self.config.lease_dir.as_deref().map_or_else(|| "-".to_string(), |dir| dir.display().to_string()),
            path = %self.config.cursor_path.as_deref().map_or_else(|| "-".to_string(), |path| path.display().to_string()),
            partitions = cursor.offsets.len(),
            namespace = cursor.namespace.as_deref().unwrap_or("-"),
            "Kafka 游标已刷新落盘（停机前保证不丢进度）"
        );
        Ok(())
    }

    /// 设置某分区游标（并落盘）。
    pub(super) fn set_offset(&self, topic: &str, partition: i32, offset: i64) -> DomainResult<()> {
        {
            let mut cursor = match self.cursor.lock() {
                Ok(cursor) => cursor,
                Err(poisoned) => poisoned.into_inner(),
            };
            if cursor.version == 0 {
                cursor.version = 1;
            }
            if cursor.namespace.is_none() {
                cursor.namespace.clone_from(&self.config.namespace);
            }
            cursor.offsets.insert(KafkaCursor::key(topic, partition), offset);
        }
        if let Some(dir) = &self.config.lease_dir {
            let prefix = self.config.cursor_shard_prefix();
            self.cursor_snapshot().save_shard(dir, &prefix, topic, partition, offset)?;
            return Ok(());
        }
        if let Some(path) = &self.config.cursor_path {
            self.cursor_snapshot().save(path)?;
        }
        Ok(())
    }

    /// 丢弃某分区游标（拉取失败后的自愈：下一轮按 `start_from` 重新定位）。
    pub(super) fn drop_offset(&self, topic: &str, partition: i32) {
        if let Ok(mut cursor) = self.cursor.lock() {
            cursor.offsets.remove(&KafkaCursor::key(topic, partition));
        }
    }

    /// 分区集合变化检测（新增分区自动纳入；消失的分区游标保留但不推进）。
    pub(super) fn note_partition_changes(&self, partitions: &[i32]) {
        let mut known = match self.known_partitions.lock() {
            Ok(known) => known,
            Err(poisoned) => poisoned.into_inner(),
        };
        if known.as_slice() == partitions {
            return;
        }
        let added: Vec<i32> = partitions.iter().copied().filter(|p| !known.contains(p)).collect();
        let removed: Vec<i32> = known.iter().copied().filter(|p| !partitions.contains(p)).collect();
        if !known.is_empty() {
            if !added.is_empty() {
                info!(topic = %self.config.topic, ?added, "Kafka topic 分区数增加：新分区自动纳入（按 start_from 解析起始 offset）");
            }
            if !removed.is_empty() {
                warn!(topic = %self.config.topic, ?removed, "Kafka topic 分区消失/不可见：该分区本轮不再消费（游标保留）");
            }
        }
        *known = partitions.to_vec();
    }

    /// 计算本轮的多副本分配决策（写心跳 → 读存活集合 → 算归属）。
    ///
    /// * 未启用多副本分配：`owners` 全为 `instance_id`（= 0）、`owned` = topic 全部分区
    ///   （与历史单副本行为**逐字节等价**）；
    /// * 启用但无租约目录：静态取模 `p % instance_count`，不接管；
    /// * 启用且配了租约目录：存活集合由心跳决定，**副本数变化即全量重分片**。
    ///
    /// 租约目录不可读/不可写时**降级为静态取模**并 `warn!`（宁可不接管，也不冒"两个副本同时消费同一分区"的险）。
    pub(super) fn resolve_ownership(&self, all_partitions: &[i32]) -> PartitionOwnership {
        let previous: BTreeMap<i32, u32> = self.stats.ownership().map(|view| view.owners).unwrap_or_default();
        if !self.config.assignment_enabled() {
            return PartitionOwnership::compute(&self.config, all_partitions, &[], &[], false, &previous);
        }
        let (me, _) = self.config.assignment_identity();
        let namespace = self.config.namespace.clone().unwrap_or_else(|| self.config.consumer_id.clone());
        let mut degraded = false;
        let (live, seen) = match &self.config.lease_dir {
            Some(dir) => match lease_write_heartbeat(dir, &namespace, me) {
                Ok(_) => lease_live_instances(dir, &namespace, self.config.lease_ttl_ms, me),
                Err(e) => {
                    warn!(
                        error = %e,
                        instance_id = me,
                        "多副本分配：心跳写入失败，本轮降级为静态取模（**不接管**，避免重复消费）"
                    );
                    degraded = true;
                    (Vec::new(), Vec::new())
                }
            },
            None => (Vec::new(), Vec::new()),
        };
        // 启动静默期：等同伴的心跳到齐再认领分区（否则"先启动的副本端走全部分区"，
        // 与随后到齐的同伴形成重叠消费窗口）。
        let settling = self.config.lease_enabled()
            && !degraded
            && self.config.assign_settle_ms > 0
            && self.started_at.elapsed() < Duration::from_millis(self.config.assign_settle_ms);
        if settling {
            debug!(
                instance_id = me,
                settle_ms = self.config.assign_settle_ms,
                live = ?live,
                "多副本分配：启动静默期内（只写心跳、不认领分区）——等价于 Kafka 的 group.initial.rebalance.delay"
            );
        }
        PartitionOwnership::compute_with_settle(
            &self.config,
            all_partitions,
            &live,
            &seen,
            degraded,
            &previous,
            settling,
        )
    }

    /// 把磁盘上的**分区分片游标**读回内存（只在内存里还没有该分区时写入）。
    ///
    /// 为什么必须有：新 owner 的内存游标是**构造接收器时**加载的，那时它还不负责这个分区，
    /// 因此接管后如果直接按 `start_from` 重新定位——`latest` 起点 = **丢消息**，
    /// `earliest` 起点 = 全量重放。读回分片游标后，接管从原 owner 的落盘进度继续：
    /// **不丢**，且最多重放"原 owner 正在处理、还没落盘"的那一批（由流水线去重吸收）。
    pub(super) fn import_shard_cursors(&self, partitions: &[i32]) {
        let Some(dir) = self.config.lease_dir.clone() else {
            return;
        };
        let prefix = self.config.cursor_shard_prefix();
        let topic = self.config.topic.clone();
        for partition in partitions {
            let key = KafkaCursor::key(&topic, *partition);
            if self.cursor_snapshot().offsets.contains_key(&key) {
                continue;
            }
            let shard = KafkaCursor::load(&dir.join(format!("{prefix}{partition}.json")));
            let Some(offset) = shard.offsets.get(&key).copied() else {
                continue;
            };
            match self.cursor.lock() {
                Ok(mut cursor) => {
                    cursor.offsets.insert(key, offset);
                    if cursor.namespace.is_none() {
                        cursor.namespace.clone_from(&shard.namespace);
                    }
                }
                Err(poisoned) => {
                    let mut cursor = poisoned.into_inner();
                    cursor.offsets.insert(key, offset);
                    if cursor.namespace.is_none() {
                        cursor.namespace.clone_from(&shard.namespace);
                    }
                }
            }
            info!(
                receiver = %self.config.receiver_name,
                topic = %topic,
                partition,
                offset,
                "多副本：已从磁盘分片游标恢复该分区进度（接管/交接，不重放已落盘进度）"
            );
        }
    }
}
