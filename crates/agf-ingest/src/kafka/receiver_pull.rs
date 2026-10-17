use super::*;

impl KafkaReceiver {
    /// 单轮消费（遍历**本副本负责的**分区，每分区独立游标）。
    ///
    /// # Errors
    /// 列分区失败（broker 不可达）或落库失败；单分区拉取失败只 warn + 计数（自愈）。
    pub async fn pull_once(
        &self,
        pipeline: &IngestPipeline,
        source: &LogSource,
        max: usize,
    ) -> DomainResult<KafkaPullReport> {
        let mut report = KafkaPullReport::default();
        // === 消费者组协议：会话续期（心跳 + rebalance 处理）===
        // 本地游标路径下 `maintain_session` 是 no-op（默认实现），因此这一段对历史行为零影响。
        // 组协议路径下：心跳撞上 rebalance 会在数据源内部**先补提交 offset 再重新入组**；
        // 只有协调器真的不可达才会返回 Err。
        if let Err(e) = self.source.maintain_session().await {
            if self.source.commits_to_broker() {
                warn!(error = %e, "Kafka 消费者组：会话续期失败（本轮跳过，交由外层退避重连；游标保持不动）");
                return Err(e);
            }
            warn!(error = %e, "Kafka 会话续期失败（本地游标路径不应发生，已忽略）");
        }
        let all_partitions = self.source.partitions(&self.config.topic).await?;
        self.note_partition_changes(&all_partitions);
        // === 多副本分区分配（本接收器自己的"消费者组替代"） ===
        // 顺序固定：先写自己的心跳 → 再读存活集合 → 再算归属。这样"自己刚起来"这一轮
        // 不会因为目录里还没自己的心跳而被判死。
        let ownership = self.resolve_ownership(&all_partitions);
        if !ownership.taken_over_partitions.is_empty() {
            warn!(
                receiver = %self.config.receiver_name,
                topic = %self.config.topic,
                taken_over = ?ownership.taken_over_partitions,
                live = ?ownership.live_instances,
                ttl_ms = ownership.lease_ttl_ms,
                "多副本分区接管：原负责副本租约判死，其分区已重分片到本副本（从**落盘游标**继续，不丢不重）"
            );
        }
        self.stats.set_ownership(ownership.clone());
        let partitions: Vec<i32> =
            all_partitions.iter().copied().filter(|partition| ownership.owns(*partition)).collect();
        // 接管/交接：先把磁盘上的分片游标读回内存，否则会按 start_from 重新定位（见方法文档）
        self.import_shard_cursors(&partitions);
        if partitions.len() != all_partitions.len() {
            debug!(
                receiver = %self.config.receiver_name,
                topic = %self.config.topic,
                instance_id = ownership.instance_id,
                live = ?ownership.live_instances,
                owned = ?ownership.owned_partitions,
                total = all_partitions.len(),
                "多副本分配：本副本只消费自己负责的分区（其余分区由同订阅名的其它副本消费）"
            );
        }
        if partitions.is_empty() {
            return Ok(report);
        }
        let budget = max.min(self.config.max_records_per_partition).max(1);
        for partition in partitions {
            let key = KafkaCursor::key(&self.config.topic, partition);
            // 组协议路径**总是**以 broker 侧已提交 offset 为准（本地游标只是镜像/降级残留）；
            // 本地游标路径维持历史语义：有本地游标就用本地游标，没有才解析起始位置。
            let local = self.cursor_snapshot().offsets.get(&key).copied();
            let offset = match local.filter(|_| !self.source.commits_to_broker()) {
                Some(offset) => offset,
                None => match self.source.resolve_offset(&self.config.topic, partition, self.config.start_from).await {
                    Ok(offset) => {
                        debug!(
                            topic = %self.config.topic,
                            partition,
                            offset,
                            start_from = self.config.start_from.as_str(),
                            "Kafka 起始 offset 已解析（新分区/新游标）"
                        );
                        // 立即落盘：避免每轮都重新解析（也避免 Latest 语义下不断后移）
                        self.set_offset(&self.config.topic, partition, offset)?;
                        offset
                    }
                    Err(e) => {
                        let first = self.stats.consecutive_failures(partition) == 0;
                        self.stats.record_failure(partition, &e.to_string());
                        if first {
                            warn!(topic = %self.config.topic, partition, error = %e, "Kafka 起始 offset 解析失败（该分区本轮跳过，下轮重试）");
                        } else {
                            debug!(topic = %self.config.topic, partition, error = %e, "Kafka 起始 offset 仍解析失败");
                        }
                        report.failed_partitions += 1;
                        continue;
                    }
                },
            };
            let batch = match self
                .source
                .fetch(&self.config.topic, partition, offset, self.config.max_bytes, self.config.max_wait_ms)
                .await
            {
                Ok(batch) => batch,
                Err(e) => {
                    let first = self.stats.consecutive_failures(partition) == 0;
                    self.stats.record_failure(partition, &e.to_string());
                    // 只 warn 一次；后续降为 debug（broker 抖动时不刷屏）
                    if first {
                        warn!(topic = %self.config.topic, partition, offset, error = %e, "Kafka 拉取失败（丢弃该分区游标，下一轮按起点重新定位自愈）");
                    } else {
                        debug!(topic = %self.config.topic, partition, offset, error = %e, "Kafka 拉取仍失败（自愈重定位中）");
                    }
                    self.drop_offset(&self.config.topic, partition);
                    report.failed_partitions += 1;
                    continue;
                }
            };
            let high_watermark = batch.high_watermark;
            if batch.records.is_empty() {
                // 空批次也要回写高水位/游标：否则空闲分区的 lag 不可观测
                self.stats.record_batch(partition, offset, high_watermark, 0);
                continue;
            }
            let consumed: Vec<&KafkaRecord> = batch.records.iter().take(budget).collect();
            let mut items: Vec<(Vec<u8>, String)> = Vec::new();
            let mut skipped = 0_usize;
            for record in &consumed {
                let Some(value) = record.value.as_ref() else {
                    // 墓碑消息（delete marker）：不是数据丢失，单列计数
                    debug!(partition, offset = record.offset, "Kafka 墓碑消息（value 为空），跳过");
                    skipped += 1;
                    continue;
                };
                let origin =
                    format!("{}://{}/{}@{}", self.config.origin_scheme, self.config.topic, partition, record.offset);
                for chunk in HttpPullReceiver::split_records(value, 10_000) {
                    items.push((chunk, origin.clone()));
                }
            }
            if skipped > 0 {
                self.stats.add_skipped(u64::try_from(skipped).unwrap_or(u64::MAX));
            }
            if !items.is_empty() {
                self.counters.add_received(u64::try_from(items.len()).unwrap_or(u64::MAX));
                let outcomes = pipeline.ingest_batch(source, self.config.protocol, &items).await?;
                let persisted = outcomes.iter().filter(|o| o.persisted).count();
                let deduped = outcomes.iter().filter(|o| o.deduped).count();
                self.counters.record_outcomes(&outcomes);
                if deduped > 0 {
                    self.stats.add_deduped(u64::try_from(deduped).unwrap_or(u64::MAX));
                }
                report.persisted += persisted;
                report.lines += items.len();
            }
            report.records += consumed.len();
            report.skipped += skipped;
            let next_offset = consumed.last().map_or(offset, |record| record.offset.saturating_add(1));
            // 游标推进必须在**消费成功之后**：崩溃最多重放当前批，不会丢
            self.set_offset(&self.config.topic, partition, next_offset)?;
            // === 消费者组协议：把进度提交到 broker（本地游标路径为 no-op）===
            // 提交失败**不阻断消费**：进度仍在本地游标里，下一批会带更大的 offset 重提交；
            // 组协议下的"重复"由流水线内容去重兜住（at-least-once + 去重 = 有效一次）。
            if self.source.commits_to_broker() {
                let commit = KafkaOffsetCommit { topic: self.config.topic.clone(), partition, offset: next_offset };
                if let Err(e) = self.source.commit_offsets(std::slice::from_ref(&commit)).await {
                    let first = self.stats.consecutive_failures(partition) == 0;
                    if first {
                        warn!(topic = %self.config.topic, partition, offset = next_offset, error = %e, "Kafka 消费者组：OffsetCommit 失败（进度仍在本地游标，下一批重提交）");
                    } else {
                        debug!(topic = %self.config.topic, partition, offset = next_offset, error = %e, "Kafka 消费者组：OffsetCommit 仍失败");
                    }
                }
            }
            self.stats.record_batch(
                partition,
                next_offset,
                high_watermark,
                u64::try_from(consumed.len()).unwrap_or(u64::MAX),
            );
        }
        Ok(report)
    }

    /// 可中断的等待：返回 `false` 表示收到停机信号（或发送端消失）。
    async fn sleep_or_shutdown(&self, duration: Duration, shutdown: &mut Option<watch::Receiver<bool>>) -> bool {
        let Some(rx) = shutdown else {
            tokio::time::sleep(duration).await;
            return true;
        };
        if *rx.borrow() {
            return false;
        }
        tokio::select! {
            () = tokio::time::sleep(duration) => true,
            changed = rx.changed() => {
                if changed.is_err() {
                    // 发送端已释放：视为停机，避免空转
                    return false;
                }
                !*rx.borrow()
            }
        }
    }

    /// 停机收尾：刷新游标 + 汇总日志。
    ///
    /// # Errors
    /// 游标落盘失败。
    pub fn finish_shutdown(&self, reason: &str) -> DomainResult<()> {
        let cursor = self.cursor_snapshot();
        info!(
            reason,
            receiver = %self.config.receiver_name,
            topic = %self.config.topic,
            partitions = cursor.offsets.len(),
            consumed = self.stats.records_consumed_total(),
            lag_total = self.stats.lag_total(),
            assignment = %self.describe_assignment(),
            "Kafka 接收器停机：游标已刷新"
        );
        self.flush_cursor()
    }

    /// 停机收尾（组协议路径额外做"补提交 + `LeaveGroup`"）。
    ///
    /// 组协议下主动退组能把同伴的分区接管时间从 `session.timeout.ms` 缩短到一个心跳周期
    /// （协调器立刻触发 rebalance），这是"杀一个成员 → 另一成员接管"最快的路径。
    ///
    /// # Errors
    /// 本地/分片游标落盘失败。
    pub async fn finish_session(&self, reason: &str) -> DomainResult<()> {
        if self.source.commits_to_broker() {
            if let Err(e) = self.source.close_session().await {
                warn!(error = %e, "Kafka 消费者组：停机补提交/LeaveGroup 失败（由 session.timeout.ms 兜底）");
            }
        }
        self.finish_shutdown(reason)
    }

    /// 当前多副本分配配置的一句话描述（日志/`describe()` 用）。
    #[must_use]
    pub fn describe_assignment(&self) -> String {
        if !self.config.assignment_enabled() {
            return "单副本（消费 topic 全部分区）".to_string();
        }
        let (me, count) = self.config.assignment_identity();
        let mode = if self.config.lease_enabled() {
            match &self.config.lease_dir {
                Some(dir) => format!("心跳租约接管（ttl={}ms，dir={}）", self.config.lease_ttl_ms, dir.display()),
                None => "静态取模".to_string(),
            }
        } else {
            "静态取模（无租约目录，不接管）".to_string()
        };
        format!("实例 {me}/{count}，{mode}")
    }
}

#[async_trait]
impl Receiver for KafkaReceiver {
    fn protocol(&self) -> IngestProtocol {
        self.config.protocol
    }

    fn describe(&self) -> ReceiverDescriptor {
        let security = KafkaSecurity::from_config(&self.config).describe();
        let mode = if self.source.commits_to_broker() {
            "**消费者组协议**（FindCoordinator/JoinGroup/SyncGroup/Heartbeat/OffsetFetch/OffsetCommit/LeaveGroup；\
             分区分配由协调器下发，offset 提交到 broker 的 __consumer_offsets）"
        } else {
            "本地游标（rskafka 纯 Rust，无消费者组：显式 offset + 游标文件 + 可选租约接管）"
        };
        ReceiverDescriptor {
            name: self.config.receiver_name.clone(),
            protocol: self.config.protocol,
            status: ReceiverStatus::Ready,
            note: format!(
                "{mode} 消费 {} topic `{}`：分区（组模式 = 协调器分配的；本地模式 = 全部分区各自独立游标，\
                 新增分区自动纳入），起始 {}，单分区单轮上限 {} 条（背压阀）；安全：{}；namespace={}；\
                 多副本分配：{}；至少一次语义（处理后推进游标/提交 offset + 流水线去重）",
                self.source.describe(),
                self.config.topic,
                self.config.start_from.as_str(),
                self.config.max_records_per_partition,
                security,
                self.config.namespace.as_deref().unwrap_or("-"),
                self.describe_assignment()
            ),
            todo: Some(
                "TODO ingest-kafka-oauthbearer（SASL/OAUTHBEARER 未接线）与 \
                 TODO ingest-kafka-group-scram（消费者组路径只实现 SASL/PLAIN，SCRAM 未接线）：\
                 两者都不影响本地游标路径（rskafka 已支持 SCRAM）"
                    .to_string(),
            ),
            mock_replay: false,
        }
    }

    async fn start(&self, pipeline: Arc<IngestPipeline>, source: LogSource) -> DomainResult<()> {
        let interval = Duration::from_secs(self.config.interval_secs.max(1));
        let (initial, max_backoff) = self.config.reconnect_bounds();
        let mut backoff = initial;
        let mut consecutive_failures: u32 = 0;
        let mut shutdown = self.shutdown.clone();
        info!(
            receiver = %self.config.receiver_name,
            topic = %self.config.topic,
            client_id = %self.config.client_id(),
            interval_secs = self.config.interval_secs.max(1),
            reconnect_initial_ms = initial.as_millis(),
            reconnect_max_ms = max_backoff.as_millis(),
            max_attempts = self.config.reconnect_max_attempts,
            "Kafka 接收器启动（全分区消费 + 本地游标 + 指数退避重连）"
        );
        loop {
            if self.stopped.load(Ordering::Relaxed) {
                return self.finish_session("stop() 被调用").await;
            }
            let wait = match self.pull_once(&pipeline, &source, self.config.max_records_per_partition).await {
                Ok(report) => {
                    if consecutive_failures > 0 {
                        info!(failures = consecutive_failures, "Kafka 连接已恢复（退避重置）");
                    }
                    consecutive_failures = 0;
                    backoff = initial;
                    if report.records > 0 {
                        info!(?report, "Kafka 消费完成一轮");
                    } else {
                        debug!("Kafka 消费：暂无新记录");
                    }
                    interval
                }
                Err(e) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    self.stats.record_reconnect(backoff);
                    let attempts = self.config.reconnect_max_attempts;
                    if attempts > 0 && consecutive_failures >= attempts {
                        warn!(
                            error = %e,
                            attempts = consecutive_failures,
                            "Kafka 连续失败达到上限（AGF_INGEST_KAFKA_RECONNECT_MAX_ATTEMPTS），接收器退出"
                        );
                        self.finish_session("连续失败达到上限").await?;
                        return Err(e);
                    }
                    let delay = backoff;
                    backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
                    if consecutive_failures == 1 {
                        warn!(
                            error = %e,
                            backoff_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                            "Kafka 消费失败：退避后重试（游标保持在上次成功位置，不丢）"
                        );
                    } else {
                        // 持续失败不再刷屏（warn 只在首次），但仍可从 debug 与 /metrics 观测
                        debug!(
                            error = %e,
                            attempt = consecutive_failures,
                            backoff_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                            "Kafka 消费仍失败（退避重试中）"
                        );
                    }
                    delay
                }
            };
            if !self.sleep_or_shutdown(wait, &mut shutdown).await {
                return self.finish_session("收到停机信号").await;
            }
        }
    }

    async fn poll_once(&self, pipeline: Arc<IngestPipeline>, source: LogSource, max: usize) -> DomainResult<usize> {
        Ok(self.pull_once(&pipeline, &source, max).await?.persisted)
    }

    async fn stop(&self) -> DomainResult<()> {
        self.stopped.store(true, Ordering::Relaxed);
        Ok(())
    }
}
