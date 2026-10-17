//! 对象拉取接收器：`ObjectPullConfig`、`ObjectPullReceiver`（轮询一轮 → 解析 → 落库）与 `Receiver` 实现。

use super::*;

/// 拉取配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectPullConfig {
    /// 桶名（仅用于来源标注）。
    pub bucket: String,
    /// 前缀（空 = 整桶）。
    pub prefix: String,
    /// 轮询间隔（秒）。
    pub interval_secs: u64,
    /// 单轮最多处理对象数。
    pub max_objects: usize,
    /// 单对象字节上限。
    pub max_object_bytes: usize,
    /// 单对象最多拆出的记录数。
    pub max_records_per_object: usize,
    /// 游标文件路径（`None` = 只存内存，适合一次性导入）。
    pub cursor_path: Option<PathBuf>,
}

impl Default for ObjectPullConfig {
    fn default() -> Self {
        Self {
            bucket: String::new(),
            prefix: String::new(),
            interval_secs: 60,
            max_objects: 200,
            max_object_bytes: 64 * 1024 * 1024,
            max_records_per_object: 10_000,
            cursor_path: None,
        }
    }
}

/// 对象存储拉取接收器。
#[derive(Debug)]
pub struct ObjectPullReceiver {
    source: Arc<dyn ObjectSource>,
    config: ObjectPullConfig,
    cursor: Mutex<ObjectCursor>,
    counters: Arc<ReceiverCounters>,
}

impl ObjectPullReceiver {
    /// 构造（游标从 `config.cursor_path` 加载）。
    #[must_use]
    pub fn new(source: Arc<dyn ObjectSource>, config: ObjectPullConfig) -> Self {
        let cursor = config.cursor_path.as_deref().map_or_else(ObjectCursor::new, ObjectCursor::load);
        if !cursor.is_empty() {
            info!(processed = cursor.len(), "对象拉取游标已恢复（进程重启不会重复拉取）");
        }
        Self { source, config, cursor: Mutex::new(cursor), counters: Arc::new(ReceiverCounters::new()) }
    }

    /// 注入共享计数器。
    #[must_use]
    pub fn with_counters(mut self, counters: Arc<ReceiverCounters>) -> Self {
        self.counters = counters;
        self
    }

    /// 配置。
    #[must_use]
    pub const fn config(&self) -> &ObjectPullConfig {
        &self.config
    }

    /// 计数器。
    #[must_use]
    pub fn counters(&self) -> &Arc<ReceiverCounters> {
        &self.counters
    }

    /// 游标快照。
    #[must_use]
    pub fn cursor_snapshot(&self) -> ObjectCursor {
        match self.cursor.lock() {
            Ok(cursor) => cursor.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// 待拉取对象数（不含已处理）。
    ///
    /// # Errors
    /// 列举失败。
    pub async fn pending_count(&self) -> DomainResult<usize> {
        let metas = self.source.list(&self.config.prefix, self.config.max_objects).await?;
        let cursor = self.cursor_snapshot();
        Ok(metas.iter().filter(|meta| cursor.needs_pull(meta)).count())
    }

    /// 标记已处理并在配置了路径时落盘。
    fn mark_processed(&self, meta: &ObjectMeta) -> DomainResult<()> {
        {
            let mut cursor = match self.cursor.lock() {
                Ok(cursor) => cursor,
                Err(poisoned) => poisoned.into_inner(),
            };
            cursor.mark(meta);
        }
        if let Some(path) = &self.config.cursor_path {
            self.cursor_snapshot().save(path)?;
        }
        Ok(())
    }

    /// 单轮拉取（供 `poll_once` 与测试复用）。
    ///
    /// # Errors
    /// 列举失败或落库失败（单个对象失败只 warn + 计数，不中断整轮）。
    pub async fn pull_once(
        &self,
        pipeline: &IngestPipeline,
        source: &LogSource,
        max: usize,
    ) -> DomainResult<ObjectPullReport> {
        let mut report = ObjectPullReport::default();
        let metas = self.source.list(&self.config.prefix, self.config.max_objects.max(max)).await?;
        report.listed = metas.len();
        let cursor = self.cursor_snapshot();
        let mut candidates: Vec<ObjectMeta> = metas.into_iter().filter(|meta| cursor.needs_pull(meta)).collect();
        // 按 key 排序：对象名通常带时间前缀，保证"先老后新"的推进顺序与可复现性
        candidates.sort_by(|a, b| a.key.cmp(&b.key));
        candidates.truncate(max.min(self.config.max_objects));
        for meta in candidates {
            let bytes = match self.source.get(&meta.key).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!(key = %meta.key, error = %e, "对象读取失败（本轮跳过，下轮重试）");
                    self.counters.add_dropped(1);
                    report.failed += 1;
                    continue;
                }
            };
            if bytes.len() > self.config.max_object_bytes {
                warn!(
                    key = %meta.key,
                    bytes = bytes.len(),
                    limit = self.config.max_object_bytes,
                    "对象超过单对象上限，跳过并标记已处理（否则每轮重试形成活锁）"
                );
                self.counters.add_dropped(1);
                report.oversized += 1;
                self.mark_processed(&meta)?;
                continue;
            }
            let records = HttpPullReceiver::split_records(&bytes, self.config.max_records_per_object);
            if records.is_empty() {
                debug!(key = %meta.key, "空对象，直接标记已处理");
                self.mark_processed(&meta)?;
                continue;
            }
            let origin = format!("s3://{}/{}", self.config.bucket, meta.key);
            let items: Vec<(Vec<u8>, String)> = records.into_iter().map(|r| (r, origin.clone())).collect();
            self.counters.add_received(u64::try_from(items.len()).unwrap_or(u64::MAX));
            let outcomes = pipeline.ingest_batch(source, IngestProtocol::ObjectStorage, &items).await?;
            let persisted = outcomes.iter().filter(|o| o.persisted).count();
            self.counters.record_outcomes(&outcomes);
            report.objects += 1;
            report.records += items.len();
            report.persisted += persisted;
            // 每个对象处理完立即推进游标：崩溃最多重放当前对象
            self.mark_processed(&meta)?;
        }
        Ok(report)
    }

    /// 待处理对象数（用于测试与运维判断）。
    ///
    /// # Errors
    /// 列举失败。
    pub async fn list_pending(&self) -> DomainResult<Vec<ObjectMeta>> {
        let metas = self.source.list(&self.config.prefix, self.config.max_objects).await?;
        let cursor = self.cursor_snapshot();
        Ok(metas.into_iter().filter(|meta| cursor.needs_pull(meta)).collect())
    }
}

/// 单轮拉取结果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectPullReport {
    /// 列出的对象数。
    pub listed: usize,
    /// 实际拉取的对象数。
    pub objects: usize,
    /// 拆出的记录数。
    pub records: usize,
    /// 落库事件数。
    pub persisted: usize,
    /// 因读取失败跳过的对象数。
    pub failed: usize,
    /// 因超限跳过的对象数。
    pub oversized: usize,
}

#[async_trait]
impl Receiver for ObjectPullReceiver {
    fn protocol(&self) -> IngestProtocol {
        IngestProtocol::ObjectStorage
    }

    fn describe(&self) -> ReceiverDescriptor {
        ReceiverDescriptor {
            name: "object-pull".to_string(),
            protocol: IngestProtocol::ObjectStorage,
            status: ReceiverStatus::Ready,
            note: format!(
                "S3/OSS 轮询拉取 {}（前缀 `{}`，间隔 {}s，ETag+LastModified 幂等游标，单轮上限 {} 对象）",
                self.source.describe(),
                self.config.prefix,
                self.config.interval_secs,
                self.config.max_objects
            ),
            todo: None,
            mock_replay: false,
        }
    }

    async fn start(&self, pipeline: Arc<IngestPipeline>, source: LogSource) -> DomainResult<()> {
        let interval = self.config.interval_secs.max(1);
        loop {
            match self.pull_once(&pipeline, &source, self.config.max_objects).await {
                Ok(report) if report.objects > 0 || report.failed > 0 => {
                    info!(?report, "对象拉取完成一轮");
                }
                Ok(_) => debug!("对象拉取：无新对象"),
                // 列举失败（MinIO 未就绪 / 凭据错 / 网络抖动）只 warn：进程照常，下轮重试
                Err(e) => warn!(error = %e, "对象拉取列举失败（下轮重试，进程不受影响）"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        }
    }

    async fn poll_once(&self, pipeline: Arc<IngestPipeline>, source: LogSource, max: usize) -> DomainResult<usize> {
        Ok(self.pull_once(&pipeline, &source, max).await?.persisted)
    }
}
