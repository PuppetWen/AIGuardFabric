//! 文件采集接收器：按轮询读取**新增的完整行**（末尾半行留给下一轮），投递流水线。

use super::*;

/// 文件采集接收器（轮询式 tail，兼容 Filebeat/Fluent Bit/Vector 落盘目录）。
///
/// **降级说明**：未引入 `notify` 依赖，采用**轮询**读取增量（默认 1s 一次），
/// `TODO ingest-notify-watch`：接入 `notify`/`ReadDirectoryChangesW` 做事件驱动，
/// 并把日志轮转（inode 变化）与多文件 glob 纳入同一 watcher。
#[derive(Debug)]
pub struct FileTailReceiver {
    path: PathBuf,
    offset: AtomicU64,
    max_line_bytes: usize,
    max_batch: usize,
}

impl FileTailReceiver {
    /// 构造（从文件开头读）。
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), offset: AtomicU64::new(0), max_line_bytes: 1_048_576, max_batch: 1_000 }
    }

    /// 由日志源配置构造（需要 `connection.file_path`）。
    ///
    /// # Errors
    /// 未配置文件路径。
    pub fn from_source(source: &LogSource) -> DomainResult<Self> {
        let path = source
            .connection
            .file_path
            .clone()
            .ok_or_else(|| DomainError::Config("文件采集需要 connection.file_path".to_string()))?;
        Ok(Self::new(path))
    }

    /// 设置批上限。
    #[must_use]
    pub const fn with_max_batch(mut self, max_batch: usize) -> Self {
        self.max_batch = max_batch;
        self
    }

    /// 路径。
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 当前读取偏移。
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset.load(Ordering::Relaxed)
    }

    /// 重置偏移（日志轮转后调用）。
    pub fn reset_offset(&self) {
        self.offset.store(0, Ordering::Relaxed);
    }

    /// 读取自上次调用以来的新增完整行。
    ///
    /// # Errors
    /// 文件不存在或读取失败。
    pub async fn read_new_lines(&self) -> DomainResult<Vec<String>> {
        let mut file = tokio::fs::File::open(&self.path)
            .await
            .map_err(|e| DomainError::NotFound { entity: "log-file", id: format!("{}: {e}", self.path.display()) })?;
        let len = file.metadata().await.map_err(|e| DomainError::Internal(format!("读取文件元数据失败: {e}")))?.len();
        let start = self.offset.load(Ordering::Relaxed);
        if len < start {
            warn!(path = %self.path.display(), len, start, "日志文件被截断/轮转，偏移归零");
            self.offset.store(0, Ordering::Relaxed);
        }
        let start = self.offset.load(Ordering::Relaxed);
        if len <= start {
            return Ok(Vec::new());
        }
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|e| DomainError::Internal(format!("seek 失败: {e}")))?;
        let mut buf = Vec::new();
        file.take(u64::try_from(self.max_line_bytes).unwrap_or(u64::MAX).saturating_mul(64))
            .read_to_end(&mut buf)
            .await
            .map_err(|e| DomainError::Internal(format!("读取文件失败: {e}")))?;
        // 只消费到最后一个换行符，半行留给下一次（避免把不完整记录当完整日志）
        let Some(last_newline) = buf.iter().rposition(|b| *b == b'\n') else {
            return Ok(Vec::new());
        };
        let consumed = last_newline + 1;
        self.offset.store(start + u64::try_from(consumed).unwrap_or(0), Ordering::Relaxed);
        let text = String::from_utf8_lossy(buf.get(..consumed).unwrap_or_default());
        let lines: Vec<String> =
            text.lines().map(|l| l.trim_end_matches('\r').to_string()).filter(|l| !l.trim().is_empty()).collect();
        Ok(lines)
    }
}

#[async_trait]
impl Receiver for FileTailReceiver {
    fn protocol(&self) -> IngestProtocol {
        IngestProtocol::File
    }

    fn describe(&self) -> ReceiverDescriptor {
        ReceiverDescriptor {
            name: "file-tail".to_string(),
            protocol: IngestProtocol::File,
            status: ReceiverStatus::Ready,
            note: format!("轮询式增量读取：{}（1s 间隔）", self.path.display()),
            todo: Some("TODO ingest-notify-watch：inotify/ReadDirectoryChangesW 事件驱动 + 轮转/glob 支持".to_string()),
            mock_replay: false,
        }
    }

    async fn start(&self, pipeline: Arc<IngestPipeline>, source: LogSource) -> DomainResult<()> {
        loop {
            let lines = self.read_new_lines().await?;
            if !lines.is_empty() {
                let items: Vec<(Vec<u8>, String)> =
                    lines.into_iter().map(|l| (l.into_bytes(), self.path.display().to_string())).collect();
                let _ = pipeline.ingest_batch(&source, IngestProtocol::File, &items).await?;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    async fn poll_once(&self, pipeline: Arc<IngestPipeline>, source: LogSource, max: usize) -> DomainResult<usize> {
        let mut lines = self.read_new_lines().await?;
        lines.truncate(max.min(self.max_batch));
        if lines.is_empty() {
            return Ok(0);
        }
        let items: Vec<(Vec<u8>, String)> =
            lines.into_iter().map(|l| (l.into_bytes(), self.path.display().to_string())).collect();
        let outcomes = pipeline.ingest_batch(&source, IngestProtocol::File, &items).await?;
        Ok(outcomes.iter().filter(|o| o.persisted).count())
    }
}

// ---------------------------------------------------------------------------
// HTTP 拉取
// ---------------------------------------------------------------------------
