//! 由 `queue.rs` 拆分：`LocalQueue`/`QueueConfig`/`QueueEntry` 的实现（纯搬移，逻辑不变）。
use super::*;

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: DEFAULT_MAX_BYTES,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            path: None,
        }
    }
}

impl QueueConfig {
    /// 指定落盘路径（链式）。
    #[must_use]
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// 指定容量（链式）。
    #[must_use]
    pub fn with_capacity(mut self, max_entries: usize, max_bytes: usize) -> Self {
        self.max_entries = max_entries;
        self.max_bytes = max_bytes;
        self
    }

    /// 生效的条目上限（`0` 视为 1，避免配置成"完全不可用"）。
    #[must_use]
    pub const fn effective_max_entries(&self) -> usize {
        if self.max_entries == 0 { 1 } else { self.max_entries }
    }

    /// 生效的字节上限。
    #[must_use]
    pub const fn effective_max_bytes(&self) -> usize {
        if self.max_bytes == 0 { 1 } else { self.max_bytes }
    }
}

impl QueueEntry {
    /// 构造条目。
    #[must_use]
    pub fn new(kind: PayloadKind, idempotency_key: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            idempotency_key: idempotency_key.into(),
            kind,
            body: body.into(),
            enqueued_at: Timestamp::now(),
            attempts: 0,
        }
    }

    /// 条目字节数（正文长度）。
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.body.len()
    }
}

impl LocalQueue {
    /// 新建（不读盘）。
    #[must_use]
    pub fn new(config: QueueConfig) -> Self {
        Self {
            config,
            entries: VecDeque::new(),
            evicted_total: 0,
            expired_total: 0,
            replaced_total: 0,
            corrupt_lines: 0,
        }
    }

    /// 配置。
    #[must_use]
    pub const fn config(&self) -> &QueueConfig {
        &self.config
    }

    /// 当前深度。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 当前字节数。
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.entries.iter().map(QueueEntry::bytes).sum()
    }

    /// 统计。
    #[must_use]
    pub fn stats(&self) -> QueueStats {
        QueueStats {
            depth: self.len(),
            bytes: self.bytes(),
            evicted_total: self.evicted_total,
            expired_total: self.expired_total,
            replaced_total: self.replaced_total,
            corrupt_lines: self.corrupt_lines,
            capacity_entries: self.config.effective_max_entries(),
            capacity_bytes: self.config.effective_max_bytes(),
        }
    }

    /// 全部幂等键（时间序，便于排障与断言）。
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.idempotency_key.clone()).collect()
    }

    /// 查看队首（最旧，优先补传）。
    #[must_use]
    pub fn peek(&self) -> Option<&QueueEntry> {
        self.entries.front()
    }

    /// 入队（同幂等键替换；超容量淘汰最旧）。
    pub fn push(&mut self, entry: QueueEntry) -> PushOutcome {
        let replaced = if let Some(pos) = self.entries.iter().position(|e| e.idempotency_key == entry.idempotency_key) {
            self.entries.remove(pos);
            self.replaced_total = self.replaced_total.saturating_add(1);
            true
        } else {
            false
        };
        self.entries.push_back(entry);
        let evicted = self.enforce_capacity();
        if evicted > 0 {
            PushOutcome::Evicted(evicted)
        } else if replaced {
            PushOutcome::Replaced
        } else {
            PushOutcome::Enqueued
        }
    }

    /// 入队（由载荷构造）。
    pub fn push_payload(&mut self, kind: PayloadKind, idempotency_key: &str, body: &str) -> PushOutcome {
        self.push(QueueEntry::new(kind, idempotency_key, body))
    }

    /// 按最旧优先取出至多 `max` 条（不删除；由 [`Self::mark_delivered`] / [`Self::note_failure`] 决定去留）。
    pub fn drain_batch(&mut self, max: usize) -> Vec<QueueEntry> {
        let take = max.min(self.entries.len());
        self.entries.drain(..take).collect()
    }

    /// 丢弃指定幂等键（补传成功）。
    pub fn mark_delivered(&mut self, idempotency_key: &str) -> bool {
        if let Some(pos) = self.entries.iter().position(|e| e.idempotency_key == idempotency_key) {
            self.entries.remove(pos);
            return true;
        }
        false
    }

    /// 记录一次失败：尝试次数 +1；超上限则丢弃（返回是否被丢弃）。
    pub fn note_failure(&mut self, idempotency_key: &str) -> bool {
        let Some(pos) = self.entries.iter().position(|e| e.idempotency_key == idempotency_key) else {
            return false;
        };
        let max = self.config.max_attempts.max(1);
        let Some(entry) = self.entries.get_mut(pos) else { return false };
        entry.attempts = entry.attempts.saturating_add(1);
        if entry.attempts >= max {
            self.entries.remove(pos);
            self.expired_total = self.expired_total.saturating_add(1);
            return true;
        }
        false
    }

    /// 回插队首（补传失败但未达上限时使用，保持时间序）。
    pub fn requeue_front(&mut self, entry: QueueEntry) {
        self.entries.push_front(entry);
        let _ = self.enforce_capacity();
    }

    /// 清空（返回清空条数）。
    pub fn clear(&mut self) -> usize {
        let n = self.entries.len();
        self.entries.clear();
        n
    }

    /// 强制容量约束（返回淘汰条数）。
    pub(crate) fn enforce_capacity(&mut self) -> usize {
        let mut evicted = 0;
        while self.entries.len() > self.config.effective_max_entries()
            || (self.entries.len() > 1 && self.bytes() > self.config.effective_max_bytes())
        {
            if self.entries.pop_front().is_none() {
                break;
            }
            evicted += 1;
        }
        self.evicted_total = self.evicted_total.saturating_add(evicted as u64);
        evicted
    }

    /// 落盘（JSONL；先写 `.tmp` 再原子改名）。
    ///
    /// # Errors
    /// 目录不可创建或写入失败时返回 `DomainError::Internal`（内存队列不受影响）。
    pub fn save(&self) -> DomainResult<()> {
        let Some(path) = &self.config.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| DomainError::Internal(format!("创建队列目录失败 {}: {e}", parent.display())))?;
            }
        }
        let tmp = tmp_path(path);
        let mut file = std::fs::File::create(&tmp)
            .map_err(|e| DomainError::Internal(format!("写入队列失败 {}: {e}", tmp.display())))?;
        for entry in &self.entries {
            let line = serde_json::to_string(entry)?;
            writeln!(file, "{line}").map_err(|e| DomainError::Internal(format!("写入队列失败: {e}")))?;
        }
        file.flush().map_err(|e| DomainError::Internal(format!("刷新队列失败: {e}")))?;
        std::fs::rename(&tmp, path).map_err(|e| DomainError::Internal(format!("替换队列文件失败: {e}")))?;
        Ok(())
    }

    /// 从落盘文件载入（文件不存在 → 空队列；损坏行跳过并计数）。
    ///
    /// # Errors
    /// 文件存在但不可读时返回 `DomainError::Internal`。
    pub fn load(config: QueueConfig) -> DomainResult<Self> {
        let mut queue = Self::new(config);
        let Some(path) = queue.config.path.clone() else {
            return Ok(queue);
        };
        if !path.exists() {
            return Ok(queue);
        }
        let content = std::fs::read_to_string(&path)
            .map_err(|e| DomainError::Internal(format!("读取队列失败 {}: {e}", path.display())))?;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<QueueEntry>(line) {
                Ok(entry) => {
                    queue.entries.push_back(entry);
                }
                Err(_) => queue.corrupt_lines = queue.corrupt_lines.saturating_add(1),
            }
        }
        let _ = queue.enforce_capacity();
        Ok(queue)
    }
}
