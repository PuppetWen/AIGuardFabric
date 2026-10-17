//! 由 `deadletter.rs` 拆分：`FlushReport`/`OfflineOp`/`OfflineOpKind`/`OfflineQueue`/`OfflineQueueConfig` 的实现（纯搬移，逻辑不变）。
use super::*;

impl OfflineOpKind {
    /// 文本形式（与 [`DeadLetterEntry::operation`] 一致）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::Sync => "sync",
            Self::Pull => "pull",
        }
    }
}

impl OfflineOp {
    /// 构造推送操作。
    #[must_use]
    pub fn push(tenant_id: TenantId, adapter: &str, payload: &PushPayload, error: &str) -> Self {
        let now = Timestamp::now();
        let key = payload
            .idempotency_key
            .clone()
            .unwrap_or_else(|| format!("{}:{}:{}", payload.entity, payload.entity_id, now.unix_millis()));
        Self {
            id: Id::new(),
            tenant_id,
            adapter: adapter.to_string(),
            kind: OfflineOpKind::Push,
            payload: Some(payload.clone()),
            direction: None,
            request: None,
            idempotency_key: key,
            last_error: error.to_string(),
            attempts: 1,
            first_failed_at: now,
            last_failed_at: now,
            dead: false,
        }
    }

    /// 构造同步操作。
    #[must_use]
    pub fn sync(
        tenant_id: TenantId,
        adapter: &str,
        direction: SyncDirection,
        request: &PullRequest,
        error: &str,
    ) -> Self {
        let now = Timestamp::now();
        Self {
            id: Id::new(),
            tenant_id,
            adapter: adapter.to_string(),
            kind: OfflineOpKind::Sync,
            payload: None,
            direction: Some(direction),
            request: Some(request.clone()),
            idempotency_key: format!("sync:{}:{}:{}", adapter, direction.as_str(), now.unix_millis()),
            last_error: error.to_string(),
            attempts: 1,
            first_failed_at: now,
            last_failed_at: now,
            dead: false,
        }
    }

    /// 构造拉取操作。
    #[must_use]
    pub fn pull(tenant_id: TenantId, adapter: &str, request: &PullRequest, error: &str) -> Self {
        let now = Timestamp::now();
        Self {
            id: Id::new(),
            tenant_id,
            adapter: adapter.to_string(),
            kind: OfflineOpKind::Pull,
            payload: None,
            direction: None,
            request: Some(request.clone()),
            idempotency_key: format!("pull:{}:{}:{}", adapter, request.resource, now.unix_millis()),
            last_error: error.to_string(),
            attempts: 1,
            first_failed_at: now,
            last_failed_at: now,
            dead: false,
        }
    }

    /// 转为平台死信条目（落 `dead_letters` 表）。
    #[must_use]
    pub fn to_dead_letter(&self) -> DeadLetterEntry {
        DeadLetterEntry {
            id: self.id,
            tenant_id: self.tenant_id,
            adapter: self.adapter.clone(),
            operation: self.kind.as_str().to_string(),
            payload: serde_json::to_value(self).unwrap_or(serde_json::Value::Null),
            error: self.last_error.clone(),
            attempts: self.attempts,
            replayed: false,
            first_failed_at: self.first_failed_at,
            last_failed_at: self.last_failed_at,
        }
    }

    /// 该操作是否可用于指定的适配器名。
    #[must_use]
    pub fn matches_adapter(&self, adapter: &str) -> bool {
        self.adapter == adapter
    }
}

impl FlushReport {
    /// 离线队列是否已彻底清空（**含**其他适配器的待处理条目）。
    ///
    /// 判定：本适配器条目全部成功重放（`flushed == attempted`）、没有仍失败的、
    /// 没有新转死信的，且**没有被跳过的其他适配器条目**（`skipped == 0`）。
    /// 只要还有任一适配器的待补传条目，就说明"恢复补传"尚未完成。
    #[must_use]
    pub const fn queue_drained(&self) -> bool {
        self.skipped == 0 && self.still_failing == 0 && self.dead_lettered == 0 && self.flushed == self.attempted
    }

    /// 摘要一行。
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "重放 {} 条：成功 {}，仍失败 {}，转死信 {}，跳过 {}",
            self.attempted, self.flushed, self.still_failing, self.dead_lettered, self.skipped
        )
    }
}

impl Default for OfflineQueueConfig {
    fn default() -> Self {
        Self { max_attempts: 5, capacity: 10_000 }
    }
}

impl Default for OfflineQueue {
    fn default() -> Self {
        Self::new(OfflineQueueConfig::default())
    }
}

impl OfflineQueue {
    /// 构造。
    #[must_use]
    pub fn new(config: OfflineQueueConfig) -> Self {
        Self { config, ops: Mutex::new(Vec::new()), dead: Mutex::new(Vec::new()) }
    }

    /// 入队（同一 `idempotency_key` 且未死信的操作会被合并：只累加尝试次数与错误）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn enqueue(&self, op: OfflineOp) -> DomainResult<usize> {
        let mut guard = self.lock_ops()?;
        if let Some(existing) = guard.iter_mut().find(|o| o.idempotency_key == op.idempotency_key && !o.dead) {
            existing.attempts = existing.attempts.saturating_add(1);
            existing.last_error = op.last_error.clone();
            existing.last_failed_at = op.last_failed_at;
            return Ok(guard.len());
        }
        guard.push(op);
        // 容量保护：优先淘汰已死信的最旧条目
        if guard.len() > self.config.capacity {
            if let Some(position) = guard.iter().position(|o| o.dead) {
                guard.remove(position);
            }
        }
        Ok(guard.len())
    }

    /// 队列长度（含死信条目）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn len(&self) -> DomainResult<usize> {
        self.lock_ops().map(|g| g.len())
    }

    /// 是否为空。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn is_empty(&self) -> DomainResult<bool> {
        self.lock_ops().map(|g| g.is_empty())
    }

    /// 待重放条目（未死信）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn pending(&self) -> DomainResult<Vec<OfflineOp>> {
        self.lock_ops().map(|g| g.iter().filter(|o| !o.dead).cloned().collect())
    }

    /// 已转死信的条目。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn dead_letters(&self) -> DomainResult<Vec<DeadLetterEntry>> {
        self.dead.lock().map(|g| g.clone()).map_err(|_| DomainError::Internal("死信队列锁中毒".to_string()))
    }

    /// 按适配器统计待重放数量。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn pending_by_adapter(&self) -> DomainResult<BTreeMap<String, usize>> {
        let guard = self.lock_ops()?;
        let mut out: BTreeMap<String, usize> = BTreeMap::new();
        for op in guard.iter().filter(|o| !o.dead) {
            *out.entry(op.adapter.clone()).or_insert(0) += 1;
        }
        Ok(out)
    }

    /// 清空（测试与运维手动重置用）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn clear(&self) -> DomainResult<()> {
        self.lock_ops()?.clear();
        self.dead.lock().map(|mut g| g.clear()).map_err(|_| DomainError::Internal("死信队列锁中毒".to_string()))
    }

    /// 重放队列中属于 `adapter` 的操作。
    ///
    /// # Errors
    /// 锁中毒（单条重放失败不返回错误，而是计入报告 —— 死信隔离的要点是**不阻塞主流程**）。
    pub async fn flush<A: Adapter + ?Sized>(&self, adapter: &A) -> DomainResult<FlushReport> {
        let adapter_name = adapter.name().to_string();
        let snapshot = self.lock_ops()?.clone();
        let mut report = FlushReport { finished_at: Some(Timestamp::now()), ..FlushReport::default() };
        let mut remaining: Vec<OfflineOp> = Vec::new();
        let mut new_dead: Vec<DeadLetterEntry> = Vec::new();

        for mut op in snapshot {
            if !op.matches_adapter(&adapter_name) {
                report.skipped += 1;
                remaining.push(op);
                continue;
            }
            if op.dead {
                remaining.push(op);
                continue;
            }
            report.attempted += 1;
            let result = Self::replay_one(adapter, &op).await;
            match result {
                Ok(()) => report.flushed += 1,
                Err(error) => {
                    op.attempts = op.attempts.saturating_add(1);
                    op.last_error = error.to_string();
                    op.last_failed_at = Timestamp::now();
                    if op.attempts >= self.config.max_attempts {
                        op.dead = true;
                        new_dead.push(op.to_dead_letter());
                        report.dead_lettered += 1;
                    } else {
                        report.still_failing += 1;
                    }
                    report.errors.push(format!("{}（{} 次）：{error}", op.idempotency_key, op.attempts));
                    remaining.push(op);
                }
            }
        }

        {
            let mut guard = self.lock_ops()?;
            *guard = remaining;
        }
        if !new_dead.is_empty() {
            let mut guard = self.dead.lock().map_err(|_| DomainError::Internal("死信队列锁中毒".to_string()))?;
            guard.extend(new_dead);
        }
        Ok(report)
    }

    /// 重放单条操作。
    pub(crate) async fn replay_one<A: Adapter + ?Sized>(adapter: &A, op: &OfflineOp) -> DomainResult<()> {
        match op.kind {
            OfflineOpKind::Push => {
                let payload = op
                    .payload
                    .clone()
                    .ok_or_else(|| DomainError::Validation("离线 push 操作缺少载荷（数据损坏）".to_string()))?;
                adapter.push(&payload).await
            }
            OfflineOpKind::Sync => {
                let direction = op.direction.unwrap_or(SyncDirection::Both);
                let request = op.request.clone().unwrap_or_default();
                adapter.sync(direction, &request).await.map(|_| ())
            }
            OfflineOpKind::Pull => {
                let request = op.request.clone().unwrap_or_default();
                adapter.pull(&request).await.map(|_| ())
            }
        }
    }

    pub(crate) fn lock_ops(&self) -> DomainResult<std::sync::MutexGuard<'_, Vec<OfflineOp>>> {
        self.ops.lock().map_err(|_| DomainError::Internal("离线队列锁中毒".to_string()))
    }
}
