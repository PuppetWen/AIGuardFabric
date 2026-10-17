//! 由 `quota.rs` 拆分：`FailMode`/`InMemoryQuotaStore`/`QuotaCheckOutcome`/`QuotaKey`/`QuotaSnapshot`/`QuotaStoreError`/`RedisQuotaStore` 的实现（纯搬移，逻辑不变）。
use super::*;

impl FailMode {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::FailClosed => "fail-closed",
            Self::FailOpen => "fail-open",
        }
    }

    /// 由配额的超限动作推导默认失败模式（见模块文档表格）。
    #[must_use]
    pub const fn for_action(action: PolicyAction) -> Self {
        match action {
            PolicyAction::Deny | PolicyAction::Isolate | PolicyAction::CircuitBreak => Self::FailClosed,
            _ => Self::FailOpen,
        }
    }
}

impl QuotaStoreError {
    /// 存储不可达。
    #[must_use]
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self { reason: reason.into(), closed: true }
    }

    /// 逻辑性失败（例如负增量、类型不匹配）。
    #[must_use]
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self { reason: reason.into(), closed: false }
    }
}

impl std::fmt::Display for QuotaStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}（closed={})", self.reason, self.closed)
    }
}

impl QuotaKey {
    /// 人类可读定位串（日志、快照与错误信息用）。
    #[must_use]
    pub fn describe(&self) -> String {
        let target = self.target.as_deref().unwrap_or("-");
        format!("{}|{}|{}|{}|{}", self.tenant, self.scope, self.dimension, self.bucket, target)
    }
}

impl RedisQuotaStore {
    /// 包装一个已连接的 [`RedisStore`]。
    #[must_use]
    pub fn new(store: std::sync::Arc<RedisStore>) -> Self {
        Self { store }
    }

    /// 底层存储。
    #[must_use]
    pub fn inner(&self) -> &RedisStore {
        &self.store
    }

    /// 由结构化定位构造计数器句柄。
    pub(crate) fn counter(&self, key: &QuotaKey) -> agf_storage::QuotaCounter {
        self.store.quota(key.tenant, &key.scope, &key.dimension, &key.bucket, key.target.as_deref())
    }
}

#[async_trait]
impl QuotaStore for RedisQuotaStore {
    async fn check_and_consume(
        &self,
        key: &QuotaKey,
        limit: i64,
        amount: i64,
        window_secs: i64,
    ) -> Result<ConsumeOutcome, QuotaStoreError> {
        if amount < 0 {
            return Err(QuotaStoreError::invalid("消费量不能为负（归还请用 release）"));
        }
        // `fail_closed = true`：由本层按 [`FailMode`] 决定最终放行/拒绝，
        // 存储层只需把"不可达"如实报上来，不要自行决定策略。
        match self.counter(key).check_and_consume(limit, amount, window_secs, true).await {
            Ok(outcome) => Ok(ConsumeOutcome { allowed: outcome.allowed, used: outcome.used }),
            Err(e) => Err(QuotaStoreError::unavailable(e.to_string())),
        }
    }

    async fn release(&self, key: &QuotaKey, amount: i64) -> Result<i64, QuotaStoreError> {
        self.counter(key).release(amount).await.map_err(|e| QuotaStoreError::unavailable(e.to_string()))
    }

    async fn peek(&self, key: &QuotaKey) -> Result<i64, QuotaStoreError> {
        self.counter(key).peek().await.map_err(|e| QuotaStoreError::unavailable(e.to_string()))
    }
}

impl InMemoryQuotaStore {
    /// 新建空存储。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 直接读取某键的当前值（测试断言用）。
    #[must_use]
    pub fn value(&self, key: &QuotaKey) -> i64 {
        self.value_of(&key.describe())
    }

    /// 按定位串读取（内部使用）。
    pub(crate) fn value_of(&self, id: &str) -> i64 {
        self.counters.lock().map(|m| m.get(id).copied().unwrap_or(0)).unwrap_or(0)
    }

    /// 键数量。
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.counters.lock().map(|m| m.len()).unwrap_or(0)
    }
}

#[async_trait]
impl QuotaStore for InMemoryQuotaStore {
    async fn check_and_consume(
        &self,
        key: &QuotaKey,
        limit: i64,
        amount: i64,
        _window_secs: i64,
    ) -> Result<ConsumeOutcome, QuotaStoreError> {
        if amount < 0 {
            return Err(QuotaStoreError::invalid("消费量不能为负（归还请用 release）"));
        }
        let id = key.describe();
        let mut guard = self.counters.lock().map_err(|_| QuotaStoreError::unavailable("内存配额计数器锁中毒"))?;
        let current = guard.get(&id).copied().unwrap_or(0);
        let projected = current.saturating_add(amount);
        if limit > 0 && projected > limit {
            // 超限：不消费（与 Lua 脚本一致）
            return Ok(ConsumeOutcome { allowed: false, used: current });
        }
        guard.insert(id, projected);
        Ok(ConsumeOutcome { allowed: true, used: projected })
    }

    async fn release(&self, key: &QuotaKey, amount: i64) -> Result<i64, QuotaStoreError> {
        let id = key.describe();
        let mut guard = self.counters.lock().map_err(|_| QuotaStoreError::unavailable("内存配额计数器锁中毒"))?;
        let current = guard.get(&id).copied().unwrap_or(0);
        let next = current.saturating_sub(amount).max(0);
        guard.insert(id, next);
        Ok(next)
    }

    async fn peek(&self, key: &QuotaKey) -> Result<i64, QuotaStoreError> {
        Ok(self.value_of(&key.describe()))
    }
}

impl QuotaCheckOutcome {
    /// 放行且未降级。
    #[must_use]
    pub fn pass() -> Self {
        Self { check: QuotaCheck::pass(), degraded: false, reason: None }
    }

    /// 放行且未降级，但带软阈值告警。
    #[must_use]
    pub fn pass_with(check: QuotaCheck) -> Self {
        Self { check, degraded: false, reason: None }
    }

    /// 是否放行。
    #[must_use]
    pub const fn allowed(&self) -> bool {
        self.check.allowed
    }

    /// 是否因降级被拒绝。
    #[must_use]
    pub const fn blocked_by_degradation(&self) -> bool {
        self.degraded && !self.check.allowed
    }

    /// 是否触发软阈值。
    #[must_use]
    pub fn soft_breached(&self) -> bool {
        !self.check.soft_breached.is_empty()
    }
}

impl QuotaSnapshot {
    /// 按作用域过滤。
    #[must_use]
    pub fn by_scope(&self, scope: QuotaScope) -> Vec<&SnapshotEntry> {
        self.entries.iter().filter(|e| e.scope == scope).collect()
    }

    /// 超限（或告警）条目数。
    #[must_use]
    pub fn breached_count(&self) -> usize {
        self.entries.iter().filter(|e| e.used >= e.limit && e.limit > 0).count()
    }
}
