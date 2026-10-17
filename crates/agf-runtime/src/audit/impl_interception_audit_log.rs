//! 由 `audit.rs` 拆分：`InterceptionAuditLog` 的实现（纯搬移，逻辑不变）。
use super::*;

impl InterceptionAuditLog {
    /// 默认缓冲容量。
    pub const DEFAULT_CAPACITY: usize = 4096;

    /// 新建（默认容量）。
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }

    /// 指定容量新建（`capacity = 0` 时取默认值，避免"永不记录"的静默失效）。
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            state: Mutex::new(ChainState::new()),
            capacity: if capacity == 0 { Self::DEFAULT_CAPACITY } else { capacity },
        }
    }

    /// 加锁访问链状态。
    pub(crate) fn lock(&self) -> Result<std::sync::MutexGuard<'_, ChainState>, String> {
        self.state.lock().map_err(|_| "拦截审计链锁中毒".to_string())
    }

    /// 追加一条记录（自动填 `sequence` / `prev_hash` / `entry_hash`）。
    ///
    /// **字段不可变约定**：调用方传入的 `sequence` / `prev_hash` / `entry_hash`
    /// 会被覆盖，避免伪造链位置；`at` 若为零值则由调用方负责设置（构造时已填当前时间）。
    ///
    /// # Errors
    /// 内部锁中毒（正常不可达）。
    pub fn append(&self, mut record: InterceptionRecord) -> Result<InterceptionRecord, String> {
        let mut guard = self.lock()?;
        guard.total += 1;
        record.sequence = i64::try_from(guard.total).unwrap_or(i64::MAX);
        record.prev_hash = guard.tail_hash.clone();
        record.seal();
        guard.tail_hash = record.entry_hash.clone();
        if guard.entries.len() >= self.capacity {
            guard.entries.pop_front();
            guard.truncated = true;
        }
        guard.entries.push_back(record.clone());
        Ok(record)
    }

    /// 已滚出缓冲（`true` 时 `verify()` 只覆盖当前缓冲内的窗口）。
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.lock().map(|g| g.truncated).unwrap_or(false)
    }

    /// 当前缓冲内的记录（按序号升序）。
    #[must_use]
    pub fn records(&self) -> Vec<InterceptionRecord> {
        self.lock().map(|g| g.entries.iter().cloned().collect()).unwrap_or_default()
    }

    /// 记录条数（缓冲内）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().map(|g| g.entries.len()).unwrap_or(0)
    }

    /// 缓冲是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 累计写入条数（含已滚出的）。
    #[must_use]
    pub fn total(&self) -> u64 {
        self.lock().map(|g| g.total).unwrap_or(0)
    }

    /// 读取游标之后当前租户/会话的新记录，按序号升序返回。
    ///
    /// # Errors
    /// 锁中毒或游标后的记录已滚出缓冲；不得把不完整审计当作成功。
    pub fn session_since(
        &self,
        tenant: TenantId,
        session: &str,
        after: u64,
    ) -> Result<Vec<InterceptionRecord>, String> {
        let guard = self.lock()?;
        if guard
            .entries
            .front()
            .is_some_and(|record| u64::try_from(record.sequence).unwrap_or(0) > after.saturating_add(1))
        {
            return Err("拦截审计缓冲已覆盖未持久化记录".into());
        }
        let mut records: Vec<_> = guard
            .entries
            .iter()
            .rev()
            .take_while(|record| u64::try_from(record.sequence).unwrap_or(0) > after)
            .filter(|record| record.tenant_id == tenant && record.session_id == session)
            .cloned()
            .collect();
        records.reverse();
        Ok(records)
    }

    /// 链尾哈希（锚点素材）。
    #[must_use]
    pub fn tail_hash(&self) -> String {
        self.lock().map(|g| g.tail_hash.clone()).unwrap_or_else(|_| GENESIS_HASH.to_string())
    }

    /// 最近 N 条（倒序：最新在前）。
    #[must_use]
    pub fn recent(&self, limit: usize) -> Vec<InterceptionRecord> {
        self.lock().map(|g| g.entries.iter().rev().take(limit).cloned().collect()).unwrap_or_default()
    }

    /// 按租户筛选。
    #[must_use]
    pub fn by_tenant(&self, tenant: TenantId) -> Vec<InterceptionRecord> {
        self.records().into_iter().filter(|r| r.tenant_id == tenant).collect()
    }

    /// 按会话筛选。
    #[must_use]
    pub fn by_session(&self, session: &str) -> Vec<InterceptionRecord> {
        self.records().into_iter().filter(|r| r.session_id == session).collect()
    }

    /// 按处置结果筛选。
    #[must_use]
    pub fn by_verdict(&self, verdict: InterceptionVerdict) -> Vec<InterceptionRecord> {
        self.records().into_iter().filter(|r| r.verdict == verdict).collect()
    }

    /// 阻断计数（控制台"今日拦截"指标）。
    #[must_use]
    pub fn blocked_count(&self) -> usize {
        self.lock().map(|g| g.entries.iter().filter(|r| r.verdict.is_blocking()).count()).unwrap_or(0)
    }

    /// 校验哈希链（要求 `sequence` 连续且 `prev_hash` 衔接）。
    ///
    /// **注意**：缓冲滚出后（[`Self::is_truncated`]）链首的 `prev_hash` 指向已滚出的
    /// 记录，此时仍会**通过**校验（因为链内衔接关系自洽），但报告里的
    /// `first_sequence` 不是 1，调用方应据此知道"这不是全链"。
    #[must_use]
    pub fn verify(&self) -> InterceptionChainReport {
        let entries = self.records();
        let mut report =
            InterceptionChainReport { checked: entries.len(), passed: true, ..InterceptionChainReport::default() };
        let mut prev: Option<&InterceptionRecord> = None;
        for e in &entries {
            if !e.verify() {
                report.passed = false;
                report.violations.push(InterceptionViolation {
                    entry_id: e.id,
                    sequence: e.sequence,
                    kind: "hash_mismatch".to_string(),
                    detail: format!("序号 {} 的内容哈希与记录不一致，疑似被篡改", e.sequence),
                });
            }
            if let Some(p) = prev {
                // 与**重算**出的前一条哈希比较（而不是它自己存的 `entry_hash`）：
                // 篡改前一条内容时，篡改者的 `entry_hash` 字段并没有跟着变，
                // 只比字段会漏掉"被篡改内容向下游传播"这一最关键的检出点。
                if e.prev_hash != p.compute_hash() {
                    report.passed = false;
                    report.violations.push(InterceptionViolation {
                        entry_id: e.id,
                        sequence: e.sequence,
                        kind: "prev_gap".to_string(),
                        detail: format!("序号 {} 的 prev_hash 与序号 {} 不衔接", e.sequence, p.sequence),
                    });
                }
                if e.sequence != p.sequence + 1 {
                    report.passed = false;
                    report.violations.push(InterceptionViolation {
                        entry_id: e.id,
                        sequence: e.sequence,
                        kind: "sequence_gap".to_string(),
                        detail: format!("序号从 {} 跳到 {}，存在缺失记录", p.sequence, e.sequence),
                    });
                }
            }
            prev = Some(e);
        }
        report.first_sequence = entries.first().map(|e| e.sequence);
        report.last_sequence = entries.last().map(|e| e.sequence);
        report.tail_hash = entries.last().map(|e| e.entry_hash.clone());
        report.verified_at = Some(Timestamp::now());
        report
    }

    /// 篡改缓冲内第 `index` 条记录的原因字段（**仅供测试**：验证链能发现篡改）。
    ///
    /// 之所以提供这个方法而不是让测试直接改 `records()` 的返回值：`records()` 返回克隆，
    /// 改它不影响链；测试需要真正改动链内数据才能验证检出能力。
    #[doc(hidden)]
    pub fn tamper_reason_for_test(&self, index: usize, new_reason: &str) -> bool {
        let Ok(mut guard) = self.lock() else { return false };
        match guard.entries.get_mut(index) {
            Some(record) => {
                record.reason = new_reason.to_string();
                true
            }
            None => false,
        }
    }

    /// 篡改缓冲内第 `index` 条记录的 `prev_hash`（**仅供测试**）。
    #[doc(hidden)]
    pub fn tamper_prev_hash_for_test(&self, index: usize, new_prev: &str) -> bool {
        let Ok(mut guard) = self.lock() else { return false };
        match guard.entries.get_mut(index) {
            Some(record) => {
                record.prev_hash = new_prev.to_string();
                true
            }
            None => false,
        }
    }

    /// 删除缓冲内第 `index` 条记录（**仅供测试**：验证删中间记录会被发现）。
    #[doc(hidden)]
    pub fn remove_at_for_test(&self, index: usize) -> bool {
        let Ok(mut guard) = self.lock() else { return false };
        guard.entries.remove(index).is_some()
    }

    /// 清空（**仅测试与"重置演示数据"使用**；生产禁止调用，否则链证据丢失）。
    pub fn clear(&mut self) {
        if let Ok(mut guard) = self.state.lock() {
            *guard = ChainState::new();
        }
    }
}

impl Default for InterceptionAuditLog {
    fn default() -> Self {
        Self::new()
    }
}
