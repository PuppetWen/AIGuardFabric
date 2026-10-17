//! 由 `approval.rs` 拆分：`ApprovalError`/`ApprovalRecord`/`Decision`/`DomainError`/`InMemoryApprovalStore` 的实现（纯搬移，逻辑不变）。
use super::*;

impl Decision {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Used => "used",
        }
    }

    /// 是否允许本次调用通过。
    #[must_use]
    pub const fn allows(&self) -> bool {
        matches!(self, Self::Approved)
    }

    /// 是否仍可被批准（审批人此刻还能操作）。
    #[must_use]
    pub const fn is_actionable(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// 中文简述。
    #[must_use]
    pub const fn display_zh(&self) -> &'static str {
        match self {
            Self::Pending => "待审批",
            Self::Approved => "已批准",
            Self::Rejected => "已拒绝",
            Self::Expired => "已过期",
            Self::Revoked => "已撤销",
            Self::Used => "已使用",
        }
    }
}

impl ApprovalRecord {
    /// 是否已过期（惰性判定；`state` 字段不会被就地改写）。
    #[must_use]
    pub fn is_expired(&self, now: Timestamp) -> bool {
        now.is_at_or_after(&self.expires_at)
    }

    /// 归一后的判定。
    #[must_use]
    pub fn effective_state(&self, now: Timestamp) -> Decision {
        if self.used_at.is_some() {
            return Decision::Used;
        }
        match self.request.state {
            ApprovalState::Pending => {
                if self.is_expired(now) {
                    Decision::Expired
                } else {
                    Decision::Pending
                }
            }
            ApprovalState::Approved => {
                if self.is_expired(now) {
                    Decision::Expired
                } else {
                    Decision::Approved
                }
            }
            ApprovalState::Rejected => Decision::Rejected,
            ApprovalState::Expired => Decision::Expired,
            ApprovalState::Revoked => Decision::Revoked,
        }
    }

    /// 剩余有效期（秒，可能为负）。
    #[must_use]
    pub fn remaining_secs(&self, now: Timestamp) -> i64 {
        self.expires_at.since_secs(&now)
    }

    /// 审批单页面链接（控制台路由）。
    #[must_use]
    pub fn console_link(&self) -> String {
        format!("approval/{}", self.request.id)
    }
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "审批单不存在: {id}"),
            Self::NotConsumable { id, state } => {
                write!(f, "审批单 {id} 当前状态为 {}，不可用于放行", state.display_zh())
            }
            Self::AlreadyUsed(id) => write!(f, "审批单 {id} 已被使用过（单次有效）"),
            Self::StoreUnavailable(reason) => write!(f, "审批存储不可用（按未通过处理）: {reason}"),
            Self::Invalid(reason) => write!(f, "审批参数非法: {reason}"),
        }
    }
}

impl std::error::Error for ApprovalError {}

impl From<ApprovalError> for agf_core::error::DomainError {
    fn from(value: ApprovalError) -> Self {
        match value {
            ApprovalError::NotFound(id) => Self::NotFound { entity: "approval", id: id.to_string() },
            ApprovalError::NotConsumable { id, state } => {
                Self::PreconditionFailed(format!("审批单 {id} 状态为 {}，不可放行", state.display_zh()))
            }
            ApprovalError::AlreadyUsed(id) => Self::PreconditionFailed(format!("审批单 {id} 已被使用过（单次有效）")),
            ApprovalError::StoreUnavailable(reason) => {
                Self::DependencyUnavailable { dependency: "approval-store".to_string(), cause: reason }
            }
            ApprovalError::Invalid(reason) => Self::Validation(reason),
        }
    }
}

impl InMemoryApprovalStore {
    /// 新建空存储。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 审批单总数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn lock_records(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<(TenantId, Id), ApprovalRecord>>, ApprovalError> {
        self.records.lock().map_err(|_| ApprovalError::StoreUnavailable("内存审批表锁中毒".into()))
    }

    pub(crate) fn lock_order(&self) -> Result<std::sync::MutexGuard<'_, Vec<(TenantId, Id)>>, ApprovalError> {
        self.order.lock().map_err(|_| ApprovalError::StoreUnavailable("内存审批索引锁中毒".into()))
    }

    pub(crate) fn lookup(&self, tenant: TenantId, id: Id) -> Result<ApprovalRecord, ApprovalError> {
        let guard = self.lock_records()?;
        guard.get(&(tenant, id)).cloned().ok_or(ApprovalError::NotFound(id))
    }
}

#[async_trait]
impl ApprovalStore for InMemoryApprovalStore {
    async fn create(&self, record: ApprovalRecord) -> Result<ApprovalRecord, ApprovalError> {
        if record.request.ttl_secs <= 0 {
            return Err(ApprovalError::Invalid("TTL 必须为正数".into()));
        }
        let key = (record.request.tenant_id, record.request.id);
        {
            let mut guard = self.lock_records()?;
            if guard.contains_key(&key) {
                return Err(ApprovalError::Invalid(format!("审批单 {} 已存在", record.request.id)));
            }
            guard.insert(key, record.clone());
        }
        self.lock_order()?.push(key);
        Ok(record)
    }

    async fn get(&self, tenant: TenantId, id: Id) -> Result<ApprovalRecord, ApprovalError> {
        self.lookup(tenant, id)
    }

    async fn list(&self, tenant: TenantId, filter: Option<Decision>) -> Result<Vec<ApprovalRecord>, ApprovalError> {
        let now = Timestamp::now();
        let order = self.lock_order()?.clone();
        let guard = self.lock_records()?;
        let mut out: Vec<ApprovalRecord> = Vec::new();
        for key in order {
            if key.0 != tenant {
                continue;
            }
            if let Some(record) = guard.get(&key) {
                if filter.is_none_or(|f| record.effective_state(now) == f) {
                    out.push(record.clone());
                }
            }
        }
        Ok(out)
    }

    async fn approve(
        &self,
        tenant: TenantId,
        id: Id,
        approver: Id,
        note: &str,
    ) -> Result<ApprovalRecord, ApprovalError> {
        self.transition(tenant, id, |record, now| {
            match record.effective_state(now) {
                Decision::Pending => Ok(()),
                other => Err(ApprovalError::NotConsumable { id, state: other }),
            }?;
            record.request.state = ApprovalState::Approved;
            record.request.approver_id = Some(approver);
            record.request.decision_note = Some(note.to_string());
            record.request.decided_at = Some(now);
            Ok(())
        })
    }

    async fn reject(
        &self,
        tenant: TenantId,
        id: Id,
        approver: Id,
        note: &str,
    ) -> Result<ApprovalRecord, ApprovalError> {
        self.transition(tenant, id, |record, now| {
            match record.effective_state(now) {
                Decision::Pending => Ok(()),
                other => Err(ApprovalError::NotConsumable { id, state: other }),
            }?;
            record.request.state = ApprovalState::Rejected;
            record.request.approver_id = Some(approver);
            record.request.decision_note = Some(note.to_string());
            record.request.decided_at = Some(now);
            Ok(())
        })
    }

    async fn revoke(&self, tenant: TenantId, id: Id, note: &str) -> Result<ApprovalRecord, ApprovalError> {
        self.transition(tenant, id, |record, now| {
            match record.effective_state(now) {
                Decision::Pending | Decision::Approved => Ok(()),
                other => Err(ApprovalError::NotConsumable { id, state: other }),
            }?;
            record.request.state = ApprovalState::Revoked;
            record.request.decision_note = Some(note.to_string());
            record.request.decided_at = Some(now);
            Ok(())
        })
    }

    async fn consume(&self, tenant: TenantId, id: Id, consumer: &str) -> Result<ApprovalRecord, ApprovalError> {
        // 原子性：在同一把锁内完成"检查 + 置位"，杜绝并发双放行。
        let mut guard = self.lock_records()?;
        let now = Timestamp::now();
        let Some(record) = guard.get_mut(&(tenant, id)) else {
            return Err(ApprovalError::NotFound(id));
        };
        if record.used_at.is_some() {
            return Err(ApprovalError::AlreadyUsed(id));
        }
        let state = record.effective_state(now);
        if !state.allows() {
            return Err(match state {
                Decision::Used => ApprovalError::AlreadyUsed(id),
                other => ApprovalError::NotConsumable { id, state: other },
            });
        }
        record.used_at = Some(now);
        record.consumed_by = Some(consumer.to_string());
        Ok(record.clone())
    }

    async fn expire_due(&self, tenant: TenantId, now: Timestamp) -> Result<usize, ApprovalError> {
        let mut guard = self.lock_records()?;
        let mut count = 0_usize;
        for ((t, _), record) in guard.iter_mut() {
            if *t != tenant {
                continue;
            }
            if record.used_at.is_none()
                && matches!(record.request.state, ApprovalState::Pending | ApprovalState::Approved)
                && record.is_expired(now)
            {
                record.request.state = ApprovalState::Expired;
                count += 1;
            }
        }
        Ok(count)
    }

    async fn count(&self) -> Result<Option<usize>, ApprovalError> {
        Ok(Some(self.len()))
    }
}

impl InMemoryApprovalStore {
    /// 在锁内执行状态迁移（读写原子）。
    pub(crate) fn transition<F>(&self, tenant: TenantId, id: Id, apply: F) -> Result<ApprovalRecord, ApprovalError>
    where
        F: FnOnce(&mut ApprovalRecord, Timestamp) -> Result<(), ApprovalError>,
    {
        let mut guard = self.lock_records()?;
        let now = Timestamp::now();
        let Some(record) = guard.get_mut(&(tenant, id)) else {
            return Err(ApprovalError::NotFound(id));
        };
        apply(record, now)?;
        Ok(record.clone())
    }
}
