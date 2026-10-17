//! 落库抽象 `Sink` 与两个实现：内存 sink（离线可测）与 SQL sink（原始日志 + 事件双写，走租户 RLS）。

use super::*;

// ---------------------------------------------------------------------------
// 持久化抽象
// ---------------------------------------------------------------------------

/// 落库目标（原始日志 + 归一化事件）。
#[async_trait]
pub trait Sink: Send + Sync + std::fmt::Debug {
    /// 后端名（`memory` / `sql`）。
    fn backend(&self) -> &'static str;

    /// Events are queued transactionally and must not be published again by the pipeline.
    fn queues_events(&self) -> bool {
        false
    }

    /// Optional durable store for native source lifecycle management.
    fn database(&self) -> Option<Arc<agf_storage::Store>> {
        None
    }

    /// Persist a prepared ingest batch. SQL and memory implementations commit atomically.
    /// Custom sinks must return an error if any expected event is not stored.
    async fn persist_ingest(&self, items: &[IngestWrite]) -> DomainResult<usize> {
        super::persistence::validate(items)?;
        for item in items {
            self.put_raw(&item.raw).await?;
        }
        let events: Vec<Event> = items.iter().filter_map(|item| item.event.clone()).collect();
        let written = self.put_events(&events).await?;
        if written != events.len() {
            return Err(DomainError::DependencyUnavailable {
                dependency: "ingest-storage".into(),
                cause: "Incomplete event batch".into(),
            });
        }
        Ok(written)
    }

    /// Atomically claim verified business events and persist audit/raw/event/outbox together.
    /// Unsupported sinks must fail; a generic sequential fallback would lose atomicity.
    async fn persist_agentteams(
        &self,
        _guard: &AgentTeamsBindingGuard,
        _items: &[AgentTeamsIngestItem],
    ) -> DomainResult<AgentTeamsIngestResult> {
        Err(super::agentteams_audit::unsupported())
    }

    /// Return one safe page in the half-open event-time window, newest first.
    async fn agentteams_audit_records(
        &self,
        _query: &AgentTeamsAuditQuery,
    ) -> DomainResult<Vec<AgentTeamsAuditRecord>> {
        Err(super::agentteams_audit::unsupported())
    }

    /// Read original collector task errors with a full count from one snapshot.
    async fn agentteams_failure_snapshot(
        &self,
        _query: &AgentTeamsFailureQuery,
    ) -> DomainResult<AgentTeamsFailureSnapshot> {
        Err(super::agentteams_audit::unsupported())
    }

    /// Tenant-filtered original task/error UUID lookup; never reconstruct from Event.raw.
    async fn agentteams_failure_record(
        &self,
        _tenant: TenantId,
        _id: Id,
    ) -> DomainResult<Option<AgentTeamsAuditRecord>> {
        Err(super::agentteams_audit::unsupported())
    }

    /// Count a whole trace window and return only its newest bounded records.
    /// Both values must come from one database statement or memory lock.
    async fn agentteams_trace_snapshot(&self, _query: &AgentTeamsTraceQuery) -> DomainResult<AgentTeamsTraceSnapshot> {
        Err(super::agentteams_audit::unsupported())
    }

    /// Count the complete event-time window independently of audit pagination.
    async fn agentteams_audit_aggregate(
        &self,
        _tenant: TenantId,
        _scope: Id,
        _from: Timestamp,
        _until: Timestamp,
    ) -> DomainResult<AgentTeamsAuditAggregate> {
        Err(super::agentteams_audit::unsupported())
    }

    /// 写入原始日志（保真层）。
    ///
    /// # Errors
    /// 写入失败。
    async fn put_raw(&self, raw: &RawLog) -> DomainResult<()>;

    /// 更新原始日志的解析状态（`parsed` / `event_id` / `parse_error`）。
    ///
    /// # Errors
    /// 记录不存在或更新失败。
    async fn mark_raw(
        &self,
        tenant: TenantId,
        raw_id: Id,
        parsed: bool,
        event_id: Option<Id>,
        error: Option<&str>,
    ) -> DomainResult<()>;

    /// 写入归一化事件。
    ///
    /// # Errors
    /// 写入失败。
    async fn put_event(&self, event: &Event) -> DomainResult<()>;

    /// 批量写入事件（返回成功条数）。
    ///
    /// # Errors
    /// 批量写入整体失败。
    async fn put_events(&self, events: &[Event]) -> DomainResult<usize>;

    /// 按 id 读取事件（回放差分用）。
    ///
    /// # Errors
    /// 查询失败。
    async fn get_event(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Event>>;

    /// 拉取未解析的原始日志（回放用）。
    ///
    /// # Errors
    /// 查询失败。
    async fn unparsed_raw(&self, tenant: TenantId, limit: i64) -> DomainResult<Vec<RawLog>>;

    /// 事件总数（运维看板用）。
    ///
    /// # Errors
    /// 查询失败。
    async fn event_count(&self, tenant: TenantId) -> DomainResult<u64>;

    /// 原始日志总数。
    ///
    /// # Errors
    /// 查询失败。
    async fn raw_count(&self, tenant: TenantId) -> DomainResult<u64>;
}

/// 进程内落库（单元测试与单机演示；重启即丢）。
#[derive(Debug, Default)]
pub struct InMemorySink {
    state: Mutex<MemoryState>,
}

#[derive(Debug, Default)]
pub(super) struct MemoryState {
    pub(super) raws: Vec<RawLog>,
    pub(super) events: Vec<Event>,
    pub(super) agentteams: BTreeMap<(TenantId, Id, String), AgentTeamsAuditRecord>,
}

impl InMemorySink {
    /// 新建。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 快照：全部事件。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn events(&self) -> DomainResult<Vec<Event>> {
        self.state.lock().map(|s| s.events.clone()).map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))
    }

    /// 快照：全部原始日志。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn raws(&self) -> DomainResult<Vec<RawLog>> {
        self.state.lock().map(|s| s.raws.clone()).map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))
    }
}

#[async_trait]
impl Sink for InMemorySink {
    async fn agentteams_failure_snapshot(
        &self,
        query: &AgentTeamsFailureQuery,
    ) -> DomainResult<AgentTeamsFailureSnapshot> {
        let state = self.state.lock().map_err(|_| DomainError::Internal("Ingest evidence lock poisoned".into()))?;
        super::agentteams_failure_memory::snapshot(&state, query)
    }
    async fn agentteams_failure_record(&self, tenant: TenantId, id: Id) -> DomainResult<Option<AgentTeamsAuditRecord>> {
        let state = self.state.lock().map_err(|_| DomainError::Internal("Ingest evidence lock poisoned".into()))?;
        super::agentteams_failure_memory::record(&state, tenant, id)
    }

    async fn persist_agentteams(
        &self,
        guard: &AgentTeamsBindingGuard,
        items: &[AgentTeamsIngestItem],
    ) -> DomainResult<AgentTeamsIngestResult> {
        let mut state = self.state.lock().map_err(|error| DomainError::Internal(error.to_string()))?;
        super::agentteams_memory::persist(&mut state, guard, items)
    }

    async fn agentteams_audit_records(&self, query: &AgentTeamsAuditQuery) -> DomainResult<Vec<AgentTeamsAuditRecord>> {
        let state = self.state.lock().map_err(|error| DomainError::Internal(error.to_string()))?;
        super::agentteams_memory::records(&state, query)
    }

    async fn agentteams_trace_snapshot(&self, query: &AgentTeamsTraceQuery) -> DomainResult<AgentTeamsTraceSnapshot> {
        let state = self.state.lock().map_err(|error| DomainError::Internal(error.to_string()))?;
        super::agentteams_trace_memory::snapshot(&state, query)
    }

    async fn agentteams_audit_aggregate(
        &self,
        tenant: TenantId,
        scope: Id,
        from: Timestamp,
        until: Timestamp,
    ) -> DomainResult<AgentTeamsAuditAggregate> {
        let state = self.state.lock().map_err(|error| DomainError::Internal(error.to_string()))?;
        super::agentteams_memory::aggregate(&state, tenant, scope, from, until)
    }
    async fn persist_ingest(&self, items: &[IngestWrite]) -> DomainResult<usize> {
        super::persistence::validate(items)?;
        let mut state = self.state.lock().map_err(|e| DomainError::Internal(format!("Sink lock poisoned: {e}")))?;
        let mut count = 0;
        for item in items {
            state.raws.push(item.raw.clone());
            if let Some(event) = &item.event {
                state.events.push(event.clone());
                count += 1;
            }
        }
        Ok(count)
    }

    fn backend(&self) -> &'static str {
        "memory"
    }

    async fn put_raw(&self, raw: &RawLog) -> DomainResult<()> {
        let mut state = self.state.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        state.raws.push(raw.clone());
        Ok(())
    }

    async fn mark_raw(
        &self,
        tenant: TenantId,
        raw_id: Id,
        parsed: bool,
        event_id: Option<Id>,
        error: Option<&str>,
    ) -> DomainResult<()> {
        let mut state = self.state.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        let Some(target) = state.raws.iter_mut().find(|r| r.id == raw_id && r.tenant_id == tenant) else {
            return Err(DomainError::NotFound { entity: "raw_log", id: raw_id.to_string() });
        };
        target.parsed = parsed;
        target.event_id = event_id;
        target.parse_error = error.map(ToString::to_string);
        Ok(())
    }

    async fn put_event(&self, event: &Event) -> DomainResult<()> {
        let mut state = self.state.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        if state.events.iter().any(|e| e.id == event.id) {
            return Err(DomainError::Conflict(format!("事件已存在: {}", event.id)));
        }
        state.events.push(event.clone());
        Ok(())
    }

    async fn put_events(&self, events: &[Event]) -> DomainResult<usize> {
        let mut state = self.state.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        let mut ok = 0;
        for event in events {
            if state.events.iter().any(|e| e.id == event.id) {
                continue;
            }
            state.events.push(event.clone());
            ok += 1;
        }
        Ok(ok)
    }

    async fn get_event(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Event>> {
        let state = self.state.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        Ok(state.events.iter().find(|e| e.id == id && e.tenant_id == tenant).cloned())
    }

    async fn unparsed_raw(&self, tenant: TenantId, limit: i64) -> DomainResult<Vec<RawLog>> {
        let state = self.state.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        let limit = usize::try_from(limit.max(0)).unwrap_or(usize::MAX);
        let mut out: Vec<RawLog> = state.raws.iter().filter(|r| !r.parsed && r.tenant_id == tenant).cloned().collect();
        out.sort_by_key(|r| r.received_at);
        out.truncate(limit);
        Ok(out)
    }

    async fn event_count(&self, tenant: TenantId) -> DomainResult<u64> {
        let state = self.state.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        Ok(u64::try_from(state.events.iter().filter(|row| row.tenant_id == tenant).count()).unwrap_or(u64::MAX))
    }

    async fn raw_count(&self, tenant: TenantId) -> DomainResult<u64> {
        let state = self.state.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        Ok(u64::try_from(state.raws.iter().filter(|row| row.tenant_id == tenant).count()).unwrap_or(u64::MAX))
    }
}

/// PostgreSQL 落库（`agf_storage::Store`，走租户 RLS 事务）。
///
/// 说明：本实现需要真实 PostgreSQL 才能运行，因此在无数据库的 CI 中**只做编译校验**，
/// 功能验证在 `deploy/docker-compose.dev.yml` 的集成环境进行（见 `docs/pending-verification.md` 约定）。
#[derive(Debug, Clone)]
pub struct SqlSink {
    pub(super) store: Arc<agf_storage::Store>,
    pub(super) event_outbox: bool,
}

impl SqlSink {
    /// 构造。
    #[must_use]
    pub fn new(store: Arc<agf_storage::Store>) -> Self {
        Self { store, event_outbox: false }
    }

    /// Queue each normalized event in the same SQL transaction as its raw evidence.
    #[must_use]
    pub fn with_event_outbox(mut self, enabled: bool) -> Self {
        self.event_outbox = enabled;
        self
    }

    /// 底层 Store。
    #[must_use]
    pub fn store(&self) -> &Arc<agf_storage::Store> {
        &self.store
    }
}
