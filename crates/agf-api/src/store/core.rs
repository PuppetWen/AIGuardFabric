//! `ApiStore` 的构造、数据库/日志句柄与内存锁。

use super::*;

impl ApiStore {
    /// 构造离线内存后端。
    #[must_use]
    pub fn offline() -> Self {
        Self { memory: Mutex::new(Memory::default()), database: None, journal: None }
    }

    /// 构造带 PostgreSQL 落库能力的后端（资源以内存为读缓存，见模块文档）。
    #[must_use]
    pub fn with_database(store: Arc<agf_storage::Store>) -> Self {
        Self { memory: Mutex::new(Memory::default()), database: Some(store), journal: None }
    }

    /// 挂上写后持久化队列（`AppState::build` 装配 `ApiStore` 时调用）。
    ///
    /// 水合（[`crate::persistence::PersistenceBridge::hydrate`]）走独立的 `hydrate_*` 方法，
    /// 只写内存、不入队，因此"挂队列"与"启动水合"的先后顺序不影响
    /// "水合不回写 PG"这一性质。
    #[must_use]
    pub fn with_journal(mut self, queue: Arc<WriteQueue>) -> Self {
        self.journal = Some(queue);
        self
    }

    /// 是否连接了数据库。
    #[must_use]
    pub const fn has_database(&self) -> bool {
        self.database.is_some()
    }

    /// 是否启用了写后持久化（有数据库且有队列）。
    #[must_use]
    pub const fn has_persistence(&self) -> bool {
        self.journal.is_some()
    }

    /// 数据库句柄。
    #[must_use]
    pub fn database(&self) -> Option<&Arc<agf_storage::Store>> {
        self.database.as_ref()
    }

    /// 塞一条写意图进写后队列（无队列时空操作：离线模式不落库）。
    ///
    /// **绝不 panic、绝不阻塞**：队列满或消费端已退出时丢弃并计数（`dropped`）。
    pub(super) fn journal(&self, intent: PgWrite) {
        if let Some(queue) = &self.journal {
            let _ = queue.enqueue(intent);
        }
    }

    pub(super) fn lock(&self) -> DomainResult<MutexGuard<'_, Memory>> {
        self.memory.lock().map_err(|e| DomainError::Internal(format!("内存后端锁中毒: {e}")))
    }
}
