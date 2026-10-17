//! 写后持久化桥的装配与句柄：构造、报告快照与水合结果写入。

use super::*;

impl PersistenceBridge {
    /// 装配桥并启动消费者任务（必须在 tokio 运行时内调用；无运行时只告警不 panic）。
    #[must_use]
    pub fn spawn(store: Arc<Store>) -> Arc<Self> {
        Self::spawn_with_capacity(store, MAX_PENDING_WRITES)
    }

    /// 指定队列上限装配（测试与压测用）。
    #[must_use]
    pub fn spawn_with_capacity(store: Arc<Store>, capacity: usize) -> Arc<Self> {
        let (queue, receiver) = WriteQueue::detached(capacity);
        let bridge = Arc::new(Self {
            queue,
            store,
            hydration: Mutex::new(HydrationReport::default()),
            remap: Mutex::new(BTreeMap::new()),
        });
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let consumer = Arc::clone(&bridge);
                handle.spawn(async move { consumer.consume(receiver).await });
            }
            Err(_) => {
                warn!("写后持久化桥装配时没有 tokio 运行时：消费者未启动，写意图会在队列满后被丢弃（计数可见）");
            }
        }
        bridge
    }

    /// 写入队列句柄（`ApiStore` 持它入队）。
    #[must_use]
    pub fn queue(&self) -> Arc<WriteQueue> {
        Arc::clone(&self.queue)
    }

    /// 数据层句柄。
    #[must_use]
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// 当前报告快照。
    #[must_use]
    pub fn report(&self) -> PersistenceReport {
        let (queued, applied, failed, dropped, id_remapped, depth) = self.queue.stats.snapshot();
        let hydration = self.hydration.lock().map(|h| h.clone()).unwrap_or_default();
        let recent_errors =
            self.queue.stats.recent_errors.lock().map(|errors| errors.iter().cloned().collect()).unwrap_or_default();
        PersistenceReport {
            durable: DURABLE_RESOURCES.iter().map(|s| (*s).to_string()).collect(),
            memory_only: MEMORY_ONLY_RESOURCES.iter().map(|s| (*s).to_string()).collect(),
            hydrate: hydration,
            queued,
            applied,
            failed,
            dropped,
            id_remapped,
            pending: depth,
            queue_capacity: self.queue.capacity(),
            recent_errors,
        }
    }

    /// 记录一次水合结果。
    pub(super) fn set_hydration(&self, report: HydrationReport) {
        if let Ok(mut slot) = self.hydration.lock() {
            *slot = report;
        }
    }
}
