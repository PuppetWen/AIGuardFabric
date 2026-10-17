//! 由 `deadletter.rs` 拆分：`ScriptedAdapter`/`impl_ScriptedAdapter` 等 15 项（纯搬移，逻辑不变）。
use super::*;

/// 可控失败的测试适配器（记录收到的推送，按脚本决定成功/失败）。
pub(crate) struct ScriptedAdapter {
    pub(crate) name: String,
    pub(crate) fail_times: Mutex<usize>,
    pub(crate) received: Mutex<Vec<String>>,
}

impl ScriptedAdapter {
    pub(crate) fn new(name: &str, fail_times: usize) -> Self {
        Self { name: name.to_string(), fail_times: Mutex::new(fail_times), received: Mutex::new(Vec::new()) }
    }

    pub(crate) fn received(&self) -> Vec<String> {
        self.received.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub(crate) fn should_fail(&self) -> bool {
        self.fail_times.lock().is_ok_and(|mut g| {
            if *g > 0 {
                *g -= 1;
                true
            } else {
                false
            }
        })
    }
}

#[async_trait]
impl Adapter for ScriptedAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> AdapterDescriptor {
        crate::mock::descriptor_of(agf_core::enums::AliCloudService::Cms)
    }

    async fn init(&mut self, _config: &AdapterConfig) -> DomainResult<()> {
        Ok(())
    }

    async fn health(&self) -> DomainResult<AdapterHealth> {
        Ok(AdapterHealth::mocked(&self.name))
    }

    async fn sync(&self, _d: SyncDirection, _r: &PullRequest) -> DomainResult<SyncOutcome> {
        if self.should_fail() {
            return Err(DomainError::DependencyUnavailable {
                dependency: self.name.clone(),
                cause: "模拟断网".to_string(),
            });
        }
        Ok(SyncOutcome::mock(1, 1))
    }

    async fn push(&self, payload: &PushPayload) -> DomainResult<()> {
        if self.should_fail() {
            return Err(DomainError::DependencyUnavailable {
                dependency: self.name.clone(),
                cause: "模拟断网".to_string(),
            });
        }
        if let Ok(mut guard) = self.received.lock() {
            guard.push(payload.entity_id.clone());
        }
        Ok(())
    }

    async fn pull(&self, _r: &PullRequest) -> DomainResult<PullResponse> {
        if self.should_fail() {
            return Err(DomainError::DependencyUnavailable {
                dependency: self.name.clone(),
                cause: "模拟断网".to_string(),
            });
        }
        Ok(PullResponse { items: Vec::new(), next_cursor: None, mocked: false, origin: "test".to_string() })
    }

    async fn shutdown(&mut self) -> DomainResult<()> {
        Ok(())
    }
}

pub(crate) fn payload(id: &str, key: &str) -> PushPayload {
    PushPayload {
        entity: "event".to_string(),
        entity_id: id.to_string(),
        body: serde_json::json!({ "k": id }),
        idempotency_key: Some(key.to_string()),
    }
}

#[tokio::test]
pub(crate) async fn three_failures_then_flush_replays_and_drains() {
    let queue = OfflineQueue::new(OfflineQueueConfig { max_attempts: 5, capacity: 100 });
    let tenant = TenantId::default_tenant();
    for index in 0..3 {
        let item = payload(&format!("ev-{index}"), &format!("key-{index}"));
        let len = record_push_failure(
            &queue,
            tenant,
            "alicloud-cms",
            &item,
            &DomainError::DependencyUnavailable { dependency: "alicloud-cms".to_string(), cause: "断网".to_string() },
        );
        assert_eq!(len.ok(), Some(index + 1));
    }
    assert_eq!(queue.len().ok(), Some(3));
    assert!(!queue.is_empty().unwrap_or(true));

    // 网络恢复：重放全部成功
    let adapter = ScriptedAdapter::new("alicloud-cms", 0);
    let report = queue.flush(&adapter).await;
    assert!(report.is_ok(), "{report:?}");
    if let Ok(report) = report {
        assert_eq!(report.attempted, 3);
        assert_eq!(report.flushed, 3);
        assert_eq!(report.still_failing, 0);
        assert_eq!(report.dead_lettered, 0);
        assert_eq!(report.skipped, 0);
        assert!(report.queue_drained());
        assert!(report.finished_at.is_some());
        assert!(report.summary().contains("成功 3"));
    }
    assert_eq!(queue.len().ok(), Some(0), "重放成功后队列必须清空");
    assert!(queue.is_empty().unwrap_or(false));
    assert_eq!(adapter.received().len(), 3);
    assert!(queue.dead_letters().is_ok_and(|d| d.is_empty()));
}

#[tokio::test]
pub(crate) async fn failing_flush_keeps_items_and_increments_attempts() {
    let queue = OfflineQueue::new(OfflineQueueConfig { max_attempts: 5, capacity: 100 });
    let tenant = TenantId::default_tenant();
    assert!(queue.enqueue(OfflineOp::push(tenant, "alicloud-apig", &payload("p-1", "k1"), "断网")).is_ok());

    let adapter = ScriptedAdapter::new("alicloud-apig", usize::MAX);
    let report = queue.flush(&adapter).await;
    assert!(report.is_ok());
    if let Ok(report) = report {
        assert_eq!(report.attempted, 1);
        assert_eq!(report.flushed, 0);
        assert_eq!(report.still_failing, 1);
        assert_eq!(report.dead_lettered, 0);
        assert!(!report.queue_drained());
        assert_eq!(report.errors.len(), 1);
    }
    let pending = queue.pending();
    assert!(pending.is_ok());
    if let Ok(pending) = pending {
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].attempts, 2, "失败一次后尝试次数应为 2");
    }
}

#[tokio::test]
pub(crate) async fn exceeding_max_attempts_moves_to_dead_letter() {
    // `max_attempts` 语义 = 允许的**总尝试次数**（入队即算 1 次）。
    // 因此 max_attempts=2 表示"再重放 1 次仍失败就落死信"。
    let queue = OfflineQueue::new(OfflineQueueConfig { max_attempts: 2, capacity: 100 });
    let tenant = TenantId::default_tenant();
    assert!(queue.enqueue(OfflineOp::push(tenant, "alicloud-mse", &payload("p", "k"), "断网")).is_ok());
    let adapter = ScriptedAdapter::new("alicloud-mse", usize::MAX);

    let first = queue.flush(&adapter).await;
    assert!(first.is_ok());
    if let Ok(report) = &first {
        assert_eq!(report.attempted, 1);
        assert_eq!(report.flushed, 0);
        assert_eq!(report.dead_lettered, 1, "达到总尝试上限必须立刻落死信: {}", report.summary());
        assert_eq!(report.still_failing, 0);
    }
    let dead = queue.dead_letters();
    assert!(dead.is_ok());
    if let Ok(dead) = dead {
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].adapter, "alicloud-mse");
        assert_eq!(dead[0].operation, "push");
        assert_eq!(dead[0].attempts, 2);
        assert!(!dead[0].replayed);
        assert!(!dead[0].error.is_empty());
    }
    // 死信条目不再参与重放
    assert!(queue.pending().is_ok_and(|p| p.is_empty()));
    assert_eq!(queue.pending_by_adapter().ok(), Some(BTreeMap::new()));
}

#[tokio::test]
pub(crate) async fn dead_letter_only_after_all_retries_exhausted() {
    // max_attempts=3：第一次重放仍失败 → 保留在离线缓存；第二次重放失败 → 落死信
    let queue = OfflineQueue::new(OfflineQueueConfig { max_attempts: 3, capacity: 100 });
    let tenant = TenantId::default_tenant();
    assert!(queue.enqueue(OfflineOp::push(tenant, "alicloud-mse", &payload("p", "k"), "断网")).is_ok());
    let adapter = ScriptedAdapter::new("alicloud-mse", usize::MAX);

    let first = queue.flush(&adapter).await;
    assert!(first.is_ok());
    if let Ok(report) = &first {
        assert_eq!(report.still_failing, 1, "未达上限必须保留待补传: {}", report.summary());
        assert_eq!(report.dead_lettered, 0);
    }
    assert_eq!(queue.pending().ok().map(|p| p.len()), Some(1));
    assert_eq!(queue.pending().ok().and_then(|p| p.first().map(|op| op.attempts)), Some(2));

    let second = queue.flush(&adapter).await;
    assert!(second.is_ok());
    if let Ok(report) = second {
        assert_eq!(report.dead_lettered, 1);
        assert_eq!(report.still_failing, 0);
        assert_eq!(report.attempted, 1);
    }
    assert!(queue.pending().is_ok_and(|p| p.is_empty()));
    assert_eq!(queue.dead_letters().ok().map(|dead| dead.len()), Some(1));
}

#[tokio::test]
pub(crate) async fn flush_skips_other_adapters() {
    let queue = OfflineQueue::new(OfflineQueueConfig::default());
    let tenant = TenantId::default_tenant();
    assert!(queue.enqueue(OfflineOp::push(tenant, "alicloud-cms", &payload("a", "ka"), "x")).is_ok());
    assert!(queue.enqueue(OfflineOp::push(tenant, "alicloud-apig", &payload("b", "kb"), "x")).is_ok());
    let adapter = ScriptedAdapter::new("alicloud-cms", 0);
    let report = queue.flush(&adapter).await;
    assert!(report.is_ok());
    if let Ok(report) = report {
        assert_eq!(report.attempted, 1, "只应尝试本适配器的条目");
        assert_eq!(report.flushed, 1);
        assert_eq!(report.skipped, 1, "其他适配器的条目计入 skipped: {}", report.summary());
        assert!(!report.queue_drained(), "仍有其他适配器条目");
    }
    let by_adapter = queue.pending_by_adapter();
    assert!(by_adapter.is_ok());
    if let Ok(map) = by_adapter {
        assert_eq!(map.get("alicloud-cms").copied(), None, "已重放成功的条目必须出队");
        assert_eq!(map.get("alicloud-apig").copied(), Some(1), "其他适配器的条目必须保留");
        assert_eq!(map.values().sum::<usize>(), 1);
    }
    assert_eq!(queue.len().ok(), Some(1));
}

#[test]
pub(crate) fn idempotency_key_merges_duplicate_enqueues() {
    let queue = OfflineQueue::new(OfflineQueueConfig::default());
    let tenant = TenantId::default_tenant();
    for _ in 0..3 {
        assert!(queue.enqueue(OfflineOp::push(tenant, "alicloud-cms", &payload("ev", "same-key"), "e")).is_ok());
    }
    assert_eq!(queue.len().ok(), Some(1), "同一幂等键必须合并");
    let pending = queue.pending();
    assert!(pending.is_ok());
    if let Ok(pending) = pending {
        assert_eq!(pending[0].attempts, 3);
        assert_eq!(pending[0].idempotency_key, "same-key");
    }
}

#[test]
pub(crate) fn sync_and_pull_ops_serialize_round_trip() {
    let tenant = TenantId::default_tenant();
    let request = PullRequest { resource: "teams".to_string(), limit: Some(5), ..PullRequest::default() };
    let sync_op = OfflineOp::sync(tenant, "alicloud-agentteams", SyncDirection::Both, &request, "断网");
    let pull_op = OfflineOp::pull(tenant, "alicloud-agentteams", &request, "断网");
    assert_eq!(sync_op.kind.as_str(), "sync");
    assert_eq!(pull_op.kind.as_str(), "pull");
    assert!(sync_op.idempotency_key.starts_with("sync:"));
    assert!(pull_op.idempotency_key.starts_with("pull:"));

    // 序列化 → 反序列化（落库形态）
    let json = serde_json::to_string(&sync_op);
    assert!(json.is_ok());
    if let Ok(json) = json {
        let back: Result<OfflineOp, _> = serde_json::from_str(&json);
        assert!(back.is_ok());
        if let Ok(back) = back {
            assert_eq!(back.id, sync_op.id);
            assert_eq!(back.direction, Some(SyncDirection::Both));
            assert_eq!(back.request.and_then(|r| r.limit), Some(5));
        }
    }
    let dead = sync_op.to_dead_letter();
    assert_eq!(dead.operation, "sync");
    assert_eq!(dead.adapter, "alicloud-agentteams");
    assert!(dead.payload.get("idempotency_key").is_some());
}

#[tokio::test]
pub(crate) async fn sync_replay_uses_direction_and_request() {
    let queue = OfflineQueue::new(OfflineQueueConfig { max_attempts: 3, capacity: 10 });
    let tenant = TenantId::default_tenant();
    let request = PullRequest { resource: "alarms".to_string(), ..PullRequest::default() };
    assert!(
        record_sync_failure(
            &queue,
            tenant,
            "alicloud-cms",
            SyncDirection::Pull,
            &request,
            &DomainError::DependencyUnavailable { dependency: "cms".to_string(), cause: "断网".to_string() },
        )
        .is_ok()
    );
    let adapter = ScriptedAdapter::new("alicloud-cms", 0);
    let report = queue.flush(&adapter).await;
    assert!(report.is_ok_and(|r| r.flushed == 1));
    assert!(queue.is_empty().unwrap_or(false));
}

#[test]
pub(crate) fn capacity_guard_evicts_dead_entries_first() {
    let queue = OfflineQueue::new(OfflineQueueConfig { max_attempts: 1, capacity: 3 });
    let tenant = TenantId::default_tenant();
    let mut first = OfflineOp::push(tenant, "alicloud-cms", &payload("a", "ka"), "e");
    first.dead = true;
    assert!(queue.enqueue(first).is_ok());
    for index in 0..3 {
        assert!(
            queue
                .enqueue(OfflineOp::push(
                    tenant,
                    "alicloud-cms",
                    &payload(&format!("p{index}"), &format!("k{index}")),
                    "e"
                ))
                .is_ok()
        );
    }
    assert_eq!(queue.len().ok(), Some(3), "容量保护必须生效");
    let pending = queue.pending();
    assert!(pending.is_ok_and(|p| p.len() == 3), "被淘汰的是死信条目");
}

#[test]
pub(crate) fn clear_resets_queue_and_dead_letters() {
    let queue = OfflineQueue::new(OfflineQueueConfig::default());
    let tenant = TenantId::default_tenant();
    assert!(queue.enqueue(OfflineOp::push(tenant, "alicloud-cms", &payload("a", "ka"), "e")).is_ok());
    assert!(queue.clear().is_ok());
    assert!(queue.is_empty().unwrap_or(false));
    assert!(queue.dead_letters().is_ok_and(|d| d.is_empty()));
}

#[tokio::test]
pub(crate) async fn push_without_payload_is_reported_not_panicking() {
    let queue = OfflineQueue::new(OfflineQueueConfig { max_attempts: 1, capacity: 10 });
    let mut op = OfflineOp::push(TenantId::default_tenant(), "alicloud-cms", &payload("a", "ka"), "e");
    op.payload = None; // 模拟损坏数据
    assert!(queue.enqueue(op).is_ok());
    let adapter = ScriptedAdapter::new("alicloud-cms", 0);
    let report = queue.flush(&adapter).await;
    assert!(report.is_ok());
    if let Ok(report) = report {
        assert_eq!(report.flushed, 0);
        assert_eq!(report.dead_lettered, 1, "损坏数据应落死信而不是 panic");
        assert!(report.errors.iter().any(|e| e.contains("缺少载荷")));
    }
}
