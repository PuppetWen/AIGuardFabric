//! 由 `queue.rs` 拆分：`queue` 等 12 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn queue(max_entries: usize, max_bytes: usize) -> LocalQueue {
    LocalQueue::new(QueueConfig::default().with_capacity(max_entries, max_bytes))
}

#[test]
pub(crate) fn fifo_order_and_peek() {
    let mut q = queue(10, 10_000);
    for i in 0..3 {
        assert_eq!(q.push_payload(PayloadKind::Snapshot, &format!("k{i}"), "{}"), PushOutcome::Enqueued);
    }
    assert_eq!(q.len(), 3);
    assert_eq!(q.peek().map(|e| e.idempotency_key.clone()), Some("k0".to_string()));
    assert_eq!(q.keys(), vec!["k0", "k1", "k2"]);
}

#[test]
pub(crate) fn entry_capacity_evicts_oldest() {
    let mut q = queue(3, 100_000);
    for i in 0..3 {
        q.push_payload(PayloadKind::Snapshot, &format!("k{i}"), "{}");
    }
    assert_eq!(q.push_payload(PayloadKind::Snapshot, "k3", "{}"), PushOutcome::Evicted(1));
    assert_eq!(q.keys(), vec!["k1", "k2", "k3"], "必须淘汰最旧");
    let stats = q.stats();
    assert_eq!(stats.depth, 3);
    assert_eq!(stats.evicted_total, 1);
    assert_eq!(stats.capacity_entries, 3);
}

#[test]
pub(crate) fn byte_capacity_evicts_until_fit() {
    let body = "x".repeat(100);
    let mut q = queue(100, 250);
    q.push_payload(PayloadKind::Snapshot, "k0", &body);
    q.push_payload(PayloadKind::Snapshot, "k1", &body);
    q.push_payload(PayloadKind::Snapshot, "k2", &body);
    assert!(q.bytes() <= 250, "字节上限必须生效: {}", q.bytes());
    assert!(!q.keys().contains(&"k0".to_string()), "必须从最旧开始淘汰");
}

#[test]
pub(crate) fn same_idempotency_key_replaces_instead_of_duplicating() {
    let mut q = queue(10, 10_000);
    q.push_payload(PayloadKind::Snapshot, "same", "{\"v\":1}");
    assert_eq!(q.push_payload(PayloadKind::Snapshot, "same", "{\"v\":2}"), PushOutcome::Replaced);
    assert_eq!(q.len(), 1, "同幂等键只能保留一份");
    assert!(q.peek().map(|e| e.body.clone()).unwrap_or_default().contains("\"v\":2"), "必须保留最新载荷");
    assert_eq!(q.stats().replaced_total, 1);
}

#[test]
pub(crate) fn zero_capacity_is_clamped_to_one() {
    let config = QueueConfig::default().with_capacity(0, 0);
    assert_eq!(config.effective_max_entries(), 1);
    assert_eq!(config.effective_max_bytes(), 1);
    let mut q = LocalQueue::new(config);
    q.push_payload(PayloadKind::Heartbeat, "k0", "{}");
    q.push_payload(PayloadKind::Heartbeat, "k1", "{}");
    assert_eq!(q.len(), 1);
}

#[test]
pub(crate) fn drain_batch_takes_oldest_first_without_dropping() {
    let mut q = queue(10, 10_000);
    for i in 0..5 {
        q.push_payload(PayloadKind::Snapshot, &format!("k{i}"), "{}");
    }
    let batch = q.drain_batch(2);
    assert_eq!(batch.len(), 2);
    assert_eq!(batch[0].idempotency_key, "k0");
    // drain_batch 已移出，队列剩 3 条
    assert_eq!(q.len(), 3);
    q.requeue_front(batch[0].clone());
    assert_eq!(q.len(), 4);
    assert_eq!(q.peek().map(|e| e.idempotency_key.clone()), Some("k0".to_string()));
}

#[test]
pub(crate) fn failure_attempts_expire_and_mark_delivered_removes() {
    let mut q = LocalQueue::new(QueueConfig { max_attempts: 2, ..QueueConfig::default() });
    q.push_payload(PayloadKind::Diff, "k0", "{}");
    assert!(!q.note_failure("k0"), "第一次失败仍应保留");
    assert_eq!(q.peek().map(|e| e.attempts), Some(1));
    assert!(q.note_failure("k0"), "达到上限必须丢弃");
    assert!(q.is_empty());
    assert_eq!(q.stats().expired_total, 1);
    assert!(!q.note_failure("missing"), "不存在的键不得 panic");

    q.push_payload(PayloadKind::Diff, "k1", "{}");
    assert!(q.mark_delivered("k1"));
    assert!(!q.mark_delivered("k1"));
    assert!(q.is_empty());
}

#[test]
pub(crate) fn save_and_load_roundtrip() {
    let dir = tempfile::tempdir().expect("临时目录");
    let path = dir.path().join("nested").join("queue.jsonl");
    let config = QueueConfig::default().with_capacity(10, 10_000).with_path(&path);
    let mut q = LocalQueue::new(config.clone());
    q.push_payload(PayloadKind::Snapshot, "k0", "{\"a\":1}");
    q.push_payload(PayloadKind::Heartbeat, "k1", "{\"b\":2}");
    q.save().expect("落盘应成功");
    assert!(path.exists());
    assert!(!tmp_path(&path).exists(), "临时文件必须被改名清理");

    let loaded = LocalQueue::load(config).expect("载入应成功");
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded.keys(), vec!["k0", "k1"]);
    assert_eq!(loaded.peek().map(|e| e.kind), Some(PayloadKind::Snapshot));
    assert_eq!(loaded.stats().corrupt_lines, 0);
}

#[test]
pub(crate) fn load_missing_file_is_empty_and_corrupt_lines_are_skipped() {
    let dir = tempfile::tempdir().expect("临时目录");
    let path = dir.path().join("queue.jsonl");
    let config = QueueConfig::default().with_path(&path);
    let empty = LocalQueue::load(config.clone()).expect("不存在也算成功");
    assert!(empty.is_empty());

    let good = serde_json::to_string(&QueueEntry::new(PayloadKind::Snapshot, "k0", "{}")).unwrap_or_default();
    std::fs::write(&path, format!("{good}\nnot-json\n\n{good}\n")).expect("写入");
    let loaded = LocalQueue::load(config).expect("载入");
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded.stats().corrupt_lines, 1, "损坏行必须计数并跳过");
}

#[test]
pub(crate) fn in_memory_queue_ignores_save_without_path() {
    let mut q = LocalQueue::new(QueueConfig::default());
    q.push_payload(PayloadKind::Register, "k0", "{}");
    q.save().expect("无路径时落盘为 no-op");
    assert_eq!(q.clear(), 1);
    assert!(q.is_empty());
}

#[test]
pub(crate) fn stats_expose_capacity_and_facts() {
    let mut q = queue(2, 100);
    q.push_payload(PayloadKind::Snapshot, "k0", &"y".repeat(80));
    q.push_payload(PayloadKind::Snapshot, "k1", &"y".repeat(80));
    let stats = q.stats();
    assert_eq!(stats.capacity_entries, 2);
    assert_eq!(stats.capacity_bytes, 100);
    assert!(stats.bytes <= 100);
    assert!(stats.evicted_total >= 1);
}
