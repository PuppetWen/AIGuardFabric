//! 分区归属 / 租约用例：确定性分配、租约过期接管、sharded 游标移交与多副本不重叠。

use super::*;

/// 归属函数必须**确定性**、**无重叠**、**无遗漏**：任意存活集合下每个分区恰好一个 owner。
#[test]
fn partition_owner_is_deterministic_and_covers_every_partition_once() {
    let partitions: Vec<i32> = (0..8).collect();
    for live in [vec![0_u32], vec![0, 1], vec![0, 1, 2], vec![1, 3], vec![2, 0, 3]] {
        let mut live_sorted = live.clone();
        live_sorted.sort_unstable();
        let mut seen: BTreeMap<i32, u32> = BTreeMap::new();
        for partition in &partitions {
            let owner = partition_owner(*partition, &live_sorted).unwrap_or(99);
            assert!(live.contains(&owner), "owner 必须来自存活集合: p={partition} owner={owner} live={live:?}");
            assert!(seen.insert(*partition, owner).is_none(), "每个分区只能算一次");
        }
        // 两副本用同一 live 集合必须算出**同一个** owner（否则会重复消费）
        for partition in &partitions {
            assert_eq!(partition_owner(*partition, &live_sorted), partition_owner(*partition, &live_sorted));
        }
        // 交集覆盖：每个存活副本至少负责一个分区（8 分区 ≥ 副本数）
        let mut per_owner: BTreeMap<u32, usize> = BTreeMap::new();
        for owner in seen.values() {
            *per_owner.entry(*owner).or_insert(0) += 1;
        }
        assert_eq!(per_owner.len(), live_sorted.len(), "每个存活副本都必须分到分区: {per_owner:?}");
    }
    assert_eq!(partition_owner(3, &[]), None, "空存活集合 = 无主");
    assert_eq!(partition_owner(-1, &[0]), None, "负分区号非法");
    assert_eq!(normalize_live(vec![2, 0, 2, 0]), vec![0, 2], "存活集合必须去重升序");
}

/// 静态取模（无租约目录）：两个副本的分区集合**不重叠**，且并集 = 全部分区。
#[test]
fn static_assignment_is_disjoint_and_complete() {
    let all: Vec<i32> = (0..5).collect();
    let cfg0 = assignment_config(0, 2, None);
    let cfg1 = assignment_config(1, 2, None);
    assert!(cfg0.assignment_enabled() && !cfg0.lease_enabled(), "无租约目录 = 静态取模");
    let view0 = PartitionOwnership::compute(&cfg0, &all, &[], &[], false, &BTreeMap::new());
    let view1 = PartitionOwnership::compute(&cfg1, &all, &[], &[], false, &BTreeMap::new());
    assert_eq!(view0.owned_partitions, vec![0, 2, 4]);
    assert_eq!(view1.owned_partitions, vec![1, 3]);
    assert!(view0.owned_partitions.iter().all(|p| !view1.owns(*p)), "两个副本不得同时负责同一分区");
    assert!(view0.taken_over_partitions.is_empty(), "静态模式没有接管概念");
    // 单副本（未配置）必须与历史行为一致：消费全部分区
    let single = PartitionOwnership::compute(&config(None, 10), &all, &[], &[], false, &BTreeMap::new());
    assert!(!single.enabled, "未配置 = 单副本");
    assert_eq!(single.owned_partitions, all, "单副本消费全部分区");
    assert!(single.owns(4));
}

/// 租约接管：对端心跳过期 ⇒ 它的分区重分片到存活副本，且**只有**那些分区被记为接管。
#[test]
fn stale_lease_triggers_takeover_of_dead_instance_partitions() {
    let dir = temp_dir("lease-takeover");
    let namespace = "agf-ingest";
    let all: Vec<i32> = (0..3).collect();
    // 两个副本都活着：p0→0, p1→1, p2→0
    lease_write_heartbeat(&dir, namespace, 0).unwrap_or_else(|e| panic!("{e}"));
    lease_write_heartbeat(&dir, namespace, 1).unwrap_or_else(|e| panic!("{e}"));
    let cfg = assignment_config(0, 2, Some(dir.clone()));
    let (live, seen) = lease_live_instances(&dir, namespace, 2_000, 0);
    assert_eq!(live, vec![0, 1], "两个心跳都新鲜 ⇒ 都算存活: {seen:?}");
    let two_up = PartitionOwnership::compute(&cfg, &all, &live, &seen, false, &BTreeMap::new());
    assert!(two_up.leased, "配了租约目录 ⇒ leased");
    assert_eq!(two_up.owned_partitions, vec![0, 2]);
    assert_eq!(two_up.owner_of(1), Some(1), "p1 归副本 1");
    // 副本 1 心跳过期（> ttl）
    write_stale_heartbeat(&dir, namespace, 1, 10_000);
    let (live, seen) = lease_live_instances(&dir, namespace, 2_000, 0);
    assert_eq!(live, vec![0], "过期心跳不算存活（seen 仍记录它存在过）: {seen:?}");
    assert_eq!(seen, vec![0, 1]);
    let previous = two_up.owners.clone();
    let taken = PartitionOwnership::compute(&cfg, &all, &live, &seen, false, &previous);
    assert_eq!(taken.owned_partitions, vec![0, 1, 2], "死者的分区必须重分片到存活副本");
    assert_eq!(taken.taken_over_partitions, vec![1], "只有原属副本 1 的分区算接管");
    assert_eq!(taken.live_instances, vec![0]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// 租约目录不可写 ⇒ **降级为静态取模**（宁可不接管，也不冒重复消费的险）。
#[test]
fn unusable_lease_dir_degrades_to_static_assignment() {
    let dir = temp_dir("lease-degraded");
    // 用一个"文件"占住目录路径，制造 create_dir_all 失败
    let blocked = dir.join("not-a-dir");
    std::fs::write(&blocked, b"x").unwrap_or_else(|e| panic!("{e}"));
    let err = lease_write_heartbeat(&blocked, "agf-ingest", 0);
    assert!(err.is_err(), "路径被文件占用时写心跳必须失败: {err:?}");
    let all: Vec<i32> = (0..4).collect();
    let cfg = assignment_config(1, 2, Some(blocked));
    let view = PartitionOwnership::compute(&cfg, &all, &[], &[], true, &BTreeMap::new());
    assert!(view.degraded, "必须标记降级");
    assert!(!view.leased, "降级后不得声称租约生效");
    assert_eq!(view.owned_partitions, vec![1, 3], "降级 = 静态取模（不接管）");
    assert!(view.taken_over_partitions.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// 接管后**不丢**：新 owner 从原 owner 落盘的分片游标继续（`latest` 起点也不会丢消息）。
#[test]
fn sharded_cursor_hands_offsets_over_to_the_taking_instance() {
    let dir = temp_dir("shard-handover");
    let namespace = "agf-ingest";
    let cfg = assignment_config(0, 2, Some(dir.clone()));
    let prefix = cfg.cursor_shard_prefix();
    assert_eq!(prefix, "cursor-agf-ingest-agf-sec-logs-p");
    assert_eq!(cfg.cursor_path_for(1), Some(dir.join("cursor-agf-ingest-agf-sec-logs-p1.json")));
    // 副本 1 消费到 p1 offset=7 后落盘，然后死掉
    let producer = KafkaCursor { version: 1, namespace: Some(namespace.to_string()), offsets: BTreeMap::new() };
    producer.save_shard(&dir, &prefix, "agf-sec-logs", 1, 7).unwrap_or_else(|e| panic!("分片游标落盘失败: {e}"));
    // 副本 0 接管：从目录合并加载，p1 的进度**必须**在
    let taken = KafkaCursor::load_sharded(&dir, &prefix);
    assert_eq!(taken.offsets.get("agf-sec-logs/1").copied(), Some(7), "接管必须继承原 owner 的落盘进度");
    assert_eq!(taken.namespace.as_deref(), Some(namespace));
    // 分区分片互不干扰：另一个分区写自己的文件不会覆盖 p1
    producer.save_shard(&dir, &prefix, "agf-sec-logs", 0, 3).unwrap_or_else(|e| panic!("{e}"));
    let merged = KafkaCursor::load_sharded(&dir, &prefix);
    assert_eq!(merged.offsets.get("agf-sec-logs/1").copied(), Some(7));
    assert_eq!(merged.offsets.get("agf-sec-logs/0").copied(), Some(3));
    assert_eq!(cursor_partition_of("agf-sec-logs/12", "agf-sec-logs"), Some(12));
    assert_eq!(cursor_partition_of("other/1", "agf-sec-logs"), None, "别的 topic 的键不得被误认");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `/stats` 与 `/metrics` 必须能看出"每个副本负责哪些分区"。
#[test]
fn ownership_is_visible_in_stats_and_metrics() {
    let stats = Arc::new(KafkaStats::new());
    let all: Vec<i32> = (0..3).collect();
    let cfg = assignment_config(0, 2, None);
    let owned = PartitionOwnership::compute(&cfg, &all, &[0, 1], &[0, 1], false, &BTreeMap::new());
    assert_eq!(owned.owned_partitions, vec![0, 2]);
    stats.record_batch(0, 5, 9, 5);
    stats.set_ownership(owned.clone());
    let snapshot = stats.snapshot();
    assert_eq!(snapshot.len(), 3, "全部分区都要出现在 /stats（含不由本副本负责的）");
    let p0 = snapshot.get("0").unwrap_or_else(|| panic!("缺少 p0: {snapshot:?}"));
    assert!(p0.owned && p0.lag == 4, "自有分区: {p0:?}");
    assert_eq!(p0.owner_instance, 0);
    let p1 = snapshot.get("1").unwrap_or_else(|| panic!("缺少 p1: {snapshot:?}"));
    assert!(!p1.owned, "p1 归副本 1");
    assert_eq!(p1.owner_instance, 1);
    assert_eq!((p1.next_offset, p1.lag), (-1, -1), "-1 = 未知（不由本副本负责），不是负滞后");
    assert_eq!(stats.lag_total(), 4, "lag_total 只累加本副本负责的分区");
    let text = kafka_prometheus(&[KafkaSeries {
        receiver: "pulsar".to_string(),
        topic: "agf-sec-logs".to_string(),
        stats: Arc::clone(&stats),
    }]);
    assert!(
            text.contains("agf_ingest_kafka_partition_owned{receiver=\"pulsar\",topic=\"agf-sec-logs\",partition=\"1\",owner_instance=\"1\"} 0"),
            "{text}"
        );
    assert!(
            text.contains("agf_ingest_kafka_partition_owned{receiver=\"pulsar\",topic=\"agf-sec-logs\",partition=\"2\",owner_instance=\"0\"} 1"),
            "{text}"
        );
    assert!(
        text.contains("instance_id=\"0\",instance_count=\"2\",live_instances=\"0,1\",leased=\"0\",degraded=\"0\""),
        "{text}"
    );
    assert!(
        text.contains(
            "agf_ingest_kafka_partition_takeovers_total{receiver=\"pulsar\",topic=\"agf-sec-logs\",partition=\"0\"} 0"
        ),
        "{text}"
    );
    // 接管后计数必须 +1（p1：原属副本 1）——接管只在**租约模式**下发生
    let lease_dir = temp_dir("metrics-lease");
    let leased = assignment_config(0, 2, Some(lease_dir.clone()));
    let after = PartitionOwnership::compute(&leased, &all, &[0], &[0, 1], false, &owned.owners);
    assert_eq!(after.taken_over_partitions, vec![1]);
    assert!(after.leased && !after.degraded);
    stats.set_ownership(after);
    assert_eq!(stats.takeover_snapshot().get(&1).copied(), Some(1));
    let text = kafka_prometheus(&[KafkaSeries {
        receiver: "pulsar".to_string(),
        topic: "agf-sec-logs".to_string(),
        stats: Arc::clone(&stats),
    }]);
    assert!(
        text.contains(
            "agf_ingest_kafka_partition_takeovers_total{receiver=\"pulsar\",topic=\"agf-sec-logs\",partition=\"1\"} 1"
        ),
        "{text}"
    );
    assert!(text.contains("live_instances=\"0\",leased=\"1\""), "{text}");
    let _ = std::fs::remove_dir_all(&lease_dir);
}

/// 未启用多副本分配时，`/stats`/`/metrics` 必须仍然是"单副本消费全部分区"（不能出现 owned=0）。
#[test]
fn single_replica_renders_every_partition_as_owned() {
    let stats = Arc::new(KafkaStats::new());
    stats.record_batch(0, 1, 2, 1);
    stats.record_batch(1, 1, 1, 1);
    let snapshot = stats.snapshot();
    assert!(snapshot.values().all(|state| state.owned), "{snapshot:?}");
    assert_eq!(stats.lag_total(), 1, "单副本 lag 仍按全分区累加");
    let text = kafka_prometheus(&[KafkaSeries {
        receiver: "kafka".to_string(),
        topic: "t".to_string(),
        stats: Arc::clone(&stats),
    }]);
    assert!(text.contains("instance_id=\"0\",instance_count=\"1\",live_instances=\"0\""), "{text}");
}

/// 多副本分配贯穿到真实消费路径：两个接收器各自只取自己负责的分区（游标不交叉）。
#[tokio::test]
async fn multi_replica_consumers_do_not_overlap_partitions() {
    let source = Arc::new(FakeKafkaSource::with_partitions(4));
    for partition in 0..4 {
        source.append(partition, SYSLOG_A);
    }
    let source_trait = Arc::clone(&source) as Arc<dyn KafkaSource>;
    let dir = temp_dir("multi-replica");
    let first = KafkaReceiver::new(Arc::clone(&source_trait), assignment_config(0, 2, None))
        .with_stats(Arc::new(KafkaStats::new()));
    let second =
        KafkaReceiver::new(source_trait, assignment_config(1, 2, None)).with_stats(Arc::new(KafkaStats::new()));
    let (pipeline, _sink) = pipeline_and_sink();
    let a = first.pull_once(&pipeline, &log_source(), 10).await;
    let b = second.pull_once(&pipeline, &log_source(), 10).await;
    assert_eq!(a.map(|r| r.records).unwrap_or(0), 2, "副本 0 只消费 p0/p2");
    assert_eq!(b.map(|r| r.records).unwrap_or(0), 2, "副本 1 只消费 p1/p3");
    let a_cursor: Vec<String> = first.cursor_snapshot().offsets.keys().cloned().collect();
    let b_cursor: Vec<String> = second.cursor_snapshot().offsets.keys().cloned().collect();
    assert_eq!(a_cursor, vec!["agf-sec-logs/0".to_string(), "agf-sec-logs/2".to_string()]);
    assert_eq!(b_cursor, vec!["agf-sec-logs/1".to_string(), "agf-sec-logs/3".to_string()]);
    assert!(
        first.stats().snapshot().get("1").is_some_and(|state| !state.owned && state.owner_instance == 1),
        "副本 0 的 /stats 必须显示 p1 归副本 1"
    );
    assert!(first.stats().snapshot().get("0").is_some_and(|state| state.owned));
    assert!(first.describe().note.contains("实例 0/2"), "{}", first.describe().note);
    assert!(first.describe_assignment().contains("静态取模"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// 租约接管走完真实消费路径：一个副本死后，另一副本接管其分区**并从落盘游标继续**。
#[tokio::test]
async fn lease_takeover_resumes_from_handed_over_cursor() {
    let dir = temp_dir("lease-e2e");
    let source = Arc::new(FakeKafkaSource::with_partitions(2));
    source.append(0, SYSLOG_A);
    source.append(1, SYSLOG_B);
    let source_trait = Arc::clone(&source) as Arc<dyn KafkaSource>;
    let cfg0 = KafkaPullConfig {
        instance_id: Some(0),
        instance_count: 2,
        lease_dir: Some(dir.clone()),
        lease_ttl_ms: 1_000,
        assign_settle_ms: 0,
        interval_secs: 1,
        ..config(None, 10)
    };
    let cfg1 = KafkaPullConfig { instance_id: Some(1), ..cfg0.clone() };
    let first = KafkaReceiver::new(Arc::clone(&source_trait), cfg0);
    let second = KafkaReceiver::new(source_trait, cfg1);
    let (pipeline, sink) = pipeline_and_sink();
    let log = log_source();
    // 两个副本**都已在运行**（心跳都新鲜）：p0 归 0、p1 归 1
    lease_write_heartbeat(&dir, "agf-ingest", 0).unwrap_or_else(|e| panic!("{e}"));
    lease_write_heartbeat(&dir, "agf-ingest", 1).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(first.pull_once(&pipeline, &log, 10).await.map(|r| r.records).unwrap_or(99), 1);
    assert_eq!(second.pull_once(&pipeline, &log, 10).await.map(|r| r.records).unwrap_or(99), 1);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(2));
    assert_eq!(first.cursor_snapshot().offsets.get("agf-sec-logs/1").copied(), None, "副本 0 不得消费 p1");
    // 副本 1 死掉（心跳过期）→ 副本 0 接管 p1，并从副本 1 落盘的分片游标继续（offset=1 ⇒ 无新记录）
    write_stale_heartbeat(&dir, "agf-ingest", 1, 10_000);
    let takeover = first.pull_once(&pipeline, &log, 10).await;
    assert_eq!(takeover.map(|r| r.records).unwrap_or(99), 0, "p1 已消费到 1，接管后不得重放");
    assert_eq!(first.cursor_snapshot().offsets.get("agf-sec-logs/1").copied(), Some(1), "接管继承落盘游标");
    assert_eq!(first.stats().takeover_snapshot().get(&1).copied(), Some(1), "接管必须计数");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(2), "接管不得重复落库");
    // 接管后新增消息必须被消费（接管不是"死锁"）
    source.append(1, SYSLOG_C);
    assert_eq!(first.pull_once(&pipeline, &log, 10).await.map(|r| r.records).unwrap_or(0), 1);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(3));
    let _ = std::fs::remove_dir_all(&dir);
}

/// 新副本**加入**触发重分片：先到的副本让出分区，让出后不得重复消费（分片游标交接）。
/// 启动静默期：**不认领任何分区**（否则"先启动的副本端走全部分区"会与同伴重叠）。
#[tokio::test]
async fn settle_window_defers_claims_until_peers_are_visible() {
    let dir = temp_dir("settle");
    let source = Arc::new(FakeKafkaSource::with_partitions(3));
    for partition in 0..3 {
        source.append(partition, SYSLOG_A);
    }
    let source_trait = Arc::clone(&source) as Arc<dyn KafkaSource>;
    // 静默期 10s：本轮一定还在静默期内
    let cfg = KafkaPullConfig {
        instance_id: Some(0),
        instance_count: 2,
        lease_dir: Some(dir.clone()),
        lease_ttl_ms: 2_000,
        assign_settle_ms: 10_000,
        interval_secs: 1,
        ..config(None, 10)
    };
    let receiver = KafkaReceiver::new(source_trait, cfg);
    let (pipeline, sink) = pipeline_and_sink();
    let report = receiver.pull_once(&pipeline, &log_source(), 10).await;
    assert_eq!(report.map(|r| r.records).unwrap_or(99), 0, "静默期内不得消费任何记录");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(0));
    let view = receiver.stats().ownership().unwrap_or_else(|| panic!("必须有分配决策"));
    assert!(view.settling, "必须标记静默期");
    assert!(view.owned_partitions.is_empty(), "静默期内不得认领分区: {view:?}");
    assert_eq!(view.partitions, vec![0, 1, 2], "topic 分区仍然要如实报告");
    assert!(!view.owners.is_empty(), "归属仍要可观测（排障用）");
    assert!(receiver.cursor_snapshot().offsets.is_empty(), "静默期不得推进游标");
    // /metrics 必须暴露 settling=1（运维看得见"为什么还没消费"）
    let text = kafka_prometheus(&[KafkaSeries {
        receiver: "pulsar".to_string(),
        topic: "agf-sec-logs".to_string(),
        stats: Arc::clone(receiver.stats()),
    }]);
    assert!(text.contains("settling=\"1\""), "{text}");
    // 心跳必须已经写出（静默期内也要让同伴看见自己）
    assert!(lease_path(&dir, "agf-ingest", 0).exists(), "静默期必须照样写心跳");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn lease_join_rebalances_without_double_consumption() {
    let dir = temp_dir("lease-join");
    let source = Arc::new(FakeKafkaSource::with_partitions(2));
    source.append(0, SYSLOG_A);
    source.append(1, SYSLOG_B);
    let source_trait = Arc::clone(&source) as Arc<dyn KafkaSource>;
    let cfg = KafkaPullConfig {
        instance_id: Some(0),
        instance_count: 2,
        lease_dir: Some(dir.clone()),
        lease_ttl_ms: 5_000,
        assign_settle_ms: 0,
        interval_secs: 1,
        ..config(None, 10)
    };
    let first = KafkaReceiver::new(Arc::clone(&source_trait), cfg.clone());
    let (pipeline, sink) = pipeline_and_sink();
    let log = log_source();
    // 只有副本 0 在跑 ⇒ 它负责**全部分区**（不会留下无主分区）
    assert_eq!(first.pull_once(&pipeline, &log, 10).await.map(|r| r.records).unwrap_or(0), 2);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(2));
    assert_eq!(first.stats().ownership().map(|view| view.owned_partitions), Some(vec![0, 1]));
    // 副本 1 加入（心跳出现）⇒ 下一轮重分片：p0 归 0、p1 归 1
    lease_write_heartbeat(&dir, "agf-ingest", 1).unwrap_or_else(|e| panic!("{e}"));
    let second = KafkaReceiver::new(source_trait, KafkaPullConfig { instance_id: Some(1), ..cfg });
    assert_eq!(first.pull_once(&pipeline, &log, 10).await.map(|r| r.records).unwrap_or(0), 0);
    assert_eq!(first.stats().ownership().map(|view| view.owned_partitions), Some(vec![0]));
    assert_eq!(
        second.pull_once(&pipeline, &log, 10).await.map(|r| r.records).unwrap_or(99),
        0,
        "p1 已由副本 0 消费并落盘，交接后不得重放"
    );
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(2), "重分片不得重复落库");
    // 新副本接手后的新消息必须落到它身上（证明重分片不是"停摆"）
    source.append(1, SYSLOG_C);
    assert_eq!(second.pull_once(&pipeline, &log, 10).await.map(|r| r.records).unwrap_or(0), 1);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(3));
    let _ = std::fs::remove_dir_all(&dir);
}
