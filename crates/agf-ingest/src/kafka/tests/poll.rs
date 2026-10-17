//! 拉取循环用例：单/多分区消费、tombstone、游标持久化、退避重连、优雅停机与去重计数。

use super::*;

#[tokio::test]
async fn poll_consumes_records_and_advances_offsets() {
    let source = Arc::new(FakeKafkaSource::with_partitions(1));
    source.append(0, SYSLOG_A);
    source.append(0, SYSLOG_B);
    source.append(0, SYSLOG_A);
    let stats = Arc::new(KafkaStats::new());
    let receiver =
        KafkaReceiver::new(Arc::clone(&source) as Arc<dyn KafkaSource>, config(None, 2)).with_stats(Arc::clone(&stats));
    let (pipeline, sink) = pipeline_and_sink();
    let log_source = log_source();

    let first = receiver.pull_once(&pipeline, &log_source, 10).await;
    assert!(first.is_ok(), "{first:?}");
    let Ok(first) = first else { return };
    assert_eq!(first.records, 2, "单分区单轮上限必须生效");
    assert_eq!(first.persisted, 2);
    assert_eq!(receiver.cursor_snapshot().offsets.get("agf-sec-logs/0").copied(), Some(2));

    let second = receiver.pull_once(&pipeline, &log_source, 10).await;
    assert_eq!(second.map(|r| r.records).unwrap_or(0), 1);
    assert_eq!(receiver.cursor_snapshot().offsets.get("agf-sec-logs/0").copied(), Some(3));
    let third = receiver.pull_once(&pipeline, &log_source, 10).await;
    assert_eq!(third.map(|r| r.records).unwrap_or(99), 0, "无新记录时不得重复消费");
    // 第 1 条与第 3 条内容相同 ⇒ 流水线去重后事件数为 2（保真层 3 条原始日志）
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(2));
    assert_eq!(sink.raw_count(TenantId::default_tenant()).await.ok(), Some(3), "原始日志全部保真");
    // offset / lag 指标：游标=3、高水位=3 ⇒ lag=0
    let snapshot = stats.snapshot();
    let state = snapshot.get("0");
    assert_eq!(state.map(|s| s.next_offset), Some(3));
    assert_eq!(state.map(|s| s.lag), Some(0));
    assert_eq!(state.map(|s| s.records_total), Some(3));
    assert_eq!(stats.lag_total(), 0);
    assert_eq!(stats.records_consumed_total(), 3);
}

#[tokio::test]
async fn poll_handles_multiple_partitions_and_fetch_failures() {
    let source = Arc::new(FakeKafkaSource::with_partitions(2));
    source.append(0, SYSLOG_A);
    source.append(1, SYSLOG_B);
    source.fail_fetch(1);
    let stats = Arc::new(KafkaStats::new());
    let receiver = KafkaReceiver::new(Arc::clone(&source) as Arc<dyn KafkaSource>, config(None, 10))
        .with_stats(Arc::clone(&stats));
    let (pipeline, _sink) = pipeline_and_sink();
    let report = receiver.pull_once(&pipeline, &log_source(), 10).await;
    assert!(report.is_ok(), "{report:?}");
    let Ok(report) = report else { return };
    assert_eq!(report.records, 1, "分区 0 正常消费");
    assert_eq!(report.failed_partitions, 1, "分区 1 失败必须计数");
    assert!(receiver.cursor_snapshot().offsets.contains_key("agf-sec-logs/0"));
    assert!(!receiver.cursor_snapshot().offsets.contains_key("agf-sec-logs/1"), "失败分区游标必须被丢弃以便自愈");
    assert!(receiver.counters().snapshot().received >= 1);
    let snapshot = stats.snapshot();
    assert_eq!(snapshot.get("1").map(|s| s.consecutive_failures), Some(1), "失败必须进分区状态");
    assert!(snapshot.get("1").and_then(|s| s.last_error.clone()).unwrap_or_default().contains("注入的拉取失败"));
}

#[tokio::test]
async fn multi_partition_cursors_are_independent_and_new_partitions_join() {
    let source = Arc::new(FakeKafkaSource::with_partitions(2));
    source.append(0, SYSLOG_A);
    source.append(1, SYSLOG_B);
    let receiver = KafkaReceiver::new(Arc::clone(&source) as Arc<dyn KafkaSource>, config(None, 10));
    let (pipeline, _sink) = pipeline_and_sink();
    let log = log_source();

    let first = receiver.pull_once(&pipeline, &log, 10).await;
    assert_eq!(first.map(|r| r.records).unwrap_or(0), 2, "两个分区都要消费");
    let cursor = receiver.cursor_snapshot();
    assert_eq!(cursor.offsets.get("agf-sec-logs/0").copied(), Some(1), "分区 0 独立游标");
    assert_eq!(cursor.offsets.get("agf-sec-logs/1").copied(), Some(1), "分区 1 独立游标");
    // 分区扩到 3 个：新分区必须被自动纳入（无游标 ⇒ 按 start_from 解析）
    source.add_partition(2);
    source.append(2, SYSLOG_A);
    let second = receiver.pull_once(&pipeline, &log, 10).await;
    assert_eq!(second.map(|r| r.records).unwrap_or(0), 1, "新增分区必须自动纳入");
    let cursor = receiver.cursor_snapshot();
    assert_eq!(cursor.offsets.len(), 3, "三分区三游标: {cursor:?}");
    assert_eq!(cursor.offsets.get("agf-sec-logs/2").copied(), Some(1));
    assert_eq!(
        receiver.stats().snapshot().keys().cloned().collect::<Vec<_>>(),
        vec!["0".to_string(), "1".to_string(), "2".to_string()],
        "每个分区都要有状态（/stats 逐分区）"
    );
}

#[tokio::test]
async fn tombstones_are_skipped_and_counted_not_dropped() {
    let source = Arc::new(FakeKafkaSource::with_partitions(1));
    source.append(0, SYSLOG_A);
    source.append_tombstone(0);
    source.append(0, SYSLOG_B);
    let stats = Arc::new(KafkaStats::new());
    let receiver = KafkaReceiver::new(Arc::clone(&source) as Arc<dyn KafkaSource>, config(None, 10))
        .with_stats(Arc::clone(&stats));
    let (pipeline, sink) = pipeline_and_sink();
    let report = receiver.pull_once(&pipeline, &log_source(), 10).await;
    assert_eq!(report.map(|r| r.skipped).unwrap_or(0), 1, "墓碑必须计数");
    assert_eq!(receiver.cursor_snapshot().offsets.get("agf-sec-logs/0").copied(), Some(3), "墓碑也要越过（否则卡住）");
    assert_eq!(stats.skipped_total(), 1);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(2), "墓碑不产生事件");
}

#[tokio::test]
async fn cursor_file_prevents_reconsumption_after_restart() {
    let dir = temp_dir("restart");
    let path = dir.join("cursor.json");
    let source = Arc::new(FakeKafkaSource::with_partitions(1));
    source.append(0, SYSLOG_A);
    let source_trait = Arc::clone(&source) as Arc<dyn KafkaSource>;
    let (pipeline, sink) = pipeline_and_sink();

    let first = KafkaReceiver::new(Arc::clone(&source_trait), config(Some(path.clone()), 10));
    assert_eq!(first.pull_once(&pipeline, &log_source(), 10).await.map(|r| r.records).unwrap_or(0), 1);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1));
    drop(first);

    let restarted = KafkaReceiver::new(source_trait, config(Some(path.clone()), 10));
    assert_eq!(restarted.cursor_snapshot().offsets.get("agf-sec-logs/0").copied(), Some(1), "游标必须恢复");
    assert_eq!(restarted.pull_once(&pipeline, &log_source(), 10).await.map(|r| r.records).unwrap_or(99), 0);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1), "重启后不得重复落库");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn start_from_latest_skips_history() {
    let source = Arc::new(FakeKafkaSource::with_partitions(1));
    source.append(0, SYSLOG_A);
    source.append(0, SYSLOG_B);
    let mut cfg = config(None, 10);
    cfg.start_from = KafkaStartFrom::Latest;
    let receiver = KafkaReceiver::new(Arc::clone(&source) as Arc<dyn KafkaSource>, cfg);
    let (pipeline, _sink) = pipeline_and_sink();
    let report = receiver.pull_once(&pipeline, &log_source(), 10).await;
    assert_eq!(report.map(|r| r.records).unwrap_or(99), 0, "latest 起点必须跳过已存在记录");
    source.append(0, SYSLOG_A);
    let after = receiver.pull_once(&pipeline, &log_source(), 10).await;
    assert_eq!(after.map(|r| r.records).unwrap_or(0), 1, "起点之后的新记录必须被消费");
}

#[tokio::test]
async fn graceful_shutdown_flushes_cursor_and_exits() {
    let dir = temp_dir("shutdown");
    let path = dir.join("cursor.json");
    let source = Arc::new(FakeKafkaSource::with_partitions(1));
    source.append(0, SYSLOG_A);
    let shutdown = KafkaShutdown::new();
    let receiver = Arc::new(
        KafkaReceiver::new(Arc::clone(&source) as Arc<dyn KafkaSource>, config(Some(path.clone()), 10))
            .with_shutdown(shutdown.handle()),
    );
    let (pipeline, _sink) = pipeline_and_sink();
    let running = Arc::clone(&receiver);
    let handle = tokio::spawn(async move { running.start(pipeline, log_source()).await });
    // 等首轮消费完成（游标 1）再触发停机
    tokio::time::sleep(Duration::from_millis(200)).await;
    shutdown.trigger();
    let joined = tokio::time::timeout(Duration::from_secs(5), handle).await;
    assert!(joined.is_ok(), "停机后必须及时退出（不得挂住）");
    assert!(matches!(joined, Ok(Ok(Ok(())))), "优雅停机必须返回 Ok");
    assert!(shutdown.triggered());
    let flushed = KafkaCursor::load(&path);
    assert_eq!(flushed.offsets.get("agf-sec-logs/0").copied(), Some(1), "停机前游标必须落盘: {flushed:?}");
    assert_eq!(receiver.cursor_snapshot().offsets.get("agf-sec-logs/0").copied(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn stop_flag_exits_loop_and_flushes() {
    let dir = temp_dir("stop");
    let path = dir.join("cursor.json");
    let source = Arc::new(FakeKafkaSource::with_partitions(1));
    source.append(0, SYSLOG_A);
    let receiver =
        Arc::new(KafkaReceiver::new(Arc::clone(&source) as Arc<dyn KafkaSource>, config(Some(path.clone()), 10)));
    let (pipeline, _sink) = pipeline_and_sink();
    let running = Arc::clone(&receiver);
    let handle = tokio::spawn(async move { running.start(pipeline, log_source()).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(receiver.stop().await.is_ok());
    let joined = tokio::time::timeout(Duration::from_secs(5), handle).await;
    assert!(matches!(joined, Ok(Ok(Ok(())))), "stop() 后必须优雅退出: {joined:?}");
    assert_eq!(KafkaCursor::load(&path).offsets.get("agf-sec-logs/0").copied(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn broker_outage_backs_off_with_cap_and_recovers() {
    let source = Arc::new(FakeKafkaSource::with_partitions(1));
    source.append(0, SYSLOG_A);
    let mut cfg = config(None, 10);
    cfg.reconnect_initial_ms = 20;
    cfg.reconnect_max_ms = 40;
    let shutdown = KafkaShutdown::new();
    let stats = Arc::new(KafkaStats::new());
    let receiver = Arc::new(
        KafkaReceiver::new(Arc::clone(&source) as Arc<dyn KafkaSource>, cfg)
            .with_shutdown(shutdown.handle())
            .with_stats(Arc::clone(&stats)),
    );
    source.set_broker_down(true);
    let (pipeline, sink) = pipeline_and_sink();
    let running = Arc::clone(&receiver);
    let handle = tokio::spawn(async move { running.start(pipeline, log_source()).await });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let reconnects = stats.reconnects_total();
    assert!(reconnects >= 3, "broker 不可达必须持续退避重试: {reconnects}");
    assert!(stats.reconnect_backoff() <= Duration::from_millis(40), "退避必须有上限: {:?}", stats.reconnect_backoff());
    assert!(reconnects < 100, "退避必须有实际等待，不能忙等刷日志: {reconnects}");
    // broker 恢复 ⇒ 自动续传，游标不丢
    source.set_broker_down(false);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1), "恢复后必须继续消费");
    assert_eq!(receiver.cursor_snapshot().offsets.get("agf-sec-logs/0").copied(), Some(1));
    shutdown.trigger();
    let joined = tokio::time::timeout(Duration::from_secs(5), handle).await;
    assert!(matches!(joined, Ok(Ok(Ok(())))), "停机必须优雅退出: {joined:?}");
}

#[tokio::test]
async fn reconnect_max_attempts_gives_up_with_error() {
    let source = Arc::new(FakeKafkaSource::with_partitions(1));
    let mut cfg = config(None, 10);
    cfg.reconnect_initial_ms = 20;
    cfg.reconnect_max_ms = 20;
    cfg.reconnect_max_attempts = 3;
    source.set_broker_down(true);
    let receiver = KafkaReceiver::new(Arc::clone(&source) as Arc<dyn KafkaSource>, cfg);
    let (pipeline, _sink) = pipeline_and_sink();
    let result = tokio::time::timeout(Duration::from_secs(5), receiver.start(pipeline, log_source())).await;
    assert!(matches!(result, Ok(Err(DomainError::DependencyUnavailable { .. }))), "达到上限必须如实报错: {result:?}");
}

#[tokio::test]
async fn deduped_replay_is_counted() {
    let dir = temp_dir("dedup");
    let path = dir.join("cursor.json");
    let source = Arc::new(FakeKafkaSource::with_partitions(1));
    source.append(0, SYSLOG_A);
    let stats = Arc::new(KafkaStats::new());
    let (pipeline, sink) = pipeline_and_sink();
    // 同一个日志源（source_id 是去重键的一部分：换源就不会被判重）
    let log = log_source();
    let first = KafkaReceiver::new(Arc::clone(&source) as Arc<dyn KafkaSource>, config(Some(path.clone()), 10))
        .with_stats(Arc::clone(&stats));
    assert_eq!(first.pull_once(&pipeline, &log, 10).await.map(|r| r.records).unwrap_or(0), 1);
    assert_eq!(stats.deduped_total(), 0);
    drop(first);
    // 模拟"崩溃后游标丢失 ⇒ 重放"：删掉游标文件后重启
    let _ = std::fs::remove_file(&path);
    let replayed = KafkaReceiver::new(Arc::clone(&source) as Arc<dyn KafkaSource>, config(Some(path), 10))
        .with_stats(Arc::clone(&stats));
    let report = replayed.pull_once(&pipeline, &log, 10).await;
    assert_eq!(report.map(|r| r.records).unwrap_or(0), 1, "重放会再次读到该记录");
    assert_eq!(stats.deduped_total(), 1, "重放必须体现为 deduped 计数（有效一次，不重复产生事件）");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn kop_style_config_tags_pulsar_protocol_and_origin() {
    // KoP 复用路径：协议标签 = pulsar、origin scheme = pulsar（其余取数逻辑完全复用）
    let source = Arc::new(FakeKafkaSource::with_partitions(1));
    source.append(0, SYSLOG_A);
    let mut cfg = config(None, 10);
    cfg.protocol = IngestProtocol::Pulsar;
    cfg.receiver_name = "pulsar".to_string();
    cfg.origin_scheme = "pulsar".to_string();
    cfg.namespace = Some("agf-prod".to_string());
    cfg.sasl = Some(KafkaSaslConfig::new(KafkaSaslMechanism::Plain, "token", "tok-SECRET-VALUE"));
    cfg.tls = Some(KafkaTlsConfig::default());
    assert_eq!(cfg.client_id(), "pulsar@agf-prod");
    let receiver = KafkaReceiver::new(Arc::clone(&source) as Arc<dyn KafkaSource>, cfg);
    assert_eq!(receiver.protocol(), IngestProtocol::Pulsar);
    let (pipeline, sink) = pipeline_and_sink();
    let report = receiver.pull_once(&pipeline, &log_source(), 10).await;
    assert_eq!(report.map(|r| r.records).unwrap_or(0), 1);
    let raws = sink.raws().unwrap_or_default();
    assert_eq!(raws.len(), 1);
    assert!(raws.first().map(|r| r.origin.starts_with("pulsar://")).unwrap_or(false), "{raws:?}");
    let descriptor = receiver.describe();
    assert_eq!(descriptor.name, "pulsar");
    assert!(descriptor.note.contains("SASL PLAIN user=token"), "{}", descriptor.note);
    assert!(!descriptor.note.contains("SECRET-VALUE"), "note 不得含口令: {}", descriptor.note);
}
