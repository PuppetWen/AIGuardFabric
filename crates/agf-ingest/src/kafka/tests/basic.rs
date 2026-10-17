//! 基础语义用例：解析、配置校验、SASL/TLS、游标往返、指标渲染与能力描述。

use super::*;

#[test]
fn partition_probe_range_is_bounded() {
    assert_eq!(partition_probe_range(64).count(), 64);
    assert_eq!(partition_probe_range(3).collect::<Vec<i32>>(), vec![0, 1, 2]);
    assert_eq!(partition_probe_range(0).count(), 1, "至少探测分区 0");
    assert_eq!(partition_probe_range(-5).count(), 1);
    assert_eq!(partition_probe_range(i32::MAX).count(), 1024, "探测上限必须有界（避免打爆 broker）");
}

#[test]
fn broker_and_start_from_parsing() {
    assert_eq!(parse_brokers("a:9092, b:9092").ok(), Some(vec!["a:9092".to_string(), "b:9092".to_string()]));
    assert!(matches!(parse_brokers("  "), Err(DomainError::Config(_))));
    assert!(matches!(parse_brokers("a"), Err(DomainError::Config(_))), "缺端口必须报错");
    assert_eq!(KafkaStartFrom::parse("LATEST"), Some(KafkaStartFrom::Latest));
    assert_eq!(KafkaStartFrom::parse("earliest"), Some(KafkaStartFrom::Earliest));
    assert_eq!(KafkaStartFrom::parse("bogus"), None);
    assert_eq!(KafkaStartFrom::default().as_str(), "earliest");
    assert_eq!(KafkaCursor::key("t", 3), "t/3");
}

#[test]
fn config_from_source_validates() {
    let mut source = log_source();
    assert!(KafkaPullConfig::from_source(&source).is_err(), "缺 broker 必须报错");
    source.connection.endpoint = Some("kafka-1:9092,kafka-2:9092".to_string());
    assert!(KafkaPullConfig::from_source(&source).is_err(), "缺 topic 必须报错");
    source.connection.topic = Some("sec-logs".to_string());
    source.connection.headers.insert("group.id".to_string(), "agf-prod".to_string());
    let config = KafkaPullConfig::from_source(&source);
    assert!(config.is_ok(), "{config:?}");
    let Ok(config) = config else { return };
    assert_eq!(config.brokers.len(), 2);
    assert_eq!(config.topic, "sec-logs");
    assert_eq!(config.consumer_id, "agf-prod");
    assert_eq!(config.protocol, IngestProtocol::Kafka);
    assert_eq!(config.receiver_name, "kafka");
    assert!(config.sasl.is_none(), "默认不启用 SASL");
    assert!(config.tls.is_none(), "默认不启用 TLS");
    assert_eq!(config.client_id(), "kafka@agf-prod");
}

#[test]
fn sasl_mechanism_parsing_and_redaction() {
    assert_eq!(KafkaSaslMechanism::parse("plain"), Some(KafkaSaslMechanism::Plain));
    assert_eq!(KafkaSaslMechanism::parse("SCRAM-SHA-256"), Some(KafkaSaslMechanism::ScramSha256));
    assert_eq!(KafkaSaslMechanism::parse("scram_sha_512"), Some(KafkaSaslMechanism::ScramSha512));
    assert_eq!(KafkaSaslMechanism::parse("GSSAPI"), None);
    assert_eq!(KafkaSaslMechanism::ScramSha512.as_str(), "SCRAM-SHA-512");

    let sasl = KafkaSaslConfig::new(KafkaSaslMechanism::Plain, "token", "eyJhbGciOiJSUPER-SECRET");
    // Debug / redacted / describe 三处都不得出现明文口令
    let debug = format!("{sasl:?}");
    assert!(!debug.contains("SUPER-SECRET"), "Debug 泄漏口令: {debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
    let security = KafkaSecurity { sasl: Some(sasl.clone()), tls: None };
    let described = security.describe();
    assert!(!described.contains("SUPER-SECRET"), "describe 泄漏口令: {described}");
    assert!(described.contains("SASL PLAIN user=token"), "{described}");
    // 序列化配置也必须跳过 SASL（凭据不落任何序列化产物）
    let config = KafkaPullConfig { sasl: Some(sasl.clone()), ..config(None, 10) };
    let json = serde_json::to_string(&config).unwrap_or_default();
    assert!(!json.contains("SUPER-SECRET"), "序列化泄漏口令: {json}");
    assert!(!json.contains("sasl"), "SASL 字段必须整体跳过序列化: {json}");
    // 明文只在 to_rskafka 出口存在
    assert_eq!(sasl.password(), "eyJhbGciOiJSUPER-SECRET");
    assert_eq!(sasl.mechanism, KafkaSaslMechanism::Plain);
}

#[test]
fn tls_config_builds_trust_store_and_reports_insecure() {
    // 默认：不启用 TLS
    let config = KafkaPullConfig::default();
    assert!(config.tls.is_none());
    assert_eq!(KafkaSecurity::from_config(&config).describe(), "SASL 关闭；TLS 关闭");

    // 仅校验链（无 CA）：用 webpki 公共根
    let verified = KafkaTlsConfig::default();
    assert!(verified.build_client_config().is_ok());
    assert!(verified.describe().contains("证书链校验开启"));

    // 注入自签 CA（rcgen 生成本地 PEM，不落私钥）
    let dir = temp_dir("tls");
    let ca_path = dir.join("ca.pem");
    let ca_pem = self_signed_ca_pem();
    assert!(ca_pem.contains("BEGIN CERTIFICATE"), "rcgen 必须产出 PEM: {ca_pem}");
    assert!(std::fs::write(&ca_path, &ca_pem).is_ok());
    let with_ca = KafkaTlsConfig { ca_pem: Some(ca_path.clone()), ..KafkaTlsConfig::default() };
    assert!(with_ca.build_client_config().is_ok(), "{with_ca:?}");
    assert!(with_ca.describe().contains("ca="));
    // 非法 CA 必须报错（而不是静默接受）
    let broken = KafkaTlsConfig { ca_pem: Some(dir.join("missing.pem")), ..KafkaTlsConfig::default() };
    assert!(broken.build_client_config().is_err());
    // 客户端证书与私钥必须成对
    let half = KafkaTlsConfig { client_cert_pem: Some(ca_path), ..KafkaTlsConfig::default() };
    assert!(half.build_client_config().is_err());

    // 显式跳过校验：仅在该开关下装配，且描述里必须如实标注
    let insecure = KafkaTlsConfig { insecure_skip_verify: true, ..KafkaTlsConfig::default() };
    assert!(insecure.build_client_config().is_ok());
    assert!(insecure.describe().contains("校验已关闭"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cursor_roundtrips_and_survives_corruption() {
    let dir = temp_dir("cursor");
    let path = dir.join("cursor.json");
    let mut cursor = KafkaCursor { version: 1, namespace: Some("agf-prod".to_string()), offsets: BTreeMap::new() };
    cursor.offsets.insert(KafkaCursor::key("t", 0), 42);
    assert!(cursor.save(&path).is_ok());
    let loaded = KafkaCursor::load(&path);
    assert_eq!(loaded.offsets.get("t/0").copied(), Some(42));
    assert_eq!(loaded.namespace.as_deref(), Some("agf-prod"), "命名空间随游标落盘");
    assert!(std::fs::write(&path, b"[[[").is_ok());
    assert!(KafkaCursor::load(&path).offsets.is_empty(), "损坏文件必须降级为空游标");
    assert!(KafkaCursor::load(&dir.join("none.json")).offsets.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
#[test]
fn kafka_prometheus_renders_offset_lag_and_failures() {
    let stats = Arc::new(KafkaStats::new());
    stats.record_batch(0, 42, 50, 3);
    stats.record_batch(1, 7, 7, 0);
    stats.record_failure(1, "注入的拉取失败\n带控制字符");
    stats.record_reconnect(Duration::from_millis(1500));
    stats.add_deduped(2);
    stats.add_skipped(1);
    let text = kafka_prometheus(&[KafkaSeries {
        receiver: "kafka".to_string(),
        topic: "agf-sec-logs".to_string(),
        stats: Arc::clone(&stats),
    }]);
    assert!(text.contains("# TYPE agf_ingest_kafka_offset gauge"), "{text}");
    assert!(
        text.contains("agf_ingest_kafka_offset{receiver=\"kafka\",topic=\"agf-sec-logs\",partition=\"0\"} 42"),
        "{text}"
    );
    assert!(
        text.contains("agf_ingest_kafka_lag{receiver=\"kafka\",topic=\"agf-sec-logs\",partition=\"0\"} 8"),
        "{text}"
    );
    assert!(
        text.contains("agf_ingest_kafka_lag{receiver=\"kafka\",topic=\"agf-sec-logs\",partition=\"1\"} 0"),
        "{text}"
    );
    assert!(
        text.contains(
            "agf_ingest_kafka_fetch_failures_total{receiver=\"kafka\",topic=\"agf-sec-logs\",partition=\"1\"} 1"
        ),
        "{text}"
    );
    assert!(text.contains("agf_ingest_kafka_reconnects_total{receiver=\"kafka\",topic=\"agf-sec-logs\"} 1"), "{text}");
    assert!(
        text.contains("agf_ingest_kafka_reconnect_backoff_seconds{receiver=\"kafka\",topic=\"agf-sec-logs\"} 1.5"),
        "{text}"
    );
    assert!(text.contains("agf_ingest_kafka_deduped_total{receiver=\"kafka\",topic=\"agf-sec-logs\"} 2"), "{text}");
    assert!(
        text.contains("agf_ingest_kafka_skipped_records_total{receiver=\"kafka\",topic=\"agf-sec-logs\"} 1"),
        "{text}"
    );
    // 每族 HELP/TYPE 只出现一次（多接收器聚合时不重复）
    assert_eq!(text.matches("# TYPE agf_ingest_kafka_offset gauge").count(), 1, "{text}");
    // 失败原因里的控制字符必须被过滤、超长必须截断（/stats 的分区状态同样走 sanitize_error）
    assert!(!sanitize_error("a\nb").contains('\n'), "控制字符必须被过滤");
    assert_eq!(sanitize_error(&"x".repeat(500)).chars().count(), 200, "错误文本必须截断");
}

#[test]
fn describe_reports_ready_with_honest_todo() {
    let source = Arc::new(FakeKafkaSource::with_partitions(1));
    let receiver = KafkaReceiver::new(Arc::clone(&source) as Arc<dyn KafkaSource>, config(None, 10));
    let descriptor = receiver.describe();
    assert_eq!(descriptor.status, ReceiverStatus::Ready);
    assert_eq!(descriptor.protocol, IngestProtocol::Kafka);
    assert!(descriptor.note.contains("rskafka"), "{}", descriptor.note);
    assert!(descriptor.note.contains("全部分区各自独立游标"), "{}", descriptor.note);
    assert!(descriptor.note.contains("至少一次"), "{}", descriptor.note);
    // 本地游标源（FakeKafkaSource）不覆写 commits_to_broker ⇒ 必须是"本地游标"口径
    assert!(!source.commits_to_broker(), "默认数据源必须走本地游标，不得声称提交到 broker");
    assert!(descriptor.note.contains("本地游标"), "{}", descriptor.note);
    // 组协议已实现，剩下的 TODO 是 OAuthbearer 与组路径的 SCRAM
    let todo = descriptor.todo.unwrap_or_default();
    assert!(todo.contains("TODO ingest-kafka-oauthbearer"), "{todo}");
    assert!(todo.contains("TODO ingest-kafka-group-scram"), "{todo}");
    assert_eq!(receiver.protocol(), IngestProtocol::Kafka);
    assert_eq!(receiver.config().topic, "agf-sec-logs");
}

#[test]
fn reconnect_bounds_never_invert() {
    let cfg = KafkaPullConfig { reconnect_initial_ms: 500, reconnect_max_ms: 100, ..KafkaPullConfig::default() };
    let (initial, max) = cfg.reconnect_bounds();
    assert!(initial <= max, "上限不得小于初始: {initial:?} {max:?}");
    let cfg = KafkaPullConfig { reconnect_initial_ms: 0, reconnect_max_ms: 0, ..KafkaPullConfig::default() };
    let (initial, max) = cfg.reconnect_bounds();
    assert!(initial >= Duration::from_millis(20), "退避不得为 0（忙等）: {initial:?}");
    assert!(max >= initial);
}

// -----------------------------------------------------------------------
// 多副本分区分配（无消费者组时的并行消费语义）
// -----------------------------------------------------------------------
