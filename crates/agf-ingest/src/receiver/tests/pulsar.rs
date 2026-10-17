//! Pulsar（KoP 复用）与能力矩阵/装配态用例：复用 Kafka 内核、未配置即如实 NotReady、`NotWired` 绝不报 `Ready`。

use super::*;

/// Pulsar 的 KoP 路径：**经 KoP 复用 Kafka 接收器**，协议标签 = `pulsar`，
/// 配置映射（topic/subscription/token/TLS）如实落地，且凭据不进描述文本。
#[test]
fn pulsar_receiver_maps_kop_config_and_reuses_kafka() {
    let mut source = log_source(IngestProtocol::Pulsar);
    source.connection.endpoint = Some("kafka://kop-1:9092".to_string());
    source.connection.topic = Some("persistent://public/default/sec-logs".to_string());
    source.connection.headers.insert("subscription".to_string(), "agf-prod".to_string());
    source.connection.headers.insert("token".to_string(), "eyJhbGciOiJSUPER-SECRET".to_string());
    source.connection.headers.insert("tls".to_string(), "1".to_string());
    source.connection.headers.insert("tenant.namespace".to_string(), "public/default".to_string());
    let pulsar = PulsarReceiver::from_source(&source);
    assert!(pulsar.is_ok(), "{pulsar:?}");
    let Ok(pulsar) = pulsar else { return };
    assert!(pulsar.kop_enabled(), "配置了 KoP 地址即启用");
    assert_eq!(pulsar.service_url.as_deref(), Some("kafka://kop-1:9092"));
    assert_eq!(pulsar.topic, "sec-logs", "Kafka 侧 topic 名取 Pulsar topic 末段");
    assert_eq!(pulsar.subscription, "agf-prod");
    assert_eq!(pulsar.tenant_namespace.as_deref(), Some("public/default"));
    assert_eq!(pulsar.protocol(), IngestProtocol::Pulsar);
    let config = pulsar.config.as_ref();
    assert_eq!(config.map(|c| c.brokers.clone()), Some(vec!["kop-1:9092".to_string()]));
    assert_eq!(config.map(|c| c.namespace.clone()), Some(Some("agf-prod".to_string())));
    assert_eq!(config.map(|c| c.protocol), Some(IngestProtocol::Pulsar));
    assert_eq!(config.map(|c| c.origin_scheme.clone()), Some("pulsar".to_string()));
    // KoP 鉴权：SASL/PLAIN + username=token（Pulsar 官方 KoP 鉴权方式）
    let sasl = config.and_then(|c| c.sasl.clone());
    assert_eq!(sasl.as_ref().map(|s| s.mechanism), Some(KafkaSaslMechanism::Plain));
    assert_eq!(sasl.as_ref().map(|s| s.username.clone()), Some("token".to_string()));
    assert_eq!(
        sasl.as_ref().map(|s| s.password().to_string()),
        Some("token:eyJhbGciOiJSUPER-SECRET".to_string()),
        "KoP PLAIN 的 password 必须是 <authMethod>:<authData>（实测）"
    );
    assert!(config.and_then(|c| c.tls.as_ref()).is_some(), "AGF_INGEST_PULSAR_TLS=1 必须启用 TLS");
    assert!(!config.and_then(|c| c.tls.as_ref()).map(|t| t.insecure_skip_verify).unwrap_or(true));

    let descriptor = pulsar.describe();
    assert_eq!(descriptor.status, ReceiverStatus::Ready);
    assert!(!descriptor.mock_replay, "KoP 路径是真实取数通道，不是 Mock 回放");
    assert!(descriptor.note.contains("经 KoP（Kafka on Pulsar）复用 Kafka 接收器"), "{}", descriptor.note);
    assert!(descriptor.note.contains("Pulsar 原生协议未实现"), "{}", descriptor.note);
    assert!(!descriptor.note.contains("SUPER-SECRET"), "描述不得含 token: {}", descriptor.note);
    let todo = descriptor.todo.unwrap_or_default();
    assert!(todo.contains("TODO ingest-pulsar-native"), "{todo}");
    assert!(todo.contains("经 KoP"), "{todo}");

    // 缺 topic 必须报错；指向原生端口必须报错（不静默降级）
    let mut broken = log_source(IngestProtocol::Pulsar);
    broken.connection.endpoint = Some("kafka://kop:9092".to_string());
    assert!(PulsarReceiver::from_source(&broken).is_err());
    let mut native = log_source(IngestProtocol::Pulsar);
    native.connection.endpoint = Some("pulsar://pulsar-1:6650".to_string());
    native.connection.topic = Some("t".to_string());
    assert!(PulsarReceiver::from_source(&native).is_err(), "原生协议端口必须显式拒绝");
    // non-persistent topic 经 KoP 不支持
    let mut non_persistent = log_source(IngestProtocol::Pulsar);
    non_persistent.connection.endpoint = Some("kafka://kop:9092".to_string());
    non_persistent.connection.topic = Some("non-persistent://public/default/t".to_string());
    assert!(PulsarReceiver::from_source(&non_persistent).is_err());
}

/// 未配置 KoP 地址：**不假装 ready**（not-implemented + Mock 回放），
/// 若只配了原生地址则能力矩阵同样显示未启用。
#[test]
fn pulsar_without_kop_is_honestly_not_ready() {
    let mut source = log_source(IngestProtocol::Pulsar);
    source.connection.topic = Some("persistent://public/default/sec-logs".to_string());
    let pulsar = PulsarReceiver::from_source(&source);
    assert!(pulsar.is_ok(), "{pulsar:?}");
    let Ok(pulsar) = pulsar else { return };
    assert!(!pulsar.kop_enabled());
    let descriptor = pulsar.describe();
    assert_eq!(descriptor.status, ReceiverStatus::NotImplemented, "未配置 KoP 不得显示 ready");
    assert!(descriptor.mock_replay);
    assert!(descriptor.note.contains("未启用"), "{}", descriptor.note);

    // 能力矩阵：同一个未配置前提 ⇒ pulsar 也是 not-implemented
    let matrix_entry = pulsar_descriptor(None);
    assert_eq!(matrix_entry.status, ReceiverStatus::NotImplemented);
    assert!(matrix_entry.note.contains("未配置 AGF_INGEST_PULSAR_SERVICE_URL"), "{}", matrix_entry.note);
    assert!(matrix_entry.todo.unwrap_or_default().contains("TODO ingest-pulsar-native"));
    // 配置了 KoP 地址 ⇒ ready，且 note 一字不差写明"经 KoP 复用"+"原生协议未实现"
    let ready = pulsar_descriptor(Some("kafka://kop:9092"));
    assert_eq!(ready.status, ReceiverStatus::Ready);
    assert!(!ready.mock_replay);
    assert!(ready.note.contains("经 KoP（Kafka on Pulsar）复用 Kafka 接收器；Pulsar 原生协议未实现"), "{}", ready.note);
    assert!(ready.todo.unwrap_or_default().contains("TODO ingest-pulsar-native"), "TODO 字段必须保留");
    // 空字符串 = 未配置
    assert_eq!(pulsar_descriptor(Some("   ")).status, ReceiverStatus::NotImplemented);
}

/// KoP 复用取数：**走 Kafka 接收器真消费**（注入内存 Kafka 源），协议标签 = pulsar。
#[tokio::test]
async fn pulsar_poll_once_reuses_kafka_receiver() {
    let kafka_source = Arc::new(crate::kafka::tests::FakeKafkaSource::with_partitions(1));
    kafka_source.append(
        0,
        "<34>Feb 21 10:23:45 web-prod-01 sshd[2311]: Failed password for root from 203.0.113.77 port 51234 ssh2",
    );
    let mut source = log_source(IngestProtocol::Pulsar);
    source.connection.endpoint = Some("kafka://kop:9092".to_string());
    source.connection.topic = Some("persistent://public/default/sec-logs".to_string());
    source.connection.headers.insert("subscription".to_string(), "agf-prod".to_string());
    let built = PulsarReceiver::from_source(&source);
    assert!(built.is_ok(), "{built:?}");
    let Ok(receiver) = built else { return };
    let receiver = receiver.with_kafka_source(Arc::clone(&kafka_source) as Arc<dyn KafkaSource>);
    let (pipeline, sink) = pipeline_and_sink();
    let count = receiver.poll_once(Arc::clone(&pipeline), source.clone(), 10).await;
    assert_eq!(count.ok(), Some(1), "KoP 路径必须真的消费到记录");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1));
    let raws = sink.raws().unwrap_or_default();
    assert!(
        raws.first().map(|r| r.origin.starts_with("pulsar://")).unwrap_or(false),
        "origin 必须标注 pulsar（来源可区分）: {raws:?}"
    );
    // 内层就是 Kafka 接收器（复用同一份取数内核 + 同一份游标）
    assert!(receiver.reused_kafka().is_some(), "必须复用出 Kafka 接收器");
    assert_eq!(receiver.reused_kafka().map(|r| r.protocol()), Some(IngestProtocol::Pulsar));
}

/// 未配置 KoP 时的 Mock 回放通道仍然可用（链路先跑通），但 `start()` 如实报未实现。
#[tokio::test]
async fn mock_replay_channel_works_when_kop_absent() {
    let mut source = log_source(IngestProtocol::Pulsar);
    source.connection.topic = Some("t".to_string());
    let built = PulsarReceiver::from_source(&source);
    assert!(built.is_ok(), "{built:?}");
    let Ok(mut receiver) = built else { return };
    receiver.mock.payloads = vec![(SYSLOG.to_vec(), "pulsar://t/0".to_string())];
    assert_eq!(receiver.mock.len(), 1);
    assert!(!receiver.mock.is_empty());

    let (pipeline, sink) = pipeline_and_sink();
    // start 必须明确报未实现（不假装可用）
    let started = receiver.start(Arc::clone(&pipeline), source.clone()).await;
    assert!(matches!(started, Err(DomainError::NotImplemented(_))), "{started:?}");
    // poll_once 走 Mock 回放，链路（归一化 + 落库）可用
    let count = receiver.poll_once(Arc::clone(&pipeline), source, 10).await;
    assert_eq!(count.ok(), Some(1));
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1));
}

/// 已实现协议的**配置模型**必须能从 `LogSource` 构造出来（matrix 与运行时共用同一入口）。
#[test]
fn implemented_receivers_build_config_models() {
    let (pipeline, _sink) = pipeline_and_sink();

    let mut mqtt_source = log_source(IngestProtocol::Mqtt);
    mqtt_source.connection.endpoint = Some("mqtt://broker:1883".to_string());
    mqtt_source.connection.topic = Some("sec/#".to_string());
    mqtt_source.connection.headers.insert("qos".to_string(), "2".to_string());
    let mqtt = MqttReceiver::from_source(Arc::clone(&pipeline), &mqtt_source);
    assert!(mqtt.is_ok(), "{mqtt:?}");
    assert_eq!(mqtt.ok().map(|m| m.qos()), Some(2));

    let snmp_source = log_source(IngestProtocol::SnmpTrap);
    let snmp = SnmpTrapReceiver::from_source(Arc::clone(&pipeline), &snmp_source);
    assert!(snmp.is_ok(), "{snmp:?}");
    assert_eq!(snmp.ok().map(|s| s.protocol()), Some(IngestProtocol::SnmpTrap));

    let mut jdbc_source = log_source(IngestProtocol::Jdbc);
    jdbc_source.connection.sql = Some("SELECT id, ts FROM audit_log".to_string());
    jdbc_source.connection.cursor_field = Some("id".to_string());
    let jdbc = crate::jdbc::SqlPullConfig::from_source(&jdbc_source);
    assert!(jdbc.is_ok(), "{jdbc:?}");
    assert_eq!(jdbc.ok().and_then(|c| c.cursor_field), Some("id".to_string()));

    let mut kafka_source = log_source(IngestProtocol::Kafka);
    kafka_source.connection.endpoint = Some("kafka:9092".to_string());
    kafka_source.connection.topic = Some("sec-logs".to_string());
    let kafka = crate::kafka::KafkaPullConfig::from_source(&kafka_source);
    assert!(kafka.is_ok(), "{kafka:?}");
    assert_eq!(kafka.ok().map(|c| c.topic), Some("sec-logs".to_string()));
}

#[test]
fn capability_matrix_covers_all_protocols_with_honest_status() {
    let matrix = receiver_capability_matrix();
    let ready: Vec<&str> =
        matrix.iter().filter(|d| d.status == ReceiverStatus::Ready).map(|d| d.name.as_str()).collect();
    for expected in [
        "webhook",
        "syslog-tcp",
        "syslog-tls",
        "file-tail",
        "http-pull",
        "object-pull",
        "jdbc",
        "mqtt",
        "snmp-trap",
        "kafka",
        "collector-uplink",
    ] {
        assert!(ready.contains(&expected), "{expected} 已实现，必须出现在就绪清单里: {ready:?}");
    }
    // **装配事实驱动的四个模块必须在**（OTLP 三信号 + JetStream 入向）：它们的就绪与否
    // 取决于装配点有没有真的挂路由/起订阅，因此不出现在上面的固定 ready 清单里，
    // 由 `not_wired_state_is_never_reported_as_ready` 逐行与装配登记表对账。
    for module in WIRING_TRACKED_MODULES {
        let row = matrix.iter().find(|d| d.name == *module);
        assert!(row.is_some(), "能力矩阵必须包含 {module} 一行");
        let Some(row) = row else { continue };
        assert!(!row.note.is_empty(), "{module} 必须说明实现能力");
    }
    // Syslog TLS 已实现但默认需要运维提供证书：能力就绪 ≠ 本进程已在监听
    assert!(
        matrix.iter().any(|d| d.name == "syslog-tls" && d.protocol == IngestProtocol::Syslog),
        "两个 syslog 监听器（明文 TCP / TLS）必须都在矩阵里"
    );
    // Pulsar：**经 KoP 复用**。状态取决于是否配置 KoP 地址（未配置不得假装 ready），
    // 但无论哪种状态，note/todo 都必须如实写明"经 KoP 复用"+"原生协议未实现"。
    let kop_env = std::env::var("AGF_INGEST_PULSAR_SERVICE_URL").ok();
    let kop_configured = kop_env.as_deref().map(str::trim).is_some_and(|url| !url.is_empty());
    let pulsar = matrix.iter().find(|d| d.protocol == IngestProtocol::Pulsar);
    assert!(pulsar.is_some(), "矩阵必须包含 Pulsar 项");
    let Some(pulsar) = pulsar else { return };
    assert_eq!(pulsar.name, "pulsar");
    assert_eq!(
        pulsar.status,
        if kop_configured { ReceiverStatus::Ready } else { ReceiverStatus::NotImplemented },
        "未配置 KoP 地址时不得显示 ready"
    );
    let pulsar_todo = pulsar.todo.clone().unwrap_or_default();
    assert!(pulsar_todo.contains("TODO ingest-pulsar-native"), "{pulsar_todo}");
    assert!(pulsar_todo.contains("经 KoP"), "TODO 必须写明经 KoP 复用: {pulsar_todo}");
    assert!(
        !pulsar.note.contains("原生协议已支持") && !pulsar.note.contains("原生协议已实现"),
        "绝不允许写成原生协议已支持: {}",
        pulsar.note
    );
    // 未实现协议必须带 TODO + Mock 回放（本轮只可能是"未配置 KoP"的 Pulsar）
    let not_implemented: Vec<&str> =
        matrix.iter().filter(|d| d.status == ReceiverStatus::NotImplemented).map(|d| d.name.as_str()).collect();
    assert_eq!(
        not_implemented,
        if kop_configured { Vec::new() } else { vec!["pulsar"] },
        "未实现协议清单必须如实：只允许是未配置 KoP 的 Pulsar"
    );
    for descriptor in &matrix {
        if descriptor.status == ReceiverStatus::NotImplemented {
            assert!(descriptor.todo.is_some(), "未实现协议必须带 TODO 锚点: {}", descriptor.name);
            assert!(descriptor.mock_replay, "未实现协议必须提供 Mock 回放通道: {}", descriptor.name);
        }
        assert!(descriptor.todo.is_some() || descriptor.name != "pulsar", "Pulsar 必须保留 TODO 字段");
    }
    // 每个协议都必须出现在矩阵里（不能漏项）
    for protocol in [
        IngestProtocol::Webhook,
        IngestProtocol::Syslog,
        IngestProtocol::File,
        IngestProtocol::HttpPull,
        IngestProtocol::Otlp,
        IngestProtocol::ObjectStorage,
        IngestProtocol::Jdbc,
        IngestProtocol::Mqtt,
        IngestProtocol::SnmpTrap,
        IngestProtocol::Kafka,
        IngestProtocol::Pulsar,
        IngestProtocol::Nats,
        IngestProtocol::Mcp,
    ] {
        assert!(matrix.iter().any(|d| d.protocol == protocol), "矩阵缺少协议 {:?}", protocol.as_str());
    }
}

// ---- 第四态 `NotWired`（防"Ready 但路由没挂"复发）----

/// **防复发的关键断言**：`Ready` 只能来自"装配点已登记 wired=true"，
/// 未装配（未登记 / 登记为 false）必须是 `NotWired`，绝不是 `Ready`。
#[test]
fn not_wired_state_is_never_reported_as_ready() {
    // 纯函数层：三态组合逐一钉死
    assert_eq!(status_for(ReceiverStatus::Ready, None), ReceiverStatus::NotWired, "未登记装配不得自称 ready");
    assert_eq!(status_for(ReceiverStatus::Ready, Some(false)), ReceiverStatus::NotWired, "登记未装配不得自称 ready");
    assert_eq!(status_for(ReceiverStatus::Ready, Some(true)), ReceiverStatus::Ready, "真正挂上了才是 ready");
    // 未实现/Mock 与装配无关，不得被折算成 NotWired
    for declared in [ReceiverStatus::NotImplemented, ReceiverStatus::Mock, ReceiverStatus::NotWired] {
        for wired in [None, Some(false), Some(true)] {
            assert_eq!(status_for(declared, wired), declared, "{declared:?} 不该被装配事实改写（wired={wired:?}）");
        }
    }
    assert_eq!(ReceiverStatus::NotWired.as_str(), "not-wired");
    assert_eq!(ReceiverStatus::Ready.as_str(), "ready");

    // 矩阵层：**装配事实驱动的每个模块**都必须与装配登记表逐行一致
    // （这是"口径与实际一致"的机器判定：登记了什么就是什么，没登记一律 not-wired）
    let matrix = receiver_capability_matrix();
    for module in WIRING_TRACKED_MODULES {
        let row = matrix.iter().find(|d| d.name == *module);
        assert!(row.is_some(), "能力矩阵缺少装配事实驱动的模块 {module}");
        let Some(row) = row else { continue };
        let registered = wired_state(module);
        assert_eq!(
            row.status,
            status_for(ReceiverStatus::Ready, registered),
            "{module} 的状态与装配登记表不一致（登记 {registered:?}）"
        );
    }
    // 库测试进程里没有任何装配点报到 ⇒ 这四个模块必须显示 NotWired（而不是 Ready）
    for module in WIRING_TRACKED_MODULES {
        let row = matrix.iter().find(|d| d.name == *module);
        assert_eq!(
            row.map(|d| d.status),
            Some(ReceiverStatus::NotWired),
            "{module} 未装配时必须显示 not-wired（这正是本轮修掉的口径不实）"
        );
        assert_eq!(wired_state(module), None, "{module} 在库测试进程里不得预置装配登记");
    }
    assert!(wiring_snapshot().is_empty(), "库测试进程的装配登记表必须为空：{:?}", wiring_snapshot());
    // 非装配驱动的模块不受影响（状态是代码事实）
    for name in ["webhook", "syslog-tcp", "kafka"] {
        let row = matrix.iter().find(|d| d.name == name);
        assert_eq!(row.map(|d| d.status), Some(ReceiverStatus::Ready), "{name} 不该被装配事实改写");
    }
}

// ---- 采集器上行 ----
