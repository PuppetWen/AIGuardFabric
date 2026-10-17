//! MQTT 接收器用例：from_source 校验、消息拆分落库、消费循环、能力描述与环境键接线。

use super::*;

#[test]
fn endpoint_message_shapes_map_into_options() {
    // 共享订阅 + TLS + 遗嘱 三者同时配置时的订阅计划
    let endpoint = parse_endpoint("mqtts://broker.local").unwrap_or(MqttEndpoint {
        host: "broker.local".to_string(),
        port: 8883,
        tls: true,
        websocket: false,
        path: String::new(),
    });
    let subscription = RumqttSubscription::new(endpoint, "agf-combo")
        .with_credentials("user", "p@ssw0rd-should-not-leak")
        .with_will(MqttWill {
            topic: "agf/sec/status".to_string(),
            payload: b"offline".to_vec(),
            qos: 0,
            retain: false,
        })
        .with_backoff(BackoffPolicy::new(3, 12));
    // `mqtts://` 却没有 TLS 材料：**必须显式报错**（绝不静默明文连接）
    let missing = subscription.options();
    assert!(missing.is_err(), "mqtts 缺 TLS 材料必须报错: {missing:?}");
    assert!(!subscription.tls_enabled());
    let debug = format!("{subscription:?}");
    assert!(!debug.contains("p@ssw0rd-should-not-leak"), "口令不得进 Debug: {debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
    assert!(subscription.describe().contains("client_id=agf-combo"));
    let plan = plan_subscribe("$share/agf/agf/sec/#", 1).unwrap_or_default();
    assert_eq!(plan.topic, "$share/agf/agf/sec/#");

    // 装上 TLS 材料后即可组装完备选项（握手仍需真实 broker，见 docker 端到端）
    let Some((ca_pem, _, _)) = test_pki() else { return };
    let subscription =
        subscription.with_tls(MqttTlsMaterial { ca_pem: Some(ca_pem.into_bytes()), ..MqttTlsMaterial::default() });
    assert!(subscription.tls_enabled());
    let options = subscription.options();
    assert!(options.is_ok(), "装配 TLS 材料后必须可组装: {options:?}");
}

#[test]
fn from_source_requires_broker_topic_and_valid_qos() {
    let (pipeline, _sink) = pipeline_and_sink();
    assert!(MqttReceiver::from_source(Arc::clone(&pipeline), &log_source()).is_err(), "缺 endpoint 必须报错");

    let mut source = log_source();
    source.connection.endpoint = Some("mqtt://127.0.0.1:1883".to_string());
    assert!(MqttReceiver::from_source(Arc::clone(&pipeline), &source).is_err(), "缺 topic 必须报错");

    source.connection.topic = Some("agf/sec/#".to_string());
    let mut headers = BTreeMap::new();
    headers.insert("qos".to_string(), "2".to_string());
    source.connection.headers = headers;
    let receiver = MqttReceiver::from_source(Arc::clone(&pipeline), &source);
    assert!(receiver.is_ok(), "{receiver:?}");
    let Ok(receiver) = receiver else { return };
    assert_eq!(receiver.topic(), "agf/sec/#");
    assert_eq!(receiver.qos(), 2);

    source.connection.headers.insert("qos".to_string(), "7".to_string());
    assert!(MqttReceiver::from_source(pipeline, &source).is_err(), "越界 qos 必须报错");
}

#[test]
fn from_source_rejects_invalid_shared_subscription() {
    let (pipeline, _sink) = pipeline_and_sink();
    let mut source = log_source();
    source.connection.endpoint = Some("mqtt://127.0.0.1:1883".to_string());
    source.connection.topic = Some("$share//agf/#".to_string());
    let receiver = MqttReceiver::from_source(Arc::clone(&pipeline), &source);
    assert!(receiver.is_ok(), "启用阶段先不判主题：{receiver:?}");
    // 订阅时才严格校验（`subscribe` 是 broker 交互的入口）
    let Ok(receiver) = receiver else { return };
    assert_eq!(receiver.topic(), "$share//agf/#");
    assert!(plan_subscribe(receiver.topic(), receiver.qos()).is_err());

    source.connection.topic = Some("$share/agf/agf/sec/#".to_string());
    let receiver = MqttReceiver::from_source(pipeline, &source);
    assert!(receiver.is_ok(), "{receiver:?}");
    let Ok(receiver) = receiver else { return };
    assert_eq!(
        receiver.plan().shared.as_ref().map(|s| s.group.clone()),
        Some("agf".to_string()),
        "共享订阅信息必须进订阅计划（/readyz 如实展示）"
    );
}

#[tokio::test]
async fn message_split_shapes_and_pipeline_ingest() {
    let (subscription, _sender) = FakeSubscription::new(8);
    let (pipeline, sink) = pipeline_and_sink();
    let counters = Arc::new(ReceiverCounters::new());
    let receiver = MqttReceiver::new(Arc::clone(&pipeline), log_source(), "t", 1, subscription)
        .with_counters(Arc::clone(&counters));
    let topic = "agf/sec/events";

    // 单条 syslog 正文
    let one = MqttMessage::new(topic, SYSLOG.to_vec(), 1, false);
    let report = receiver.ingest_message(&one).await;
    assert!(report.is_ok(), "{report:?}");
    assert_eq!(report.map(|r| r.persisted).ok(), Some(1), "syslog 正文应命中内置模板");
    assert_eq!(counters.snapshot().matched, 1, "syslog 载荷必须命中内置模板");

    // JSON 数组：3 条
    let array = MqttMessage::new(topic, br#"[{"a":1},{"b":2},{"c":3}]"#.to_vec(), 0, false);
    assert_eq!(receiver.ingest_message(&array).await.map(|r| r.records).ok(), Some(3));
    // NDJSON：2 条
    let ndjson = MqttMessage::new(topic, b"{\"x\":1}\n{\"y\":2}\n".to_vec(), 1, false);
    assert_eq!(receiver.ingest_message(&ndjson).await.map(|r| r.records).ok(), Some(2));
    // 空载荷：0 条且不报错
    let empty = MqttMessage::new(topic, Vec::new(), 1, false);
    assert_eq!(receiver.ingest_message(&empty).await.map(|r| r.records).ok(), Some(0));

    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(6));
    assert_eq!(counters.snapshot().received, 4, "收到 4 条 PUBLISH");
}

#[tokio::test]
async fn run_consumes_subscription_until_closed() {
    let (subscription, sender) = FakeSubscription::new(8);
    let (pipeline, sink) = pipeline_and_sink();
    let receiver = Arc::new(MqttReceiver::new(
        Arc::clone(&pipeline),
        log_source(),
        "agf/sec/#",
        1,
        Arc::clone(&subscription) as Arc<dyn MqttSubscription>,
    ));
    let runner = {
        let receiver = Arc::clone(&receiver);
        tokio::spawn(async move {
            let _ = receiver.run().await;
        })
    };
    for index in 0..3 {
        // 三条**内容不同**的载荷：相同载荷会被流水线按"同源+同时间+同哈希"去重，
        // 那不是本测试要验证的语义。
        let payload = format!(
            "<34>Feb 21 10:23:4{index} web-prod-0{index} sshd[2311]: Failed password for root from 203.0.113.7{index} port 5123{index} ssh2"
        );
        let message = MqttMessage::new(format!("agf/sec/site-{index}"), payload.into_bytes(), 1, false);
        if sender.send(message).await.is_err() {
            break;
        }
    }
    let mut landed = 0;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(25)).await;
        landed = sink.event_count(TenantId::default_tenant()).await.unwrap_or(0);
        if landed == 3 {
            break;
        }
    }
    drop(sender);
    runner.abort();
    assert_eq!(landed, 3, "订阅通道里的 3 条消息都必须落库");
    let seen = subscription.topic_seen.lock().await.clone();
    assert_eq!(seen, vec![("agf/sec/#".to_string(), 1)], "订阅必须使用配置的主题与 QoS");
    assert!(receiver.describe().note.contains("agf/sec/#"));
}

#[test]
fn describe_reports_ready_with_honest_todo() {
    let (subscription, _sender) = FakeSubscription::new(1);
    let (pipeline, _sink) = pipeline_and_sink();
    let receiver = MqttReceiver::new(pipeline, log_source(), "t", 1, subscription);
    let descriptor = receiver.describe();
    assert_eq!(descriptor.status, ReceiverStatus::Ready);
    assert_eq!(descriptor.protocol, IngestProtocol::Mqtt);
    assert!(descriptor.note.contains("QoS 1"), "{}", descriptor.note);
    // WebSocket 已接线：不再是 TODO，而是能力描述里的事实
    let todo = descriptor.todo.unwrap_or_default();
    assert!(!todo.contains("ingest-mqtt-websocket"), "WebSocket 已实现，不得再挂「未接线」的 TODO: {todo}");
    assert!(todo.contains("ingest-mqtt-v5-auth"), "{todo}");
    assert!(descriptor.note.contains("MQTT 3.1.1"), "协议版本必须如实进 /readyz: {}", descriptor.note);
    assert_eq!(receiver.protocol(), IngestProtocol::Mqtt);
    // 共享订阅必须出现在能力描述里（/readyz 如实）
    let (subscription, _sender) = FakeSubscription::new(1);
    let (pipeline, _sink) = pipeline_and_sink();
    let shared = MqttReceiver::new(pipeline, log_source(), "$share/agf/agf/sec/#", 1, subscription);
    let note = shared.describe().note;
    assert!(note.contains("共享订阅 group=agf filter=agf/sec/#"), "{note}");
    // rumqttc 客户端可离线构造（不发起连接）
    let Ok(endpoint) = parse_endpoint("mqtt://127.0.0.1:1883") else { return };
    let rumqtt = RumqttSubscription::new(endpoint, "agf-test");
    assert_eq!(rumqtt.client_id(), "agf-test");
    assert!(rumqtt.describe().contains("mqtt://127.0.0.1:1883"));
    assert!(!rumqtt.tls_enabled());
    assert!(rumqtt.will().is_none());
    assert!(rumqtt.options().is_ok(), "明文选项必须可离线组装");
}

/// 进程环境只读快照式测试：确保"从环境读取"这条路径真的能走通（不改进程环境）。
#[test]
fn env_readers_are_wired_to_the_documented_keys() {
    let snapshot = EnvMap::from_process();
    let _ = MqttTlsConfig::from_lookup(|key| snapshot.get(key));
    let _ = MqttWill::from_lookup(|key| snapshot.get(key));
    let _ = BackoffPolicy::from_lookup(|key| snapshot.get(key));
    // 键名必须与文档一致（改键名就改文档，避免"文档说一套、代码读另一套"）
    assert_eq!(ENV_TLS, "AGF_INGEST_MQTT_TLS");
    assert_eq!(ENV_TLS_CA, "AGF_INGEST_MQTT_TLS_CA");
    assert_eq!(ENV_TLS_CERT, "AGF_INGEST_MQTT_TLS_CERT");
    assert_eq!(ENV_TLS_KEY, "AGF_INGEST_MQTT_TLS_KEY");
    assert_eq!(ENV_TLS_INSECURE_SKIP_VERIFY, "AGF_INGEST_MQTT_TLS_INSECURE_SKIP_VERIFY");
    assert_eq!(ENV_WILL_TOPIC, "AGF_INGEST_MQTT_WILL_TOPIC");
    assert_eq!(ENV_WILL_PAYLOAD, "AGF_INGEST_MQTT_WILL_PAYLOAD");
    assert_eq!(ENV_WILL_QOS, "AGF_INGEST_MQTT_WILL_QOS");
    assert_eq!(ENV_WILL_RETAIN, "AGF_INGEST_MQTT_WILL_RETAIN");
    assert_eq!(ENV_RECONNECT_INITIAL_SECS, "AGF_INGEST_MQTT_RECONNECT_INITIAL_SECS");
    assert_eq!(ENV_RECONNECT_MAX_SECS, "AGF_INGEST_MQTT_RECONNECT_MAX_SECS");
}
