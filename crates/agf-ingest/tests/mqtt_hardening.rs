//! MQTT 加固集成测试：TLS 配置、共享订阅、遗嘱（LWT）、退避状态机、错误分类。
//!
//! 全部**离线**运行（不需要 broker / docker）：真实 broker 侧的验证（TLS 握手、同组竞争
//! 消费、异常断开触发遗嘱）见 `tools/simulators/run_otlpgrpc_mqtt_e2e.ps1`。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use agf_core::enums::{HealthState, IngestProtocol};
use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, LogSource, SourceConnection};
use agf_core::time::Timestamp;
use agf_ingest::bus::NoopEventBus;
use agf_ingest::metrics::ReceiverCounters;
use agf_ingest::mqtt::{
    BackoffPolicy, MqttLinkCounters, MqttLinkError, MqttMessage, MqttReceiver, MqttSubscription, MqttTlsConfig,
    MqttTlsMaterial, MqttWill, RumqttSubscription, SharedSubscription, classify_link_error, link_counters,
    link_prometheus, parse_endpoint, parse_shared_subscription, plan_subscribe, validate_topic_filter,
};
use agf_ingest::pipeline::{InMemorySink, IngestConfig, IngestPipeline, Sink};
use agf_ingest::registry::ParserRegistry;
use async_trait::async_trait;
use tokio::sync::mpsc;

const SYSLOG: &[u8] =
    b"<34>Feb 21 10:23:45 web-prod-01 sshd[2311]: Failed password for root from 203.0.113.77 port 51234 ssh2";

fn env(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries.iter().map(|(key, value)| ((*key).to_string(), (*value).to_string())).collect()
}

fn log_source() -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "mqtt-hardening".to_string(),
        protocol: IngestProtocol::Mqtt,
        vendor: "generic".to_string(),
        product: "json".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: CollectionMode::Push,
        poll_interval_secs: None,
        require_mtls: false,
        allowed_cidrs: vec![],
        max_message_bytes: 1_048_576,
        max_eps: 0,
        tags: vec![],
        health: HealthState::Healthy,
        last_event_at: None,
        total_events: 0,
        last_error: None,
        created_at: now,
        updated_at: now,
    }
}

fn pipeline_and_sink() -> (Arc<IngestPipeline>, Arc<InMemorySink>) {
    let sink = Arc::new(InMemorySink::new());
    let pipeline = IngestPipeline::new(
        ParserRegistry::with_builtins(),
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::new(NoopEventBus),
        IngestConfig { emit_to_bus: false, ..IngestConfig::default() },
    );
    (Arc::new(pipeline), sink)
}

/// 记录订阅请求的内存订阅实现（不需要 broker），并回放给定的消息。
#[derive(Debug)]
struct RecordingSubscription {
    topics: tokio::sync::Mutex<Vec<(String, u8)>>,
    messages: tokio::sync::Mutex<Option<mpsc::Receiver<MqttMessage>>>,
}

impl RecordingSubscription {
    fn new(capacity: usize) -> (Arc<Self>, mpsc::Sender<MqttMessage>) {
        let (sender, receiver) = mpsc::channel(capacity);
        let subscription = Arc::new(Self {
            topics: tokio::sync::Mutex::new(Vec::new()),
            messages: tokio::sync::Mutex::new(Some(receiver)),
        });
        (subscription, sender)
    }

    async fn topics(&self) -> Vec<(String, u8)> {
        self.topics.lock().await.clone()
    }
}

#[async_trait]
impl MqttSubscription for RecordingSubscription {
    async fn subscribe(&self, topic: &str, qos: u8) -> DomainResult<mpsc::Receiver<MqttMessage>> {
        self.topics.lock().await.push((topic.to_string(), qos));
        let mut guard = self.messages.lock().await;
        guard.take().ok_or_else(|| DomainError::Conflict("订阅通道已被取走（每个接收器只订阅一次）".to_string()))
    }

    fn describe(&self) -> String {
        "memory://mqtt-hardening".to_string()
    }
}

/// 自签 CA + 由该 CA 签发的服务端证书（测试内生成、不落盘）。
fn test_pki() -> Option<(String, String, String)> {
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).ok()?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, "agf-mqtt-it-ca");
    let ca_key = rcgen::KeyPair::generate().ok()?;
    let ca_cert = ca_params.self_signed(&ca_key).ok()?;
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);

    let server_params = rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).ok()?;
    let server_key = rcgen::KeyPair::generate().ok()?;
    let server_cert = server_params.signed_by(&server_key, &issuer).ok()?;
    Some((ca_cert.pem(), server_cert.pem(), server_key.serialize_pem()))
}

#[test]
fn broker_schemes_cover_plaintext_tls_and_websocket() {
    let plain = parse_endpoint("mqtt://127.0.0.1:1883").expect("mqtt:// 必须可用");
    assert!(!plain.tls && !plain.websocket);
    let tls = parse_endpoint("mqtts://broker.example").expect("mqtts:// 必须可用");
    assert!(tls.tls, "mqtts:// 必须启用 TLS");
    assert_eq!(tls.port, 8883, "TLS scheme 默认端口是 8883");
    assert!(parse_endpoint("ssl://broker.example").expect("ssl:// 兼容").tls);
    // WebSocket 已接线（本轮）：解析为 websocket=true，且 broker 地址是**完整 URL**
    let ws = parse_endpoint("ws://broker:8083").expect("ws:// 必须可用");
    assert!(ws.websocket && !ws.tls);
    assert_eq!(ws.broker_address(), "ws://broker:8083/mqtt");
    let wss = parse_endpoint("wss://broker:8084").expect("wss:// 必须可用");
    assert!(wss.websocket && wss.tls);
    assert_eq!(wss.broker_address(), "wss://broker:8084/mqtt");
    assert!(matches!(parse_endpoint("amqp://broker:5672"), Err(DomainError::Config(_))));
    println!("[mqtt] schemes ok: {plain:?} {tls:?} {ws:?} {wss:?}");
}

#[test]
fn tls_config_reads_env_and_validates_mutual_tls_pairing() {
    let empty: BTreeMap<String, String> = BTreeMap::new();
    assert!(!MqttTlsConfig::from_lookup(|key| empty.get(key).cloned()).enabled);

    let full = env(&[
        ("AGF_INGEST_MQTT_TLS", "1"),
        ("AGF_INGEST_MQTT_TLS_CA", "certs/ca.pem"),
        ("AGF_INGEST_MQTT_TLS_CERT", "certs/client.pem"),
        ("AGF_INGEST_MQTT_TLS_KEY", "certs/client.key"),
    ]);
    let config = MqttTlsConfig::from_lookup(|key| full.get(key).cloned());
    assert!(config.enabled);
    assert!(config.validate().is_ok());
    assert!(config.describe().contains("mTLS=开启"), "{}", config.describe());
    assert!(!config.describe().contains("client.key"), "描述不得泄露私钥路径");

    let half = env(&[("AGF_INGEST_MQTT_TLS", "1"), ("AGF_INGEST_MQTT_TLS_CERT", "certs/client.pem")]);
    let half = MqttTlsConfig::from_lookup(|key| half.get(key).cloned());
    assert!(matches!(half.validate(), Err(DomainError::Config(_))), "mTLS 证书/私钥必须成对");
    assert!(matches!(half.load(), Err(DomainError::Config(_))));

    let missing = env(&[("AGF_INGEST_MQTT_TLS", "1"), ("AGF_INGEST_MQTT_TLS_CA", "certs/nope.pem")]);
    let missing = MqttTlsConfig::from_lookup(|key| missing.get(key).cloned());
    assert!(matches!(missing.load(), Err(DomainError::Config(_))), "PEM 不可读必须明确报错");
}

#[test]
fn tls_material_builds_rustls_transport_and_redacts_secrets() {
    let Some((ca_pem, cert_pem, key_pem)) = test_pki() else { return };
    let material = MqttTlsMaterial {
        ca_pem: Some(ca_pem.into_bytes()),
        client_cert_pem: Some(cert_pem.into_bytes()),
        client_key_pem: Some(key_pem.into_bytes()),
        insecure_skip_verify: false,
    };
    let transport = material.transport();
    assert!(
        transport.is_ok(),
        "rustls 传输层装配失败: {}",
        transport.as_ref().err().map(ToString::to_string).unwrap_or_default()
    );
    let debug = format!("{material:?}");
    assert!(debug.contains("<PEM:REDACTED>"), "{debug}");
    assert!(!debug.contains("BEGIN"), "Debug 输出必须隐藏 PEM 内容: {debug}");

    let skip =
        MqttTlsMaterial { ca_pem: None, client_cert_pem: None, client_key_pem: None, insecure_skip_verify: true };
    assert!(skip.transport().is_ok(), "跳过校验路径也必须能装配（并已在配置层 warn）");
    let broken = MqttTlsMaterial { ca_pem: Some(b"not-a-pem".to_vec()), ..MqttTlsMaterial::default() };
    assert!(matches!(broken.transport(), Err(DomainError::Config(_))));
}

#[test]
fn shared_subscription_parsing_is_strict() {
    assert_eq!(parse_shared_subscription("agf/sec/#").expect("普通主题"), None);
    assert_eq!(
        parse_shared_subscription("$share/agf/agf/sec/#").expect("合法共享订阅"),
        Some(SharedSubscription { group: "agf".to_string(), filter: "agf/sec/#".to_string() })
    );
    for bad in [
        "$share/",
        "$share/only-group",
        "$share//agf/#",
        "$share/agf/",
        "$share/agf/#/x",
        "$share/ag+/agf/#",
        "$share/ag#/agf/#",
        "$share/agf/$share/other/agf/#",
    ] {
        assert!(parse_shared_subscription(bad).is_err(), "{bad} 必须被判为非法");
    }
    assert!(validate_topic_filter("$SYS/#").is_ok());
    assert!(validate_topic_filter("a/b/#").is_ok());
    assert!(validate_topic_filter("a/#/b").is_err());
    assert!(validate_topic_filter("a/b+").is_err());
}

#[test]
fn subscribe_plan_keeps_the_shared_prefix_for_the_broker() {
    let plan = plan_subscribe("$share/agf-replicas/agf/sec/#", 1).expect("合法共享订阅");
    assert_eq!(plan.topic, "$share/agf-replicas/agf/sec/#", "提交给 broker 的必须是完整共享主题");
    assert_eq!(
        plan.shared.as_ref().map(SharedSubscription::share_topic),
        Some("$share/agf-replicas/agf/sec/#".to_string())
    );
    // 普通主题的形态可疑只 warn（保持既有行为），共享订阅非法才硬失败
    assert!(plan_subscribe("agf/#/x", 1).is_ok());
    assert!(plan_subscribe("$share/agf/#/x", 1).is_err());
    assert!(plan_subscribe("", 1).is_err());
}

#[test]
fn will_configuration_maps_to_rumqttc_last_will() {
    let empty: BTreeMap<String, String> = BTreeMap::new();
    assert_eq!(MqttWill::from_lookup(|key| empty.get(key).cloned()), None);

    let partial = env(&[("AGF_INGEST_MQTT_WILL_PAYLOAD", "gone")]);
    assert_eq!(MqttWill::from_lookup(|key| partial.get(key).cloned()), None, "缺主题不注册遗嘱");

    let full = env(&[
        ("AGF_INGEST_MQTT_WILL_TOPIC", "agf/sec/collector-status"),
        ("AGF_INGEST_MQTT_WILL_PAYLOAD", "collector offline (e2e)"),
        ("AGF_INGEST_MQTT_WILL_QOS", "1"),
        ("AGF_INGEST_MQTT_WILL_RETAIN", "1"),
    ]);
    let will = MqttWill::from_lookup(|key| full.get(key).cloned()).expect("配齐即生效");
    assert_eq!(will.topic, "agf/sec/collector-status");
    assert_eq!(will.qos, 1);
    assert!(will.retain);
    assert_eq!(will.payload, b"collector offline (e2e)".to_vec());
    let last_will = will.to_last_will();
    assert_eq!(last_will.topic, "agf/sec/collector-status");
    assert_eq!(last_will.message, b"collector offline (e2e)"[..]);
    assert!(will.describe().contains("retain=true"));
    println!("[mqtt] will describe={}", will.describe());
}

#[test]
fn backoff_state_machine_caps_and_resets() {
    let mut backoff = BackoffPolicy::new(1, 30);
    let sequence: Vec<u64> = (0..7).map(|_| backoff.next_delay().as_secs()).collect();
    assert_eq!(sequence, vec![1, 2, 4, 8, 16, 30, 30]);
    backoff.reset();
    assert_eq!(backoff.next_delay(), Duration::from_secs(1));
    assert_eq!(BackoffPolicy::new(0, 0).bounds_secs(), (1, 1));
    assert_eq!(BackoffPolicy::new(5, 2).bounds_secs(), (5, 5));
}

#[test]
fn link_errors_are_classified_and_exported_to_prometheus() {
    assert_eq!(classify_link_error("TLS: Web Pki: invalid peer certificate"), MqttLinkError::Tls);
    assert_eq!(classify_link_error("Connection refused, return code: `NotAuthorized`"), MqttLinkError::Auth);
    assert_eq!(classify_link_error("Connection refused, return code: `BadUsernameOrPassword`"), MqttLinkError::Auth);
    assert_eq!(classify_link_error("I/O: connection refused"), MqttLinkError::Network);
    assert_eq!(classify_link_error("Mqtt state: Expected ConnAck packet"), MqttLinkError::Protocol);
    assert_eq!(classify_link_error("unknown failure"), MqttLinkError::Other);

    let counters = MqttLinkCounters::new();
    counters.record_error(MqttLinkError::Tls);
    counters.record_error(MqttLinkError::Auth);
    counters.record_reconnect();
    let snapshot = counters.snapshot();
    assert_eq!(snapshot.tls_errors, 1);
    assert_eq!(snapshot.auth_errors, 1);
    assert_eq!(snapshot.reconnects, 1);
    assert_eq!(snapshot.total_errors(), 2);

    link_counters().record_error(MqttLinkError::Other);
    let text = link_prometheus();
    assert!(text.contains("agf_ingest_mqtt_link_errors_total{receiver=\"mqtt\",kind=\"tls\"}"), "{text}");
    assert!(text.contains("agf_ingest_mqtt_reconnects_total{receiver=\"mqtt\"}"), "{text}");
    println!("[mqtt] prometheus:\n{text}");
}

#[test]
fn receiver_from_source_requires_broker_topic_and_valid_qos() {
    let (pipeline, _sink) = pipeline_and_sink();
    assert!(MqttReceiver::from_source(Arc::clone(&pipeline), &log_source()).is_err());

    let mut source = log_source();
    source.connection.endpoint = Some("mqtts://127.0.0.1:8883".to_string());
    assert!(MqttReceiver::from_source(Arc::clone(&pipeline), &source).is_err(), "缺主题必须报错");

    source.connection.topic = Some("$share/agf/agf/sec/#".to_string());
    let mut headers = BTreeMap::new();
    headers.insert("qos".to_string(), "1".to_string());
    headers.insert("client.id".to_string(), "agf-it-mqtt".to_string());
    source.connection.headers = headers;
    // 明文端点：验证连接级参数的解析路径（TLS 材料装配另有专门用例覆盖）
    let mut plain = source.clone();
    plain.connection.endpoint = Some("mqtt://127.0.0.1:1883".to_string());
    let receiver = MqttReceiver::from_source(pipeline, &plain).expect("明文配置应可用");
    assert_eq!(receiver.topic(), "$share/agf/agf/sec/#");
    assert_eq!(receiver.qos(), 1);
    assert_eq!(
        receiver.plan().shared.as_ref().map(|s| s.group.clone()),
        Some("agf".to_string()),
        "共享订阅信息必须进订阅计划（/readyz 如实展示）"
    );
}

#[tokio::test]
async fn receiver_passes_the_shared_topic_to_the_subscription_layer() {
    let (subscription, sender) = RecordingSubscription::new(4);
    let (pipeline, sink) = pipeline_and_sink();
    let counters = Arc::new(ReceiverCounters::new());
    let receiver = Arc::new(
        MqttReceiver::new(
            Arc::clone(&pipeline),
            log_source(),
            "$share/agf-replicas/agf/sec/#",
            1,
            Arc::clone(&subscription) as Arc<dyn MqttSubscription>,
        )
        .with_counters(Arc::clone(&counters)),
    );

    let runner = {
        let receiver = Arc::clone(&receiver);
        tokio::spawn(async move {
            let _ = receiver.run().await;
        })
    };
    sender.send(MqttMessage::new("agf/sec/e2e", SYSLOG.to_vec(), 1, false)).await.expect("投递消息");
    let mut landed = 0;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(25)).await;
        landed = sink.event_count(TenantId::default_tenant()).await.unwrap_or(0);
        if landed > 0 {
            break;
        }
    }
    drop(sender);
    runner.abort();
    assert_eq!(landed, 1, "共享订阅通道里的消息必须落库");
    assert_eq!(
        subscription.topics().await,
        vec![("$share/agf-replicas/agf/sec/#".to_string(), 1)],
        "订阅层必须拿到完整的 $share 主题（broker 据此做同组竞争分发）"
    );
    assert_eq!(counters.snapshot().received, 1);
    println!("[mqtt] shared topic reached subscription layer; counters={:?}", counters.snapshot());
}

#[test]
fn describe_reports_tls_will_and_shared_state_honestly() {
    let endpoint = parse_endpoint("mqtts://broker.local:8883").expect("mqtts 端点");
    let Some((ca_pem, _, _)) = test_pki() else { return };
    let subscription = RumqttSubscription::new(endpoint, "agf-describe")
        .with_tls(MqttTlsMaterial { ca_pem: Some(ca_pem.into_bytes()), ..MqttTlsMaterial::default() })
        .with_will(MqttWill {
            topic: "agf/sec/collector-status".to_string(),
            payload: b"offline".to_vec(),
            qos: 1,
            retain: true,
        });
    let described = subscription.describe();
    assert!(described.contains("mqtts://broker.local:8883"), "{described}");
    assert!(described.contains("TLS 开启"), "{described}");
    assert!(described.contains("遗嘱 agf/sec/collector-status"), "{described}");
    assert!(subscription.tls_enabled());
    assert!(subscription.options().is_ok(), "TLS + 遗嘱选项必须可离线组装");
    println!("[mqtt] describe={described}");
}
