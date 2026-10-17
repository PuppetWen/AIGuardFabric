//! MQTT 单元测试：环境表/假订阅夹具与端点、共享订阅、TLS、遗嘱、退避、链路指标用例（接收器用例见 `receiver` 子模块）。

use super::*;
use crate::bus::NoopEventBus;
use crate::pipeline::{InMemorySink, IngestConfig, Sink};
use crate::registry::ParserRegistry;
use agf_core::enums::HealthState;
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, SourceConnection};
use agf_core::time::Timestamp;
use std::collections::BTreeMap;

const SYSLOG: &[u8] =
    b"<34>Feb 21 10:23:45 web-prod-01 sshd[2311]: Failed password for root from 203.0.113.77 port 51234 ssh2";

/// 测试用环境变量表（拥有所有权，避免与临时集合的生命周期纠缠）。
struct EnvMap(BTreeMap<String, String>);

impl EnvMap {
    fn new(pairs: &[(&str, &str)]) -> Self {
        Self(pairs.iter().map(|(key, value)| ((*key).to_string(), (*value).to_string())).collect())
    }

    /// 从进程环境过滤出 MQTT 相关项（**只读**，不修改进程环境）。
    fn from_process() -> Self {
        let mut map = BTreeMap::new();
        for key in [
            ENV_TLS,
            ENV_TLS_CA,
            ENV_TLS_CERT,
            ENV_TLS_KEY,
            ENV_TLS_INSECURE_SKIP_VERIFY,
            ENV_WILL_TOPIC,
            ENV_WILL_PAYLOAD,
            ENV_WILL_QOS,
            ENV_WILL_RETAIN,
            ENV_RECONNECT_INITIAL_SECS,
            ENV_RECONNECT_MAX_SECS,
            ENV_PROTOCOL_VERSION,
            ENV_CLEAN_START,
            ENV_SESSION_EXPIRY_SECS,
            ENV_TOPIC_ALIAS_MAX,
            ENV_RECEIVE_MAXIMUM,
            ENV_SUBSCRIBE_NOLOCAL,
            ENV_SUBSCRIBE_RETAIN_AS_PUBLISHED,
            ENV_SUBSCRIBE_RETAIN_HANDLING,
            ENV_USER_PROPERTIES,
        ] {
            if let Ok(value) = std::env::var(key) {
                map.insert(key.to_string(), value);
            }
        }
        Self(map)
    }

    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
}

/// 内存订阅：测试直接把消息推进通道（无需 broker）。
#[derive(Debug)]
struct FakeSubscription {
    receiver: tokio::sync::Mutex<Option<mpsc::Receiver<MqttMessage>>>,
    topic_seen: tokio::sync::Mutex<Vec<(String, u8)>>,
}

impl FakeSubscription {
    fn new(capacity: usize) -> (Arc<Self>, mpsc::Sender<MqttMessage>) {
        let (sender, receiver) = mpsc::channel(capacity);
        let subscription = Arc::new(Self {
            receiver: tokio::sync::Mutex::new(Some(receiver)),
            topic_seen: tokio::sync::Mutex::new(Vec::new()),
        });
        (subscription, sender)
    }
}

#[async_trait]
impl MqttSubscription for FakeSubscription {
    async fn subscribe(&self, topic: &str, qos: u8) -> DomainResult<mpsc::Receiver<MqttMessage>> {
        self.topic_seen.lock().await.push((topic.to_string(), qos));
        let mut guard = self.receiver.lock().await;
        guard.take().ok_or_else(|| DomainError::Conflict("订阅通道已被取走（每个接收器只订阅一次）".to_string()))
    }

    fn describe(&self) -> String {
        "memory://mqtt".to_string()
    }
}

fn log_source() -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "mqtt-test".to_string(),
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

/// 自签 CA + 由该 CA 签发的服务端证书（**测试内生成、不落盘**）。
fn test_pki() -> Option<(String, String, String)> {
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).ok()?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, "agf-mqtt-test-ca");
    let ca_key = rcgen::KeyPair::generate().ok()?;
    let ca_cert = ca_params.self_signed(&ca_key).ok()?;
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);

    let server_params = rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).ok()?;
    let server_key = rcgen::KeyPair::generate().ok()?;
    let server_cert = server_params.signed_by(&server_key, &issuer).ok()?;
    Some((ca_cert.pem(), server_cert.pem(), server_key.serialize_pem()))
}

#[test]
fn broker_endpoint_parsing_is_strict() {
    let ok = parse_endpoint("mqtt://127.0.0.1:1883");
    assert_eq!(
        ok.ok(),
        Some(MqttEndpoint {
            host: "127.0.0.1".to_string(),
            port: 1883,
            tls: false,
            websocket: false,
            path: String::new(),
        })
    );
    assert_eq!(parse_endpoint("broker.local").ok().map(|e| e.port), Some(1883));
    assert_eq!(parse_endpoint("tcp://broker:1884/logs").ok().map(|e| e.port), Some(1884));
    assert!(parse_endpoint("").is_err());
    assert!(matches!(parse_endpoint("mqtt://:1883"), Err(DomainError::Config(_))));
    assert!(matches!(parse_endpoint("mqtt://host:abc"), Err(DomainError::Config(_))));
    // TLS scheme 是**真实支持**的：解析出 tls=true、默认端口 8883
    assert_eq!(
        parse_endpoint("mqtts://broker:8883").ok(),
        Some(MqttEndpoint { host: "broker".to_string(), port: 8883, tls: true, websocket: false, path: String::new() })
    );
    assert_eq!(parse_endpoint("mqtts://broker").ok().map(|e| e.port), Some(8883));
    assert_eq!(parse_endpoint("ssl://broker").ok().map(|e| e.tls), Some(true));
    assert_eq!(parse_endpoint("tls://broker:9883").ok().map(|e| e.port), Some(9883));
    // WebSocket：解析为 websocket=true + 默认路径 /mqtt（真实接线，不再是 NotImplemented）
    let ws = parse_endpoint("ws://broker:9001");
    assert_eq!(
        ws.ok(),
        Some(MqttEndpoint {
            host: "broker".to_string(),
            port: 9001,
            tls: false,
            websocket: true,
            path: DEFAULT_WS_PATH.to_string(),
        })
    );
    assert_eq!(parse_endpoint("ws://broker").ok().map(|e| e.port), Some(80));
    assert_eq!(parse_endpoint("wss://broker").ok().map(|e| e.port), Some(443));
    assert_eq!(parse_endpoint("wss://broker:9002").ok().map(|e| e.tls), Some(true));
    assert_eq!(parse_endpoint("ws://broker:9001/custom/ws").ok().map(|e| e.path), Some("/custom/ws".to_string()));
    assert!(matches!(parse_endpoint("amqp://broker:5672"), Err(DomainError::Config(_))));
    assert_eq!(qos_to_u8(qos_from_u8(0)), 0);
    assert_eq!(qos_to_u8(qos_from_u8(1)), 1);
    assert_eq!(qos_to_u8(qos_from_u8(2)), 2);
    assert_eq!(qos_to_u8(qos_from_u8(9)), 1, "越界 QoS 回退为 AtLeastOnce");
    // MQTT 5 的 QoS 是另一个枚举：映射必须一致
    assert_eq!(qos_to_u8_v5(qos_from_u8_v5(0)), 0);
    assert_eq!(qos_to_u8_v5(qos_from_u8_v5(2)), 2);
    assert_eq!(qos_to_u8_v5(qos_from_u8_v5(9)), 1);
}

#[test]
fn shared_subscription_parsing_accepts_valid_and_rejects_invalid() {
    assert_eq!(parse_shared_subscription("agf/sec/#").ok().flatten(), None, "普通主题不是共享订阅");
    let shared = parse_shared_subscription("$share/agf-ingest/agf/sec/#");
    assert_eq!(
        shared.ok().flatten(),
        Some(SharedSubscription { group: "agf-ingest".to_string(), filter: "agf/sec/#".to_string() })
    );
    let plan = plan_subscribe("$share/g1/agf/+/alarm", 2);
    assert_eq!(
        plan.ok(),
        Some(SubscribePlan {
            topic: "$share/g1/agf/+/alarm".to_string(),
            shared: Some(SharedSubscription { group: "g1".to_string(), filter: "agf/+/alarm".to_string() }),
            qos: 2,
        })
    );
    for bad in [
        "$share/",
        "$share/g1",
        "$share//agf/#",
        "$share/g1/",
        "$share/g1/#/x",
        "$share/g1/a/#/b",
        "$share/g+/a",
        "$share/g#/a",
        "$share/g1/$share/g2/a",
        "$share/g1/a+b",
    ] {
        let parsed = parse_shared_subscription(bad);
        assert!(parsed.is_err(), "{bad} 必须被判为非法共享订阅：{parsed:?}");
    }
    assert!(plan_subscribe("", 1).is_err(), "空主题必须报错");
    assert!(plan_subscribe("agf/#", 3).is_err(), "越界 QoS 必须报错");
    // 普通主题的非法形态只 warn（保持既有行为），共享订阅的非法形态才硬失败
    let loose = plan_subscribe("agf/#/x", 1);
    assert!(loose.is_ok(), "{loose:?}");
    assert_eq!(loose.ok().map(|p| p.topic), Some("agf/#/x".to_string()));
    assert!(validate_topic_filter("$SYS/#").is_ok());
    assert!(validate_topic_filter("a/b/c").is_ok());
    assert!(validate_topic_filter("#").is_ok());
    assert!(validate_topic_filter("a/#/b").is_err());
    assert!(validate_topic_filter("a/b#").is_err());
    assert!(validate_topic_filter("+a/b").is_err());
    assert!(validate_topic_filter("").is_err());
}

#[test]
fn tls_config_parsing_and_validation() {
    let empty = EnvMap::new(&[]);
    let off = MqttTlsConfig::from_lookup(|key| empty.get(key));
    assert!(!off.enabled);
    assert!(off.ca_pem.is_none());
    assert!(!off.insecure_skip_verify);
    assert!(off.describe().contains("明文"), "{}", off.describe());
    assert!(off.describe().contains("WebSocket"), "明文描述必须同时覆盖 ws:// 明文的语义: {}", off.describe());

    let env = EnvMap::new(&[
        (ENV_TLS, "1"),
        (ENV_TLS_CA, "C:/certs/ca.pem"),
        (ENV_TLS_CERT, "C:/certs/client.pem"),
        (ENV_TLS_KEY, "C:/certs/client.key"),
        (ENV_TLS_INSECURE_SKIP_VERIFY, "yes"),
    ]);
    let on = MqttTlsConfig::from_lookup(|key| env.get(key));
    assert!(on.enabled);
    assert_eq!(on.ca_pem.as_deref(), Some(Path::new("C:/certs/ca.pem")));
    assert_eq!(on.client_cert_pem.as_deref(), Some(Path::new("C:/certs/client.pem")));
    assert!(on.insecure_skip_verify);
    assert!(on.validate().is_ok());
    let described = on.describe();
    assert!(described.contains("mTLS=开启"), "{described}");
    assert!(described.contains("证书链校验已跳过"), "{described}");
    assert!(!described.contains("client.key"), "描述里不得出现私钥路径: {described}");

    // mTLS 必须成对：只给证书 ⇒ 明确报错（不静默变成"不带客户端证书"）
    let half = EnvMap::new(&[(ENV_TLS, "1"), (ENV_TLS_CERT, "C:/certs/client.pem")]);
    let half = MqttTlsConfig::from_lookup(|key| half.get(key));
    assert!(matches!(half.validate(), Err(DomainError::Config(_))));
    assert!(matches!(half.load(), Err(DomainError::Config(_))));

    // 未提供 CA 时用内置公共根证书（不是"不校验"）
    let no_ca = EnvMap::new(&[(ENV_TLS, "1")]);
    let no_ca = MqttTlsConfig::from_lookup(|key| no_ca.get(key));
    assert!(no_ca.describe().contains("webpki"), "{}", no_ca.describe());

    // 不可读的 PEM 路径必须明确报错（不静默降级）
    let missing = EnvMap::new(&[(ENV_TLS, "1"), (ENV_TLS_CA, "C:/definitely/missing/ca.pem")]);
    let missing = MqttTlsConfig::from_lookup(|key| missing.get(key));
    assert!(matches!(missing.load(), Err(DomainError::Config(_))));
}

#[test]
fn tls_scheme_enables_tls_and_material_assembles_transport() {
    let endpoint = parse_endpoint("mqtts://broker:8883");
    assert!(endpoint.is_ok(), "{endpoint:?}");
    let Ok(endpoint) = endpoint else { return };
    let config = MqttTlsConfig::default().for_scheme(&endpoint);
    assert!(config.enabled, "mqtts:// 必须自动启用 TLS");

    let Some((ca_pem, cert_pem, key_pem)) = test_pki() else { return };
    let material = MqttTlsMaterial {
        ca_pem: Some(ca_pem.clone().into_bytes()),
        client_cert_pem: Some(cert_pem.into_bytes()),
        client_key_pem: Some(key_pem.into_bytes()),
        insecure_skip_verify: false,
    };
    let transport = material.transport();
    assert!(
        transport.is_ok(),
        "TLS 传输层装配失败: {}",
        transport.as_ref().err().map(ToString::to_string).unwrap_or_default()
    );
    let debug = format!("{material:?}");
    assert!(!debug.contains("BEGIN"), "Debug 输出必须隐藏 PEM 内容: {debug}");
    assert!(debug.contains("<PEM:REDACTED>"), "{debug}");

    // 跳过校验：装配也必须成功（自定义校验器路径）
    let skip =
        MqttTlsMaterial { ca_pem: None, client_cert_pem: None, client_key_pem: None, insecure_skip_verify: true };
    assert!(skip.transport().is_ok());
    // CA 内容非法 ⇒ 明确报错
    let broken = MqttTlsMaterial { ca_pem: Some(b"not a pem".to_vec()), ..MqttTlsMaterial::default() };
    assert!(matches!(broken.transport(), Err(DomainError::Config(_))));

    // 离线组装 MqttOptions：TLS 已真正挂上（不发起任何连接）
    let subscription = RumqttSubscription::new(endpoint, "agf-tls-test")
        .with_credentials("agf-user", "s3cret-pw")
        .with_tls(material)
        .with_will(MqttWill {
            topic: "agf/sec/collector-status".to_string(),
            payload: b"offline".to_vec(),
            qos: 1,
            retain: true,
        });
    let options = subscription.options();
    assert!(options.is_ok(), "{options:?}");
    assert!(subscription.tls_enabled());
    assert!(subscription.describe().contains("mqtts://"));
    assert!(subscription.describe().contains("TLS 开启"));
    assert!(subscription.describe().contains("遗嘱 agf/sec/collector-status"));
    let debug = format!("{subscription:?}");
    assert!(!debug.contains("s3cret-pw"), "口令绝不能进 Debug: {debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
}

#[test]
fn will_config_mapping_is_explicit() {
    let none = EnvMap::new(&[]);
    assert_eq!(MqttWill::from_lookup(|key| none.get(key)), None);

    // 只有载荷/QoS 而没有主题：不注册遗嘱（并 warn），绝不猜主题
    let partial = EnvMap::new(&[(ENV_WILL_PAYLOAD, "bye"), (ENV_WILL_QOS, "2")]);
    assert_eq!(MqttWill::from_lookup(|key| partial.get(key)), None);

    let env = EnvMap::new(&[
        (ENV_WILL_TOPIC, "agf/sec/collector-status"),
        (ENV_WILL_PAYLOAD, "collector-gone"),
        (ENV_WILL_QOS, "2"),
        (ENV_WILL_RETAIN, "1"),
    ]);
    let will = MqttWill::from_lookup(|key| env.get(key));
    assert_eq!(
        will,
        Some(MqttWill {
            topic: "agf/sec/collector-status".to_string(),
            payload: b"collector-gone".to_vec(),
            qos: 2,
            retain: true,
        })
    );
    let Some(will) = will else { return };
    assert!(will.describe().contains("retain=true"));
    let last_will = will.to_last_will();
    assert_eq!(last_will.topic, "agf/sec/collector-status");
    assert_eq!(last_will.message, b"collector-gone"[..], "LastWill 载荷字段名为 message（rumqttc v4）");
    assert_eq!(qos_to_u8(last_will.qos), 2);
    assert!(last_will.retain);

    // 默认值：QoS 1、retain false、默认载荷；越界 QoS 回退 1
    let defaults = EnvMap::new(&[(ENV_WILL_TOPIC, "t/offline"), (ENV_WILL_QOS, "9")]);
    let will = MqttWill::from_lookup(|key| defaults.get(key));
    let Some(will) = will else { return };
    assert_eq!(will.qos, 1, "越界 QoS 必须回退 1");
    assert!(!will.retain);
    assert_eq!(will.payload, DEFAULT_WILL_PAYLOAD.as_bytes());
}

#[test]
fn backoff_state_machine_is_deterministic() {
    let mut backoff = BackoffPolicy::new(1, 30);
    assert_eq!(backoff.bounds_secs(), (1, 30));
    let sequence: Vec<u64> = (0..8).map(|_| backoff.next_delay().as_secs()).collect();
    assert_eq!(sequence, vec![1, 2, 4, 8, 16, 30, 30, 30], "指数退避必须封顶");
    backoff.reset();
    assert_eq!(backoff.current_secs(), 1);
    assert_eq!(backoff.next_delay().as_secs(), 1);

    // 非法/颠倒的参数被收敛（max < initial ⇒ 取 initial；0 ⇒ 至少 1）
    let degenerate = BackoffPolicy::new(0, 0);
    assert_eq!(degenerate.bounds_secs(), (1, 1));
    let inverted = BackoffPolicy::new(5, 2);
    assert_eq!(inverted.bounds_secs(), (5, 5));

    let env = EnvMap::new(&[(ENV_RECONNECT_INITIAL_SECS, "2"), (ENV_RECONNECT_MAX_SECS, "8")]);
    let from_env = BackoffPolicy::from_lookup(|key| env.get(key));
    assert_eq!(from_env.bounds_secs(), (2, 8));
    let broken = EnvMap::new(&[(ENV_RECONNECT_INITIAL_SECS, "abc")]);
    assert_eq!(BackoffPolicy::from_lookup(|key| broken.get(key)).bounds_secs(), (1, 30));
}

#[test]
fn link_error_classification_and_prometheus_text() {
    assert_eq!(classify_link_error("TLS: Web Pki: invalid peer certificate"), MqttLinkError::Tls);
    assert_eq!(classify_link_error("TLS: No valid CA certificate provided"), MqttLinkError::Tls);
    assert_eq!(classify_link_error("Connection refused, return code: `NotAuthorized`"), MqttLinkError::Auth);
    assert_eq!(classify_link_error("Connection refused, return code: `BadUsernameOrPassword`"), MqttLinkError::Auth);
    assert_eq!(classify_link_error("I/O: connection refused"), MqttLinkError::Network);
    assert_eq!(classify_link_error("Network timeout"), MqttLinkError::Network);
    assert_eq!(classify_link_error("Mqtt state: Expected ConnAck packet"), MqttLinkError::Protocol);
    assert_eq!(classify_link_error("something else entirely"), MqttLinkError::Other);

    let counters = MqttLinkCounters::new();
    counters.record_error(MqttLinkError::Tls);
    counters.record_error(MqttLinkError::Tls);
    counters.record_error(MqttLinkError::Auth);
    counters.record_reconnect();
    let snapshot = counters.snapshot();
    assert_eq!(snapshot.tls_errors, 2);
    assert_eq!(snapshot.auth_errors, 1);
    assert_eq!(snapshot.total_errors(), 3);
    assert_eq!(snapshot.reconnects, 1);
    assert_eq!(snapshot.errors(MqttLinkError::Network), 0);

    // 进程内单例：同一份计数器 + Prometheus 文本五类齐全
    let first = link_counters();
    first.record_error(MqttLinkError::Auth);
    assert_eq!(link_counters().snapshot().auth_errors, first.snapshot().auth_errors, "单例必须共享");
    let text = link_prometheus();
    assert!(text.contains("# TYPE agf_ingest_mqtt_link_errors_total counter"), "{text}");
    assert!(text.contains("agf_ingest_mqtt_reconnects_total{receiver=\"mqtt\"}"), "{text}");
    for kind in ["tls", "auth", "network", "protocol", "other"] {
        assert!(text.contains(&format!("kind=\"{kind}\"")), "缺少类别 {kind}: {text}");
    }
}

mod protocol;
mod receiver;
mod websocket;
