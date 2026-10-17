//! WebSocket / MQTT 5 传输与属性用例：ws URL 解析、Transport 选择、topic alias 解析、
//! 属性透传、`ws://` + TLS 的矛盾配置拒绝。
//!
//! 真机（mosquitto `protocol websockets` + MQTT5）见 `tools/simulators/run_mqtt_ws_v5_e2e.ps1`
//! 与 `tests/mqtt_ws_v5_live.rs`。

use super::*;
use crate::pipeline::{InMemorySink, IngestConfig, IngestPipeline, Sink};
use crate::registry::ParserRegistry;
use agf_core::enums::HealthState;
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, SourceConnection};
use agf_core::time::Timestamp;
use rumqttc::Transport;
use rumqttc::v5::mqttbytes::v5::RetainForwardRule;

fn log_source() -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "mqtt-ws-v5".to_string(),
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
        Arc::new(crate::bus::NoopEventBus),
        IngestConfig { emit_to_bus: false, ..IngestConfig::default() },
    );
    (Arc::new(pipeline), sink)
}

/// 传输层判定结果：`(tcp, tls, ws, wss)`。
///
/// **不比较 `Transport` 本身**：`rumqttc::Transport` 只派生 `Clone`（无 `Debug`/`PartialEq`），
/// 因此在测试里按变体解构成布尔量再断言。
type TransportFlags = (bool, bool, bool, bool);

fn transport_flags(endpoint: &str, tls: Option<MqttTlsMaterial>) -> Result<TransportFlags, String> {
    let parsed = parse_endpoint(endpoint).map_err(|e| e.to_string())?;
    let mut subscription = RumqttSubscription::new(parsed, "agf-ws-test");
    if let Some(material) = tls {
        subscription = subscription.with_tls(material);
    }
    let options = subscription.options().map_err(|e| e.to_string())?;
    let transport = options.transport();
    Ok((
        matches!(transport, Transport::Tcp),
        matches!(transport, Transport::Tls(_)),
        matches!(transport, Transport::Ws),
        matches!(transport, Transport::Wss(_)),
    ))
}

#[test]
fn websocket_urls_parse_into_full_rumqttc_addresses() {
    // ws：明文 WebSocket，默认端口 80、默认路径 /mqtt
    let Some(ws) = parse_endpoint("ws://broker.local:9001").ok() else { return };
    assert!(ws.websocket && !ws.tls);
    assert_eq!(ws.scheme(), "ws");
    assert_eq!(ws.port, 9001);
    assert_eq!(ws.path, DEFAULT_WS_PATH);
    assert_eq!(ws.broker_address(), "ws://broker.local:9001/mqtt", "rumqttc 需要完整 URL");
    assert_eq!(ws.describe(), "ws://broker.local:9001");

    // wss：TLS WebSocket，默认端口 443
    let Some(wss) = parse_endpoint("wss://broker.local").ok() else { return };
    assert!(wss.websocket && wss.tls);
    assert_eq!(wss.scheme(), "wss");
    assert_eq!(wss.port, 443);
    assert_eq!(wss.broker_address(), "wss://broker.local:443/mqtt");

    // 显式路径必须原样保留（代理/网关常按路径分流）
    let Some(custom) = parse_endpoint("ws://broker.local:9001/agf/ingest").ok() else { return };
    assert_eq!(custom.path, "/agf/ingest");
    assert_eq!(custom.broker_address(), "ws://broker.local:9001/agf/ingest");

    // 非 WS 端点：broker_address 仍只是主机（TCP/TLS 走 host+port 两个字段）
    let Some(tcp) = parse_endpoint("mqtt://broker.local:1883").ok() else { return };
    assert!(!tcp.websocket);
    assert_eq!(tcp.broker_address(), "broker.local");
    assert_eq!(tcp.path, "");
    let Some(tls) = parse_endpoint("mqtts://broker.local").ok() else { return };
    assert_eq!(tls.scheme(), "mqtts");
    assert_eq!(tls.broker_address(), "broker.local");
    // 非法 WS 端点仍然报错
    assert!(matches!(parse_endpoint("ws://:9001"), Err(DomainError::Config(_))));
    assert!(matches!(parse_endpoint("ws://broker:abc"), Err(DomainError::Config(_))));
    assert!(matches!(parse_endpoint("ws://"), Err(DomainError::Config(_))));
}

#[test]
fn transport_selection_covers_tcp_tls_ws_and_wss() {
    // 明文 TCP
    assert_eq!(transport_flags("mqtt://broker:1883", None), Ok((true, false, false, false)));
    // 明文 WebSocket（以前是 NotImplemented，现在必须真的走 Ws）
    assert_eq!(transport_flags("ws://broker:9001", None), Ok((false, false, true, false)));
    // 无需 TLS 材料的 mqtts 会明确报错；ws 不会
    assert!(transport_flags("mqtts://broker:8883", None).is_err());

    // wss 有材料 ⇒ Wss；没有材料 ⇒ 明确报错（绝不静默降级成明文 ws）
    let material = MqttTlsMaterial { insecure_skip_verify: true, ..MqttTlsMaterial::default() };
    assert_eq!(transport_flags("wss://broker:9002", Some(material.clone())), Ok((false, false, false, true)));
    assert!(transport_flags("wss://broker:9002", None).is_err());
    // mqtts + 材料 ⇒ 经典 Tcp+TLS
    assert_eq!(transport_flags("mqtts://broker:8883", Some(material.clone())), Ok((false, true, false, false)));
    // ws + TLS 材料 = 矛盾配置 ⇒ 明确拒绝（要加密请用 wss://）
    let conflict = transport_flags("ws://broker:9001", Some(material));
    assert!(conflict.is_err(), "{conflict:?}");
    assert!(conflict.err().unwrap_or_default().contains("wss://"), "错误必须点名 wss://");
}

#[test]
fn v5_options_carry_session_expiry_alias_receive_maximum_and_properties() {
    let Some(endpoint) = parse_endpoint("mqtt://broker.local:1883").ok() else { return };
    let v5 = MqttV5Config {
        session_expiry_secs: Some(7200),
        clean_start: false,
        topic_alias_max: 16,
        receive_maximum: Some(32),
        subscribe: SubscribeOptions {
            no_local: true,
            retain_as_published: true,
            retain_handling: RetainHandling::Never,
        },
        user_properties: vec![("site".to_string(), "hg".to_string())],
        configured: vec![ENV_SESSION_EXPIRY_SECS],
    };
    let subscription = RumqttV5Subscription::new(endpoint, "agf-v5-test").with_v5(v5);
    let options = subscription.options();
    assert!(options.is_ok(), "{:?}", options.as_ref().err().map(ToString::to_string));
    let Ok(options) = options else { return };
    // CONNECT 属性：会话过期 / Receive Maximum / Topic Alias / 用户属性 都必须真的下发
    assert!(!options.clean_start(), "CleanStart=false 必须下发（否则会话永远重建）");
    assert!(options.connect_properties().is_some(), "v5 属性必须落在 CONNECT 上");
    assert_eq!(options.session_expiry_interval(), Some(7200));
    assert_eq!(options.receive_maximum(), Some(32));
    assert_eq!(options.topic_alias_max(), Some(16), "声明的 topic_alias_maximum 必须下发");
    assert_eq!(options.user_properties(), vec![("site".to_string(), "hg".to_string())]);
    assert_eq!(options.broker_address(), ("broker.local".to_string(), 1883));

    // 订阅过滤器：NoLocal / RetainAsPublished / RetainHandling 逐位映射
    let filter = subscription.filter("$share/agf/agf/sec/#", 2);
    assert_eq!(filter.path, "$share/agf/agf/sec/#");
    assert_eq!(qos_to_u8_v5(filter.qos), 2);
    assert!(filter.nolocal, "NoLocal 必须进 SUBSCRIBE 选项");
    assert!(filter.preserve_retain, "RetainAsPublished 必须进 SUBSCRIBE 选项");
    assert_eq!(filter.retain_forward_rule, RetainForwardRule::Never);
    assert!(subscription.describe().contains("MQTT 5"), "{}", subscription.describe());

    // 默认（未配置）时：不下发任何 v5 属性，但仍声明 clean start = true
    let Some(default_endpoint) = parse_endpoint("mqtt://broker:1883").ok() else { return };
    let plain = RumqttV5Subscription::new(default_endpoint, "agf-v5-default");
    let Ok(options) = plain.options() else { return };
    assert!(options.clean_start());
    assert_eq!(options.session_expiry_interval(), None);
    assert_eq!(options.receive_maximum(), None);
    assert_eq!(options.topic_alias_max(), None, "topic_alias_max=0 时不下发（= 不接受别名）");
    assert!(options.user_properties().is_empty());
    let filter = plain.filter("agf/sec/#", 1);
    assert!(!filter.nolocal && !filter.preserve_retain);
    assert_eq!(filter.retain_forward_rule, RetainForwardRule::OnEverySubscribe);
}

#[test]
fn v5_endpoint_and_ws_combine_into_wss() {
    // v5 + wss：TLS 材料 + WebSocket + v5 特性三者可同时成立
    let Some(endpoint) = parse_endpoint("wss://broker.local:9002").ok() else { return };
    let subscription = RumqttV5Subscription::new(endpoint, "agf-v5-wss")
        .with_tls(MqttTlsMaterial { insecure_skip_verify: true, ..MqttTlsMaterial::default() })
        .with_will(MqttWill { topic: "agf/sec/status".to_string(), payload: b"offline".to_vec(), qos: 1, retain: true })
        .with_v5(MqttV5Config { topic_alias_max: 4, ..MqttV5Config::default() });
    let options = subscription.options();
    assert!(options.is_ok(), "{:?}", options.as_ref().err().map(ToString::to_string));
    let Ok(options) = options else { return };
    assert_eq!(options.broker_address().0, "wss://broker.local:9002/mqtt", "WS 必须拿完整 URL");
    assert!(matches!(options.transport(), Transport::Wss(_)));
    assert!(!matches!(options.transport(), Transport::Tcp | Transport::Ws));
    assert!(options.last_will().is_some(), "v5 遗嘱必须挂在选项上");
    assert_eq!(options.topic_alias_max(), Some(4));
    assert!(subscription.describe().contains("wss://"), "{}", subscription.describe());
    assert!(subscription.describe().contains("遗嘱 agf/sec/status"), "{}", subscription.describe());

    // 明文 ws + v5：Transport::Ws（绝不能被当成明文 TCP 连接）
    let Some(plain_endpoint) = parse_endpoint("ws://broker:9001").ok() else { return };
    let plain = RumqttV5Subscription::new(plain_endpoint, "agf-v5-ws");
    let Ok(options) = plain.options() else { return };
    assert_eq!(options.broker_address().0, "ws://broker:9001/mqtt");
    assert!(matches!(options.transport(), Transport::Ws));
    assert!(!matches!(options.transport(), Transport::Tcp));

    // 明文 ws + TLS 材料：同样是矛盾配置 ⇒ 报错
    let Some(conflict_endpoint) = parse_endpoint("ws://broker:9001").ok() else { return };
    let conflict = RumqttV5Subscription::new(conflict_endpoint, "agf-v5-conflict")
        .with_tls(MqttTlsMaterial { insecure_skip_verify: true, ..MqttTlsMaterial::default() })
        .options();
    assert!(matches!(conflict, Err(DomainError::Config(_))), "{conflict:?}");
}

#[test]
fn topic_alias_table_follows_the_v5_rules() {
    let mut table = TopicAliasTable::new(8);
    assert_eq!(table.max(), 8);
    assert!(table.is_empty());

    // ① 无别名：原样使用
    assert_eq!(table.resolve("agf/sec/a", None), Ok("agf/sec/a".to_string()));
    assert!(table.is_empty());
    // ② 有主题 + 别名：登记
    assert_eq!(table.resolve("agf/sec/a", Some(3)), Ok("agf/sec/a".to_string()));
    assert_eq!(table.len(), 1);
    // ③ 只有别名：用登记的映射
    assert_eq!(table.resolve("", Some(3)), Ok("agf/sec/a".to_string()));
    // ④ 别名可以改指向（broker 复用同一别名指向新主题）
    assert_eq!(table.resolve("agf/sec/b", Some(3)), Ok("agf/sec/b".to_string()));
    assert_eq!(table.resolve("", Some(3)), Ok("agf/sec/b".to_string()));
    // ⑤ 未登记的别名：协议错误（绝不猜主题）
    assert_eq!(table.resolve("", Some(5)), Err(TopicAliasError::Unknown(5)));
    // ⑥ 越界：别名 0 / 超过我方声明上限
    assert_eq!(table.resolve("", Some(0)), Err(TopicAliasError::OutOfRange { alias: 0, max: 8 }));
    assert_eq!(table.resolve("agf/x", Some(9)), Err(TopicAliasError::OutOfRange { alias: 9, max: 8 }));
    // ⑦ 无主题也无别名：畸形
    assert_eq!(table.resolve("", None), Err(TopicAliasError::MissingTopic));
    // ⑧ 未声明别名（max=0）⇒ 任何别名都越界
    let mut disabled = TopicAliasTable::new(0);
    assert_eq!(disabled.resolve("agf/x", Some(1)), Err(TopicAliasError::OutOfRange { alias: 1, max: 0 }));
    assert_eq!(disabled.resolve("agf/x", None), Ok("agf/x".to_string()));
    // 错误文本可读（进日志）且类别稳定（进指标标签）
    assert_eq!(TopicAliasError::Unknown(3).as_str(), "unknown_alias");
    assert_eq!(TopicAliasError::OutOfRange { alias: 9, max: 8 }.as_str(), "alias_out_of_range");
    assert_eq!(TopicAliasError::MissingTopic.as_str(), "missing_topic");
    assert!(TopicAliasError::OutOfRange { alias: 9, max: 8 }.to_string().contains("越界"));
}

#[test]
fn v5_properties_are_preserved_and_passed_through_origin() {
    let properties = MqttMessageProperties {
        topic_alias: Some(7),
        message_expiry_interval: Some(60),
        content_type: Some("application/json".to_string()),
        response_topic: Some("agf/resp".to_string()),
        correlation_data: Some("AQID".to_string()),
        payload_format_indicator: Some(1),
        subscription_identifiers: vec![1, 2],
        user_properties: vec![("site".to_string(), "shanghai".to_string()), ("note".to_string(), "a&b=c".to_string())],
    };
    assert!(!properties.is_empty());
    let query = properties.to_origin_query().unwrap_or_default();
    for needle in [
        "agf.mqtt.topic_alias=7",
        "agf.mqtt.message_expiry_interval=60",
        "agf.mqtt.content_type=application%2Fjson",
        "agf.mqtt.response_topic=agf%2Fresp",
        "agf.mqtt.correlation_data=AQID",
        "agf.mqtt.payload_format_indicator=1",
        "agf.mqtt.subscription_identifier=1",
        "agf.mqtt.subscription_identifier=2",
        "agf.mqtt.up.site=shanghai",
        "agf.mqtt.up.note=a%26b%3Dc",
    ] {
        assert!(query.contains(needle), "缺少 {needle}: {query}");
    }
    assert!(properties.describe().contains("topic_alias=7"));
    assert!(properties.describe().contains("user_properties=2"));

    // v5 无属性 / v3.1.1：不产生查询串（既有 origin 形状不变）
    assert!(MqttMessageProperties::default().is_empty());
    assert_eq!(MqttMessageProperties::default().to_origin_query(), None);
    let legacy = MqttMessage::new("agf/sec/a", b"x".to_vec(), 1, false);
    assert_eq!(legacy.origin("broker:1883"), "mqtt://broker:1883/agf/sec/a");
    let with_props = legacy.clone().with_properties(properties);
    let origin = with_props.origin("ws://broker:9001/mqtt");
    assert!(origin.starts_with("mqtt://ws://broker:9001/mqtt/agf/sec/a?"), "{origin}");
    assert!(origin.contains("agf.mqtt.topic_alias=7"), "{origin}");
    assert_eq!(with_props.topic, "agf/sec/a");
    assert!(!with_props.retain);

    // v5 连接上的 origin 额外带 qos/retain —— RetainAsPublished 的真实效果必须可被外部观测
    let facts = with_props.origin_with_facts("ws://broker:9001/mqtt (client_id=agf)");
    assert!(facts.contains("agf.mqtt.qos=1"), "{facts}");
    assert!(facts.contains("agf.mqtt.retain=false"), "{facts}");
    assert!(facts.contains("agf.mqtt.topic_alias=7"), "{facts}");
    let retained = MqttMessage::new("agf/sec/r", b"x".to_vec(), 0, true);
    let facts = retained.origin_with_facts("ws://broker:9001/mqtt");
    assert!(facts.contains("agf.mqtt.retain=true"), "{facts}");
    assert!(facts.contains("agf.mqtt.qos=0"), "{facts}");
    assert!(facts.starts_with("mqtt://ws://broker:9001/mqtt/agf/sec/r?"), "{facts}");
}

/// 属性透传到**事件**：`origin` → `extra["log.origin"]`（v5 用户属性不丢）。
#[tokio::test]
async fn v5_user_properties_reach_the_stored_event_origin() {
    let (pipeline, sink) = pipeline_and_sink();
    let source = log_source();
    let properties = MqttMessageProperties {
        user_properties: vec![("site".to_string(), "shanghai".to_string())],
        content_type: Some("text/plain".to_string()),
        ..MqttMessageProperties::default()
    };
    let message = MqttMessage::new(
        "agf/sec/events",
        b"<34>Feb 21 10:23:45 ws-prod-01 sshd[2311]: Failed password for root from 203.0.113.9 port 5123 ssh2".to_vec(),
        1,
        true,
    )
    .with_properties(properties);
    let origin = message.origin("ws://broker:9001/mqtt (client_id=agf-v5)");
    assert!(origin.contains("agf.mqtt.up.site=shanghai"), "{origin}");
    let outcomes = pipeline.ingest_batch(&source, IngestProtocol::Mqtt, &[(message.payload.clone(), origin)]).await;
    assert!(outcomes.is_ok(), "{:?}", outcomes.as_ref().err().map(ToString::to_string));
    let events = sink.events().unwrap_or_default();
    assert_eq!(events.len(), 1, "消息必须落库");
    let extra = events.first().map(|e| e.extra.clone()).unwrap_or_default();
    let stored = extra.get("log.origin").and_then(serde_json::Value::as_str).unwrap_or_default().to_string();
    assert!(stored.contains("agf.mqtt.up.site=shanghai"), "用户属性必须随 origin 落在事件 extra：{stored}");
    assert!(stored.contains("agf.mqtt.content_type=text%2Fplain"), "{stored}");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1));
}
