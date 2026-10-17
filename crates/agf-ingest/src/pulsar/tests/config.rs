//! 配置与 topic 解析的离线单测（从 `pulsar/tests.rs` 拆出，见该文件的模块说明）。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::match_wildcard_for_single_variants)]

use super::*;

/// topic 归一化：短名补全、完整名保留、`tenant/ns/topic` 补 domain。
#[test]
fn topic_normalization() {
    assert_eq!(normalize_topic("agf-native"), "persistent://public/default/agf-native");
    assert_eq!(normalize_topic("  agf-native  "), "persistent://public/default/agf-native");
    assert_eq!(normalize_topic("persistent://public/default/x"), "persistent://public/default/x");
    assert_eq!(normalize_topic("non-persistent://public/default/x"), "non-persistent://public/default/x");
    assert_eq!(normalize_topic("public/default/x"), "persistent://public/default/x");
    assert_eq!(normalize_topic(""), "");

    let parts = topic_parts("agf-native").expect("parts");
    assert_eq!(parts.tenant, "public");
    assert_eq!(parts.namespace, "default");
    assert_eq!(parts.topic, "agf-native");
    assert_eq!(parts.domain, "persistent");
    assert_eq!(parts.full(), "persistent://public/default/agf-native");
    assert!(topic_is_valid("persistent://public/default/x"));
    // 短名在**归一化之后**是合法的（`normalize_topic("x")` = persistent://public/default/x）
    assert!(topic_is_valid("x"));
    // 但真正畸形的写法必须被判非法（缺 tenant/namespace 段）
    assert!(!topic_is_valid("persistent://public//x"));
    assert!(!topic_is_valid("persistent://public/default/"));
    assert!(!topic_is_valid(""));
}

/// URL 解析：明文 / TLS / 多端点 / 各类非法写法。
#[test]
fn pulsar_url_parsing() {
    let (endpoints, tls) = parse_pulsar_url("pulsar://127.0.0.1:6650").expect("parse");
    assert!(!tls);
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].authority(), "127.0.0.1:6650");

    let (endpoints, tls) = parse_pulsar_url("pulsar+ssl://pulsar.example:6651/").expect("parse");
    assert!(tls);
    assert_eq!(endpoints[0].port, 6651);

    let (endpoints, _) = parse_pulsar_url("pulsar://a:6650, pulsar://b:6651").expect("parse");
    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[1].host, "b");

    // KoP 的 kafka:// 必须被明确拒绝（不能静默按 6650 连）
    assert!(matches!(parse_pulsar_url("kafka://host:19092"), Err(ConfigError::BadUrl(_))));
    assert!(matches!(parse_pulsar_url("pulsar://host"), Err(ConfigError::BadUrl(_))));
    assert!(matches!(parse_pulsar_url(""), Err(ConfigError::Missing(_))));
    assert!(matches!(parse_pulsar_url("pulsar://a:6650,"), Err(ConfigError::BadUrl(_))));
}

/// 配置校验：许可数为 0、退避倒置、mTLS 不成对、明文 URL + 证书都必须报错。
#[test]
fn config_validation_rules() {
    let mut config = PulsarNativeConfig::new("pulsar://127.0.0.1:6650", "agf-native").expect("config");
    assert_eq!(config.subscription, "agf-ingest");
    assert_eq!(config.subscription_type, PulsarSubscriptionType::Exclusive);
    assert_eq!(config.initial_position, PulsarInitialPosition::Latest);
    assert_eq!(config.ack_mode, PulsarAckMode::Individual);
    assert_eq!(config.receiver_queue_size, 1000);
    assert!(config.batch_split);
    assert!(config.validate().is_ok());

    config.receiver_queue_size = 0;
    assert!(matches!(config.validate(), Err(ConfigError::InvalidValue { field: "RECEIVER_QUEUE_SIZE", .. })));
    config.receiver_queue_size = 100;

    config.reconnect_initial = Duration::from_secs(10);
    config.reconnect_max = Duration::from_secs(1);
    assert!(matches!(config.validate(), Err(ConfigError::InvalidValue { field: "RECONNECT_MAX_MS", .. })));
    config.reconnect_initial = Duration::from_millis(500);
    config.reconnect_max = Duration::from_secs(30);

    config.tls_cert = Some(std::path::PathBuf::from("c.pem"));
    assert!(matches!(config.validate(), Err(ConfigError::IncompleteTls(_))));
    config.tls_cert = None;

    config.tls_key = Some(std::path::PathBuf::from("k.pem"));
    assert!(matches!(config.validate(), Err(ConfigError::IncompleteTls(_))));
    config.tls_key = None;

    config.tls_ca = Some(std::path::PathBuf::from("ca.pem"));
    assert!(matches!(config.validate(), Err(ConfigError::IncompleteTls(_))), "明文 URL 配证书必须报错");
    config.tls_ca = None;

    config.subscription = "  ".to_string();
    assert!(matches!(config.validate(), Err(ConfigError::Missing(_))));
}

/// 枚举解析：合法取值 + 非法取值报错。
#[test]
fn enum_parsing() {
    assert_eq!(PulsarSubscriptionType::parse("SHARED").expect("shared"), PulsarSubscriptionType::Shared);
    assert_eq!(PulsarSubscriptionType::parse("key-shared").expect("ks"), PulsarSubscriptionType::KeyShared);
    assert_eq!(PulsarSubscriptionType::parse("Key_Shared").expect("ks"), PulsarSubscriptionType::KeyShared);
    assert_eq!(PulsarSubscriptionType::Shared.as_i32(), sub_type::SHARED);
    assert_eq!(PulsarSubscriptionType::Exclusive.as_i32(), sub_type::EXCLUSIVE);
    assert_eq!(PulsarSubscriptionType::Failover.as_i32(), sub_type::FAILOVER);
    assert!(PulsarSubscriptionType::parse("nope").is_err());

    assert_eq!(PulsarInitialPosition::parse("earliest").expect("e").as_i32(), initial_position::EARLIEST);
    assert_eq!(PulsarInitialPosition::parse("LATEST").expect("l").as_i32(), initial_position::LATEST);
    assert!(PulsarInitialPosition::parse("now").is_err());

    assert_eq!(PulsarAckMode::parse("cumulative").expect("c").as_i32(), ack_type::CUMULATIVE);
    assert_eq!(PulsarAckMode::parse("INDIVIDUAL").expect("i").as_i32(), ack_type::INDIVIDUAL);
    assert!(PulsarAckMode::parse("bulk").is_err());
}

/// 多端点轮换（重连时换 broker），且 `describe()` 里**不得出现凭据**。
#[test]
fn endpoint_rotation() {
    let config = PulsarNativeConfig::new("pulsar://a:6650,pulsar://b:6650", "t").expect("config");
    assert_eq!(config.endpoint_for_attempt(0).expect("0").host, "a");
    assert_eq!(config.endpoint_for_attempt(1).expect("1").host, "b");
    assert_eq!(config.endpoint_for_attempt(2).expect("2").host, "a");
    let mut with_token = config.clone();
    with_token.token = Some("secret-jwt".to_string());
    assert!(!with_token.describe().contains("secret-jwt"));
}

/// `describe()` 必须如实带出关键参数（能力矩阵渲染依赖它）。
#[test]
fn config_describe_is_honest() {
    let mut config = PulsarNativeConfig::new("pulsar://127.0.0.1:6650", "agf-native").expect("config");
    config.subscription_type = PulsarSubscriptionType::Shared;
    config.initial_position = PulsarInitialPosition::Earliest;
    config.batch_split = false;
    let text = config.describe();
    assert!(text.contains("persistent://public/default/agf-native"), "{text}");
    assert!(text.contains("sub_type=shared"), "{text}");
    assert!(text.contains("initial=earliest"), "{text}");
    assert!(text.contains("batch=whole"), "{text}");
}

/// **SUBSCRIBE 帧不得携带 `schema` 字段**（真机回归：给已有 `bytes` schema 的 topic 声明
/// `Schema{type=NONE}` 会被 broker 拒绝 —— `Failed to add schema to an active topic with
/// empty(BYTES) schema: new schema type NONE`）。
#[test]
fn subscribe_frame_carries_no_schema() {
    let subscribe = CommandSubscribe {
        topic: Some("persistent://public/default/agf-native".to_string()),
        subscription: Some("sub".to_string()),
        sub_type: Some(sub_type::EXCLUSIVE),
        consumer_id: Some(1),
        request_id: Some(2),
        consumer_name: None,
        durable: Some(true),
        metadata: Vec::new(),
        read_compacted: Some(false),
        schema: None,
        initial_position: Some(initial_position::EARLIEST),
        force_topic_creation: Some(true),
    };
    assert!(subscribe.schema.is_none());
    let bytes = encode_command_frame(&BaseCommand::subscribe(subscribe.clone()));
    match decode_frame(&bytes).expect("decode") {
        DecodedFrame::Command(command) => {
            assert!(command.subscribe.expect("subscribe").schema.is_none(), "不得携带 schema");
        }
        other => panic!("期望命令帧，得到 {other:?}"),
    }
    // 差分对照：**带** schema 的同一条订阅一定更长（proto tag 12 = 0x62 + 长度 + 正文），
    // 这比"在字节流里找 0x62"可靠 —— topic 名里本来就可能出现 0x62。
    let mut with_schema = subscribe;
    with_schema.schema = Some(Schema {
        name: Some("x".to_string()),
        schema_data: Some(Vec::new()),
        r#type: Some(schema_type::NONE),
        properties: Vec::new(),
    });
    assert!(
        encode_command_frame(&BaseCommand::subscribe(with_schema)).len() > bytes.len(),
        "带 schema 的 SUBSCRIBE 必须更长（证明 schema 字段确实被省略了）"
    );
}
