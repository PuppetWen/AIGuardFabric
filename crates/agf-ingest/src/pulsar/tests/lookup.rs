//! LOOKUP、路由与可读性标签的离线单测（从 `pulsar/tests.rs` 拆出，见该文件的模块说明）。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::match_wildcard_for_single_variants)]

use super::*;

/// `CommandLookupTopic` 必须落在 tag 23，`CommandLookupTopicResponse` 在 tag 24。
#[test]
fn lookup_command_roundtrip() {
    let command = BaseCommand::lookup(CommandLookupTopic {
        topic: Some("persistent://public/default/x".to_string()),
        request_id: Some(7),
        authoritative: Some(true),
    });
    let bytes = encode_command_frame(&command);
    match decode_frame(&bytes).expect("decode") {
        DecodedFrame::Command(decoded) => {
            assert_eq!(decoded.command_type(), command_type::LOOKUP);
            let lookup = decoded.lookup_topic.expect("lookup");
            assert_eq!(lookup.request_id, Some(7));
            assert_eq!(lookup.authoritative, Some(true));
            assert_eq!(lookup.topic.as_deref(), Some("persistent://public/default/x"));
        }
        other => panic!("期望命令帧，得到 {other:?}"),
    }
    // tag 23 << 3 | 2 = 0xba 0x01（两字节 varint）
    let raw = command.encode_to_vec();
    assert!(raw.starts_with(&[0x08, command_type::LOOKUP as u8]), "raw={raw:02x?}");
    assert!(raw.windows(2).any(|pair| pair == [0xba, 0x01]), "CommandLookupTopic 必须是 tag 23");
}

/// LOOKUP 应答分类：Connect / Redirect / Failed，以及 TLS 地址优先。
#[test]
fn lookup_response_classification() {
    let make = |response: i32, plain: Option<&str>, tls: Option<&str>| CommandLookupTopicResponse {
        broker_service_url: plain.map(ToString::to_string),
        broker_service_url_tls: tls.map(ToString::to_string),
        response: Some(response),
        request_id: Some(1),
        authoritative: Some(false),
        error: None,
        message: None,
        proxy_through_service_url: None,
    };
    assert_eq!(make(lookup_type::CONNECT, Some("pulsar://a:6650"), None).lookup_type(), lookup_type::CONNECT);
    let redirect = make(lookup_type::REDIRECT, Some("pulsar://a:6650"), Some("pulsar+ssl://a:6651"));
    assert_eq!(redirect.lookup_type(), lookup_type::REDIRECT);
    assert_eq!(redirect.best_broker_url(), Some("pulsar+ssl://a:6651"), "TLS 地址优先");
    let plain_only = make(lookup_type::REDIRECT, Some("pulsar://a:6650"), Some(""));
    assert_eq!(plain_only.best_broker_url(), Some("pulsar://a:6650"));
    // 缺失 response ⇒ 按 Failed 处理（宁可失败也不瞎连）
    let mut missing = make(lookup_type::FAILED, None, None);
    missing.response = None;
    assert_eq!(missing.lookup_type(), lookup_type::FAILED);
    assert_eq!(missing.best_broker_url(), None);
}

/// LOOKUP 重定向 URL 解析（TLS 判定、裸 host:port、非法输入）。
#[test]
fn lookup_url_parsing() {
    let (endpoint, tls) = parse_lookup_url("pulsar://127.0.0.1:6650").expect("parse");
    assert_eq!(endpoint.authority(), "127.0.0.1:6650");
    assert!(!tls);
    let (endpoint, tls) = parse_lookup_url("pulsar+ssl://broker.internal:6651/").expect("parse");
    assert_eq!(endpoint.host, "broker.internal");
    assert!(tls);
    let (endpoint, tls) = parse_lookup_url("10.0.0.9:6650").expect("parse");
    assert_eq!(endpoint.port, 6650);
    assert!(!tls);
    assert!(parse_lookup_url("kafka://x:9092").is_none());
    assert!(parse_lookup_url("pulsar://noport").is_none());
    assert!(parse_lookup_url("").is_none());
}

/// 原生 URL 优先、KoP 兜底的路由判定（与既有 KoP 路径并存的判据）。
#[test]
fn pulsar_route_priority() {
    assert_eq!(pulsar_route(Some("pulsar://a:6650"), None), PulsarRoute::Native);
    assert_eq!(pulsar_route(Some("pulsar://a:6650"), Some("kafka://b:9092")), PulsarRoute::Native);
    assert_eq!(pulsar_route(None, Some("kafka://b:9092")), PulsarRoute::Kop);
    assert_eq!(pulsar_route(Some("  "), Some(" kafka://b:9092 ")), PulsarRoute::Kop);
    assert_eq!(pulsar_route(None, None), PulsarRoute::Disabled);
    assert_eq!(pulsar_route(Some(""), Some("")), PulsarRoute::Disabled);
    assert_eq!(PulsarRoute::Native.as_str(), "native");
    assert_eq!(PulsarRoute::Kop.as_str(), "kop");
    assert_eq!(PulsarRoute::Disabled.as_str(), "disabled");
}

/// 能力矩阵行：未配置 ⇒ `not-wired`（不是 `not-implemented`）；配置非法 ⇒ `not-wired` 且带原因。
#[test]
fn capability_row_is_honest() {
    let missing = super::super::config::pulsar_native_descriptor(None);
    assert_eq!(missing.name, "pulsar-native");
    assert_eq!(missing.status, crate::receiver::ReceiverStatus::NotWired);
    assert!(missing.note.contains("已实现"), "note 必须写明代码已实现：{}", missing.note);
    assert!(missing.note.contains("AGF_INGEST_PULSAR_URL"), "note 必须写明缺哪个变量：{}", missing.note);
    assert!(missing.todo.is_some());
    // 空白取值与未配置等价 ⇒ 同样 not-wired
    assert_eq!(
        super::super::config::pulsar_native_descriptor(Some("   ")).status,
        crate::receiver::ReceiverStatus::NotWired
    );
}

/// 命令类型名与压缩名（日志/指标标签正确性）。
#[test]
fn type_names_are_readable() {
    assert_eq!(super::super::proto::base_command_type_name(command_type::MESSAGE), "MESSAGE");
    assert_eq!(super::super::proto::base_command_type_name(command_type::CLOSE_CONSUMER), "CLOSE_CONSUMER");
    assert_eq!(super::super::proto::base_command_type_name(999), "unknown(999)");
    assert_eq!(frame::compression_name(compression_type::ZLIB), "ZLIB");
    assert_eq!(frame::compression_name(99), "UNKNOWN");
    assert!(frame::compression_supported(compression_type::ZLIB));
    assert!(!frame::compression_supported(compression_type::SNAPPY));
    assert_eq!(BaseCommand::with_type(command_type::PING).type_name(), "PING");
}

/// 消息元数据的 batch 计数与属性映射（batch=0/1 都按单条处理）。
///
/// 注意用**本项目定义**的 `batch_len()` / `compression_kind()`：prost 会为 `optional` 字段
/// 生成同名访问器（`num_messages_in_batch()` / `compression()`），返回的是原始 `Option`。
#[test]
fn metadata_batch_and_properties() {
    let mut metadata = sample_metadata(4);
    assert_eq!(metadata.batch_len(), 4);
    metadata.num_messages_in_batch = Some(1);
    assert_eq!(metadata.batch_len(), 1);
    metadata.num_messages_in_batch = Some(0);
    assert_eq!(metadata.batch_len(), 1);
    metadata.num_messages_in_batch = None;
    assert_eq!(metadata.batch_len(), 1);
    metadata.compression = None;
    assert_eq!(metadata.compression_kind(), compression_type::NONE);
    let props = metadata.properties_map();
    assert_eq!(props.len(), 2);
    assert!(props.contains_key("k1"));
}

/// `should_replenish`：信用降到一半以下才补 FLOW。
#[test]
fn flow_replenish_threshold() {
    use super::super::client::PulsarClient;
    assert!(PulsarClient::should_replenish(499, 1000));
    assert!(!PulsarClient::should_replenish(500, 1000));
    assert!(!PulsarClient::should_replenish(999, 1000));
    assert!(PulsarClient::should_replenish(0, 1000));
}
