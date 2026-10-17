//! 原生 Pulsar 协议的**离线**单元测试（全部纯逻辑：帧编解码、CRC32C、batch、配置、退避）。
//!
//! 真机用例（需要 docker 里的 Pulsar broker）在 `crates/agf-ingest/tests/pulsar_native_live.rs`，
//! 未配置 `AGF_E2E_PULSAR_URL` 时自动 `#[ignore]`。
//!
//! 拆分（`pulsar/tests/` 子模块）：`ack.rs` ack 构造 / `config.rs` 配置与 topic / `lookup.rs` LOOKUP 与路由。
//!
//! 测试体内 `unwrap/expect/panic` 是**断言手法**（失败即用例失败），与本仓库其它测试模块同口径；
//! `match_wildcard_for_single_variants` 也显式放行：这里的 catch-all 分支是 `panic!`，
//! 一旦 `DecodedFrame` 新增变体会立刻炸出来——正是测试想要的行为。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::match_wildcard_for_single_variants)]

use super::batch::{self, BatchError, validation_error_for};
use super::client::{attempts_exhausted, backoff_delay};
use super::config::{
    ConfigError, PulsarAckMode, PulsarInitialPosition, PulsarNativeConfig, PulsarRoute, PulsarSubscriptionType,
    normalize_topic, parse_lookup_url, parse_pulsar_url, pulsar_route, topic_is_valid, topic_parts,
};
use super::frame::{
    self, DecodedFrame, FrameError, MAGIC_CRC32C, MAX_FRAME_BYTES, decode_frame, encode_command_frame,
    encode_message_frame, peek_frame_len,
};
use super::proto::{
    BaseCommand, CommandAck, CommandConnect, CommandFlow, CommandLookupTopic, CommandLookupTopicResponse,
    CommandSubscribe, KeyValue, MessageIdData, MessageMetadata, Schema, ServerError, SingleMessageMetadata, ack_type,
    command_type, compression_type, initial_position, lookup_type, schema_type, sub_type, validation_error,
};
use super::receiver::{ack_for_batch_error, cumulative_ack, individual_ack};
use prost::Message as _;
use std::time::Duration;

/// 造一条 `MessageMetadata`（producer/sequence/publish_time/properties 都填上，模拟真实消息）。
fn sample_metadata(batch: i32) -> MessageMetadata {
    MessageMetadata {
        producer_name: Some("agf-test-producer".to_string()),
        sequence_id: Some(7),
        publish_time: Some(1_700_000_000_123),
        properties: vec![
            KeyValue { key: Some("k1".to_string()), value: Some("v1".to_string()) },
            KeyValue { key: Some("k2".to_string()), value: Some("v2".to_string()) },
        ],
        partition_key: Some("key-a".to_string()),
        compression: Some(compression_type::NONE),
        uncompressed_size: Some(0),
        num_messages_in_batch: Some(batch),
        event_time: Some(1_700_000_000_456),
        partition_key_b64_encoded: Some(false),
        highest_sequence_id: Some(7),
    }
}

/// 造一个 batch 载荷（每条带 properties / sequence_id）。
fn build_batch(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (index, payload) in entries.iter().enumerate() {
        let meta = SingleMessageMetadata {
            properties: vec![KeyValue { key: Some(format!("idx{index}")), value: Some(payload.1.to_string()) }],
            partition_key: Some(format!("pk{index}")),
            payload_size: Some(i32::try_from(payload.0.len()).unwrap_or(0)),
            compacted_out: Some(false),
            event_time: Some(1_700_000_000_000 + index as u64),
            partition_key_b64_encoded: Some(false),
            sequence_id: Some(index as u64),
            null_value: Some(false),
        };
        let mut meta_buf = Vec::new();
        meta.encode(&mut meta_buf).expect("encode meta");
        out.extend_from_slice(&u32::try_from(meta_buf.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&meta_buf);
        out.extend_from_slice(payload.0.as_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// 1. proto / 字段号
// ---------------------------------------------------------------------------

/// `BaseCommand.type` 的字段号必须是 1、命令载荷必须落在 proto 定义的 tag 上——
/// 写错一个数字 broker 就整条读不出来，因此把它钉在测试里。
#[test]
fn proto_field_numbers_match_pulsar_api() {
    let connect = BaseCommand::connect(CommandConnect {
        client_version: Some("t".to_string()),
        auth_method: None,
        auth_data: None,
        protocol_version: Some(12),
        auth_method_name: None,
    });
    let bytes = connect.encode_to_vec();
    // tag 1 (type) → 0x08；tag 2 (connect) → 0x12
    assert_eq!(bytes[0], 0x08, "BaseCommand.type 必须是 tag 1 varint");
    assert_eq!(bytes[1], command_type::CONNECT as u8);
    assert_eq!(bytes[2], 0x12, "CommandConnect 必须是 tag 2 length-delimited");

    let ack = BaseCommand::ack(individual_ack(9, vec![MessageIdData::new(1, 0, -1)]));
    let bytes = ack.encode_to_vec();
    assert_eq!(bytes[0], 0x08);
    assert_eq!(bytes[1], command_type::ACK as u8);
    assert_eq!(bytes[2], 0x52, "CommandAck 必须是 tag 10（field 10 << 3 | 2）");
}

/// **proto2 required 零值必须显式写出**：`ack_type = Individual = 0` 若被省略，
/// broker 的 proto2 解析器会报 missing required fields（历史坑，故用 `Option`）。
#[test]
fn proto_optional_zero_values_are_encoded() {
    let ack = CommandAck {
        consumer_id: Some(0),
        ack_type: Some(ack_type::INDIVIDUAL),
        message_id: vec![MessageIdData::new(0, 0, 0)],
        validation_error: None,
    };
    let bytes = ack.encode_to_vec();
    // field2 (ack_type) tag = 2<<3|0 = 0x10, value 0 → 0x10 0x00 必须存在
    let has_ack_type_tag = bytes.windows(2).any(|pair| pair == [0x10, 0x00]);
    assert!(has_ack_type_tag, "ack_type=Individual(0) 必须显式编码，实际字节：{bytes:02x?}");

    // 反向：`None` 才不写
    let empty = CommandAck { consumer_id: Some(1), ack_type: None, message_id: Vec::new(), validation_error: None };
    assert!(!empty.encode_to_vec().windows(2).any(|pair| pair == [0x10, 0x00]));
}

// ---------------------------------------------------------------------------
// 2. 帧编解码往返
// ---------------------------------------------------------------------------

/// 命令帧往返：长度前缀 = 4 + cmdSize，解码后类型一致。
#[test]
fn command_frame_roundtrip() {
    let command = BaseCommand::subscribe(CommandSubscribe {
        topic: Some("persistent://public/default/agf".to_string()),
        subscription: Some("sub".to_string()),
        sub_type: Some(sub_type::SHARED),
        consumer_id: Some(11),
        request_id: Some(12),
        consumer_name: None,
        durable: Some(true),
        metadata: Vec::new(),
        read_compacted: Some(false),
        schema: None,
        initial_position: Some(initial_position::EARLIEST),
        force_topic_creation: Some(true),
    });
    let bytes = encode_command_frame(&command);
    assert_eq!(peek_frame_len(&bytes).expect("peek").expect("len"), bytes.len() - 4);
    match decode_frame(&bytes).expect("decode") {
        DecodedFrame::Command(decoded) => {
            assert_eq!(decoded.command_type(), command_type::SUBSCRIBE);
            let subscribe = decoded.subscribe.expect("subscribe");
            assert_eq!(subscribe.topic.as_deref(), Some("persistent://public/default/agf"));
            assert_eq!(subscribe.sub_type, Some(sub_type::SHARED));
            assert_eq!(subscribe.initial_position, Some(initial_position::EARLIEST));
        }
        other => panic!("期望命令帧，得到 {other:?}"),
    }
}

/// 消息帧往返：metadata 与 payload 都要保真，且 CRC32C 被校验通过。
#[test]
fn message_frame_roundtrip_with_checksum() {
    let metadata = sample_metadata(1);
    let payload = b"{\"msg\":\"hello agf\"}";
    let bytes =
        encode_message_frame(&BaseCommand::with_type(command_type::MESSAGE), &metadata, payload, true).expect("encode");
    assert_eq!(peek_frame_len(&bytes).expect("peek").expect("len"), bytes.len() - 4);
    // magic 出现在 metadataSize 之前的 2 字节
    let magic_at = bytes.windows(2).position(|pair| pair == MAGIC_CRC32C.to_be_bytes()).expect("magic");
    assert!(magic_at > 0);
    match decode_frame(&bytes).expect("decode") {
        DecodedFrame::Message { metadata: decoded, payload: got, checksummed, .. } => {
            assert!(checksummed);
            assert_eq!(got, payload);
            assert_eq!(decoded.sequence_id, Some(7));
            assert_eq!(decoded.producer_name.as_deref(), Some("agf-test-producer"));
            assert_eq!(decoded.publish_time, Some(1_700_000_000_123));
            assert_eq!(decoded.event_time, Some(1_700_000_000_456));
            assert_eq!(decoded.partition_key.as_deref(), Some("key-a"));
            let props = decoded.properties_map();
            assert_eq!(props.get("k1").map(String::as_str), Some("v1"));
            assert_eq!(props.get("k2").map(String::as_str), Some("v2"));
        }
        other => panic!("期望消息帧，得到 {other:?}"),
    }
}

/// CRC32C 被篡改 ⇒ **必须**报 `ChecksumMismatch`（而不是把损坏的消息当好消息交出去）。
#[test]
fn crc32c_mismatch_is_detected() {
    let mut bytes =
        encode_message_frame(&BaseCommand::with_type(command_type::MESSAGE), &sample_metadata(1), b"payload", true)
            .expect("encode");
    // 改 payload 的最后一个字节（CRC 覆盖 metadataSize+metadata+payload）
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    match decode_frame(&bytes) {
        Err(FrameError::ChecksumMismatch { expected, actual }) => assert_ne!(expected, actual),
        other => panic!("期望 ChecksumMismatch，得到 {other:?}"),
    }
}

/// 没有 checksum（`ChecksumType.None`）是**合法**的：必须能解出来并标 `checksummed=false`。
#[test]
fn message_frame_without_checksum_is_accepted() {
    let bytes = encode_message_frame(&BaseCommand::with_type(command_type::MESSAGE), &sample_metadata(1), b"x", false)
        .expect("encode");
    match decode_frame(&bytes).expect("decode") {
        DecodedFrame::Message { checksummed, payload, .. } => {
            assert!(!checksummed);
            assert_eq!(payload, b"x");
        }
        other => panic!("期望消息帧，得到 {other:?}"),
    }
}

/// 帧不完整 ⇒ `Truncated`（流式读取时"再等等"），不是致命错误。
#[test]
fn truncated_frame_reports_need_and_have() {
    let bytes =
        encode_message_frame(&BaseCommand::with_type(command_type::MESSAGE), &sample_metadata(1), b"abcdef", true)
            .expect("encode");
    let short = &bytes[..bytes.len() - 3];
    assert!(matches!(peek_frame_len(short), Ok(Some(_))));
    match decode_frame(short) {
        Err(FrameError::Truncated { need, have }) => {
            assert_eq!(need, bytes.len());
            assert_eq!(have, short.len());
        }
        other => panic!("期望 Truncated，得到 {other:?}"),
    }
    // 长度前缀本身不完整 ⇒ Ok(None)（继续等）
    assert_eq!(peek_frame_len(&bytes[..2]).expect("peek"), None);
}

/// 声明长度超限 ⇒ `TooLarge`（不能按该长度等下去，必须断开）。
#[test]
fn oversized_frame_is_rejected() {
    let mut prefix = Vec::new();
    prefix.extend_from_slice(&u32::try_from(MAX_FRAME_BYTES + 1).unwrap_or(u32::MAX).to_be_bytes());
    match peek_frame_len(&prefix) {
        Err(FrameError::TooLarge { size, max }) => {
            assert_eq!(size, MAX_FRAME_BYTES + 1);
            assert_eq!(max, MAX_FRAME_BYTES);
        }
        other => panic!("期望 TooLarge，得到 {other:?}"),
    }
}

/// 非消息帧的可选 **broker entry metadata**（MAGIC 0x0e02）必须被跳过而不是当成魔数错误。
#[test]
fn broker_entry_metadata_is_skipped() {
    let metadata = sample_metadata(1);
    let mut meta_buf = Vec::new();
    metadata.encode(&mut meta_buf).expect("encode meta");
    let payload = b"entry-metadata-case";
    let mut rest = Vec::new();
    // [BROKER_ENTRY_METADATA_MAGIC][SIZE][body]
    rest.extend_from_slice(&frame::MAGIC_BROKER_ENTRY_METADATA.to_be_bytes());
    rest.extend_from_slice(&3_u32.to_be_bytes());
    rest.extend_from_slice(b"be!");
    // [MAGIC][CHECKSUM][METADATA_SIZE][METADATA][PAYLOAD]
    let size_field = u32::try_from(meta_buf.len()).unwrap_or(0).to_be_bytes();
    rest.extend_from_slice(&MAGIC_CRC32C.to_be_bytes());
    rest.extend_from_slice(&frame::checksum_of(&size_field, &meta_buf, payload).to_be_bytes());
    rest.extend_from_slice(&size_field);
    rest.extend_from_slice(&meta_buf);
    rest.extend_from_slice(payload);

    let command = BaseCommand::with_type(command_type::MESSAGE);
    let cmd_size = command.encoded_len();
    let total = 4 + cmd_size + rest.len();
    let mut frame_bytes = Vec::new();
    frame_bytes.extend_from_slice(&u32::try_from(total).unwrap_or(0).to_be_bytes());
    frame_bytes.extend_from_slice(&u32::try_from(cmd_size).unwrap_or(0).to_be_bytes());
    command.encode(&mut frame_bytes).expect("encode command");
    frame_bytes.extend_from_slice(&rest);

    match decode_frame(&frame_bytes).expect("decode") {
        DecodedFrame::Message { payload: got, checksummed, .. } => {
            assert!(checksummed);
            assert_eq!(got, payload);
        }
        other => panic!("期望消息帧，得到 {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 3. batch 拆条
// ---------------------------------------------------------------------------

/// 3 条消息的 batch ⇒ 拆出 3 条，正文/属性/序号逐条对上。
#[test]
fn batch_split_returns_each_message() {
    let payload = build_batch(&[("first", "a"), ("second", "b"), ("third", "c")]);
    let entries = batch::split_batch(&payload).expect("split");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].payload, b"first");
    assert_eq!(entries[1].payload, b"second");
    assert_eq!(entries[2].payload, b"third");
    assert_eq!(entries[1].properties.get("idx1").map(String::as_str), Some("b"));
    assert_eq!(entries[2].partition_key.as_deref(), Some("pk2"));
    assert_eq!(entries[2].sequence_id, Some(2));
    assert_eq!(entries[0].event_time, Some(1_700_000_000_000));
    assert!(!entries[0].compacted_out);
    assert_eq!(batch::counted_entries(&entries), 3);
}

/// batch 载荷被截断 ⇒ `Malformed`（调用方按 BatchDeSerializeError 回执，不静默丢）。
#[test]
fn batch_split_detects_truncated_payload() {
    let payload = build_batch(&[("aaa", "a"), ("bbb", "b")]);
    let truncated = &payload[..payload.len() - 2];
    match batch::split_batch(truncated) {
        Err(BatchError::Malformed(reason)) => assert!(reason.contains("payload_size"), "原因：{reason}"),
        other => panic!("期望 Malformed，得到 {other:?}"),
    }
}

/// `compacted_out` 的条目不计数（Pulsar 语义：已被 compaction 淘汰）。
#[test]
fn compacted_out_entries_are_not_counted() {
    let mut out = Vec::new();
    for (index, compacted) in [(0_u32, false), (1, true)] {
        let meta = SingleMessageMetadata {
            properties: Vec::new(),
            partition_key: None,
            payload_size: Some(1),
            compacted_out: Some(compacted),
            event_time: None,
            partition_key_b64_encoded: None,
            sequence_id: Some(u64::from(index)),
            null_value: None,
        };
        let mut meta_buf = Vec::new();
        meta.encode(&mut meta_buf).expect("encode");
        out.extend_from_slice(&u32::try_from(meta_buf.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&meta_buf);
        out.push(b'x');
    }
    let entries = batch::split_batch(&out).expect("split");
    assert_eq!(entries.len(), 2);
    assert_eq!(batch::counted_entries(&entries), 1);
}

// ---------------------------------------------------------------------------
// 4. 压缩
// ---------------------------------------------------------------------------

/// ZLIB 往返（Pulsar 的 `CompressionType.ZLIB` 就是 zlib 流）。
#[test]
fn zlib_payload_is_decompressed() {
    use std::io::Write as _;
    let raw = b"hello zlib from agf pulsar native consumer";
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(raw).expect("write");
    let compressed = encoder.finish().expect("finish");
    let out = batch::decompress(compression_type::ZLIB, raw.len() as u32, &compressed).expect("decompress");
    assert_eq!(out, raw);
}

/// `uncompressed_size` 与实际不符 ⇒ 报错（不静默接受半截数据）。
#[test]
fn zlib_size_mismatch_is_rejected() {
    use std::io::Write as _;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(b"abc").expect("write");
    let compressed = encoder.finish().expect("finish");
    assert!(matches!(batch::decompress(compression_type::ZLIB, 999, &compressed), Err(BatchError::Decompress(_))));
}

/// LZ4/ZSTD/SNAPPY 未实现 ⇒ `UnsupportedCompression`，并映射到 `DecompressionError` 回执。
#[test]
fn unsupported_compression_maps_to_validation_error() {
    for code in [compression_type::LZ4, compression_type::ZSTD, compression_type::SNAPPY] {
        let error = batch::decompress(code, 0, b"x").expect_err("应未实现");
        assert_eq!(error, BatchError::UnsupportedCompression(code));
        assert_eq!(ack_for_batch_error(&error), validation_error::DECOMPRESSION_ERROR);
        assert_eq!(validation_error_for(code), Some(validation_error::DECOMPRESSION_ERROR));
    }
    assert_eq!(validation_error_for(compression_type::NONE), None);
    assert_eq!(validation_error_for(compression_type::ZLIB), None);
}

// ---------------------------------------------------------------------------
// 5. ServerError 分类
// ---------------------------------------------------------------------------

/// `CommandError` 分类：可重试 / 不可重试必须**逐条**正确（决定重连还是快速失败）。
#[test]
fn server_error_classification() {
    let cases: &[(i32, ServerError, bool)] = &[
        (4, ServerError::Authorization, false),
        (3, ServerError::Authentication, false),
        (11, ServerError::TopicNotFound, false),
        (17, ServerError::InvalidTopicName, false),
        (9, ServerError::Checksum, false),
        (12, ServerError::SubscriptionNotFound, false),
        (5, ServerError::ConsumerBusy, true),
        (6, ServerError::ServiceNotReady, true),
        (14, ServerError::TooManyRequests, true),
        (1, ServerError::Metadata, true),
        (2, ServerError::Persistence, true),
        (0, ServerError::Unknown, true),
        (99, ServerError::Other(99), true),
    ];
    for (code, expected, retryable) in cases {
        let parsed = ServerError::from_code(*code);
        assert_eq!(parsed, *expected, "错误码 {code} 分类错误");
        assert_eq!(parsed.code(), *code, "错误码 {code} 往返丢失");
        assert_eq!(parsed.retryable(), *retryable, "错误码 {code} 可重试性判定错误");
    }
}

/// `CommandError` 解出来之后分类一致（端到端：proto → 分类）。
#[test]
fn command_error_decodes_and_classifies() {
    let command = BaseCommand {
        error: Some(super::proto::CommandError {
            request_id: Some(5),
            error: Some(4),
            message: Some("not authorized".to_string()),
        }),
        ..BaseCommand::with_type(command_type::ERROR)
    };
    let bytes = encode_command_frame(&command);
    match decode_frame(&bytes).expect("decode") {
        DecodedFrame::Command(decoded) => {
            let error = decoded.error.expect("error");
            assert_eq!(error.server_error(), ServerError::Authorization);
            assert!(!error.server_error().retryable());
            assert_eq!(error.request_id, Some(5));
        }
        other => panic!("期望命令帧，得到 {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 6. 重连退避
// ---------------------------------------------------------------------------

/// 指数退避：逐次翻倍、封顶、且 `attempt` 溢出不会 panic。
#[test]
fn backoff_is_exponential_and_capped() {
    let initial = Duration::from_millis(500);
    let max = Duration::from_secs(30);
    assert_eq!(backoff_delay(0, initial, max), Duration::from_millis(500));
    assert_eq!(backoff_delay(1, initial, max), Duration::from_secs(1));
    assert_eq!(backoff_delay(2, initial, max), Duration::from_secs(2));
    assert_eq!(backoff_delay(5, initial, max), Duration::from_secs(16));
    assert_eq!(backoff_delay(6, initial, max), max, "第 6 次应已封顶 30s");
    assert_eq!(backoff_delay(1000, initial, max), max, "极大 attempt 必须封顶而不是溢出");
}

/// `max_attempts = 0` ⇒ 永不放弃；非 0 ⇒ 到点即放弃。
#[test]
fn attempts_exhausted_semantics() {
    assert!(!attempts_exhausted(1, 0));
    assert!(!attempts_exhausted(9999, 0));
    assert!(!attempts_exhausted(1, 3));
    assert!(attempts_exhausted(3, 3));
    assert!(attempts_exhausted(4, 3));
}

// ---------------------------------------------------------------------------
// 7. ack 构造 → `pulsar/tests/ack.rs`
// 8. 配置与 topic 解析 → `pulsar/tests/config.rs`
// 9/10. LOOKUP、路由与可读性标签 → `pulsar/tests/lookup.rs`
// ---------------------------------------------------------------------------

mod ack;
mod config;
mod lookup;
