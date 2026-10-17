//! 消费者协议（`ConsumerProtocolSubscription` / `ConsumerProtocolAssignment`）编解码与分配不变量自检。
//!
//! 这两个结构是**嵌在 JoinGroup/SyncGroup 的 `metadata` / `assignment` 字节串里**的子协议
//! （Kafka 官方称为 "consumer protocol"，Java 侧是 `ConsumerProtocol.serializeSubscription`），
//! 与 JoinGroup/SyncGroup 自身的 API 版本**相互独立**。这里固定写 **v0 正文**：
//! 只有 `topics[] / user_data` 与 `assigned_partitions[] / user_data`，
//! 是所有实现（含 KoP）都能解的最简形态；v1+ 的 `owned_partitions` / `generation_id` / `rack_id`
//! 属于"粘性分配（cooperative sticky）"，本接收器不实现。
//!
//! ## ⚠️ 线上格式：**必须先写 2 字节版本前缀**（真机踩坑，见 `tools/simulators/out/kafka-group-blocker.md`）
//!
//! 消费者协议的两个结构**不是**裸的 `kafka-protocol` 报文：Java 侧
//! `ConsumerProtocol.serializeSubscription/serializeAssignment` 走的是
//! `MessageUtil.toVersionPrefixedByteBuffer(version, message)` —— 即
//! `[version: int16 BE][按该版本编码的正文]`；读侧 `deserializeVersion(buffer)` 先吃掉这 2 字节，
//! 再按该版本解析正文。`kafka-protocol` 的 `ConsumerProtocolSubscription` struct
//! **没有** version 字段（上游 JSON schema 里它由 `MessageUtil` 单独写），
//! 所以只 `encode(&mut buf, 0)` 会**少写这 2 字节**。
//!
//! 少了前缀的后果不是"报个错"，而是**协调器静默卡死**（实测 `apache/kafka:3.9.0`）：
//! 协调器在 `GroupMetadata.computeSubscribedTopics()`（由 `GroupCoordinator.onCompleteJoin`
//! → `GroupMetadata.initNextGeneration()` 调用）里用
//! `deserializeVersion()` + `deserializeSubscription(buffer, 0)` 解析成员元数据，
//! 而 `kafka-protocol` 的 23 字节正文被读成"数组长度 65549" ⇒ 抛
//! `RuntimeException("Tried to allocate a collection of size ...")`。
//! 该异常**既不是 `BufferUnderflowException` 也不是 `SchemaException`**，两层 catch 都拦不住，
//! 于是异常从 `onCompleteJoin` 抛出：`Stabilized group` 日志不打印、join 回调不触发、
//! **响应永远不发**；成员只能等协调器的 `NewMemberJoinTimeoutMs` = 5 分钟（300000ms）被判死，
//! 客户端此时才收到 `UNKNOWN_MEMBER_ID(25)`。纯函数单测与"逐字段对照协议规范"都发现不了它，
//! 只有真机 + 官方解码器对照才能证伪。

use std::collections::BTreeMap;

use agf_core::error::{DomainError, DomainResult};
use bytes::{BufMut as _, Bytes, BytesMut};
use kafka_protocol::messages::consumer_protocol_assignment::TopicPartition as AssignmentTopicPartition;
use kafka_protocol::messages::sync_group_request::SyncGroupRequestAssignment;
use kafka_protocol::messages::{ConsumerProtocolAssignment, ConsumerProtocolSubscription, TopicName};
use kafka_protocol::protocol::{Decodable, Encodable, StrBytes};
use kafka_protocol::records::RecordBatchDecoder;

use super::assign::{AssignmentPlan, GroupMember, verify_plan};
use crate::kafka::KafkaRecord;

/// 消费者协议编码版本（见模块文档：正文固定 v0）。
const CONSUMER_PROTOCOL_VERSION: i16 = 0;

/// 版本前缀长度（`int16`，大端；Java `MessageUtil.toVersionPrefixedByteBuffer` 写的就是它）。
const CONSUMER_PROTOCOL_PREFIX_BYTES: usize = 2;

/// 能接受的最高消费者协议版本（`ConsumerProtocolSubscription.json` / `Assignment.json` 的
/// `validVersions` 上界）。**读侧必须容忍比自己高的版本**：Java 客户端默认就写 v3
/// （多出 `owned_partitions` / `generation_id` / `rack_id`），我们不实现粘性分配，
/// 但要能读出它订阅的 topic。
const CONSUMER_PROTOCOL_MAX_VERSION: i16 = 3;

/// 最小合法正文（`version=0` + 空数组 + `user_data=null`）：
/// 编码理论不可达失败时的**兜底**，保证协调器永远解得出（比半截/空字节串安全 —— 空字节串同样会让
/// 协调器的元数据解析抛异常）。
const CONSUMER_PROTOCOL_EMPTY_BODY: [u8; 10] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff];

/// 编码成员订阅元数据（`[version=0][ConsumerProtocolSubscription v0]`）。
pub(super) fn encode_subscription(topics: &[String]) -> Bytes {
    let mut subscription = ConsumerProtocolSubscription::default();
    subscription.topics = topics.iter().map(|topic| StrBytes::from_string(topic.clone())).collect();
    encode_or_empty(&subscription)
}

/// 解码成员订阅元数据 → topic 列表。
///
/// # Errors
/// 字节串不是合法的 `ConsumerProtocolSubscription`（缺版本前缀 / 版本不支持 / 正文损坏）。
pub(super) fn decode_subscription(metadata: &Bytes) -> DomainResult<Vec<String>> {
    let subscription: ConsumerProtocolSubscription = decode_versioned(metadata, "成员订阅元数据")?;
    Ok(subscription.topics.iter().map(ToString::to_string).collect())
}

/// 编码分区分配（`[version=0][ConsumerProtocolAssignment v0]`）。
pub(super) fn encode_assignment(assigned: &[(String, i32)]) -> Bytes {
    let mut grouped: BTreeMap<String, Vec<i32>> = BTreeMap::new();
    for (topic, partition) in assigned {
        grouped.entry(topic.clone()).or_default().push(*partition);
    }
    let assigned_partitions: Vec<AssignmentTopicPartition> = grouped
        .into_iter()
        .map(|(topic, partitions)| {
            let mut entry = AssignmentTopicPartition::default();
            entry.topic = TopicName(StrBytes::from_string(topic));
            entry.partitions = partitions;
            entry
        })
        .collect();
    let mut assignment = ConsumerProtocolAssignment::default();
    assignment.assigned_partitions = assigned_partitions;
    encode_or_empty(&assignment)
}

/// 编码失败（理论不可达：无外部输入、无长度溢出）时返回最小合法正文：
/// 协调器/组长会把"空订阅/空分配"理解为该成员不负责任何分区，比 panic 或半截字节串安全。
fn encode_or_empty<T: Encodable>(value: &T) -> Bytes {
    let mut buffer = BytesMut::with_capacity(64);
    buffer.put_i16(CONSUMER_PROTOCOL_VERSION);
    if value.encode(&mut buffer, CONSUMER_PROTOCOL_VERSION).is_err() {
        return Bytes::from_static(&CONSUMER_PROTOCOL_EMPTY_BODY);
    }
    buffer.freeze()
}

/// 校验并吃掉 2 字节版本前缀（**所有读取路径的唯一入口**）。
///
/// # Errors
/// 字节串短于前缀长度，或版本号超出 `0..=CONSUMER_PROTOCOL_MAX_VERSION`。
fn check_version_prefix(bytes: &Bytes, what: &str) -> DomainResult<()> {
    if bytes.len() < CONSUMER_PROTOCOL_PREFIX_BYTES {
        return Err(DomainError::Internal(format!(
            "{what} 缺 {CONSUMER_PROTOCOL_PREFIX_BYTES} 字节消费者协议版本前缀（实得 {} 字节）",
            bytes.len()
        )));
    }
    let version = i16::from_be_bytes([bytes[0], bytes[1]]);
    if !(CONSUMER_PROTOCOL_VERSION..=CONSUMER_PROTOCOL_MAX_VERSION).contains(&version) {
        return Err(DomainError::Internal(format!(
            "{what} 的消费者协议版本 {version} 不受支持（支持 {CONSUMER_PROTOCOL_VERSION}..={CONSUMER_PROTOCOL_MAX_VERSION}）"
        )));
    }
    Ok(())
}

/// 解码"+版本前缀"的消费者协议结构。
///
/// 正文**一律按 v0 解析**，与协调器同一口径（`GroupMetadata.computeSubscribedTopics` 的注释：
/// "The consumer protocol is parsed with V0 which is the based prefix of all versions"）：
/// v0 是所有后续版本的公共前缀，因此 Java 成员写出的 v1~v3 元数据也能读出订阅的 topic
/// （多出来的 `owned_partitions` / `generation_id` / `rack_id` 留在缓冲里，不影响解析）。
///
/// # Errors
/// 前缀非法，或正文不是合法的 v0 结构。
fn decode_versioned<T: Decodable>(bytes: &Bytes, what: &str) -> DomainResult<T> {
    check_version_prefix(bytes, what)?;
    let mut body = bytes.slice(CONSUMER_PROTOCOL_PREFIX_BYTES..);
    T::decode(&mut body, CONSUMER_PROTOCOL_VERSION).map_err(|e| DomainError::Internal(format!("{what} 解码失败: {e}")))
}

/// 解码协调器下发给**本成员**的分配。
///
/// # Errors
/// 字节串不是合法的 `ConsumerProtocolAssignment`（缺版本前缀 / 版本不支持 / 正文损坏）。
pub(super) fn decode_assignment(assignment: &Bytes) -> DomainResult<Vec<(String, i32)>> {
    let decoded: ConsumerProtocolAssignment = decode_versioned(assignment, "SyncGroup 分配")?;
    let mut out = Vec::new();
    for topic in &decoded.assigned_partitions {
        for partition in &topic.partitions {
            out.push((topic.topic.to_string(), *partition));
        }
    }
    Ok(out)
}

/// 分配不变量自检 + 编码成 SyncGroup 的下发体（组长的最后一道闸）。
///
/// 为什么必须在**下发之前**校验：一旦把重叠/遗漏的分配写进 `__consumer_offsets` 的组状态，
/// 协调器会以它为真，表现为两个成员消费同一分区（重复）或某分区无人消费（滞后无界）。
/// 校验失败 ⇒ 返回 `Err` ⇒ 不 `SyncGroup`，协调器超时后重新 rebalance（宁可重来，不要脏分配）。
///
/// # Errors
/// 分配重叠或遗漏，或编码失败。
pub(super) fn verify_and_encode(
    plan: &AssignmentPlan,
    members: &[GroupMember],
    topic_partitions: &BTreeMap<String, Vec<i32>>,
) -> DomainResult<Vec<SyncGroupRequestAssignment>> {
    verify_plan(plan, members, topic_partitions)?;
    Ok(plan
        .iter()
        .map(|(member_id, assigned)| {
            let mut entry = SyncGroupRequestAssignment::default();
            entry.member_id = StrBytes::from_string(member_id.clone());
            entry.assignment = encode_assignment(assigned);
            entry
        })
        .collect())
}

/// record batch → 接收器内部记录（含压缩解压；`kafka-protocol` 的 gzip/snappy/lz4/zstd 四个特性均已开启）。
///
/// # Errors
/// record batch 结构非法或压缩算法不被支持。
pub(super) fn decode_records(bytes: Bytes) -> DomainResult<Vec<KafkaRecord>> {
    let mut buffer = bytes;
    let sets = RecordBatchDecoder::decode_all(&mut buffer).map_err(|e| DomainError::DependencyUnavailable {
        dependency: "kafka".to_string(),
        cause: format!("解析 Fetch 响应中的 record batch 失败: {e}"),
    })?;
    let mut records = Vec::new();
    for set in sets {
        for record in set.records {
            records.push(KafkaRecord {
                offset: record.offset,
                key: record.key.map(|key| key.to_vec()),
                value: record.value.map(|value| value.to_vec()),
                timestamp_millis: Some(record.timestamp),
            });
        }
    }
    Ok(records)
}
