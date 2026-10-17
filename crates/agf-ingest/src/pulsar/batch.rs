//! 消息载荷处理：**压缩解压**（`NONE` / `ZLIB`）与 **batch 拆条**。
//!
//! ## batch 载荷布局（`Commands.deSerializeSingleMessageInBatch`）
//!
//! `MessageMetadata.num_messages_in_batch > 1` 时，payload 不是一条日志，而是 N 条：
//!
//! ```text
//! [SINGLE_META_SIZE u32 BE][SingleMessageMetadata][正文 payload_size 字节]  × num_messages_in_batch
//! ```
//!
//! 拆条后每条都有**自己的** `properties` / `partition_key` / `event_time` / `sequence_id`，
//! 与单条消息的语义完全一致（差异只在 `MessageIdData.batch_index`）。
//!
//! ## `AGF_INGEST_PULSAR_BATCH=0`（如实说明）
//!
//! 关掉后**不拆条**：整段 batch payload 作为**一条**原始报文选进流水线（`origin` 上加
//! `#batch` 后缀），条数计数为 1。这是"宁可粗粒度也不猜坏结构"的保守降级，
//! 指标 `agf_ingest_pulsar_batch_split_disabled` 会显式计数（不静默）。
//! 默认**开启**（`=1`），因为拆条是 Pulsar 官方语义，不拆会丢属性/丢事件边界。
//!
//! ## 压缩（如实说明）
//!
//! * 已实现：`NONE`、`ZLIB`（`flate2`，Pulsar 的 `CompressionCodecZlib` 就是 zlib 格式）；
//! * **未实现**：`LZ4` / `ZSTD` / `SNAPPY` ⇒ 返回 [`BatchError::UnsupportedCompression`]，
//!   由调用方按 `CommandAck.validation_error = DecompressionError` 显式回执并计数
//!   （**不静默丢**，也不会让 broker 无限重投同一条）。

use std::collections::BTreeMap;
use std::io::Read as _;

use prost::Message as _;

use super::proto::{SingleMessageMetadata, command_type, compression_type};

/// batch / 压缩处理错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchError {
    /// 压缩类型未实现（LZ4 / ZSTD / SNAPPY）。
    UnsupportedCompression(i32),
    /// 解压失败（zlib 流损坏或 `uncompressed_size` 与实际不符）。
    Decompress(String),
    /// batch 载荷结构损坏（缺 `SINGLE_META_SIZE` / `payload_size` / 正文不够）。
    Malformed(String),
}

impl std::fmt::Display for BatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedCompression(code) => write!(
                f,
                "Pulsar 压缩类型 {}（{code}）未实现（已实现 NONE/ZLIB）",
                super::frame::compression_name(*code)
            ),
            Self::Decompress(reason) => write!(f, "Pulsar 解压失败：{reason}"),
            Self::Malformed(reason) => write!(f, "Pulsar batch 载荷损坏：{reason}"),
        }
    }
}

impl std::error::Error for BatchError {}

/// 压缩类型对应的 `CommandAck.validation_error`（供 receiver 显式回执）。
#[must_use]
pub const fn validation_error_for(compression: i32) -> Option<i32> {
    match compression {
        compression_type::NONE | compression_type::ZLIB => None,
        _ => Some(super::proto::validation_error::DECOMPRESSION_ERROR),
    }
}

/// batch 里的一条消息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchEntry {
    /// 在 batch 内的下标（0 起）。
    pub index: usize,
    /// 正文。
    pub payload: Vec<u8>,
    /// 该条的属性（`SingleMessageMetadata.properties`；批量消息的属性在这里，不在外层）。
    pub properties: BTreeMap<String, String>,
    /// 该条的分区键。
    pub partition_key: Option<String>,
    /// 该条的业务时间（缺失 ⇒ 用外层 `event_time`/`publish_time`）。
    pub event_time: Option<u64>,
    /// 该条的序号（生产者显式设置时才有）。
    pub sequence_id: Option<u64>,
    /// 是否被压缩器标记为 `compacted_out`（已淘汰，按 Pulsar 语义应跳过）。
    pub compacted_out: bool,
}

/// 解压（`NONE` 原样返回；`ZLIB` 走 `flate2`）。
///
/// # Errors
/// 压缩类型未实现或解压失败。
pub fn decompress(compression: i32, uncompressed_size: u32, payload: &[u8]) -> Result<Vec<u8>, BatchError> {
    match compression {
        compression_type::NONE => Ok(payload.to_vec()),
        compression_type::ZLIB => {
            let mut decoder = flate2::read::ZlibDecoder::new(payload);
            let mut out = Vec::with_capacity(usize::try_from(uncompressed_size).unwrap_or(0));
            decoder.read_to_end(&mut out).map_err(|e| BatchError::Decompress(format!("zlib: {e}")))?;
            // `uncompressed_size = 0` 表示发送端没填，不做一致性断言（Pulsar 客户端允许为 0）
            if uncompressed_size > 0 && out.len() != usize::try_from(uncompressed_size).unwrap_or(0) {
                return Err(BatchError::Decompress(format!(
                    "uncompressed_size 声明 {} 字节，实际解出 {} 字节",
                    uncompressed_size,
                    out.len()
                )));
            }
            Ok(out)
        }
        other => Err(BatchError::UnsupportedCompression(other)),
    }
}

/// 把 batch 载荷拆成逐条 [`BatchEntry`]。
///
/// # Errors
/// 载荷结构损坏（长度字段越界、缺 `payload_size`、protobuf 解码失败）。
pub fn split_batch(payload: &[u8]) -> Result<Vec<BatchEntry>, BatchError> {
    let mut entries = Vec::new();
    let mut cursor = payload;
    let mut index = 0_usize;
    while !cursor.is_empty() {
        if cursor.len() < 4 {
            return Err(BatchError::Malformed(format!(
                "第 {index} 条：剩余 {} 字节装不下 SINGLE_META_SIZE",
                cursor.len()
            )));
        }
        let mut size = [0_u8; 4];
        size.copy_from_slice(&cursor[..4]);
        let meta_size = u32::from_be_bytes(size) as usize;
        if cursor.len() < 4 + meta_size {
            return Err(BatchError::Malformed(format!(
                "第 {index} 条：SINGLE_META_SIZE={meta_size} 超出剩余 {} 字节",
                cursor.len() - 4
            )));
        }
        let meta = SingleMessageMetadata::decode(&cursor[4..4 + meta_size])
            .map_err(|e| BatchError::Malformed(format!("第 {index} 条 SingleMessageMetadata: {e}")))?;
        let body_size =
            meta.payload_len().ok_or_else(|| BatchError::Malformed(format!("第 {index} 条缺 payload_size")))?;
        let body_start = 4 + meta_size;
        if cursor.len() < body_start + body_size {
            return Err(BatchError::Malformed(format!(
                "第 {index} 条：payload_size={body_size} 超出剩余 {} 字节",
                cursor.len() - body_start
            )));
        }
        entries.push(BatchEntry {
            index,
            payload: cursor[body_start..body_start + body_size].to_vec(),
            properties: meta.properties_map(),
            partition_key: meta.partition_key.clone(),
            event_time: meta.event_time.filter(|value| *value > 0),
            sequence_id: meta.sequence_id,
            compacted_out: meta.compacted_out.unwrap_or(false),
        });
        cursor = &cursor[body_start + body_size..];
        index += 1;
    }
    Ok(entries)
}

/// 把一条非 batch 消息包装成**单元素** [`BatchEntry`]（统一后续处理路径）。
///
/// 单条消息的属性在外层 `MessageMetadata`，因此这里由调用方把外层属性传进来。
#[must_use]
pub fn single_entry(payload: &[u8], properties: BTreeMap<String, String>, partition_key: Option<String>) -> BatchEntry {
    BatchEntry {
        index: 0,
        payload: payload.to_vec(),
        properties,
        partition_key,
        event_time: None,
        sequence_id: None,
        compacted_out: false,
    }
}

/// 命令类型名（把 `BaseCommand.type` 渲染给人看；receiver 日志用）。
#[must_use]
pub fn command_name(command_type_value: i32) -> String {
    super::proto::base_command_type_name(command_type_value)
}

/// 每个 batch 条目是否都应被计数为 `received`（`compacted_out` 跳过）。
#[must_use]
pub fn counted_entries(entries: &[BatchEntry]) -> usize {
    entries.iter().filter(|entry| !entry.compacted_out).count()
}

/// 该命令类型是否是"需要 flow 许可回复的消息"（`MESSAGE`）。
#[must_use]
pub const fn is_message_command(command_type_value: i32) -> bool {
    command_type_value == command_type::MESSAGE
}
