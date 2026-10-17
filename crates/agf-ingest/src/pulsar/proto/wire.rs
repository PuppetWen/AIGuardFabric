//! 原生 Pulsar 的**消息级** protobuf 定义：消息 id、属性、schema、消息元数据、batch 单条元数据。
//!
//! 从 `pulsar/proto.rs` 拆出来（`proto.rs` 会被仓库的**单文件 500 行**门禁卡住）；
//! 命令信封（`BaseCommand` 及其载荷）见 [`super::commands`]，错误分类与协议枚举见 [`super`]。
//!
//! **proto2 required 零值必须显式写出**：本文件所有可能取 0 的必填标量都声明为
//! `optional`（`Option<T>`）——prost 对 `Option` 是"`Some` 就写"，用裸标量会按 proto3 语义
//! 省略零值，broker 的 proto2 解析器会报 missing required fields。

use prost::Message;

/// `MessageIdData`：消息在 ledger 里的坐标。
///
/// `ledger_id` / `entry_id` 在 proto2 里是 **required**，因此这里用 `Optional` 承载
/// （`Some(0)` 会被显式编码，`None` 表示对端未给——解析时按 0 处理）。
#[derive(Clone, PartialEq, Message)]
pub struct MessageIdData {
    /// `ledgerId = 1`（required uint64）。
    #[prost(uint64, optional, tag = "1")]
    pub ledger_id: Option<u64>,
    /// `entryId = 2`（required uint64）。
    #[prost(uint64, optional, tag = "2")]
    pub entry_id: Option<u64>,
    /// `partition = 3`（default -1）。
    #[prost(int32, optional, tag = "3")]
    pub partition: Option<i32>,
    /// `batch_index = 4`（default -1）：batch 内第几条。
    #[prost(int32, optional, tag = "4")]
    pub batch_index: Option<i32>,
    /// `ack_set = 5`（packed int64）—— Cumulative ack 的位图，本消费者不构造。
    #[prost(int64, repeated, tag = "5")]
    pub ack_set: Vec<i64>,
    /// `batch_size = 6`。
    #[prost(int32, optional, tag = "6")]
    pub batch_size: Option<i32>,
}

impl MessageIdData {
    /// 构造（`partition` 显式给出）。
    ///
    /// `ledger_id` / `entry_id` 一律写成 `Some(..)`：proto2 的 **required** 字段
    /// 即使是 0 也必须出现在线路上（prost 对 `Option` 的语义就是"`Some` 就写"）。
    #[must_use]
    pub const fn new(ledger_id: u64, entry_id: u64, partition: i32) -> Self {
        Self {
            ledger_id: Some(ledger_id),
            entry_id: Some(entry_id),
            partition: Some(partition),
            batch_index: None,
            ack_set: Vec::new(),
            batch_size: None,
        }
    }

    /// `(ledger_id, entry_id)`；缺失按 0 处理（proto2 required 缺失只是解析侧的降级）。
    #[must_use]
    pub fn coord(&self) -> (u64, u64) {
        (self.ledger_id.unwrap_or(0), self.entry_id.unwrap_or(0))
    }

    /// 是否 batch 内单条（`batch_index >= 0`）。
    ///
    /// 名字带 `_opt` 后缀：prost 会为 `optional` 字段生成同名字段访问器
    /// （`pub fn batch_index(&self) -> Option<i32>`），直接同名会与之冲突。
    #[must_use]
    pub fn batch_index_opt(&self) -> Option<i32> {
        self.batch_index.filter(|index| *index >= 0)
    }

    /// 紧凑可读形式（日志/指标用；protobuf 全量 `Debug` 噪音太大）。
    #[must_use]
    pub fn describe(&self) -> String {
        format!("{}:{}:{}", self.ledger_id.unwrap_or(0), self.entry_id.unwrap_or(0), self.partition.unwrap_or(-1))
    }
}

/// `KeyValue`：消息属性（`properties`）与订阅元数据共用。
#[derive(Clone, PartialEq, Message)]
pub struct KeyValue {
    /// `key = 1`（required string）。
    #[prost(string, optional, tag = "1")]
    pub key: Option<String>,
    /// `value = 2`（required string）。
    #[prost(string, optional, tag = "2")]
    pub value: Option<String>,
}

impl KeyValue {
    /// 紧凑可读形式。
    #[must_use]
    pub fn describe(&self) -> String {
        format!("{}={}", self.key.as_deref().unwrap_or(""), self.value.as_deref().unwrap_or(""))
    }
}

/// `Schema`：订阅时只用于声明"本消费者按字节消费"（**实测：订阅时不发该字段**，见 [`super::commands`]）。
#[derive(Clone, PartialEq, Message)]
pub struct Schema {
    /// `name = 1`（required string）。
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    /// `schema_data = 3`（required bytes）。
    #[prost(bytes = "vec", optional, tag = "3")]
    pub schema_data: Option<Vec<u8>>,
    /// `type = 4`（required Type）。
    #[prost(int32, optional, tag = "4")]
    pub r#type: Option<i32>,
    /// `properties = 5`。
    #[prost(message, repeated, tag = "5")]
    pub properties: Vec<KeyValue>,
}

/// `Schema.Type` 里本消费者使用的取值。
///
/// `PulsarApi.proto` 的 `Schema.Type` **没有** `Bytes` 成员（`None = 0`、`String = 1`、…），
/// 所以"按原始字节消费"在协议上只能表达为 [`NONE`]——而真机上给已有 `bytes` schema 的 topic
/// 声明 `NONE` 会被 broker 拒绝，因此实际做法是**订阅时不带 `schema` 字段**。
pub mod schema_type {
    /// `None = 0`：不做 schema 校验（消费者侧只取原始 bytes）。
    pub const NONE: i32 = 0;
    /// 别名：本消费者一律按 [`NONE`] 声明（协议里无 `Bytes` 成员，仅为可读性保留）。
    pub const BYTES: i32 = NONE;
}

/// `SingleMessageMetadata`（batch 载荷里**每条**消息前面的那段元数据）。
///
/// batch 载荷布局（`Commands.deSerializeSingleMessageInBatch`）：
/// `[SINGLE_META_SIZE u32 BE][SingleMessageMetadata][payload_size 字节的正文]` × N。
#[derive(Clone, PartialEq, Message)]
pub struct SingleMessageMetadata {
    /// `properties = 1`
    #[prost(message, repeated, tag = "1")]
    pub properties: Vec<KeyValue>,
    /// `partition_key = 2`
    #[prost(string, optional, tag = "2")]
    pub partition_key: Option<String>,
    /// `payload_size = 3`（**required int32**）——没有它就无法切分 batch。
    #[prost(int32, optional, tag = "3")]
    pub payload_size: Option<i32>,
    /// `compacted_out = 4`（default false）
    #[prost(bool, optional, tag = "4")]
    pub compacted_out: Option<bool>,
    /// `event_time = 5`（default 0）
    #[prost(uint64, optional, tag = "5")]
    pub event_time: Option<u64>,
    /// `partition_key_b64_encoded = 6`（default false）
    #[prost(bool, optional, tag = "6")]
    pub partition_key_b64_encoded: Option<bool>,
    /// `sequence_id = 8`（生产者显式设置的逐条序号）
    #[prost(uint64, optional, tag = "8")]
    pub sequence_id: Option<u64>,
    /// `null_value = 9`（default false）
    #[prost(bool, optional, tag = "9")]
    pub null_value: Option<bool>,
}

impl SingleMessageMetadata {
    /// `payload_size`（缺失或为负 ⇒ `None`，调用方按"batch 损坏"处理）。
    ///
    /// 名字带 `_len` 后缀：prost 已生成同名字段访问器 `payload_size()`。
    #[must_use]
    pub fn payload_len(&self) -> Option<usize> {
        match self.payload_size {
            Some(size) if size >= 0 => usize::try_from(size).ok(),
            _ => None,
        }
    }

    /// 属性表。
    #[must_use]
    pub fn properties_map(&self) -> std::collections::BTreeMap<String, String> {
        self.properties
            .iter()
            .filter_map(|kv| kv.key.clone().map(|key| (key, kv.value.clone().unwrap_or_default())))
            .collect()
    }
}

/// `CommandMessage`（broker → 客户端，携带一条消息；payload 在帧尾）。
#[derive(Clone, PartialEq, Message)]
pub struct CommandMessage {
    /// `consumer_id = 1`（required uint64）。
    #[prost(uint64, optional, tag = "1")]
    pub consumer_id: Option<u64>,
    /// `message_id = 2`（required）。
    #[prost(message, optional, tag = "2")]
    pub message_id: Option<MessageIdData>,
    /// `redelivery_count = 3`（default 0）。
    #[prost(uint32, optional, tag = "3")]
    pub redelivery_count: Option<u32>,
    /// `ack_set = 4`。
    #[prost(int64, repeated, tag = "4")]
    pub ack_set: Vec<i64>,
    /// `consumer_epoch = 5`。
    #[prost(uint64, optional, tag = "5")]
    pub consumer_epoch: Option<u64>,
}

/// `CompressionType`（`PulsarApi.proto`）。
pub mod compression_type {
    /// `NONE = 0`
    pub const NONE: i32 = 0;
    /// `LZ4 = 1`（**未实现**：见 [`crate::pulsar::batch`]）
    pub const LZ4: i32 = 1;
    /// `ZLIB = 2`（已实现，`flate2`）
    pub const ZLIB: i32 = 2;
    /// `ZSTD = 3`（**未实现**）
    pub const ZSTD: i32 = 3;
    /// `SNAPPY = 4`（**未实现**）
    pub const SNAPPY: i32 = 4;
}

/// `MessageMetadata`（帧里 `[MAGIC][CHECKSUM][METADATA_SIZE]` 之后的那段）。
#[derive(Clone, PartialEq, Message)]
pub struct MessageMetadata {
    /// `producer_name = 1`（required string）。
    #[prost(string, optional, tag = "1")]
    pub producer_name: Option<String>,
    /// `sequence_id = 2`（required uint64）。
    #[prost(uint64, optional, tag = "2")]
    pub sequence_id: Option<u64>,
    /// `publish_time = 3`（required uint64，毫秒）。
    #[prost(uint64, optional, tag = "3")]
    pub publish_time: Option<u64>,
    /// `properties = 4`。
    #[prost(message, repeated, tag = "4")]
    pub properties: Vec<KeyValue>,
    /// `partition_key = 6`。
    #[prost(string, optional, tag = "6")]
    pub partition_key: Option<String>,
    /// `compression = 8`（default NONE）。
    #[prost(int32, optional, tag = "8")]
    pub compression: Option<i32>,
    /// `uncompressed_size = 9`（default 0）。
    #[prost(uint32, optional, tag = "9")]
    pub uncompressed_size: Option<u32>,
    /// `num_messages_in_batch = 11`（default 1；> 1 ⇒ payload 是 batch 编码）。
    #[prost(int32, optional, tag = "11")]
    pub num_messages_in_batch: Option<i32>,
    /// `event_time = 12`（default 0）。
    #[prost(uint64, optional, tag = "12")]
    pub event_time: Option<u64>,
    /// `partition_key_b64_encoded = 17`（default false）。
    #[prost(bool, optional, tag = "17")]
    pub partition_key_b64_encoded: Option<bool>,
    /// `highest_sequence_id = 24`（default 0）：batch 里最后一条的 sequence_id。
    #[prost(uint64, optional, tag = "24")]
    pub highest_sequence_id: Option<u64>,
}

impl MessageMetadata {
    /// 压缩类型（缺失 = `NONE`）。
    ///
    /// 名字带 `_kind` 后缀：prost 已生成同名字段访问器 `compression()`。
    #[must_use]
    pub fn compression_kind(&self) -> i32 {
        self.compression.unwrap_or(compression_type::NONE)
    }

    /// batch 条数（缺失或非法 = 1）。
    ///
    /// 名字带 `_len` 后缀：prost 已生成同名字段访问器 `num_messages_in_batch()`。
    #[must_use]
    pub fn batch_len(&self) -> usize {
        match self.num_messages_in_batch {
            Some(n) if n > 1 => usize::try_from(n).unwrap_or(1),
            _ => 1,
        }
    }

    /// 属性表（重复键后者覆盖前者，与 Pulsar 客户端 `Map` 语义一致）。
    #[must_use]
    pub fn properties_map(&self) -> std::collections::BTreeMap<String, String> {
        self.properties
            .iter()
            .filter_map(|kv| kv.key.clone().map(|key| (key, kv.value.clone().unwrap_or_default())))
            .collect()
    }
}
