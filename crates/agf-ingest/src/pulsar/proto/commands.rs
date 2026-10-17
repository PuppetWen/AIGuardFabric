//! 原生 Pulsar 的**命令载荷** protobuf 定义（`BaseCommand` 里除信封本身之外的各命令）。
//!
//! 从 `pulsar/proto.rs` 拆出来（`proto.rs` 会被仓库的**单文件 500 行**门禁卡住）；
//! 消息级类型（message id / 元数据 / batch）见 [`super::wire`]，
//! 信封 `BaseCommand`、错误分类 `ServerError` 与协议枚举见 [`super`]。

use prost::Message;

use super::ServerError;
use super::wire::MessageIdData;

/// `CommandConnect`（客户端 → broker 的第一条命令）。
#[derive(Clone, PartialEq, Message)]
pub struct CommandConnect {
    /// `client_version = 1`（required string）。
    #[prost(string, optional, tag = "1")]
    pub client_version: Option<String>,
    /// `auth_method = 2`（**已废弃**，不使用）。
    #[prost(int32, optional, tag = "2")]
    pub auth_method: Option<i32>,
    /// `auth_data = 3`（bytes）：token 鉴权时放 JWT 原文。
    #[prost(bytes = "vec", optional, tag = "3")]
    pub auth_data: Option<Vec<u8>>,
    /// `protocol_version = 4`（default 0）。
    #[prost(int32, optional, tag = "4")]
    pub protocol_version: Option<i32>,
    /// `auth_method_name = 5`：token 鉴权时为 `"token"`。
    #[prost(string, optional, tag = "5")]
    pub auth_method_name: Option<String>,
}

/// `CommandConnected`（broker → 客户端的握手应答）。
#[derive(Clone, PartialEq, Message)]
pub struct CommandConnected {
    /// `server_version = 1`（required string）。
    #[prost(string, optional, tag = "1")]
    pub server_version: Option<String>,
    /// `protocol_version = 2`。
    #[prost(int32, optional, tag = "2")]
    pub protocol_version: Option<i32>,
    /// `max_message_size = 3`。
    #[prost(int32, optional, tag = "3")]
    pub max_message_size: Option<i32>,
}

/// `CommandSubscribe.SubType` 的枚举值。
pub mod sub_type {
    /// `Exclusive = 0`
    pub const EXCLUSIVE: i32 = 0;
    /// `Shared = 1`
    pub const SHARED: i32 = 1;
    /// `Failover = 2`
    pub const FAILOVER: i32 = 2;
    /// `Key_Shared = 3`
    pub const KEY_SHARED: i32 = 3;
}

/// `CommandSubscribe.InitialPosition`。
pub mod initial_position {
    /// `Latest = 0`
    pub const LATEST: i32 = 0;
    /// `Earliest = 1`
    pub const EARLIEST: i32 = 1;
}

/// `CommandSubscribe`（客户端 → broker）。
///
/// **`schema` 字段留空是刻意的**（实测）：给一个已有 `bytes` schema 的 topic 声明
/// `Schema{type=NONE}` 会被 broker 拒绝——`Failed to add schema to an active topic with
/// empty(BYTES) schema: new schema type NONE`。官方 Java 客户端的 `Schema.BYTES`
/// 本来就不携带 schema（`getSchemaInfo() == null`），因此"不发 schema 字段"才与官方一致。
#[derive(Clone, PartialEq, Message)]
pub struct CommandSubscribe {
    /// `topic = 1`（required string）。
    #[prost(string, optional, tag = "1")]
    pub topic: Option<String>,
    /// `subscription = 2`（required string）。
    #[prost(string, optional, tag = "2")]
    pub subscription: Option<String>,
    /// `subType = 3`（required SubType）——**必须是 `Some`**，`Exclusive = 0` 也要显式写。
    #[prost(int32, optional, tag = "3")]
    pub sub_type: Option<i32>,
    /// `consumer_id = 4`（required uint64）。
    #[prost(uint64, optional, tag = "4")]
    pub consumer_id: Option<u64>,
    /// `request_id = 5`（required uint64）。
    #[prost(uint64, optional, tag = "5")]
    pub request_id: Option<u64>,
    /// `consumer_name = 6`。
    #[prost(string, optional, tag = "6")]
    pub consumer_name: Option<String>,
    /// `durable = 8`（default true）。
    #[prost(bool, optional, tag = "8")]
    pub durable: Option<bool>,
    /// `metadata = 10`。
    #[prost(message, repeated, tag = "10")]
    pub metadata: Vec<super::wire::KeyValue>,
    /// `read_compacted = 11`。
    #[prost(bool, optional, tag = "11")]
    pub read_compacted: Option<bool>,
    /// `schema = 12`（**保持 `None`**，见本结构体的说明）。
    #[prost(message, optional, tag = "12")]
    pub schema: Option<super::wire::Schema>,
    /// `initialPosition = 13`（default Latest）。
    #[prost(int32, optional, tag = "13")]
    pub initial_position: Option<i32>,
    /// `force_topic_creation = 15`（default true）。
    #[prost(bool, optional, tag = "15")]
    pub force_topic_creation: Option<bool>,
}

/// `CommandSuccess`（broker → 客户端，应答 Subscribe）。
#[derive(Clone, PartialEq, Message)]
pub struct CommandSuccess {
    /// `request_id = 1`（required uint64）。
    #[prost(uint64, optional, tag = "1")]
    pub request_id: Option<u64>,
    /// `schema = 2`。
    #[prost(message, optional, tag = "2")]
    pub schema: Option<super::wire::Schema>,
}

/// `CommandLookupTopic`（客户端 → broker）：**订阅前必须做的一步**。
///
/// 为什么必须有它（**实测踩过**）：不做 LOOKUP 直接 SUBSCRIBE，broker 会回
/// `CommandError{error=ServiceNotReady(6)}`，正文是
/// `Namespace bundle for topic (...) not served by this instance:... Please redo the lookup.`
/// ——`public/default` 的 bundle 只有在一次 LOOKUP（或产者路径）之后才会被本 broker 认领。
/// 原始证据见 `tools/simulators/README.md` 的 Pulsar 原生一节。
#[derive(Clone, PartialEq, Message)]
pub struct CommandLookupTopic {
    /// `topic = 1`（required string）。
    #[prost(string, optional, tag = "1")]
    pub topic: Option<String>,
    /// `request_id = 2`（required uint64）。
    #[prost(uint64, optional, tag = "2")]
    pub request_id: Option<u64>,
    /// `authoritative = 3`（default false）：重定向回同一个 broker 时会置 true 再问一次。
    #[prost(bool, optional, tag = "3")]
    pub authoritative: Option<bool>,
}

/// `CommandLookupTopicResponse.LookupType`。
pub mod lookup_type {
    /// `Redirect = 0`：topic 归另一个 broker，按给的 URL 重连。
    pub const REDIRECT: i32 = 0;
    /// `Connect = 1`：就在当前连接上订阅。
    pub const CONNECT: i32 = 1;
    /// `Failed = 2`
    pub const FAILED: i32 = 2;
}

/// `CommandLookupTopicResponse`（broker → 客户端）。
#[derive(Clone, PartialEq, Message)]
pub struct CommandLookupTopicResponse {
    /// `brokerServiceUrl = 1`。
    #[prost(string, optional, tag = "1")]
    pub broker_service_url: Option<String>,
    /// `brokerServiceUrlTls = 2`。
    #[prost(string, optional, tag = "2")]
    pub broker_service_url_tls: Option<String>,
    /// `response = 3`（LookupType）。
    #[prost(int32, optional, tag = "3")]
    pub response: Option<i32>,
    /// `request_id = 4`（required uint64）。
    #[prost(uint64, optional, tag = "4")]
    pub request_id: Option<u64>,
    /// `authoritative = 5`（default false）。
    #[prost(bool, optional, tag = "5")]
    pub authoritative: Option<bool>,
    /// `error = 6`。
    #[prost(int32, optional, tag = "6")]
    pub error: Option<i32>,
    /// `message = 7`。
    #[prost(string, optional, tag = "7")]
    pub message: Option<String>,
    /// `proxy_through_service_url = 8`（default false）。
    #[prost(bool, optional, tag = "8")]
    pub proxy_through_service_url: Option<bool>,
}

impl CommandLookupTopicResponse {
    /// 解析结果分类（缺失按 `Failed` 处理——宁可失败也不要瞎连）。
    #[must_use]
    pub fn lookup_type(&self) -> i32 {
        self.response.unwrap_or(lookup_type::FAILED)
    }

    /// 该走 TLS 还是明文（TLS 地址优先，因为 `pulsar+ssl://` 的 broker 只给这个）。
    #[must_use]
    pub fn best_broker_url(&self) -> Option<&str> {
        self.broker_service_url_tls
            .as_deref()
            .filter(|url| !url.is_empty())
            .or_else(|| self.broker_service_url.as_deref().filter(|url| !url.is_empty()))
    }
}

/// `CommandAck.AckType`。
pub mod ack_type {
    /// `Individual = 0`（逐条；`message_id` 为被 ack 的 id 列表）
    pub const INDIVIDUAL: i32 = 0;
    /// `Cumulative = 1`（累积到某个 id）
    pub const CUMULATIVE: i32 = 1;
}

/// `CommandAck.ValidationError`：**必须**用它把"收到了但解不开"的消息显式回执，
/// 否则 broker 会一直重投同一条（毒消息）。
pub mod validation_error {
    /// `UncompressedSizeCorruption = 0`
    pub const UNCOMPRESSED_SIZE_CORRUPTION: i32 = 0;
    /// `DecompressionError = 1`
    pub const DECOMPRESSION_ERROR: i32 = 1;
    /// `ChecksumMismatch = 2`
    pub const CHECKSUM_MISMATCH: i32 = 2;
    /// `BatchDeSerializeError = 3`
    pub const BATCH_DESERIALIZE_ERROR: i32 = 3;
}

/// `CommandAck`（客户端 → broker）。
#[derive(Clone, PartialEq, Message)]
pub struct CommandAck {
    /// `consumer_id = 1`（required uint64）。
    #[prost(uint64, optional, tag = "1")]
    pub consumer_id: Option<u64>,
    /// `ack_type = 2`（required AckType）——`Individual = 0` 也必须显式写出。
    #[prost(int32, optional, tag = "2")]
    pub ack_type: Option<i32>,
    /// `message_id = 3`（Individual 时的 id 列表；Cumulative 时只放最后一个）。
    #[prost(message, repeated, tag = "3")]
    pub message_id: Vec<MessageIdData>,
    /// `validation_error = 4`：置位表示"消息已收到但判为无效"。
    #[prost(int32, optional, tag = "4")]
    pub validation_error: Option<i32>,
}

/// `CommandFlow`（客户端 → broker）：授予消息许可（信用）。
#[derive(Clone, PartialEq, Message)]
pub struct CommandFlow {
    /// `consumer_id = 1`（required uint64）。
    #[prost(uint64, optional, tag = "1")]
    pub consumer_id: Option<u64>,
    /// `messagePermits = 2`（required uint32）。
    #[prost(uint32, optional, tag = "2")]
    pub message_permits: Option<u32>,
}

/// `CommandCloseConsumer`（broker → 客户端）：服务端主动关消费者（topic 迁移等）⇒ 重新订阅。
#[derive(Clone, PartialEq, Message)]
pub struct CommandCloseConsumer {
    /// `consumer_id = 1`（required uint64）。
    #[prost(uint64, optional, tag = "1")]
    pub consumer_id: Option<u64>,
    /// `request_id = 2`（required uint64）。
    #[prost(uint64, optional, tag = "2")]
    pub request_id: Option<u64>,
    /// `assignedBrokerServiceUrl = 3`。
    #[prost(string, optional, tag = "3")]
    pub assigned_broker_service_url: Option<String>,
    /// `assignedBrokerServiceUrlTls = 4`。
    #[prost(string, optional, tag = "4")]
    pub assigned_broker_service_url_tls: Option<String>,
}

/// `CommandError`（broker → 客户端）。
#[derive(Clone, PartialEq, Message)]
pub struct CommandError {
    /// `request_id = 1`（required uint64）。
    #[prost(uint64, optional, tag = "1")]
    pub request_id: Option<u64>,
    /// `error = 2`（required ServerError）。
    #[prost(int32, optional, tag = "2")]
    pub error: Option<i32>,
    /// `message = 3`（required string）。
    #[prost(string, optional, tag = "3")]
    pub message: Option<String>,
}

impl CommandError {
    /// 分类后的错误码。
    #[must_use]
    pub fn server_error(&self) -> ServerError {
        ServerError::from_code(self.error.unwrap_or(0))
    }
}

/// `CommandActiveConsumerChange`（broker → 客户端，Failover 订阅的活跃者变更）。
#[derive(Clone, PartialEq, Message)]
pub struct CommandActiveConsumerChange {
    /// `consumer_id = 1`（required uint64）。
    #[prost(uint64, optional, tag = "1")]
    pub consumer_id: Option<u64>,
    /// `is_active = 2`（default false）。
    #[prost(bool, optional, tag = "2")]
    pub is_active: Option<bool>,
}

/// `CommandPing` / `CommandPong`（空消息，靠 `BaseCommand.type` 区分）。
#[derive(Clone, PartialEq, Message)]
pub struct CommandPing {}
