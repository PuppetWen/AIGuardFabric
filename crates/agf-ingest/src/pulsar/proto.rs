//! Pulsar **原生二进制协议**所需的最小 protobuf 消息子集（**手写**，不使用 protoc / 不做代码生成）。
//!
//! ## 覆盖范围（逐条对应 `PulsarApi.proto`，字段号与 `branch-3.3` 一致）
//!
//! | 消息 | 用途 | proto 定义位置 |
//! |---|---|---|
//! | [`BaseCommand`] | 所有命令/响应的信封（`type` + 载荷） | `BaseCommand` |
//! | [`CommandConnect`] / [`CommandConnected`] | 握手与 `auth_method_name="token"` | 同名 |
//! | [`CommandSubscribe`] | 订阅（subType / initialPosition / durable / read_compacted） | 同名 |
//! | [`CommandSuccess`] | 订阅成功应答 | 同名 |
//! | [`CommandMessage`] | 收到的消息命令 | 同名 |
//! | [`MessageMetadata`] | 消息元数据（producer/sequence/publish_time/properties/…） | 同名 |
//! | [`CommandAck`] | 应答（Individual / Cumulative） | 同名 |
//! | [`CommandFlow`] | 流控许可 | 同名 |
//! | [`CommandCloseConsumer`] | 服务端主动关消费者 | 同名 |
//! | [`CommandError`] | 错误（`ServerError` 分类） | 同名 |
//! | [`Schema`] | 订阅时的 schema（用 `None`/`Bytes` 简化） | 同名 |
//!
//! ## 为什么"手写"而不是 `.proto` + `build.rs`
//!
//! 本仓库不引入 `protoc`（Windows 上还要额外装编译器），而 `PulsarApi.proto` 有 1000+ 行、
//! 本消费者只用到其中 12 个消息 ⇒ 手写子集并把**字段号写在测试里**（见
//! [`super::tests`] 的 `proto_field_numbers_*`）比引入整套生成链路更可控。
//!
//! ## prost 的 proto2 陷阱（实现要点，踩过）
//!
//! `PulsarApi.proto` 是 `syntax = "proto2"`，字段大量是 **required**。prost 按 proto3 语义
//! 编码——**裸标量取默认值（0）时不写进流**。若把 `CommandAck.ack_type`（Individual = 0）
//! 写成裸 `i32`，编码结果里就没有字段 2，broker 的 proto2 解析器会直接抛
//! `Protocol message had invalid UTF-8`／`missing required fields`。
//! 因此本文件里**凡是可能取 0 的必填标量都声明为 `optional`（`Option<T>`）**：
//! prost 对 `Option` 的编码是"`Some` 就写"，`Some(0)` 会显式写出 0，语义与 Java 客户端
//! `setAckType(Individual)` 一致。
//!
//! 反过来，**解析**方向不受影响：proto2 的 required 在 prost 里就是 `Option`，缺失即 `None`。

#![allow(clippy::doc_markdown)]

use prost::Message;

/// `BaseCommand.Type`（`PulsarApi.proto` 的枚举值，**不是**顺序下标）。
///
/// 只列出本消费者会收发的成员；未列出的成员在 [`base_command_type_name`] 里如实显示为 `unknown`。
pub mod command_type {
    /// `CONNECT = 2`（客户端 → broker）。
    pub const CONNECT: i32 = 2;
    /// `CONNECTED = 3`（broker → 客户端）。
    pub const CONNECTED: i32 = 3;
    /// `SUBSCRIBE = 4`（客户端 → broker）。
    pub const SUBSCRIBE: i32 = 4;
    /// `LOOKUP = 23`（客户端 → broker，订阅前解析 topic 归属）。
    pub const LOOKUP: i32 = 23;
    /// `LOOKUP_RESPONSE = 24`（broker → 客户端）。
    pub const LOOKUP_RESPONSE: i32 = 24;
    /// `MESSAGE = 9`（broker → 客户端，带 metadata + payload）。
    pub const MESSAGE: i32 = 9;
    /// `ACK = 10`（客户端 → broker）。
    pub const ACK: i32 = 10;
    /// `FLOW = 11`（客户端 → broker）。
    pub const FLOW: i32 = 11;
    /// `SUCCESS = 13`（broker → 客户端，应答 Subscribe）。
    pub const SUCCESS: i32 = 13;
    /// `ERROR = 14`（broker → 客户端）。
    pub const ERROR: i32 = 14;
    /// `CLOSE_CONSUMER = 16`（broker → 客户端，服务端主动关消费者）。
    pub const CLOSE_CONSUMER: i32 = 16;
    /// `PING = 18`。
    pub const PING: i32 = 18;
    /// `PONG = 19`。
    pub const PONG: i32 = 19;
    /// `ACTIVE_CONSUMER_CHANGE = 31`。
    pub const ACTIVE_CONSUMER_CHANGE: i32 = 31;
    /// `REACHED_END_OF_TOPIC = 27`。
    pub const REACHED_END_OF_TOPIC: i32 = 27;
}

/// 把 `BaseCommand.type` 渲染成可读名字（日志/指标/测试报告用；未知值原样带出）。
#[must_use]
pub fn base_command_type_name(value: i32) -> String {
    match value {
        command_type::CONNECT => "CONNECT".to_string(),
        command_type::CONNECTED => "CONNECTED".to_string(),
        command_type::SUBSCRIBE => "SUBSCRIBE".to_string(),
        command_type::LOOKUP => "LOOKUP".to_string(),
        command_type::LOOKUP_RESPONSE => "LOOKUP_RESPONSE".to_string(),
        command_type::MESSAGE => "MESSAGE".to_string(),
        command_type::ACK => "ACK".to_string(),
        command_type::FLOW => "FLOW".to_string(),
        command_type::SUCCESS => "SUCCESS".to_string(),
        command_type::ERROR => "ERROR".to_string(),
        command_type::CLOSE_CONSUMER => "CLOSE_CONSUMER".to_string(),
        command_type::PING => "PING".to_string(),
        command_type::PONG => "PONG".to_string(),
        command_type::ACTIVE_CONSUMER_CHANGE => "ACTIVE_CONSUMER_CHANGE".to_string(),
        command_type::REACHED_END_OF_TOPIC => "REACHED_END_OF_TOPIC".to_string(),
        other => format!("unknown({other})"),
    }
}

/// `ServerError`（`PulsarApi.proto`）：本消费者需要**分类处理**的错误码。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerError {
    /// `UnknownError = 0`
    Unknown,
    /// `MetadataError = 1`
    Metadata,
    /// `PersistenceError = 2`
    Persistence,
    /// `AuthenticationError = 3`
    Authentication,
    /// `AuthorizationError = 4`（token 角色无权限 ⇒ 不重试，直接失败）
    Authorization,
    /// `ConsumerBusy = 5`（同订阅名 Exclusive 已被占用 ⇒ 退避重试）
    ConsumerBusy,
    /// `ServiceNotReady = 6`（topic 尚未 owned ⇒ 退避重试）
    ServiceNotReady,
    /// `ChecksumError = 9`
    Checksum,
    /// `TopicNotFound = 11`（未开自动建 topic ⇒ 不重试）
    TopicNotFound,
    /// `SubscriptionNotFound = 12`
    SubscriptionNotFound,
    /// `TooManyRequests = 14`
    TooManyRequests,
    /// `ProducerBusy = 16`
    ProducerBusy,
    /// `InvalidTopicName = 17`
    InvalidTopicName,
    /// 其它/未知错误码。
    Other(i32),
}

impl ServerError {
    /// 从协议里的整型错误码解析。
    #[must_use]
    pub const fn from_code(code: i32) -> Self {
        Self::from_i32(code)
    }

    /// 常量版解析（避免 `From` 与 `const` 冲突）。
    #[must_use]
    pub const fn from_i32(code: i32) -> Self {
        match code {
            0 => Self::Unknown,
            1 => Self::Metadata,
            2 => Self::Persistence,
            3 => Self::Authentication,
            4 => Self::Authorization,
            5 => Self::ConsumerBusy,
            6 => Self::ServiceNotReady,
            9 => Self::Checksum,
            11 => Self::TopicNotFound,
            12 => Self::SubscriptionNotFound,
            14 => Self::TooManyRequests,
            16 => Self::ProducerBusy,
            17 => Self::InvalidTopicName,
            other => Self::Other(other),
        }
    }

    /// 原始错误码。
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Unknown => 0,
            Self::Metadata => 1,
            Self::Persistence => 2,
            Self::Authentication => 3,
            Self::Authorization => 4,
            Self::ConsumerBusy => 5,
            Self::ServiceNotReady => 6,
            Self::Checksum => 9,
            Self::TopicNotFound => 11,
            Self::SubscriptionNotFound => 12,
            Self::TooManyRequests => 14,
            Self::ProducerBusy => 16,
            Self::InvalidTopicName => 17,
            Self::Other(code) => code,
        }
    }

    /// 协议名（日志/指标标签）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "UnknownError",
            Self::Metadata => "MetadataError",
            Self::Persistence => "PersistenceError",
            Self::Authentication => "AuthenticationError",
            Self::Authorization => "AuthorizationError",
            Self::ConsumerBusy => "ConsumerBusy",
            Self::ServiceNotReady => "ServiceNotReady",
            Self::Checksum => "ChecksumError",
            Self::TopicNotFound => "TopicNotFound",
            Self::SubscriptionNotFound => "SubscriptionNotFound",
            Self::TooManyRequests => "TooManyRequests",
            Self::ProducerBusy => "ProducerBusy",
            Self::InvalidTopicName => "InvalidTopicName",
            Self::Other(_) => "Other",
        }
    }

    /// 是否**可重试**（退避重连后可能成功）。
    ///
    /// 判据是"这个错误是否可能随时间/换 broker 而消失"：
    /// * 可重试：`ServiceNotReady`（topic 正在迁移/尚未 owned）、`ConsumerBusy`
    ///   （同订阅的 Exclusive 消费者尚未断开）、`TooManyRequests`（限流）、
    ///   `Metadata`/`Persistence`（broker 侧瞬时故障）、`Unknown`/`Other`（保守重试）；
    /// * **不可重试**：`Authorization`/`Authentication`（重试只会刷日志，凭据问题必须暴露）、
    ///   `TopicNotFound`/`InvalidTopicName`（配置问题）、`Checksum`（对端实现有问题）、
    ///   `SubscriptionNotFound`（订阅被删，需人工确认）。
    #[must_use]
    pub const fn retryable(self) -> bool {
        match self {
            Self::Authorization
            | Self::Authentication
            | Self::TopicNotFound
            | Self::InvalidTopicName
            | Self::Checksum
            | Self::SubscriptionNotFound => false,
            Self::Unknown
            | Self::Metadata
            | Self::Persistence
            | Self::ConsumerBusy
            | Self::ServiceNotReady
            | Self::TooManyRequests
            | Self::ProducerBusy
            | Self::Other(_) => true,
        }
    }
}

mod commands;
mod wire;

pub use commands::*;
pub use wire::*;

/// `BaseCommand`：**所有**帧的信封。
///
/// `PulsarApi.proto` 里这些字段是并列的 proto2 optional（不是 `oneof`），因此 prost 侧
/// 也是一组 `Option<T>`；`type_` 用 `Option<i32>` 保证 `Some(0)`（不存在）与
/// `Some(CONNECT)` 都能显式写出（`type` 是 Rust 关键字，字段名取 `type_`）。
#[derive(Clone, PartialEq, Message)]
pub struct BaseCommand {
    /// `type = 1`（required Type）。
    #[prost(int32, optional, tag = "1")]
    pub type_: Option<i32>,
    /// `connect = 2`
    #[prost(message, optional, tag = "2")]
    pub connect: Option<CommandConnect>,
    /// `connected = 3`
    #[prost(message, optional, tag = "3")]
    pub connected: Option<CommandConnected>,
    /// `subscribe = 4`
    #[prost(message, optional, tag = "4")]
    pub subscribe: Option<CommandSubscribe>,
    /// `lookupTopic = 23`
    #[prost(message, optional, tag = "23")]
    pub lookup_topic: Option<CommandLookupTopic>,
    /// `lookupTopicResponse = 24`
    #[prost(message, optional, tag = "24")]
    pub lookup_topic_response: Option<CommandLookupTopicResponse>,
    /// `message = 9`
    #[prost(message, optional, tag = "9")]
    pub message: Option<CommandMessage>,
    /// `ack = 10`
    #[prost(message, optional, tag = "10")]
    pub ack: Option<CommandAck>,
    /// `flow = 11`
    #[prost(message, optional, tag = "11")]
    pub flow: Option<CommandFlow>,
    /// `success = 13`
    #[prost(message, optional, tag = "13")]
    pub success: Option<CommandSuccess>,
    /// `error = 14`
    #[prost(message, optional, tag = "14")]
    pub error: Option<CommandError>,
    /// `close_consumer = 16`
    #[prost(message, optional, tag = "16")]
    pub close_consumer: Option<CommandCloseConsumer>,
    /// `ping = 18`
    #[prost(message, optional, tag = "18")]
    pub ping: Option<CommandPing>,
    /// `pong = 19`
    #[prost(message, optional, tag = "19")]
    pub pong: Option<CommandPing>,
    /// `active_consumer_change = 31`
    #[prost(message, optional, tag = "31")]
    pub active_consumer_change: Option<CommandActiveConsumerChange>,
}

impl BaseCommand {
    /// 命令类型（缺失按 -1 → `unknown(-1)`）。
    #[must_use]
    pub fn command_type(&self) -> i32 {
        self.type_.unwrap_or(-1)
    }

    /// 命令类型名（日志/测试）。
    #[must_use]
    pub fn type_name(&self) -> String {
        base_command_type_name(self.command_type())
    }

    /// 只带 `type` 的空命令（PING/PONG）。
    #[must_use]
    pub const fn with_type(command_type: i32) -> Self {
        Self {
            type_: Some(command_type),
            connect: None,
            connected: None,
            subscribe: None,
            lookup_topic: None,
            lookup_topic_response: None,
            message: None,
            ack: None,
            flow: None,
            success: None,
            error: None,
            close_consumer: None,
            ping: None,
            pong: None,
            active_consumer_change: None,
        }
    }

    /// `CONNECT` 命令。
    #[must_use]
    pub fn connect(command: CommandConnect) -> Self {
        Self { connect: Some(command), ..Self::with_type(command_type::CONNECT) }
    }

    /// `SUBSCRIBE` 命令。
    #[must_use]
    pub fn subscribe(command: CommandSubscribe) -> Self {
        Self { subscribe: Some(command), ..Self::with_type(command_type::SUBSCRIBE) }
    }

    /// `FLOW` 命令。
    #[must_use]
    pub fn flow(command: CommandFlow) -> Self {
        Self { flow: Some(command), ..Self::with_type(command_type::FLOW) }
    }

    /// `ACK` 命令。
    #[must_use]
    pub fn ack(command: CommandAck) -> Self {
        Self { ack: Some(command), ..Self::with_type(command_type::ACK) }
    }

    /// `LOOKUP` 命令。
    #[must_use]
    pub fn lookup(command: CommandLookupTopic) -> Self {
        Self { lookup_topic: Some(command), ..Self::with_type(command_type::LOOKUP) }
    }
}
