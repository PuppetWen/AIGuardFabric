//! 原生 Pulsar 客户端的**取值类型**：错误分类、LOOKUP 结果、连接事件、连接级指标。
//!
//! 从 `pulsar/client.rs` 拆出来（该文件会被仓库的**单文件 500 行**门禁卡住）；
//! 这里只有类型与纯方法，连接状态机与读写循环留在 `client.rs`。

use std::sync::atomic::{AtomicU64, Ordering};

use super::super::frame::FrameError;
use super::super::proto::{MessageMetadata, ServerError};

/// 一次 LOOKUP 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupOutcome {
    /// 直接在**当前连接**上订阅。
    ConnectHere,
    /// 需要连到另一个 broker（`pulsar://`/`pulsar+ssl://` URL）。
    Redirect {
        /// broker 给的地址。
        url: String,
        /// 该应答是否已是权威的（否则可再问一次本 broker）。
        authoritative: bool,
    },
}

/// 原生 Pulsar 客户端错误（**分类**，决定重连/放弃）。
#[derive(Debug)]
pub enum PulsarError {
    /// 网络/IO 失败（连接被拒、被重置、EOF…）。
    Io(String),
    /// TLS 装配或握手失败。
    Tls(String),
    /// 配置非法。
    Config(String),
    /// 帧编解码失败（含 CRC32C 不匹配）。
    Frame(FrameError),
    /// broker 返回 `CommandError`。
    Server {
        /// 分类后的错误。
        error: ServerError,
        /// broker 给的消息。
        message: String,
        /// 对应的 request_id。
        request_id: u64,
    },
    /// 连接被对端关闭（含 EOF）。
    Disconnected,
    /// 服务端主动 `CommandCloseConsumer`（topic 迁移等）⇒ **重新订阅**即可。
    ConsumerClosed {
        /// broker 建议的新地址（可为空）。
        assigned_broker: Option<String>,
    },
    /// 收到了本实现未处理的命令（如实报错，不假装成功）。
    Unsupported(String),
}

impl PulsarError {
    /// 是否**可重试**（退避重连后可能成功）。
    #[must_use]
    pub fn retryable(&self) -> bool {
        match self {
            Self::Server { error, .. } => error.retryable(),
            Self::Config(_) | Self::Unsupported(_) => false,
            Self::Io(_) | Self::Tls(_) | Self::Frame(_) | Self::Disconnected | Self::ConsumerClosed { .. } => true,
        }
    }

    /// 服务端错误码（非 `CommandError` ⇒ `None`）。
    #[must_use]
    pub const fn server_error(&self) -> Option<ServerError> {
        match self {
            Self::Server { error, .. } => Some(*error),
            _ => None,
        }
    }

    /// 指标标签用的错误类别名。
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Io(_) => "io",
            Self::Tls(_) => "tls",
            Self::Config(_) => "config",
            Self::Frame(_) => "frame",
            Self::Server { .. } => "server",
            Self::Disconnected => "disconnected",
            Self::ConsumerClosed { .. } => "consumer-closed",
            Self::Unsupported(_) => "unsupported",
        }
    }
}

impl std::fmt::Display for PulsarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(reason) => write!(f, "Pulsar 连接 IO 失败：{reason}"),
            Self::Tls(reason) => write!(f, "Pulsar TLS 失败：{reason}"),
            Self::Config(reason) => write!(f, "Pulsar 配置错误：{reason}"),
            Self::Frame(error) => write!(f, "{error}"),
            Self::Server { error, message, request_id } => {
                write!(f, "Pulsar broker 返回 {}（request_id={request_id}）：{message}", error.as_str())
            }
            Self::Disconnected => write!(f, "Pulsar 连接被对端关闭"),
            Self::ConsumerClosed { assigned_broker } => write!(
                f,
                "Pulsar 服务端主动关闭消费者（CommandCloseConsumer）{}：需重新订阅",
                assigned_broker.as_deref().unwrap_or("-")
            ),
            Self::Unsupported(item) => write!(f, "Pulsar 收到未处理的命令/能力：{item}"),
        }
    }
}

impl std::error::Error for PulsarError {}

/// 连接级指标（进程内原子计数）。`/metrics` 目前只有四族接收器计数器，
/// 这一组经 [`super::super::receiver::stats_snapshot`] 暴露（见能力矩阵的如实说明）。
#[derive(Debug, Default)]
pub struct PulsarNativeStats {
    /// 建连成功次数。
    pub connects: AtomicU64,
    /// 重连次数（第二次及以后）。
    pub reconnects: AtomicU64,
    /// 重新订阅次数（含 `CommandCloseConsumer` 触发）。
    pub resubscribes: AtomicU64,
    /// 收到的消息帧数（**帧**，不是 batch 里的条数）。
    pub frames: AtomicU64,
    /// 收到并**通过** CRC32C 校验的帧数。
    pub checksum_ok: AtomicU64,
    /// CRC32C 校验失败次数（**绝不静默**）。
    pub checksum_failures: AtomicU64,
    /// 收到的字节数。
    pub bytes_in: AtomicU64,
    /// 发出的字节数。
    pub bytes_out: AtomicU64,
    /// 发出的 ack 条数（消息 id 计数，非帧数）。
    pub acks: AtomicU64,
    /// 发出的 FLOW 许可总数。
    pub permits: AtomicU64,
    /// 服务端错误计数。
    pub server_errors: AtomicU64,
    /// 因压缩未实现而按 ValidationError 回执的条数。
    pub unsupported_compression: AtomicU64,
    /// `AGF_INGEST_PULSAR_BATCH=0` 时**未拆条**的 batch 帧数。
    pub batch_split_disabled: AtomicU64,
    /// batch 拆条产生的总条数。
    pub batch_entries: AtomicU64,
}

impl PulsarNativeStats {
    /// 新建（全零）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 累加。
    pub fn bump(counter: &AtomicU64, by: u64) {
        counter.fetch_add(by, Ordering::Relaxed);
    }

    /// 读取。
    #[must_use]
    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// 从 broker 收到的一个事件。
#[derive(Debug)]
pub enum ClientEvent {
    /// 一条消息（metadata + 未解压未拆条的原始 payload）。
    Message {
        /// `CommandMessage`（consumer_id / message_id / redelivery_count）。
        command: super::super::proto::CommandMessage,
        /// 元数据。
        metadata: Box<MessageMetadata>,
        /// 原始载荷。
        payload: Vec<u8>,
        /// 是否带 CRC32C（且已通过校验）。
        checksummed: bool,
    },
    /// 订阅成功（`CommandSuccess`）。
    Subscribed {
        /// request_id。
        request_id: u64,
    },
    /// 服务端主动关消费者。
    CloseConsumer {
        /// broker 建议的新地址。
        assigned_broker: Option<String>,
    },
    /// broker 错误。
    Error {
        /// 分类后的错误码。
        error: ServerError,
        /// broker 消息。
        message: String,
        /// request_id。
        request_id: u64,
    },
    /// topic 已到末尾且被终止（`CommandReachedEndOfTopic`）。
    ReachedEndOfTopic,
    /// Failover 订阅的活跃者变更。
    ActiveConsumerChange {
        /// 本消费者是否成为活跃者。
        is_active: bool,
    },
}

/// 指数退避：`initial * 2^attempt`，上限 `max`（**纯函数**，无抖动 ⇒ 可单测）。
///
/// 为什么要有上限：broker 长时间不可用时不能把重试间隔也炸到小时级；
/// `attempt` 超过 32 时按 32 处理（避免移位溢出）。
#[must_use]
pub fn backoff_delay(attempt: u32, initial: std::time::Duration, max: std::time::Duration) -> std::time::Duration {
    let shift = attempt.min(32);
    let factor = 1_u64.checked_shl(shift).unwrap_or(u64::MAX);
    let scaled = initial.as_millis().saturating_mul(u128::from(factor));
    let capped = scaled.min(max.as_millis());
    std::time::Duration::from_millis(u64::try_from(capped).unwrap_or(u64::MAX))
}

/// 已重试次数是否已达上限（`max_attempts = 0` ⇒ 永不放弃，返回 `false`）。
#[must_use]
pub const fn attempts_exhausted(attempt: u32, max_attempts: u32) -> bool {
    max_attempts != 0 && attempt >= max_attempts
}
