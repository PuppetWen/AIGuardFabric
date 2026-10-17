//! 接收器的辅助件：停机判定/等待、`CommandAck` 构造、`BatchError` → 校验错误映射、连接指标快照。
//!
//! 从 `pulsar/receiver.rs` 拆出来（该文件会被仓库的**单文件 500 行**门禁卡住）；
//! 这里都是**纯函数/纯构造**，不含消费循环逻辑。

use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::watch;

use super::super::batch::BatchError;
use super::super::client::PulsarNativeStats;
use super::super::proto::{CommandAck, MessageIdData, ack_type, validation_error};

/// 一条消息处理完毕后要发的 ack 计划。
#[derive(Debug, Clone, PartialEq)]
pub struct AckPlan {
    /// `CommandAck.ack_type`。
    pub(crate) ack_type: i32,
    /// 要 ack 的消息 id（正常为 1 个；batch 也是整条 entry 的 id）。
    pub(crate) message_ids: Vec<MessageIdData>,
    /// `CommandAck.validation_error`（毒消息才有）。
    pub(crate) validation_error: Option<i32>,
    /// **是否应该发 ack**：`false` 仅表示"落库失败，故意不 ack 等重投"。
    pub(crate) should_ack: bool,
    /// 本次计为"协议层收到"的条数。
    pub(crate) received: usize,
    /// 本次计为"丢弃"的条数。
    pub(crate) dropped: u64,
}

impl AckPlan {
    /// "不 ack、等重投"的计划（落库失败 ⇒ broker 按 `ackTimeout` 重投）。
    pub(crate) fn defer(received: usize) -> Self {
        Self {
            ack_type: ack_type::INDIVIDUAL,
            message_ids: Vec::new(),
            validation_error: None,
            should_ack: false,
            received,
            dropped: 0,
        }
    }

    /// 毒消息计划（用 `CommandAck.validation_error` 显式回执 + 计入丢弃）。
    pub(crate) fn poison(message_id: MessageIdData, code: i32) -> Self {
        Self {
            ack_type: ack_type::INDIVIDUAL,
            message_ids: vec![message_id],
            validation_error: Some(code),
            should_ack: true,
            received: 1,
            dropped: 1,
        }
    }
}

/// 是否已收到停机信号（`None` 或 `false` ⇒ 继续跑）。
pub(crate) fn is_stopped(shutdown: Option<&watch::Receiver<bool>>) -> bool {
    shutdown.is_some_and(|rx| *rx.borrow())
}

/// 睡 `delay`，期间收到停机信号 ⇒ 立即返回 `true`。
pub(crate) async fn sleep_or_stop(delay: Duration, shutdown: Option<&mut watch::Receiver<bool>>) -> bool {
    match shutdown {
        Some(rx) => tokio::select! {
            biased;
            changed = rx.changed() => { let _ = changed; true }
            () = tokio::time::sleep(delay) => false,
        },
        None => {
            tokio::time::sleep(delay).await;
            false
        }
    }
}

/// `BatchError` → `CommandAck.validation_error` 的映射。
#[must_use]
pub const fn ack_for_batch_error(error: &BatchError) -> i32 {
    match error {
        BatchError::UnsupportedCompression(_) | BatchError::Decompress(_) => validation_error::DECOMPRESSION_ERROR,
        BatchError::Malformed(_) => validation_error::BATCH_DESERIALIZE_ERROR,
    }
}

/// 显式构造一条 Individual ack（`ack_type` 必须**显式写出 0**，proto2 required）。
#[must_use]
pub fn individual_ack(consumer_id: u64, ids: Vec<MessageIdData>) -> CommandAck {
    CommandAck {
        consumer_id: Some(consumer_id),
        ack_type: Some(ack_type::INDIVIDUAL),
        message_id: ids,
        validation_error: None,
    }
}

/// 显式构造一条 Cumulative ack（只带最新一条 id，broker 把之前的都算已读）。
#[must_use]
pub fn cumulative_ack(consumer_id: u64, last: MessageIdData) -> CommandAck {
    CommandAck {
        consumer_id: Some(consumer_id),
        ack_type: Some(ack_type::CUMULATIVE),
        message_id: vec![last],
        validation_error: None,
    }
}

/// 连接级指标快照（`/stats` 用；进程内计数，重启归零）。
#[must_use]
pub fn stats_snapshot(stats: &PulsarNativeStats) -> Vec<(&'static str, u64)> {
    vec![
        ("connects", stats.connects.load(Ordering::Relaxed)),
        ("reconnects", stats.reconnects.load(Ordering::Relaxed)),
        ("resubscribes", stats.resubscribes.load(Ordering::Relaxed)),
        ("frames", stats.frames.load(Ordering::Relaxed)),
        ("checksum_ok", stats.checksum_ok.load(Ordering::Relaxed)),
        ("checksum_failures", stats.checksum_failures.load(Ordering::Relaxed)),
        ("bytes_in", stats.bytes_in.load(Ordering::Relaxed)),
        ("bytes_out", stats.bytes_out.load(Ordering::Relaxed)),
        ("acks", stats.acks.load(Ordering::Relaxed)),
        ("permits", stats.permits.load(Ordering::Relaxed)),
        ("server_errors", stats.server_errors.load(Ordering::Relaxed)),
        ("unsupported_compression", stats.unsupported_compression.load(Ordering::Relaxed)),
        ("batch_split_disabled", stats.batch_split_disabled.load(Ordering::Relaxed)),
        ("batch_entries", stats.batch_entries.load(Ordering::Relaxed)),
    ]
}
