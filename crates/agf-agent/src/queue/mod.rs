//! 本地上报队列：断网积压 + 上限与淘汰策略 + 落盘续传。
//!
//! ## 淘汰策略（明确定义，不静默丢数据）
//!
//! | 触发 | 行为 |
//! |---|---|
//! | 同 `idempotency_key` 再次入队 | **替换**旧条目（幂等语义：同一载荷只留最新一份） |
//! | 条目数超过 `max_entries` | 从**最旧**开始淘汰（时间序上报，最新数据价值最高），并累计 `evicted_total` |
//! | 字节数超过 `max_bytes` | 同上，按最旧淘汰 |
//! | 单条尝试次数超过 `max_attempts` | 丢弃并累计 `expired_total`（该条已无补传价值，避免队头阻塞） |
//! | 落盘文件行损坏 | 跳过该行并累计 `corrupt_lines`（**不影响**其余条目） |
//!
//! 形如 `agf_agent_queue_evicted_total{reason="capacity"}` 的指标由上层按
//! [`QueueStats`] 暴露（本 crate 只产出事实，不绑定具体指标库）。
//!
//! ## 降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 未配置 `path` | 仅内存队列（进程退出即丢失，由上层决定是否落盘） |
//! | 落盘目录不可创建/不可写 | 返回 `DomainError::Internal`，但**内存队列仍可用**（调用方记 warning 后继续） |
//! | `max_entries = 0` | 视为 1（拒绝"配置成完全不可用"的最坏取值） |

pub(crate) use std::collections::VecDeque;

use std::io::Write as _;

pub(crate) use std::path::Path;
pub(crate) use std::path::PathBuf;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use crate::payload::PayloadKind;

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
pub use tmp_path::*;

/// 默认容量（条目数）。
pub const DEFAULT_MAX_ENTRIES: usize = 1_000;

/// 默认容量（字节数，8 MiB）。
pub const DEFAULT_MAX_BYTES: usize = 8 * 1024 * 1024;

/// 默认单条最大尝试次数。
pub const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// 队列配置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueConfig {
    /// 最大条目数。
    pub max_entries: usize,
    /// 最大字节数。
    pub max_bytes: usize,
    /// 单条最大尝试次数。
    pub max_attempts: u32,
    /// 落盘路径（`None` = 纯内存）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

/// 队列条目。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueEntry {
    /// 幂等键。
    pub idempotency_key: String,
    /// 载荷种类。
    pub kind: PayloadKind,
    /// 上行 JSON 正文。
    pub body: String,
    /// 入队时间。
    pub enqueued_at: Timestamp,
    /// 已尝试次数。
    #[serde(default)]
    pub attempts: u32,
}

/// 入队结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PushOutcome {
    /// 新入队。
    Enqueued,
    /// 替换了同幂等键的旧条目。
    Replaced,
    /// 入队并淘汰了 `n` 条最旧条目。
    Evicted(usize),
}

/// 队列统计（事实产出，供上层映射为指标）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueStats {
    /// 当前深度。
    pub depth: usize,
    /// 当前字节数。
    pub bytes: usize,
    /// 累计因容量淘汰。
    pub evicted_total: u64,
    /// 累计因超尝试次数丢弃。
    pub expired_total: u64,
    /// 累计替换。
    pub replaced_total: u64,
    /// 载入时跳过的损坏行数。
    pub corrupt_lines: u64,
    /// 条目上限。
    pub capacity_entries: usize,
    /// 字节上限。
    pub capacity_bytes: usize,
}

/// 补传统计。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlushStats {
    /// 本次尝试条数。
    pub attempted: usize,
    /// 成功补传条数。
    pub delivered: usize,
    /// 仍留在队列（可重试）。
    pub requeued: usize,
    /// 因超尝试次数丢弃。
    pub dropped: usize,
}

/// 本地队列。
#[derive(Debug, Clone)]
pub struct LocalQueue {
    config: QueueConfig,
    entries: VecDeque<QueueEntry>,
    evicted_total: u64,
    expired_total: u64,
    replaced_total: u64,
    corrupt_lines: u64,
}

mod impl_queue_config;
#[cfg(test)]
mod tests;
mod tmp_path;
