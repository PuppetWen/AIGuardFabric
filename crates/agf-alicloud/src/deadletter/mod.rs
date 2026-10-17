//! 离线缓存 + 死信队列 + 恢复重放（§5.3「断网进离线缓存、恢复补传」）。
//!
//! ## 数据流
//!
//! ```text
//! push/sync 失败 ──▶ OfflineQueue::enqueue（缓存载荷 + 错误 + 尝试次数）
//!                        │
//! 网络恢复 ─────────────▶ OfflineQueue::flush(adapter) 逐条重放
//!                        ├─ 成功 → 移出队列，计入 flushed
//!                        └─ 失败 → 保留在队列（attempts+1）；超过 max_attempts 转死信
//! ```
//!
//! ## 为什么"离线缓存"和"死信"放在一起
//!
//! 两者是同一个队列的两种生命周期状态：只要还在重试窗口内就是离线缓存，
//! 超过窗口就是死信。分开实现会导致"重试次数"两处计数不一致。
//! 云端持久化格式与 [`agf_core::adapter::DeadLetterEntry`] 对齐，
//! 由 `agf-storage` 落 `dead_letters` 表。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Arc;
pub(crate) use std::sync::Mutex;

pub(crate) use agf_core::adapter::PullRequest;

pub(crate) use agf_core::adapter::Adapter;
pub(crate) use agf_core::adapter::DeadLetterEntry;
pub(crate) use agf_core::adapter::PushPayload;
pub(crate) use agf_core::adapter::SyncDirection;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

#[cfg(test)]
pub(crate) use agf_core::adapter::AdapterConfig;
#[cfg(test)]
pub(crate) use agf_core::adapter::AdapterDescriptor;
#[cfg(test)]
pub(crate) use agf_core::adapter::AdapterHealth;
#[cfg(test)]
pub(crate) use agf_core::adapter::PullResponse;
#[cfg(test)]
pub(crate) use agf_core::adapter::SyncOutcome;

#[cfg(test)]
pub(crate) use async_trait::async_trait;

#[allow(unused_imports)]
pub use record_push_failure::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 队列中的操作种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OfflineOpKind {
    /// 推送单个实体。
    Push,
    /// 同步（拉/推/双向）。
    Sync,
    /// 仅拉取。
    Pull,
}

/// 一条离线操作（可序列化，落库为 `dead_letters` 行）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineOp {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 适配器名。
    pub adapter: String,
    /// 操作种类。
    pub kind: OfflineOpKind,
    /// 推送载荷（`kind == Push`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<PushPayload>,
    /// 同步方向（`kind == Sync`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<SyncDirection>,
    /// 拉取请求（`kind == Sync | Pull`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<PullRequest>,
    /// 幂等键（同一逻辑操作的多次入队会被去重）。
    pub idempotency_key: String,
    /// 最近错误。
    pub last_error: String,
    /// 尝试次数（含首次失败）。
    pub attempts: u32,
    /// 首次失败时间。
    pub first_failed_at: Timestamp,
    /// 最近失败时间。
    pub last_failed_at: Timestamp,
    /// 是否已转死信（超过重试上限后置位）。
    #[serde(default)]
    pub dead: bool,
}

/// 重放报告。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlushReport {
    /// 尝试重放数。
    pub attempted: usize,
    /// 成功数。
    pub flushed: usize,
    /// 仍失败并保留在队列中的数量。
    pub still_failing: usize,
    /// 转为死信的数量。
    pub dead_lettered: usize,
    /// 因适配器名不匹配而跳过的数量。
    pub skipped: usize,
    /// 错误摘要。
    pub errors: Vec<String>,
    /// 完成时间。
    pub finished_at: Option<Timestamp>,
}

/// 离线队列配置。
#[derive(Debug, Clone, Copy)]
pub struct OfflineQueueConfig {
    /// 允许的**总尝试次数**（入队即算 1 次）；达到上限仍失败则转死信。
    pub max_attempts: u32,
    /// 队列容量上限（超过后丢弃最旧的**已死信**条目，避免无界增长）。
    pub capacity: usize,
}

/// 离线缓存 + 死信队列（内存实现；落库由 `agf-storage` 负责，接口保持一致）。
#[derive(Debug)]
pub struct OfflineQueue {
    config: OfflineQueueConfig,
    ops: Mutex<Vec<OfflineOp>>,
    /// 已转死信的条目（保留在内存中供 console 查看；落库形态见 [`OfflineOp::to_dead_letter`]）。
    dead: Mutex<Vec<DeadLetterEntry>>,
}

/// 共享队列句柄。
pub type SharedOfflineQueue = Arc<OfflineQueue>;

mod impl_offline_op_kind;
mod record_push_failure;
#[cfg(test)]
mod tests;
