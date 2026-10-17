//! 通知渠道抽象与派发器（§4.6「升级路由 / 通知」）。
//!
//! 上游（SLA 升级、剧本、案件指派）只应该表达"**要通知谁什么事**"，而不应该知道钉钉还是邮件。
//! 本模块提供那层抽象：
//!
//! | 能力 | 说明 |
//! |---|---|
//! | 渠道抽象 | [`NotificationChannel`] trait：一个 `send` 方法 + 一个 [`ChannelKind`] |
//! | 离线可用 | [`MockChannel`]：可编程成功/失败、记录全部投递（**不联网**） |
//! | 派发器 | [`NotificationDispatcher`]：路由 + 去重 + 抑制 + 限流 + 重试退避 + 审计 |
//!
//! ## 派发决策顺序（**顺序本身是契约**）
//!
//! 1. 渠道不可用（未注入 / 关闭 / 等级不足 / 租户不符）⇒ [`DeliveryOutcome::Unroutable`]；
//! 2. 去重：同一 `(租户, 关联对象, 渠道)` 已成功投递过 ⇒ [`DeliveryOutcome::Suppressed`]（原因 `dedup`）；
//! 3. 维护窗口覆盖 ⇒ `Suppressed`（原因 `maintenance`）；
//! 4. 限流窗口内配额耗尽 ⇒ `Suppressed`（原因 `rate-limit`）；
//! 5. 投递：失败按指数退避重试，重试耗尽 ⇒ [`DeliveryOutcome::Failed`]。
//!
//! 抑制（3/4）**不消耗**令牌桶配额：被限流挡下的通知不应该把窗口继续填满。
//!
//! ## 降级行为
//!
//! | 能力 | 未实现/不可用时 | 锚点 |
//! |---|---|---|
//! | 真实渠道适配器（钉钉/飞书/企微/SMTP/短信/PagerDuty） | **不做**：一切外部系统经 [`NotificationChannel`] 注入；本 crate 只提供 Mock | `TODO(correlate-notify-adapters)` |
//! | 真实睡眠退避 | 只**计算并记录**退避毫秒数，不阻塞（离线可测）；调度由 `agf-runtime` 按 `backoff_ms` 重排 | `TODO(correlate-notify-sleep-backoff)` |
//! | 去重/限流状态的跨进程一致性 | 内存态：生产由 `agf-storage`/Redis 承载（否则多副本会各发一份） | `TODO(correlate-notify-distributed-state)` |
//! | 消息模板渲染与多渠道格式化 | 只做 `{{key}}` 直替换；富文本卡片/告警合并摘要由渠道适配器负责 | `TODO(correlate-notify-templates)` |
//! | 投递结果的异步回收（Webhook 回调确认） | 只认 `send` 的返回；不实现投递后确认 | `TODO(correlate-notify-receipts)` |

pub(crate) use std::collections::BTreeMap;

pub(crate) use agf_core::alert::MaintenanceWindow;

pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use async_trait::async_trait;

pub(crate) use chrono::SecondsFormat;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub use agf_core::notify::ChannelKind;
pub use agf_core::notify::DeliveryState;
pub use agf_core::notify::NotificationChannel as ChannelConfig;
pub use agf_core::notify::NotificationRecord;
pub use agf_core::notify::NotifyContext;

#[cfg(test)]
pub(crate) use std::sync::Arc;

#[allow(unused_imports)]
pub use dedup_key::*;
#[allow(unused_imports)]
pub(crate) use display_timestamp::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 通知渠道抽象：一个 `send` 就是"把这条消息交给这个渠道"。
///
/// 实现者负责真实 IO；本 crate 只提供 [`MockChannel`]。失败必须返回 `Err(String)`
/// （不含敏感信息），派发器据此重试。
#[async_trait]
pub trait NotificationChannel: Send + Sync + std::fmt::Debug {
    /// 渠道类型。
    fn kind(&self) -> ChannelKind;

    /// 派发一条通知，返回渠道回执（回执内容仅用于审计，不参与判定）。
    ///
    /// # Errors
    /// 渠道不可达、鉴权失败、限流等外部错误，返回可读原因。
    async fn send(&self, message: &OutboundMessage) -> Result<ChannelReceipt, String>;
}

/// 待投递消息（渠道无关的统一形态）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundMessage {
    /// 租户。
    pub tenant_id: TenantId,
    /// 渠道 id。
    pub channel_id: Id,
    /// 渠道类型。
    pub kind: ChannelKind,
    /// 关联对象类型（`case` / `alert` / `report`）。
    pub subject_kind: String,
    /// 关联对象 id。
    pub subject_id: Id,
    /// 去重键（同键同渠道只发一次）。
    pub dedup_key: String,
    /// 标题。
    pub title: String,
    /// 已渲染正文。
    pub body: String,
    /// 严重等级（渠道可据此决定 @ 谁）。
    pub severity: Severity,
    /// 收件目标（邮箱/频道名等，来自渠道配置）。
    pub targets: Vec<String>,
    /// 发生时间。
    pub at: Timestamp,
    /// 附加结构化数据（模板占位符来源）。
    pub extra: BTreeMap<String, String>,
}

/// 渠道回执。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelReceipt {
    /// 渠道侧消息 id（审计追溯）。
    pub external_id: Option<String>,
    /// 渠道侧可读回执。
    pub detail: String,
    /// 渠道侧接收时间。
    pub accepted_at: Timestamp,
}

/// 单次投递结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryOutcome {
    /// 投递成功。
    Delivered,
    /// 重试耗尽仍失败。
    Failed,
    /// 被抑制（去重 / 维护窗口 / 限流 / 渠道不可用）。
    Suppressed,
}

/// 抑制原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuppressCause {
    /// 同一关联对象同渠道已投递过（去重）。
    Dedup,
    /// 维护窗口静默。
    Maintenance,
    /// 限流窗口配额耗尽。
    RateLimit,
    /// 渠道不可用（未注入/关闭/等级不足/租户不符）。
    Unroutable,
}

/// 一次派发尝试的审计记录。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliveryAttempt {
    /// 记录 id。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 渠道 id。
    pub channel_id: Id,
    /// 渠道类型。
    pub kind: ChannelKind,
    /// 关联对象类型。
    pub subject_kind: String,
    /// 关联对象 id。
    pub subject_id: Id,
    /// 去重键。
    pub dedup_key: String,
    /// 实际投递次数（含重试）。
    pub attempts: u32,
    /// 结论。
    pub outcome: DeliveryOutcome,
    /// 抑制原因（仅 `Suppressed`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed_by: Option<SuppressCause>,
    /// 若还有下一次重试，其退避时长（毫秒）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backoff_ms: Option<u64>,
    /// 渠道回执。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
    /// 失败原因。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// 发生时间。
    pub at: Timestamp,
}

/// 渠道派发结果。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelDelivery {
    /// 渠道 id。
    pub channel_id: Id,
    /// 渠道类型。
    pub kind: ChannelKind,
    /// 结论。
    pub outcome: DeliveryOutcome,
    /// 抑制原因。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed_by: Option<SuppressCause>,
    /// 实际投递次数。
    pub attempts: u32,
    /// 渠道回执。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
    /// 失败原因。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// 一次派发（可能覆盖多个渠道）的结果。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DispatchResult {
    /// 去重键。
    pub dedup_key: String,
    /// 各渠道结果。
    pub deliveries: Vec<ChannelDelivery>,
}

/// 派发配置。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DispatchConfig {
    /// 每渠道在限流窗口内最多投递条数（默认 20）。
    pub rate_limit_max: u32,
    /// 限流窗口（秒，默认 60）。
    pub rate_limit_window_secs: i64,
    /// 最大尝试次数（含首次；默认 3）。
    pub max_attempts: u32,
    /// 指数退避基数（毫秒，默认 500）。
    pub backoff_base_ms: u64,
    /// 退避上限（毫秒，默认 30_000）。
    pub backoff_max_ms: u64,
    /// 空转模式：只做决策与审计，**不真正调用渠道**（演练/灰度用）。
    pub dry_run: bool,
}

/// 通知相关错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotifyError {
    /// 配置非法。
    #[error("通知配置非法: {0}")]
    InvalidConfig(String),
    /// 渠道配置非法。
    #[error("渠道配置非法: {0}")]
    InvalidChannel(String),
    /// 租户隔离拒绝。
    #[error("租户隔离拒绝: 期望租户 {expected}，实际 {actual}")]
    TenantViolation {
        /// 期望租户。
        expected: String,
        /// 实际租户。
        actual: String,
    },
}

/// 令牌桶 / 滑动窗口限流器（按渠道独立计数）。
#[derive(Debug, Clone, Default)]
pub struct RateLimiter {
    config: DispatchConfig,
    hits: BTreeMap<Id, Vec<i64>>,
}

/// Mock 渠道：可编程成功/失败，记录全部投递（**离线可用，不联网**）。
#[derive(Debug)]
pub struct MockChannel {
    id: Id,
    kind: ChannelKind,
    tenant_id: TenantId,
    fail_times: u32,
    fail_reason: String,
    state: std::sync::Mutex<MockState>,
}

#[derive(Debug, Default)]
struct MockState {
    attempts: u32,
    sent: Vec<OutboundMessage>,
}

/// 通知派发器：路由 + 去重 + 抑制 + 限流 + 重试退避 + 审计。
///
/// ## 租户隔离
///
/// 渠道按 id 注册；派发前校验 `message.tenant_id == channel.tenant_id`，不一致直接判
/// [`SuppressCause::Unroutable`]（并留审计），**绝不跨租户投递**。
#[derive(Debug)]
pub struct NotificationDispatcher {
    config: DispatchConfig,
    channels: BTreeMap<Id, std::sync::Arc<dyn NotificationChannel>>,
    channel_meta: BTreeMap<Id, ChannelConfig>,
    maintenance: Vec<MaintenanceWindow>,
    limiter: RateLimiter,
    delivered: BTreeMap<String, Id>,
    audit: Vec<DeliveryAttempt>,
}

mod dedup_key;
mod display_timestamp;
mod impl_notification_dispatcher;
#[cfg(test)]
mod tests;
