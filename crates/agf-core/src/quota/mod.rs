//! 三级配额模型（§4.3：租户 → Agent → 会话；维度 Token/次数/并发/金额）。

use serde::{Deserialize, Serialize};

use crate::enums::{QuotaDimension, QuotaScope};

use crate::ids::{Id, TenantId};

use crate::time::Timestamp;

#[allow(unused_imports)]
pub use impl_quota_window::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 配额窗口。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QuotaWindow {
    /// 每分钟。
    Minute,
    /// 每小时。
    Hour,
    /// 每天。
    Day,
    /// 每月。
    Month,
    /// 整个会话（仅会话级有意义）。
    Session,
    /// 不重置（累计）。
    Total,
}

/// 配额定义。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quota {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 名称。
    pub name: String,
    /// 作用域（三级）。
    pub scope: QuotaScope,
    /// 维度。
    pub dimension: QuotaDimension,
    /// 窗口。
    pub window: QuotaWindow,
    /// 上限值。
    pub limit: i64,
    /// 软阈值（达到即告警但不变更动作；0 = 不启用）。
    #[serde(default)]
    pub soft_threshold: i64,
    /// 超限动作（默认 `deny`；可配 `throttle` / `degrade`）。
    pub on_exceed: crate::enums::PolicyAction,
    /// 是否启用。
    pub enabled: bool,
    /// 作用域对象 id（Agent 级 = agent 资产 id；会话级 = 会话模板 id；租户级为空）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<Id>,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
}

/// 配额使用量记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaUsage {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 配额 id。
    pub quota_id: Id,
    /// 作用域。
    pub scope: QuotaScope,
    /// 维度。
    pub dimension: QuotaDimension,
    /// 窗口。
    pub window: QuotaWindow,
    /// 窗口键。
    pub bucket: String,
    /// 作用域对象 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<Id>,
    /// 已用量。
    pub used: i64,
    /// 更新时间。
    pub updated_at: Timestamp,
}

/// 单次配额检查的结论。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaCheck {
    /// 是否放行。
    pub allowed: bool,
    /// 超限的配额 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exceeded_quota_id: Option<Id>,
    /// 超限维度。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dimension: Option<QuotaDimension>,
    /// 超限作用域。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<QuotaScope>,
    /// 已用。
    pub used: i64,
    /// 上限。
    pub limit: i64,
    /// 触发软阈值的配额 id 列表（放行但告警）。
    #[serde(default)]
    pub soft_breached: Vec<Id>,
    /// 建议动作。
    pub action: crate::enums::PolicyAction,
    /// 重试等待（秒，节流场景）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<i64>,
}

/// 三级配额检查的输入（一次请求的用量）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuotaConsumption {
    /// Token 数。
    pub tokens: i64,
    /// 请求次数（通常 1）。
    pub requests: i64,
    /// 并发增量。
    pub concurrency: i64,
    /// 金额（微元）。
    pub cost_micro: i64,
}

mod impl_quota_window;
#[cfg(test)]
mod tests;
