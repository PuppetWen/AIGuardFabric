//! 由 `quota.rs` 拆分：`impl_QuotaWindow`/`impl_Quota` 等 6 项（纯搬移，逻辑不变）。
use super::*;

use crate::enums::{QuotaDimension, QuotaScope};
use crate::ids::{Id, TenantId, TenantScoped};
use crate::time::Timestamp;

impl QuotaWindow {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Minute => "minute",
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Month => "month",
            Self::Session => "session",
            Self::Total => "total",
        }
    }

    /// 窗口长度（秒）；`Session`/`Total` 返回 `None`（不按时间滚动）。
    #[must_use]
    pub const fn seconds(&self) -> Option<i64> {
        match self {
            Self::Minute => Some(60),
            Self::Hour => Some(3_600),
            Self::Day => Some(86_400),
            Self::Month => Some(2_592_000),
            Self::Session | Self::Total => None,
        }
    }

    /// 计算窗口键（用于 Redis 计数器 key 与使用记录分桶）。
    ///
    /// - `Minute`：`2026-03-01T10:05Z` 的 `YYYYMMDDHHMM`
    /// - `Hour`/`Day`/`Month`：对应精度的前缀
    /// - `Session`：固定 `session`
    /// - `Total`：固定 `total`
    #[must_use]
    pub fn bucket_key(&self, at: Timestamp) -> String {
        let fmt = match self {
            Self::Minute => "%Y%m%d%H%M",
            Self::Hour => "%Y%m%d%H",
            Self::Day => "%Y%m%d",
            Self::Month => "%Y%m",
            Self::Session => return "session".to_string(),
            Self::Total => return "total".to_string(),
        };
        at.as_datetime().format(fmt).to_string()
    }

    /// 全部窗口。
    #[must_use]
    pub const fn all() -> [Self; 6] {
        [Self::Minute, Self::Hour, Self::Day, Self::Month, Self::Session, Self::Total]
    }

    /// 解析文本。
    ///
    /// # Errors
    /// 未知窗口返回错误。
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "minute" | "1m" => Ok(Self::Minute),
            "hour" | "1h" => Ok(Self::Hour),
            "day" | "1d" => Ok(Self::Day),
            "month" | "1mo" => Ok(Self::Month),
            "session" => Ok(Self::Session),
            "total" | "all" => Ok(Self::Total),
            other => Err(format!("未知配额窗口: {other}")),
        }
    }
}

impl TenantScoped for Quota {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl Quota {
    /// 构造租户级默认配额。
    #[must_use]
    pub fn tenant_default(tenant_id: TenantId, dimension: QuotaDimension, limit: i64) -> Self {
        let now = Timestamp::now();
        Self {
            id: Id::new(),
            tenant_id,
            name: format!("tenant-default-{}", dimension.as_str()),
            scope: QuotaScope::Tenant,
            dimension,
            window: QuotaWindow::Day,
            limit,
            soft_threshold: limit / 10 * 8,
            on_exceed: crate::enums::PolicyAction::Deny,
            enabled: true,
            target_id: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// 用量是否**超过**上限。
    ///
    /// 语义是"严格大于"：`limit` 是允许消耗的额度，恰好用满（`used == limit`）不算超限，
    /// 只是不再有剩余额度。这与 [`check_quotas`] 的 `projected = used + 本次用量`、
    /// 以及 `QuotaStore::check_and_consume` 的"超过上限不消费"判定保持同一口径。
    #[must_use]
    pub const fn is_exceeded(&self, used: i64) -> bool {
        self.enabled && used > self.limit
    }

    /// 是否触发软阈值告警。
    #[must_use]
    pub const fn is_soft_breached(&self, used: i64) -> bool {
        self.enabled && self.soft_threshold > 0 && used >= self.soft_threshold && used < self.limit
    }

    /// 剩余额度（可为负）。
    #[must_use]
    pub const fn remaining(&self, used: i64) -> i64 {
        self.limit - used
    }

    /// 使用率（0.0-1.0+）。
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn usage_ratio(&self, used: i64) -> f32 {
        if self.limit <= 0 {
            return 1.0;
        }
        (used as f32) / (self.limit as f32)
    }
}

impl QuotaCheck {
    /// 放行结论。
    #[must_use]
    pub fn pass() -> Self {
        Self {
            allowed: true,
            exceeded_quota_id: None,
            dimension: None,
            scope: None,
            used: 0,
            limit: 0,
            soft_breached: Vec::new(),
            action: crate::enums::PolicyAction::Allow,
            retry_after_secs: None,
        }
    }
}

impl QuotaConsumption {
    /// 取某维度的值。
    #[must_use]
    pub const fn value(&self, dimension: QuotaDimension) -> i64 {
        match dimension {
            QuotaDimension::Tokens => self.tokens,
            QuotaDimension::Requests => self.requests,
            QuotaDimension::Concurrency => self.concurrency,
            QuotaDimension::Cost => self.cost_micro,
        }
    }

    /// 单次请求计费单位构造。
    #[must_use]
    pub const fn one_request() -> Self {
        Self { tokens: 0, requests: 1, concurrency: 1, cost_micro: 0 }
    }
}

/// 在给定配额集合与已用量下做三级检查（纯函数，便于单测与属性测试）。
///
/// 判定顺序：`deny` 类最优先（任一超限即拒），随后 `throttle`、最后 `degrade`。
/// 软阈值只产出告警列表，不影响 `allowed`。
#[must_use]
pub fn check_quotas(quotas: &[(Quota, i64)], consumption: &QuotaConsumption) -> QuotaCheck {
    let mut result = QuotaCheck::pass();
    let mut worst: Option<(u8, &Quota, i64)> = None;
    for (quota, used) in quotas {
        if !quota.enabled {
            continue;
        }
        let projected = used + consumption.value(quota.dimension);
        if quota.is_soft_breached(projected) {
            result.soft_breached.push(quota.id);
        }
        if quota.is_exceeded(projected) {
            let rank = match quota.on_exceed {
                crate::enums::PolicyAction::Deny | crate::enums::PolicyAction::Isolate => 3,
                crate::enums::PolicyAction::Throttle => 2,
                crate::enums::PolicyAction::Degrade => 1,
                _ => 0,
            };
            if worst.as_ref().is_none_or(|(r, _, _)| rank > *r) {
                worst = Some((rank, quota, projected));
            }
        }
    }
    if let Some((_, quota, projected)) = worst {
        result.allowed = false;
        result.exceeded_quota_id = Some(quota.id);
        result.dimension = Some(quota.dimension);
        result.scope = Some(quota.scope);
        result.used = projected;
        result.limit = quota.limit;
        result.action = quota.on_exceed;
        result.retry_after_secs = quota.window.seconds();
    }
    result
}
