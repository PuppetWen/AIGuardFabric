//! 由 `notify.rs` 拆分：`display_timestamp`/`impl_OutboundMessage` 等 12 项（纯搬移，逻辑不变）。
use super::*;

/// 通知正文里的时间戳渲染口径：**秒精度 RFC 3339**（`2026-03-02T10:00:00Z`）。
///
/// [`Timestamp::to_rfc3339`] 固定带毫秒尾巴（`...:00.000Z`），在短信/IM 正文里是纯噪声，
/// 还会让"同一分钟内的两条通知"看起来不同；通知面向人读，统一按秒精度渲染
/// （与 `agf-cli` 清单时间戳的口径一致）。
pub(crate) fn display_timestamp(at: Timestamp) -> String {
    at.as_datetime().to_rfc3339_opts(SecondsFormat::Secs, true)
}

impl OutboundMessage {
    /// 渲染上下文（供 [`NotifyContext::render`] 使用）。
    #[must_use]
    pub fn context(&self) -> NotifyContext {
        NotifyContext {
            title: self.title.clone(),
            severity: self.severity.as_str().to_string(),
            domain: self.extra.get("domain").cloned().unwrap_or_default(),
            asset: self.extra.get("asset").cloned().unwrap_or_default(),
            summary: self.body.clone(),
            console_url: self.extra.get("console_url").cloned().unwrap_or_default(),
            at: display_timestamp(self.at),
            extra: self.extra.clone(),
        }
    }

    /// 按渠道模板渲染正文（`template` 为 `None` 时返回原始正文）。
    #[must_use]
    pub fn render_body(&self, template: Option<&str>) -> String {
        match template {
            Some(t) if !t.trim().is_empty() => self.context().render(t),
            _ => self.body.clone(),
        }
    }

    /// 一行式摘要（审计展示）。
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "[{}] {} → {}#{}({})",
            self.kind.as_str(),
            self.title,
            self.subject_kind,
            self.subject_id,
            self.severity.as_str()
        )
    }
}

impl ChannelReceipt {
    /// 构造。
    #[must_use]
    pub fn new(external_id: impl Into<String>, accepted_at: Timestamp) -> Self {
        let external_id = external_id.into();
        Self { detail: format!("已受理：{external_id}"), external_id: Some(external_id), accepted_at }
    }
}

impl DeliveryOutcome {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::Suppressed => "suppressed",
        }
    }

    /// 映射到 `agf-core` 的投递状态（落库用）。
    #[must_use]
    pub const fn to_core_state(&self) -> DeliveryState {
        match self {
            Self::Delivered => DeliveryState::Delivered,
            Self::Failed => DeliveryState::Failed,
            Self::Suppressed => DeliveryState::Suppressed,
        }
    }
}

impl SuppressCause {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Dedup => "dedup",
            Self::Maintenance => "maintenance",
            Self::RateLimit => "rate-limit",
            Self::Unroutable => "unroutable",
        }
    }
}

impl DeliveryAttempt {
    /// 是否实际发生了投递动作（区分"没发"和"发了失败"）。
    #[must_use]
    pub const fn is_real_attempt(&self) -> bool {
        self.attempts > 0
    }

    /// 一行式摘要。
    #[must_use]
    pub fn summary(&self) -> String {
        use std::fmt::Write as _;
        let mut s =
            format!("{} {}#{} → {}", self.kind.as_str(), self.subject_kind, self.subject_id, self.outcome.as_str());
        if let Some(cause) = self.suppressed_by {
            let _ = write!(s, "（{}）", cause.as_str());
        }
        if self.attempts > 1 {
            let _ = write!(s, "，尝试 {} 次", self.attempts);
        }
        if let Some(ms) = self.backoff_ms {
            let _ = write!(s, "，下次退避 {ms}ms");
        }
        s
    }
}

impl DispatchResult {
    /// 是否至少有一个渠道成功。
    #[must_use]
    pub fn any_delivered(&self) -> bool {
        self.deliveries.iter().any(|d| d.outcome == DeliveryOutcome::Delivered)
    }

    /// 是否全部渠道都没发出去（全抑制/全失败）。
    #[must_use]
    pub fn is_fully_suppressed(&self) -> bool {
        !self.deliveries.is_empty() && self.deliveries.iter().all(|d| d.outcome != DeliveryOutcome::Delivered)
    }

    /// 成功投递的渠道数。
    #[must_use]
    pub fn delivered_count(&self) -> usize {
        self.deliveries.iter().filter(|d| d.outcome == DeliveryOutcome::Delivered).count()
    }

    /// 一条结果。
    #[must_use]
    pub fn delivery(&self, channel_id: Id) -> Option<&ChannelDelivery> {
        self.deliveries.iter().find(|d| d.channel_id == channel_id)
    }
}

impl Default for DispatchConfig {
    fn default() -> Self {
        Self {
            rate_limit_max: 20,
            rate_limit_window_secs: 60,
            max_attempts: 3,
            backoff_base_ms: 500,
            backoff_max_ms: 30_000,
            dry_run: false,
        }
    }
}

impl DispatchConfig {
    /// 校验配置。
    ///
    /// # Errors
    /// 限流窗口非正、最大尝试次数为 0、退避基数为 0 或上限小于基数时返回 [`NotifyError::InvalidConfig`]。
    pub fn validate(&self) -> Result<(), NotifyError> {
        if self.rate_limit_window_secs <= 0 {
            return Err(NotifyError::InvalidConfig("rate_limit_window_secs 必须为正".to_string()));
        }
        if self.max_attempts == 0 {
            return Err(NotifyError::InvalidConfig("max_attempts 必须至少为 1".to_string()));
        }
        if self.backoff_base_ms == 0 {
            return Err(NotifyError::InvalidConfig("backoff_base_ms 必须为正".to_string()));
        }
        if self.backoff_max_ms < self.backoff_base_ms {
            return Err(NotifyError::InvalidConfig("backoff_max_ms 不得小于 backoff_base_ms".to_string()));
        }
        Ok(())
    }

    /// 第 `attempt` 次失败后的退避毫秒数（`attempt` 从 1 开始，指数增长并封顶）。
    #[must_use]
    pub fn backoff_ms(&self, attempt: u32) -> u64 {
        let shift = attempt.saturating_sub(1).min(16);
        let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
        self.backoff_base_ms.saturating_mul(factor).min(self.backoff_max_ms)
    }
}

impl RateLimiter {
    /// 构造。
    #[must_use]
    pub fn new(config: DispatchConfig) -> Self {
        Self { config, hits: BTreeMap::new() }
    }

    /// 尝试消耗一个配额（会先清理窗口外的历史记录）。
    pub fn try_acquire(&mut self, channel_id: Id, now: Timestamp) -> bool {
        let window = self.config.rate_limit_window_secs;
        let cutoff = now.unix_secs().saturating_sub(window);
        let hits = self.hits.entry(channel_id).or_default();
        hits.retain(|t| *t > cutoff);
        if hits.len() >= self.config.rate_limit_max as usize {
            return false;
        }
        hits.push(now.unix_secs());
        true
    }

    /// 某渠道当前窗口内的已用配额。
    #[must_use]
    pub fn used(&self, channel_id: Id, now: Timestamp) -> usize {
        let cutoff = now.unix_secs().saturating_sub(self.config.rate_limit_window_secs);
        self.hits.get(&channel_id).map_or(0, |v| v.iter().filter(|t| **t > cutoff).count())
    }

    /// 清空全部计数（测试/演练用）。
    pub fn reset(&mut self) {
        self.hits.clear();
    }
}

impl MockChannel {
    /// 构造（默认恒成功）。
    #[must_use]
    pub fn new(id: Id, kind: ChannelKind, tenant_id: TenantId) -> Self {
        Self {
            id,
            kind,
            tenant_id,
            fail_times: 0,
            fail_reason: "mock 渠道故障".to_string(),
            state: std::sync::Mutex::new(MockState::default()),
        }
    }

    /// 前 `times` 次调用失败（用于验证重试）。
    #[must_use]
    pub fn failing_times(mut self, times: u32) -> Self {
        self.fail_times = times;
        self
    }

    /// 自定义失败原因。
    #[must_use]
    pub fn with_fail_reason(mut self, reason: impl Into<String>) -> Self {
        self.fail_reason = reason.into();
        self
    }

    /// 渠道 id。
    #[must_use]
    pub const fn id(&self) -> Id {
        self.id
    }

    /// 投递尝试次数（含失败）。
    #[must_use]
    pub fn attempts(&self) -> u32 {
        self.state.lock().map_or(0, |s| s.attempts)
    }

    /// 成功投递过的消息快照。
    #[must_use]
    pub fn sent(&self) -> Vec<OutboundMessage> {
        self.state.lock().map(|s| s.sent.clone()).unwrap_or_default()
    }

    /// 清空记录（测试复用）。
    pub fn reset(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.attempts = 0;
            state.sent.clear();
        }
    }
}

#[async_trait]
impl NotificationChannel for MockChannel {
    fn kind(&self) -> ChannelKind {
        self.kind
    }

    async fn send(&self, message: &OutboundMessage) -> Result<ChannelReceipt, String> {
        let attempt_index = {
            let mut state = self.state.lock().map_err(|_| "mock 渠道内部锁中毒".to_string())?;
            state.attempts = state.attempts.saturating_add(1);
            state.attempts
        };
        if attempt_index <= self.fail_times {
            return Err(format!("{}（第 {attempt_index} 次）", self.fail_reason));
        }
        if message.tenant_id != self.tenant_id {
            return Err(format!("mock 渠道租户不匹配：{}", message.tenant_id));
        }
        {
            let mut state = self.state.lock().map_err(|_| "mock 渠道内部锁中毒".to_string())?;
            state.sent.push(message.clone());
        }
        Ok(ChannelReceipt::new(format!("mock-{attempt_index}"), message.at))
    }
}
