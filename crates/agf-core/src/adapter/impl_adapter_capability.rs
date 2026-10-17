//! 由 `adapter.rs` 拆分：`impl_AdapterCapability`/`impl_AdapterConfig` 等 14 项（纯搬移，逻辑不变）。
use super::*;

use crate::enums::HealthState;
use crate::error::DomainResult;
use crate::ids::{TenantId, TenantScoped};
use crate::time::Timestamp;
use std::future::Future;

impl AdapterCapability {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PullInventory => "pull-inventory",
            Self::PushConfig => "push-config",
            Self::PushMetrics => "push-metrics",
            Self::PushEvents => "push-events",
            Self::SubscribeEvents => "subscribe-events",
            Self::QueryLogs => "query-logs",
            Self::EnforcePolicy => "enforce-policy",
            Self::ScheduleTask => "schedule-task",
            Self::SelfCheck => "self-check",
            Self::AssumeRole => "assume-role",
            Self::ProbePrivateLink => "probe-private-link",
        }
    }
}

impl TenantScoped for AdapterConfig {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl AdapterConfig {
    /// 读取字符串设置。
    #[must_use]
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.settings.get(key).and_then(serde_json::Value::as_str)
    }

    /// 读取布尔设置（缺省值可指定）。
    #[must_use]
    pub fn get_bool(&self, key: &str, default: bool) -> bool {
        self.settings.get(key).and_then(serde_json::Value::as_bool).unwrap_or(default)
    }

    /// 是否已配置必需凭据。
    #[must_use]
    pub fn has_secrets(&self, required: &[&str]) -> bool {
        required.iter().all(|k| self.secret_refs.contains_key(*k))
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: default_failure_threshold(),
            open_secs: default_open_secs(),
            half_open_probes: default_half_open(),
        }
    }
}

impl CircuitState {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half-open",
        }
    }
}

impl Default for CircuitSnapshot {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            opened_at: None,
            probes_left: 0,
            total_success: 0,
            total_failure: 0,
            last_error: None,
        }
    }
}

impl CircuitSnapshot {
    /// 记录一次成功并决定新状态。
    pub fn on_success(&mut self) {
        self.total_success = self.total_success.saturating_add(1);
        self.consecutive_failures = 0;
        self.state = CircuitState::Closed;
        self.opened_at = None;
        self.probes_left = 0;
        self.last_error = None;
    }

    /// 记录一次失败并决定新状态。
    pub fn on_failure(&mut self, cfg: &CircuitBreakerConfig, error: impl Into<String>, now: Timestamp) {
        self.total_failure = self.total_failure.saturating_add(1);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_error = Some(error.into());
        if cfg.enabled && self.consecutive_failures >= cfg.failure_threshold {
            self.state = CircuitState::Open;
            self.opened_at = Some(now);
        }
    }

    /// 是否允许本次调用（开路未到期则拒绝）。
    ///
    /// 半开状态的探测额度在**进入半开时一次性发放**：
    /// 每次放行消耗一个额度，额度耗尽后拒绝，直到有一次成功把熔断器闭合。
    #[must_use]
    pub fn allows_call(&mut self, cfg: &CircuitBreakerConfig, now: Timestamp) -> bool {
        if !cfg.enabled {
            return true;
        }
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let expired = self.opened_at.is_some_and(|at| now.since_secs(&at) >= cfg.open_secs);
                if expired {
                    self.state = CircuitState::HalfOpen;
                    self.probes_left = cfg.half_open_probes;
                    // 本次调用即消耗一个探测额度
                    if self.probes_left > 0 {
                        self.probes_left -= 1;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                if self.probes_left > 0 {
                    self.probes_left -= 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// 对外健康状态映射。
    #[must_use]
    pub const fn health(&self) -> HealthState {
        match self.state {
            CircuitState::Closed => HealthState::Healthy,
            CircuitState::HalfOpen => HealthState::Degraded,
            CircuitState::Open => HealthState::CircuitOpen,
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            initial_backoff_ms: default_backoff(),
            multiplier: default_multiplier(),
            max_backoff_ms: default_max_backoff(),
            jitter: true,
        }
    }
}

impl RetryConfig {
    /// 计算第 `attempt` 次（从 0 开始）重试前的等待毫秒数（不含抖动）。
    #[must_use]
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn backoff_ms(&self, attempt: u32) -> u64 {
        let base = self.initial_backoff_ms as f64 * f64::from(self.multiplier).powi(attempt as i32);
        let capped = base.min(self.max_backoff_ms as f64);
        capped as u64
    }
}

impl AdapterHealth {
    /// 未配置时的健康报告（**降级而非失败**）。
    #[must_use]
    pub fn unconfigured(adapter: &str, reason: &str) -> Self {
        Self {
            adapter: adapter.to_string(),
            state: HealthState::Unconfigured,
            configured: false,
            mocked: false,
            latency_ms: None,
            circuit: CircuitSnapshot::default(),
            capabilities: Vec::new(),
            message: Some(reason.to_string()),
            checked_at: Timestamp::now(),
        }
    }

    /// Mock 模式下的健康报告。
    #[must_use]
    pub fn mocked(adapter: &str) -> Self {
        Self {
            adapter: adapter.to_string(),
            state: HealthState::Degraded,
            configured: false,
            mocked: true,
            latency_ms: Some(0),
            circuit: CircuitSnapshot::default(),
            capabilities: Vec::new(),
            message: Some("AGF_MOCK_MODE=1：返回 fixtures 录制响应，未触达真实外部系统".to_string()),
            checked_at: Timestamp::now(),
        }
    }
}

impl SyncOutcome {
    /// 构造 Mock 结果。
    #[must_use]
    pub fn mock(pulled: usize, pushed: usize) -> Self {
        Self { pulled, pushed, mocked: true, finished_at: Some(Timestamp::now()), ..Self::default() }
    }

    /// 是否有失败。
    #[must_use]
    pub const fn has_failures(&self) -> bool {
        self.failed > 0
    }
}

impl SyncDirection {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pull => "pull",
            Self::Push => "push",
            Self::Both => "both",
        }
    }

    /// 是否包含拉取。
    #[must_use]
    pub const fn includes_pull(&self) -> bool {
        matches!(self, Self::Pull | Self::Both)
    }

    /// 是否包含推送。
    #[must_use]
    pub const fn includes_push(&self) -> bool {
        matches!(self, Self::Push | Self::Both)
    }
}

impl TenantScoped for DeadLetterEntry {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

/// 在 `invoke` 帮助函数上执行"熔断检查 → 重试 → 记录"的通用包装。
///
/// 该函数不依赖具体适配器实现，因此放在 core 中作为契约的一部分，
/// 由各 crate 传入自己的 [`CircuitSnapshot`]（通常包在 `Mutex` 内）。
///
/// # Errors
/// 熔断开路、重试耗尽或 `op` 返回错误时返回错误。
pub async fn invoke_with_policy<T, F, Fut>(
    adapter: &str,
    snapshot: &mut CircuitSnapshot,
    cfg: &CircuitBreakerConfig,
    retry: &RetryConfig,
    now: Timestamp,
    mut op: F,
) -> DomainResult<T>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = DomainResult<T>>,
{
    if !snapshot.allows_call(cfg, now) {
        return Err(crate::error::DomainError::DependencyUnavailable {
            dependency: adapter.to_string(),
            cause: format!("熔断器处于 {} 状态，快速失败", snapshot.state.as_str()),
        });
    }
    let mut last_err: Option<crate::error::DomainError> = None;
    for attempt in 0..retry.max_attempts.max(1) {
        match op(attempt).await {
            Ok(v) => {
                snapshot.on_success();
                return Ok(v);
            }
            Err(e) => {
                let retryable = e.is_degradable() || matches!(e, crate::error::DomainError::Timeout(_));
                last_err = Some(e);
                if !retryable {
                    break;
                }
                if attempt + 1 < retry.max_attempts.max(1) {
                    let backoff = retry.backoff_ms(attempt);
                    tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
                }
            }
        }
    }
    let msg = last_err.as_ref().map(ToString::to_string).unwrap_or_else(|| "未知错误".to_string());
    snapshot.on_failure(cfg, msg.clone(), now);
    Err(last_err.unwrap_or(crate::error::DomainError::Internal(msg)))
}
