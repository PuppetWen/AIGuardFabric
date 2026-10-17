//! 适配器健康模型：可用 / 降级 / 不可用 + 最近错误 + 连续失败数。
//!
//! `docs/adapter-spec.md` §1.4 的 [`agf_core::adapter::AdapterHealth`] 是**跨平台统一形态**；
//! 本模块的 [`AdapterHealthRecord`] 是它在 `agf-adapters` 内的运行时形态，
//! 额外携带三档状态（[`HealthStatus`]）、连续失败数与"是否未实现真实传输"的事实，
//! 便于控制台直接渲染"接入管理"页的三档灯。
//!
//! ## 未配置时的降级行为
//!
//! | 模式 | 状态 | 说明 |
//! |---|---|---|
//! | `Mocked` | `Degraded` | 确定性回执，未触达真实外部系统（message 含 `AGF_MOCK_MODE`） |
//! | `Unconfigured` | `Degraded`（映射 `HealthState::Unconfigured`） | 缺凭据/必需设置，调用会返回明确错误 |
//! | `Live` 且真实传输未实现 | `Unavailable` | **11 个内置适配器均已实现真实传输，当前无适配器命中此档**；新增适配器的脚手架阶段才会（`real_transport=false` 时如实标注不可用） |
//! | `Live` 且已实现真实传输、无失败 | `Available` | 真实 HTTP/UDP/TCP/SMTP 通道可用 |
//! | `Live` 且有失败 | `Degraded`（连续失败） | 熔断开路后为 `Unavailable`（映射 `CircuitOpen`） |

use agf_core::adapter::{AdapterCapability, AdapterHealth, CircuitSnapshot, CircuitState};
use agf_core::enums::HealthState;
use agf_core::time::Timestamp;

use crate::contract::AdapterMetadata;
use crate::settings::AdapterMode;

/// 三档健康状态（控制台"接入管理"页的灯色依据）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// 可用。
    Available,
    /// 降级（Mock / 未配置 / 部分失败）。
    Degraded,
    /// 不可用（真实传输未实现 / 熔断开路）。
    Unavailable,
}

impl HealthStatus {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
        }
    }

    /// 是否可承载真实流量。
    #[must_use]
    pub const fn is_serving(&self) -> bool {
        matches!(self, Self::Available)
    }
}

/// 纯函数状态评估（便于覆盖全组合单测）。
///
/// 规则：
/// 1. `Unconfigured` / `Mocked` → `Degraded`（降级不是失败）；
/// 2. `Live` 但真实传输未实现 → `Unavailable`（**不假装成功**）；
/// 3. `Live` 且熔断开路 → `Unavailable`；半开 → `Degraded`；
/// 4. `Live` 且闭合但有连续失败 → `Degraded`；否则 `Available`。
#[must_use]
pub const fn evaluate_status(
    mode: AdapterMode,
    real_transport: bool,
    circuit: CircuitState,
    consecutive_failures: u32,
) -> HealthStatus {
    match mode {
        AdapterMode::Unconfigured | AdapterMode::Mocked => HealthStatus::Degraded,
        AdapterMode::Live => {
            if !real_transport {
                return HealthStatus::Unavailable;
            }
            match circuit {
                CircuitState::Open => HealthStatus::Unavailable,
                CircuitState::HalfOpen => HealthStatus::Degraded,
                CircuitState::Closed => {
                    if consecutive_failures > 0 {
                        HealthStatus::Degraded
                    } else {
                        HealthStatus::Available
                    }
                }
            }
        }
    }
}

/// Mock 模式的固定健康说明（**必须**包含 `AGF_MOCK_MODE`，见 spec §6.4 第 6 条）。
pub const MOCK_MESSAGE: &str = "AGF_MOCK_MODE=1：返回确定性 Mock 回执，未触达真实外部系统";

/// 适配器健康记录。
///
/// 不派生 `PartialEq`：内含的 [`CircuitSnapshot`] 未派生（core 契约如此），
/// 测试断言逐字段进行即可（见模块内 `record_serde_roundtrip`）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdapterHealthRecord {
    /// 适配器名。
    pub adapter: String,
    /// 三档状态。
    pub status: HealthStatus,
    /// 配置是否齐全。
    pub configured: bool,
    /// 是否 Mock。
    pub mocked: bool,
    /// 是否需要网络。
    pub requires_network: bool,
    /// 运行模式。
    pub mode: AdapterMode,
    /// 连续失败数。
    pub consecutive_failures: u32,
    /// 累计成功。
    pub total_success: u64,
    /// 累计失败。
    pub total_failure: u64,
    /// 最近错误（脱敏后文本）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// 最近一次调用耗时（毫秒）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// 最近一次调用的尝试次数（含首次；>1 说明发生了重试）。
    #[serde(default)]
    pub last_attempts: u32,
    /// 熔断快照。
    pub circuit: CircuitSnapshot,
    /// 能力清单。
    pub capabilities: Vec<AdapterCapability>,
    /// 说明/错误（面向运维）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// 检查时间。
    pub checked_at: Timestamp,
}

impl AdapterHealthRecord {
    /// 未配置形态。
    #[must_use]
    pub fn unconfigured(name: &str, capabilities: Vec<AdapterCapability>, message: impl Into<String>) -> Self {
        Self {
            adapter: name.to_string(),
            status: HealthStatus::Degraded,
            configured: false,
            mocked: false,
            requires_network: true,
            mode: AdapterMode::Unconfigured,
            consecutive_failures: 0,
            total_success: 0,
            total_failure: 0,
            last_error: None,
            latency_ms: None,
            last_attempts: 0,
            circuit: CircuitSnapshot::default(),
            capabilities,
            message: Some(message.into()),
            checked_at: Timestamp::now(),
        }
    }

    /// Mock 形态。
    #[must_use]
    pub fn mocked(name: &str, capabilities: Vec<AdapterCapability>) -> Self {
        Self {
            adapter: name.to_string(),
            status: HealthStatus::Degraded,
            configured: false,
            mocked: true,
            requires_network: true,
            mode: AdapterMode::Mocked,
            consecutive_failures: 0,
            total_success: 0,
            total_failure: 0,
            last_error: None,
            latency_ms: Some(0),
            last_attempts: 0,
            circuit: CircuitSnapshot::default(),
            capabilities,
            message: Some(MOCK_MESSAGE.to_string()),
            checked_at: Timestamp::now(),
        }
    }

    /// 映射为 `agf-core` 的统一健康状态。
    #[must_use]
    pub const fn health_state(&self) -> HealthState {
        match self.status {
            HealthStatus::Available => HealthState::Healthy,
            HealthStatus::Degraded => {
                if matches!(self.mode, AdapterMode::Unconfigured) {
                    HealthState::Unconfigured
                } else {
                    HealthState::Degraded
                }
            }
            HealthStatus::Unavailable => {
                if matches!(self.circuit.state, CircuitState::Open) {
                    HealthState::CircuitOpen
                } else {
                    HealthState::Unhealthy
                }
            }
        }
    }

    /// 转为契约要求的 [`AdapterHealth`]。
    #[must_use]
    pub fn to_core_health(&self, meta: AdapterMetadata) -> AdapterHealth {
        AdapterHealth {
            adapter: self.adapter.clone(),
            state: self.health_state(),
            configured: self.configured,
            mocked: self.mocked,
            latency_ms: self.latency_ms,
            circuit: self.circuit.clone(),
            capabilities: if self.capabilities.is_empty() { meta.capabilities } else { self.capabilities.clone() },
            message: self.message.clone(),
            checked_at: self.checked_at,
        }
    }

    /// 是否处于降级（Mock/未配置）——"降级中"列表使用。
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        matches!(self.status, HealthStatus::Degraded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconfigured_and_mocked_are_degraded_not_failed() {
        for mode in [AdapterMode::Unconfigured, AdapterMode::Mocked] {
            let status = evaluate_status(mode, false, CircuitState::Closed, 0);
            assert_eq!(status, HealthStatus::Degraded, "{mode:?} 应降级而非失败");
            assert!(!status.is_serving());
        }
    }

    #[test]
    fn live_without_real_transport_is_unavailable() {
        assert_eq!(evaluate_status(AdapterMode::Live, false, CircuitState::Closed, 0), HealthStatus::Unavailable);
    }

    #[test]
    fn live_with_real_transport_follows_circuit() {
        assert_eq!(evaluate_status(AdapterMode::Live, true, CircuitState::Closed, 0), HealthStatus::Available);
        assert_eq!(evaluate_status(AdapterMode::Live, true, CircuitState::Closed, 1), HealthStatus::Degraded);
        assert_eq!(evaluate_status(AdapterMode::Live, true, CircuitState::HalfOpen, 3), HealthStatus::Degraded);
        assert_eq!(evaluate_status(AdapterMode::Live, true, CircuitState::Open, 9), HealthStatus::Unavailable);
    }

    #[test]
    fn core_health_state_mapping() {
        let mut rec = AdapterHealthRecord::mocked("feishu", vec![]);
        assert_eq!(rec.health_state(), HealthState::Degraded);
        assert!(rec.mocked);
        assert!(rec.message.clone().unwrap_or_default().contains("AGF_MOCK_MODE"));
        assert!(rec.is_degraded());

        rec = AdapterHealthRecord::unconfigured("feishu", vec![], "缺少 webhook_url");
        assert_eq!(rec.health_state(), HealthState::Unconfigured);
        assert!(!rec.configured);

        rec.status = HealthStatus::Unavailable;
        rec.circuit.state = CircuitState::Open;
        assert_eq!(rec.health_state(), HealthState::CircuitOpen);
        rec.circuit.state = CircuitState::Closed;
        assert_eq!(rec.health_state(), HealthState::Unhealthy);

        rec.status = HealthStatus::Available;
        assert_eq!(rec.health_state(), HealthState::Healthy);
    }

    #[test]
    fn to_core_health_carries_capabilities_from_metadata() {
        let rec = AdapterHealthRecord::mocked("feishu", vec![]);
        let meta = AdapterMetadata::new("feishu", "飞书", "字节跳动", crate::contract::AdapterCategory::Notification)
            .with_capabilities(vec![AdapterCapability::PushEvents]);
        let health = rec.to_core_health(meta);
        assert_eq!(health.capabilities, vec![AdapterCapability::PushEvents]);
        assert!(health.mocked);
        assert_eq!(health.latency_ms, Some(0));
    }

    #[test]
    fn record_serde_roundtrip() {
        let rec = AdapterHealthRecord::mocked("slack", vec![AdapterCapability::PushEvents]);
        let json = serde_json::to_string(&rec).unwrap_or_default();
        let back: AdapterHealthRecord =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("健康记录必须可反序列化: {e}"));
        assert_eq!(back.adapter, rec.adapter);
        assert_eq!(back.status, rec.status);
        assert_eq!(back.mocked, rec.mocked);
        assert_eq!(back.capabilities, rec.capabilities);
        assert_eq!(back.health_state(), rec.health_state());
    }
}
