//! 由 `redteam.rs` 拆分：`impl_AttackCategory`/`impl_ExecutionMode` 等 12 项（纯搬移，逻辑不变）。
use super::*;

use crate::enums::{RiskDomain, Severity};
use crate::ids::{TenantId, TenantScoped};

impl AttackCategory {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Jailbreak => "jailbreak",
            Self::DirectInjection => "direct-injection",
            Self::IndirectInjection => "indirect-injection",
            Self::RagPoisoning => "rag-poisoning",
            Self::ToolAbuse => "tool-abuse",
            Self::DataExfiltration => "data-exfiltration",
            Self::MultiTurnSocial => "multi-turn-social",
            Self::CredentialTheft => "credential-theft",
            Self::PrivilegeEscalation => "privilege-escalation",
            Self::SupplyChain => "supply-chain",
            Self::LateralMovement => "lateral-movement",
            Self::ResourceExhaustion => "resource-exhaustion",
        }
    }

    /// 归属的安全域。
    #[must_use]
    pub const fn domain(&self) -> RiskDomain {
        match self {
            Self::Jailbreak | Self::DirectInjection | Self::IndirectInjection | Self::MultiTurnSocial => {
                RiskDomain::PromptAttack
            }
            Self::RagPoisoning => RiskDomain::RagPoison,
            Self::ToolAbuse | Self::PrivilegeEscalation | Self::LateralMovement => RiskDomain::ToolAbuse,
            Self::DataExfiltration | Self::ResourceExhaustion | Self::SupplyChain => RiskDomain::ModelData,
            Self::CredentialTheft => RiskDomain::CredentialLeak,
        }
    }

    /// 全部类别。
    #[must_use]
    pub const fn all() -> [Self; 12] {
        [
            Self::Jailbreak,
            Self::DirectInjection,
            Self::IndirectInjection,
            Self::RagPoisoning,
            Self::ToolAbuse,
            Self::DataExfiltration,
            Self::MultiTurnSocial,
            Self::CredentialTheft,
            Self::PrivilegeEscalation,
            Self::SupplyChain,
            Self::LateralMovement,
            Self::ResourceExhaustion,
        ]
    }
}

impl ExecutionMode {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SingleTurn => "single-turn",
            Self::MultiTurn => "multi-turn",
            Self::ToolSequence => "tool-sequence",
            Self::DocumentPoison => "document-poison",
            Self::MultiAgent => "multi-agent",
        }
    }
}

pub(crate) fn default_user_role() -> String {
    "user".to_string()
}

impl RedteamCase {
    /// 校验用例完整性（加载期调用）。
    ///
    /// # Errors
    /// 返回全部问题描述。
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
        if self.key.trim().is_empty() {
            errs.push("key 不能为空".to_string());
        }
        if self.title.trim().is_empty() {
            errs.push(format!("用例 {} 缺少标题", self.key));
        }
        if self.turns.is_empty() {
            errs.push(format!("用例 {} 至少需要一个攻击轮次", self.key));
        }
        if self.turns.iter().all(|t| t.content.trim().is_empty()) {
            errs.push(format!("用例 {} 的攻击内容为空", self.key));
        }
        if self.success_signals.is_empty() {
            errs.push(format!("用例 {} 缺少成功判定信号（否则无法自动判定成功）", self.key));
        }
        let needs_tools = matches!(self.mode, ExecutionMode::ToolSequence | ExecutionMode::DocumentPoison);
        if needs_tools && self.required_tools.is_empty() {
            errs.push(format!("用例 {} 的执行方式 {:?} 需要声明 required_tools", self.key, self.mode));
        }
        if errs.is_empty() { Ok(()) } else { Err(errs) }
    }

    /// 是否适用于给定能力集合。
    #[must_use]
    pub fn applies_to_capabilities(&self, capabilities: &[&str]) -> bool {
        if self.applies_to.is_empty() {
            return true;
        }
        self.applies_to.iter().any(|need| capabilities.iter().any(|c| c.eq_ignore_ascii_case(need)))
    }
}

impl TenantScoped for RedteamCampaign {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl RedteamCampaign {
    /// 成功率（0.0-1.0）。
    #[must_use]
    pub fn success_rate(&self) -> f32 {
        if self.executed_cases == 0 {
            return 0.0;
        }
        f32::from(u16::try_from(self.succeeded_cases).unwrap_or(u16::MAX))
            / f32::from(u16::try_from(self.executed_cases).unwrap_or(1))
    }

    /// 是否通过 CI 卡点（无高危以上成功用例）。
    ///
    /// 判定逻辑与 `findings` 解耦，只看本次战役结果，保证 CI 可重复。
    #[must_use]
    pub fn passes_ci_gate(&self, critical_results: u32) -> bool {
        !self.ci_gate || critical_results == 0
    }
}

impl CampaignState {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

impl TenantScoped for RedteamResult {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl RedteamResult {
    /// Old explicitly mocked results retain their simulator-only interpretation.
    #[must_use]
    pub fn is_evaluated(&self) -> bool {
        self.evaluation == EvaluationStatus::Evaluated || (self.evaluation == EvaluationStatus::Unknown && self.mocked)
    }

    /// 风险等级（成功则取用例等级，失败则信息级）。
    #[must_use]
    pub fn effective_severity(&self, case_severity: Severity) -> Severity {
        if self.succeeded { case_severity } else { Severity::Info }
    }
}

impl TenantScoped for RedteamReport {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl CategoryStat {
    /// 成功率。
    #[must_use]
    pub fn success_rate(&self) -> f32 {
        if self.executed == 0 {
            return 0.0;
        }
        f32::from(u16::try_from(self.succeeded).unwrap_or(u16::MAX))
            / f32::from(u16::try_from(self.executed).unwrap_or(1))
    }
}

/// 由执行结果聚合统计（纯函数，便于单测）。
#[must_use]
pub fn aggregate_by_category(results: &[(AttackCategory, bool)]) -> Vec<CategoryStat> {
    let mut stats: Vec<CategoryStat> = Vec::new();
    for cat in AttackCategory::all() {
        let executed = results.iter().filter(|(c, _)| *c == cat).count();
        if executed == 0 {
            continue;
        }
        let succeeded = results.iter().filter(|(c, ok)| *c == cat && *ok).count();
        stats.push(CategoryStat {
            category: cat,
            executed: u32::try_from(executed).unwrap_or(u32::MAX),
            succeeded: u32::try_from(succeeded).unwrap_or(u32::MAX),
        });
    }
    stats
}
