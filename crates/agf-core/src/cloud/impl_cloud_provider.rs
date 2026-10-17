//! 由 `cloud.rs` 拆分：`AgentTeam`/`CloudCredentialKind`/`CloudIntegration`/`CloudProvider`/`CloudResourceMapping`/`CrossTeamCall`/`OrchestrationNode`/`PermissionCheck`/`QuotaSyncState`/`ScheduleBackend`/`ScheduleRegistration` 的实现（纯搬移，逻辑不变）。
use super::*;

use crate::ids::{TenantId, TenantScoped};
use crate::time::Timestamp;

impl CloudProvider {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AliCloud => "alicloud",
            Self::HuaweiCloud => "huaweicloud",
            Self::TencentCloud => "tencentcloud",
            Self::Aws => "aws",
            Self::Azure => "azure",
            Self::Gcp => "gcp",
            Self::Private => "private",
        }
    }
}

impl CloudCredentialKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InstanceRole => "instance-role",
            Self::StsToken => "sts-token",
            Self::AssumeRole => "assume-role",
            Self::LongTermAk => "long-term-ak",
            Self::WorkloadIdentity => "workload-identity",
        }
    }

    /// 是否为长期密钥（用于风险提示与自检红色告警）。
    #[must_use]
    pub const fn is_long_lived(&self) -> bool {
        matches!(self, Self::LongTermAk)
    }

    /// 是否会自动过期（需要刷新循环）。
    #[must_use]
    pub const fn is_temporary(&self) -> bool {
        matches!(self, Self::StsToken | Self::AssumeRole)
    }
}

impl TenantScoped for CloudIntegration {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl CloudIntegration {
    /// 是否为跨账号集成。
    #[must_use]
    pub fn is_cross_account(&self) -> bool {
        self.assume_role_arn.is_some()
    }

    /// STS 是否临近过期（15 分钟内）。
    #[must_use]
    pub fn sts_expiring_soon(&self, now: Timestamp) -> bool {
        self.sts_expires_at.is_some_and(|e| e.unix_secs() - now.unix_secs() < 900)
    }

    /// 是否存在长期密钥风险（自检页标红）。
    #[must_use]
    pub fn has_long_lived_risk(&self) -> bool {
        self.credential_kind.is_long_lived()
    }
}

impl PermissionCheck {
    /// 是否属于"最小权限不足"（必需项未通过）。
    #[must_use]
    pub const fn is_blocking(&self) -> bool {
        self.required && !self.passed
    }
}

impl TenantScoped for CloudResourceMapping {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl TenantScoped for AgentTeam {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl AgentTeam {
    /// 团队是否已纳管（有 Agent 映射到平台资产）。
    #[must_use]
    pub fn managed_ratio(&self) -> f32 {
        if self.agents.is_empty() {
            return 0.0;
        }
        let managed = self.agents.iter().filter(|a| a.asset_id.is_some()).count();
        #[allow(clippy::cast_precision_loss)]
        {
            managed as f32 / self.agents.len() as f32
        }
    }
}

impl OrchestrationNode {
    /// 该节点是否由定时调度触发。
    #[must_use]
    pub fn is_scheduled(&self) -> bool {
        self.trigger.eq_ignore_ascii_case("cron") && self.cron.is_some()
    }
}

impl TenantScoped for CrossTeamCall {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl TenantScoped for QuotaSyncState {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl QuotaSyncState {
    /// 依据"平台为准"策略解析冲突。
    ///
    /// 返回 `true` 表示**本次需要发出冲突告警**（首次发现冲突）；
    /// 冲突消失后会把 `conflict_alerted` 复位，使下次冲突能再次告警。
    pub fn resolve(&mut self) -> bool {
        let now_conflict = self.platform_value != self.cloud_value;
        let should_alert = now_conflict && !self.conflict_alerted;
        self.conflict = now_conflict;
        self.conflict_alerted = now_conflict;
        self.effective_value = self.platform_value;
        should_alert
    }
}

impl TenantScoped for ScheduleRegistration {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl ScheduleBackend {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SchedulerX3 => "schedulerx3",
            Self::LocalCron => "local-cron",
            Self::K8sCronJob => "k8s-cronjob",
            Self::Interval => "interval",
        }
    }

    /// 无云环境下的降级后端。
    #[must_use]
    pub const fn fallback(&self) -> Self {
        match self {
            Self::SchedulerX3 => Self::LocalCron,
            other => *other,
        }
    }
}
