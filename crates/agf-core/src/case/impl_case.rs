//! 由 `case.rs` 拆分：`Case`/`CaseEvent`/`CaseEventKind`/`ContainmentAction`/`Playbook`/`PlaybookTrigger` 的实现（纯搬移，逻辑不变）。
use super::*;

use crate::enums::{CaseState, Severity};
use crate::ids::{TenantId, TenantScoped};

impl TenantScoped for Case {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl Case {
    /// 生成案件编号。
    #[must_use]
    pub fn make_code(year: i32, seq: u32) -> String {
        format!("CASE-{year}-{seq:04}")
    }

    /// 是否已关闭。
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self.state, CaseState::Closed)
    }

    /// 是否可推进到目标状态（状态机校验）。
    #[must_use]
    pub const fn can_transition_to(&self, next: CaseState) -> bool {
        matches!(
            (self.state, next),
            (CaseState::New | CaseState::Resolved, CaseState::Investigating)
                | (CaseState::Investigating, CaseState::Containing | CaseState::Resolved)
                | (CaseState::Containing, CaseState::Resolved)
                | (CaseState::Resolved, CaseState::Closed)
        )
    }
}

impl CaseEventKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::StateChanged => "state-changed",
            Self::Assigned => "assigned",
            Self::EvidenceAdded => "evidence-added",
            Self::Comment => "comment",
            Self::Containment => "containment",
            Self::Isolation => "isolation",
            Self::CredentialRevoked => "credential-revoked",
            Self::Blocklisted => "blocklisted",
            Self::Escalated => "escalated",
            Self::Closed => "closed",
            Self::PlaybookRun => "playbook-run",
        }
    }
}

impl TenantScoped for CaseEvent {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl ContainmentAction {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::IsolateAgent => "isolate-agent",
            Self::IsolateHost => "isolate-host",
            Self::DeactivateExternalUser => "deactivate-external-user",
            Self::RevokeCredential => "revoke-credential",
            Self::BlockDomain => "block-domain",
            Self::BlockIp => "block-ip",
            Self::DisableMcpServer => "disable-mcp-server",
            Self::RevokeSkill => "revoke-skill",
            Self::KillSession => "kill-session",
            Self::ForceLocalModel => "force-local-model",
            Self::NotifyOwner => "notify-owner",
            Self::Archive => "archive",
        }
    }

    /// 是否可自动执行（无需人工确认）。
    ///
    /// 保守策略：可逆且低风险的自动化；不可逆动作（吊销凭据、封禁）默认需人工确认。
    #[must_use]
    pub const fn auto_executable(&self) -> bool {
        matches!(self, Self::IsolateAgent | Self::KillSession | Self::NotifyOwner | Self::ForceLocalModel)
    }

    /// 是否可逆。
    #[must_use]
    pub const fn reversible(&self) -> bool {
        matches!(
            self,
            Self::IsolateAgent | Self::ForceLocalModel | Self::BlockDomain | Self::BlockIp | Self::KillSession
        )
    }
}

impl Playbook {
    /// 校验剧本。
    ///
    /// # Errors
    /// 返回问题列表。
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
        if self.key.trim().is_empty() {
            errs.push("剧本 key 不能为空".to_string());
        }
        if self.steps.is_empty() {
            errs.push(format!("剧本 {} 至少需要一个步骤", self.key));
        }
        if self.timeout_secs <= 0 {
            errs.push(format!("剧本 {} timeout_secs 必须为正", self.key));
        }
        for (i, s) in self.steps.iter().enumerate() {
            if s.name.trim().is_empty() {
                errs.push(format!("剧本 {} 第 {} 步缺少名称", self.key, i + 1));
            }
        }
        if errs.is_empty() { Ok(()) } else { Err(errs) }
    }

    /// 该剧本是否需要人工审批（本身要求，或含不可逆动作）。
    #[must_use]
    pub fn needs_human_approval(&self) -> bool {
        self.require_approval
            || self.steps.iter().any(|s| {
                s.action.as_ref().is_some_and(|a| {
                    matches!(
                        a,
                        ContainmentAction::RevokeCredential
                            | ContainmentAction::RevokeSkill
                            | ContainmentAction::IsolateHost
                            | ContainmentAction::DeactivateExternalUser
                    )
                })
            })
    }
}

impl PlaybookTrigger {
    /// 是否触发（基础字段判定；CEL 条件由 `agf-correlate` 评估）。
    #[must_use]
    pub fn matches(
        &self,
        domain: Option<crate::enums::RiskDomain>,
        severity: Severity,
        rule_keys: &[String],
        asset_kind: Option<crate::enums::AssetKind>,
    ) -> bool {
        if let Some(min) = self.min_severity {
            if severity.weight() < min.weight() {
                return false;
            }
        }
        if !self.domains.is_empty() && !domain.is_some_and(|d| self.domains.contains(&d)) {
            return false;
        }
        if !self.rule_keys.is_empty() && !rule_keys.iter().any(|k| self.rule_keys.contains(k)) {
            return false;
        }
        if !self.asset_kinds.is_empty() && !asset_kind.is_some_and(|k| self.asset_kinds.contains(&k)) {
            return false;
        }
        true
    }
}
