//! 由 `sla.rs` 拆分：`EscalationTarget`/`SlaPauseReason`/`SlaPolicy`/`SlaStatus`/`SlaTarget`/`SlaTargetStatus` 的实现（纯搬移，逻辑不变）。
use super::*;

impl SlaTarget {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::FirstResponse => "first-response",
            Self::Containment => "containment",
            Self::Resolution => "resolution",
        }
    }

    /// 全部目标（固定顺序，便于遍历）。
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::FirstResponse, Self::Containment, Self::Resolution]
    }
}

impl SlaPauseReason {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ChangeWindow => "change-window",
            Self::BusinessConfirmation => "business-confirmation",
            Self::AwaitingApproval => "awaiting-approval",
            Self::VendorPending => "vendor-pending",
            Self::Other => "other",
        }
    }

    /// 是否属于"可以暂停 SLA"的正当理由。
    ///
    /// [`Self::Other`] 刻意**不算**：否则 `Other` 会成为万能挡箭牌。
    #[must_use]
    pub const fn is_legitimate(&self) -> bool {
        matches!(self, Self::ChangeWindow | Self::BusinessConfirmation | Self::AwaitingApproval | Self::VendorPending)
    }
}

impl EscalationTarget {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::OnCall => "on-call",
            Self::TeamLead => "team-lead",
            Self::SecurityOwner => "security-owner",
            Self::IncidentCommander => "incident-commander",
        }
    }
}

impl Default for SlaPolicy {
    fn default() -> Self {
        Self::for_severity(Severity::High)
    }
}

impl SlaPolicy {
    /// 按等级取默认策略，对齐常见 SOC 实践。
    ///
    /// | 等级 | 首次响应 | 遏制 | 解决 |
    /// |---|---|---|---|
    /// | critical | 15m | 1h | 8h |
    /// | high | 1h | 4h | 24h |
    /// | medium | 4h | 12h | 72h |
    /// | low | 24h | 72h | 7d |
    /// | info | 72h | 7d | 30d |
    ///
    /// 与 `agf-core` 的 [`agf_core::alert::Alert::sla_secs`]（单值口径）保持一致方向：
    /// 等级越高时限越短，且响应 < 遏制 < 解决。
    #[must_use]
    pub fn for_severity(severity: Severity) -> Self {
        let (first, contain, resolve, steps) = match severity {
            Severity::Critical => (
                900,
                3_600,
                28_800,
                vec![
                    EscalationStep { level: 1, overdue_secs: 900, target: EscalationTarget::OnCall },
                    EscalationStep { level: 2, overdue_secs: 3_600, target: EscalationTarget::IncidentCommander },
                ],
            ),
            Severity::High => (
                3_600,
                14_400,
                86_400,
                vec![
                    EscalationStep { level: 1, overdue_secs: 1_800, target: EscalationTarget::TeamLead },
                    EscalationStep { level: 2, overdue_secs: 7_200, target: EscalationTarget::SecurityOwner },
                ],
            ),
            Severity::Medium => (
                14_400,
                43_200,
                259_200,
                vec![EscalationStep { level: 1, overdue_secs: 7_200, target: EscalationTarget::TeamLead }],
            ),
            Severity::Low => (
                86_400,
                259_200,
                604_800,
                vec![EscalationStep { level: 1, overdue_secs: 86_400, target: EscalationTarget::TeamLead }],
            ),
            Severity::Info => (259_200, 604_800, 2_592_000, Vec::new()),
        };
        Self {
            name: format!("sla-{}", severity.as_str()),
            severity,
            first_response_secs: first,
            containment_secs: contain,
            resolution_secs: resolve,
            warning_ratio: 0.8,
            escalation: steps,
            pause_windows: Vec::new(),
        }
    }

    /// 目标时长（秒）。
    #[must_use]
    pub const fn target_secs(&self, target: SlaTarget) -> i64 {
        match target {
            SlaTarget::FirstResponse => self.first_response_secs,
            SlaTarget::Containment => self.containment_secs,
            SlaTarget::Resolution => self.resolution_secs,
        }
    }

    /// 追加暂停窗口（原因不合法时忽略并返回 false，不静默接受 `other`）。
    pub fn add_pause(&mut self, window: SlaPauseWindow) -> bool {
        if !window.reason.is_legitimate() {
            return false;
        }
        self.pause_windows.push(window);
        true
    }

    /// 校验策略。
    ///
    /// # Errors
    /// 目标时长非正、预警比例越界、升级阶梯未按层级/逾期递增时返回 [`SlaError::InvalidPolicy`]。
    pub fn validate(&self) -> Result<(), SlaError> {
        for target in SlaTarget::all() {
            if self.target_secs(target) <= 0 {
                return Err(SlaError::InvalidPolicy(format!("{} 的 {} 目标必须为正", self.name, target.as_str())));
            }
        }
        if !(0.0..=1.0).contains(&self.warning_ratio) {
            return Err(SlaError::InvalidPolicy(format!("{} 的 warning_ratio 必须落在 0.0..=1.0", self.name)));
        }
        let mut last_level = 0u8;
        let mut last_overdue = -1i64;
        for step in &self.escalation {
            if step.level <= last_level {
                return Err(SlaError::InvalidPolicy(format!("{} 的升级阶梯层级必须严格递增", self.name)));
            }
            if step.overdue_secs < last_overdue {
                return Err(SlaError::InvalidPolicy(format!("{} 的升级阶梯逾期阈值必须非递减", self.name)));
            }
            last_level = step.level;
            last_overdue = step.overdue_secs;
        }
        for window in &self.pause_windows {
            if !window.reason.is_legitimate() {
                return Err(SlaError::InvalidPolicy(format!(
                    "{} 存在非正当暂停原因（{}），请使用明确的暂停理由",
                    self.name,
                    window.reason.as_str()
                )));
            }
        }
        Ok(())
    }
}

impl SlaStatus {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::AtRisk => "at-risk",
            Self::Met => "met",
            Self::Breached => "breached",
        }
    }

    /// 是否违约。
    #[must_use]
    pub const fn is_breach(&self) -> bool {
        matches!(self, Self::Breached)
    }
}

impl SlaTargetStatus {
    /// 可读摘要。
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{}: {}（有效耗时 {}s / 目标 {}s，暂停扣除 {}s，剩余 {}s{}）",
            self.target.as_str(),
            self.status.as_str(),
            self.effective_elapsed_secs,
            self.target_secs,
            self.paused_secs,
            self.remaining_secs,
            if self.timed_out_before_met { "，达成时已逾期" } else { "" }
        )
    }
}
