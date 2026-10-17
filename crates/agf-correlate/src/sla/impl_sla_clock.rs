//! 由 `sla.rs` 拆分：`impl_SlaClock`/`pause_overlap_secs` 等 3 项（纯搬移，逻辑不变）。
use super::*;

impl SlaClock {
    /// 新建时钟（校验策略）。
    ///
    /// # Errors
    /// 策略非法时返回 [`SlaError::InvalidPolicy`]。
    pub fn new(
        tenant_id: TenantId,
        subject_id: Id,
        started_at: Timestamp,
        policy: SlaPolicy,
    ) -> Result<Self, SlaError> {
        policy.validate()?;
        Ok(Self { tenant_id, subject_id, started_at, policy, milestones: Vec::new() })
    }

    /// 按等级新建时钟（默认策略）。
    ///
    /// # Errors
    /// 默认策略理论恒合法；返回 `Result` 以统一上层写法。
    pub fn for_severity(
        tenant_id: TenantId,
        subject_id: Id,
        started_at: Timestamp,
        severity: Severity,
    ) -> Result<Self, SlaError> {
        Self::new(tenant_id, subject_id, started_at, SlaPolicy::for_severity(severity))
    }

    /// 追加暂停窗口。
    ///
    /// # Errors
    /// 原因为 [`SlaPauseReason::Other`]、窗口结束早于开始、或窗口落在时钟起点之前时返回错误。
    pub fn pause(&mut self, window: SlaPauseWindow) -> Result<(), SlaError> {
        if !window.reason.is_legitimate() {
            return Err(SlaError::IllegitimatePause(window.reason.as_str().to_string()));
        }
        if window.to < window.from {
            return Err(SlaError::InvalidTime(format!(
                "暂停窗口结束 {} 早于开始 {}",
                window.to.to_rfc3339(),
                window.from.to_rfc3339()
            )));
        }
        if window.to < self.started_at {
            return Err(SlaError::InvalidTime(format!(
                "暂停窗口 {} 早于时钟起点 {}（不允许提前声明暂停）",
                window.to.to_rfc3339(),
                self.started_at.to_rfc3339()
            )));
        }
        self.policy.pause_windows.push(window);
        Ok(())
    }

    /// 记录目标达成。
    ///
    /// # Errors
    /// 达成时间早于时钟起点时返回 [`SlaError::InvalidTime`]。
    pub fn reach(&mut self, target: SlaTarget, at: Timestamp, actor: Option<Id>) -> Result<(), SlaError> {
        if at.is_before(&self.started_at) {
            return Err(SlaError::InvalidTime(format!(
                "{} 达成时间 {} 早于起点 {}",
                target.as_str(),
                at.to_rfc3339(),
                self.started_at.to_rfc3339()
            )));
        }
        if let Some(slot) = self.milestones.iter_mut().find(|(t, _)| *t == target) {
            // 重复达成取**更早**的一次（首次达成才是 SLA 语义）。
            if at.is_before(&slot.1.at) {
                slot.1 = SlaMilestone { at, actor };
            }
            return Ok(());
        }
        self.milestones.push((target, SlaMilestone { at, actor }));
        Ok(())
    }

    /// 某目标的达成记录。
    #[must_use]
    pub fn milestone(&self, target: SlaTarget) -> Option<SlaMilestone> {
        self.milestones.iter().find(|(t, _)| *t == target).map(|(_, m)| *m)
    }

    /// 判定某目标状态。
    #[must_use]
    pub fn status(&self, target: SlaTarget, now: Timestamp) -> SlaTargetStatus {
        let target_secs = self.policy.target_secs(target);
        let judged_at = self.milestone(target).map_or(now, |m| m.at);
        let paused = self.paused_secs_until(judged_at);
        let effective = judged_at.since_secs(&self.started_at) - paused;
        let remaining = target_secs - effective;
        let (status, timed_out_before_met) = match self.milestone(target) {
            Some(_) => {
                if effective > target_secs {
                    (SlaStatus::Breached, true)
                } else {
                    (SlaStatus::Met, false)
                }
            }
            None => {
                if effective > target_secs {
                    (SlaStatus::Breached, false)
                } else if effective as f64 >= target_secs as f64 * self.policy.warning_ratio {
                    (SlaStatus::AtRisk, false)
                } else {
                    (SlaStatus::Pending, false)
                }
            }
        };
        SlaTargetStatus {
            target,
            status,
            target_secs,
            effective_elapsed_secs: effective,
            paused_secs: paused,
            remaining_secs: remaining,
            timed_out_before_met,
        }
    }

    /// 三类目标的判定（固定顺序 first-response / containment / resolution）。
    #[must_use]
    pub fn statuses(&self, now: Timestamp) -> Vec<SlaTargetStatus> {
        SlaTarget::all().iter().map(|t| self.status(*t, now)).collect()
    }

    /// 最坏结论（任一违约即违约；否则任一 at-risk 即 at-risk；否则全部 met 才算 met）。
    #[must_use]
    pub fn overall(&self, now: Timestamp) -> SlaStatus {
        let statuses = self.statuses(now);
        if statuses.iter().any(|s| s.status.is_breach()) {
            return SlaStatus::Breached;
        }
        if statuses.iter().any(|s| s.status == SlaStatus::AtRisk) {
            return SlaStatus::AtRisk;
        }
        if statuses.iter().all(|s| s.status == SlaStatus::Met) {
            return SlaStatus::Met;
        }
        SlaStatus::Pending
    }

    /// 判定时刻是否已违约（汇总口径）。
    #[must_use]
    pub fn is_breached(&self, now: Timestamp) -> bool {
        self.overall(now).is_breach()
    }

    /// 某目标截止时间（**不含暂停补偿**：暂停窗口的时长会顺延截止，故此处按已记录的暂停推算）。
    #[must_use]
    pub fn due_at(&self, target: SlaTarget) -> Timestamp {
        self.started_at.offset_secs(self.policy.target_secs(target) + self.total_paused_secs())
    }

    /// 最近一个**尚未逾期**的未达成截止时间（全部达成、或未达成的都已在 `now` 前逾期时为 `None`）。
    ///
    /// 已经逾期的目标不算"最近截止"：它的截止时刻在过去，继续拿它当最近截止
    /// 会让上层一直盯着一个已经错过的时刻（[`case_sla_fields`] 因此在首次响应逾期后
    /// 自动转到下一类目标）。
    #[must_use]
    pub fn next_due_at(&self, now: Timestamp) -> Option<(SlaTarget, Timestamp)> {
        let mut best: Option<(SlaTarget, Timestamp)> = None;
        for target in SlaTarget::all() {
            if self.milestone(target).is_some() || self.status(target, now).status.is_breach() {
                continue;
            }
            let due = self.due_at(target);
            if best.as_ref().is_none_or(|(_, b)| due.is_before(b)) {
                best = Some((target, due));
            }
        }
        best
    }

    /// 逾期秒数（未违约返回 0；按**最紧的未达成目标**计算）。
    #[must_use]
    pub fn overdue_secs(&self, now: Timestamp) -> i64 {
        let mut worst: i64 = 0;
        for target in SlaTarget::all() {
            let status = self.status(target, now);
            if status.status.is_breach() {
                worst = worst.max(-status.remaining_secs);
            }
        }
        worst
    }

    /// 当前应处的升级层级（无则 `None`）。
    #[must_use]
    pub fn due_escalation(&self, now: Timestamp) -> Option<EscalationStep> {
        let overdue = self.overdue_secs(now);
        if overdue <= 0 {
            return None;
        }
        self.policy.escalation.iter().filter(|step| overdue >= step.overdue_secs).max_by_key(|step| step.level).copied()
    }

    /// 下一档升级（用于"还差多久升级"提示）。
    #[must_use]
    pub fn next_escalation(&self, now: Timestamp) -> Option<EscalationStep> {
        let overdue = self.overdue_secs(now);
        if overdue <= 0 {
            return self.policy.escalation.first().copied();
        }
        self.policy.escalation.iter().find(|step| overdue < step.overdue_secs).copied()
    }

    /// 到判定时刻为止落在计时区间内的暂停总时长（秒）。
    #[must_use]
    pub fn paused_secs_until(&self, at: Timestamp) -> i64 {
        self.policy
            .pause_windows
            .iter()
            .map(|w| pause_overlap_secs(w, self.started_at, at))
            .fold(0i64, i64::saturating_add)
    }

    /// 全部暂停时长（截止顺延用；含未来的窗口，因为它们已被显式批准）。
    #[must_use]
    pub fn total_paused_secs(&self) -> i64 {
        self.policy.pause_windows.iter().map(|w| w.to.since_secs(&w.from).max(0)).fold(0i64, i64::saturating_add)
    }

    /// 校验对象归属租户。
    ///
    /// # Errors
    /// 租户不一致时返回 [`SlaError::TenantViolation`]。
    pub fn ensure_tenant(&self, tenant: TenantId) -> Result<(), SlaError> {
        if self.tenant_id != tenant {
            return Err(SlaError::TenantViolation { expected: tenant.to_string(), actual: self.tenant_id.to_string() });
        }
        Ok(())
    }
}

/// 暂停窗口与 `[from, to]` 的重叠秒数（无交集返回 0）。
#[must_use]
pub fn pause_overlap_secs(window: &SlaPauseWindow, from: Timestamp, to: Timestamp) -> i64 {
    if to.is_before(&from) {
        return 0;
    }
    let start = if window.from.is_before(&from) { from } else { window.from };
    let end = if window.to.is_before(&to) { window.to } else { to };
    end.since_secs(&start).max(0)
}

/// 便捷入口：把 SLA 结论回写到案件可用的两个字段（`sla_due_at` / `sla_breached`）。
#[must_use]
pub fn case_sla_fields(clock: &SlaClock, now: Timestamp) -> (Timestamp, bool) {
    let due = clock.next_due_at(now).map_or_else(|| clock.due_at(SlaTarget::Resolution), |(_, due)| due);
    (due, clock.is_breached(now))
}
