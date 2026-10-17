//! 由 `case.rs` 拆分：`impl_CaseManager`/`allowed_transitions` 等 3 项（纯搬移，逻辑不变）。
use super::*;

impl CaseManager {
    /// 升级层级 +1。
    ///
    /// # Errors
    /// 案件不存在、跨租户、或已关闭时返回错误。
    pub fn escalate(
        &mut self,
        tenant: TenantId,
        case_id: Id,
        reason: &str,
        actor: &str,
        now: Timestamp,
    ) -> Result<u8, CaseError> {
        {
            let detail = self.detail_for(tenant, case_id)?;
            if detail.is_closed() {
                return Err(CaseError::StateConflict { state: "closed", action: "escalate" });
            }
        }
        let seq = self.next_seq(case_id);
        let detail = self.cases.get_mut(&case_id).ok_or(CaseError::NotFound(case_id))?;
        let level = detail.timeline.iter().filter(|e| e.kind == TimelineKind::Escalated).count() as u8 + 1;
        detail.case.updated_at = now;
        detail.timeline.push(CaseTimelineEvent {
            id: Id::new(),
            tenant_id: tenant,
            case_id,
            kind: TimelineKind::Escalated,
            actor: actor.to_string(),
            note: if reason.is_empty() {
                format!("升级到第 {level} 级")
            } else {
                format!("升级到第 {level} 级：{reason}")
            },
            detail: serde_json::json!({ "level": level }),
            automated: false,
            at: now,
            seq,
        });
        Ok(level)
    }
    /// 用纯函数计划执行合并。
    ///
    /// # Errors
    /// 见 [`plan_merge`]；源案件未登记时返回 [`CaseError::NotFound`]。
    pub fn merge(
        &mut self,
        tenant: TenantId,
        target_id: Id,
        source_ids: &[Id],
        actor: &str,
        now: Timestamp,
    ) -> Result<CaseMergePlan, CaseError> {
        let target = self.detail_for(tenant, target_id)?.case.clone();
        let mut sources = Vec::with_capacity(source_ids.len());
        for id in source_ids {
            sources.push(self.detail_for(tenant, *id)?.case.clone());
        }
        let plan = plan_merge(tenant, &target, &sources, now)?;
        self.store_merge(tenant, plan.clone(), actor, now)?;
        Ok(plan)
    }
    pub(crate) fn store_merge(
        &mut self,
        tenant: TenantId,
        plan: CaseMergePlan,
        actor: &str,
        now: Timestamp,
    ) -> Result<(), CaseError> {
        let target_id = plan.target.id;
        let source_ids: Vec<Id> = plan.sources.iter().map(|c| c.id).collect();
        let moved: Vec<Id> = plan.sources.iter().flat_map(|c| c.finding_ids.clone()).collect();
        let total = plan.sources.len();
        let note = format!(
            "合并 {total} 个来源案件：{}",
            source_ids.iter().map(ToString::to_string).collect::<Vec<_>>().join("、")
        );
        {
            let seq = self.next_seq(target_id);
            let detail = self.cases.get_mut(&target_id).ok_or(CaseError::NotFound(target_id))?;
            detail.case = plan.target.clone();
            for id in moved {
                if !detail.findings.contains(&id) {
                    detail.findings.push(id);
                }
            }
            detail.timeline.push(CaseTimelineEvent {
                id: Id::new(),
                tenant_id: tenant,
                case_id: target_id,
                kind: TimelineKind::Merged,
                actor: actor.to_string(),
                note,
                detail: serde_json::json!({ "source_cases": source_ids }),
                automated: false,
                at: now,
                seq,
            });
        }
        for source in &plan.sources {
            let seq = self.next_seq(source.id);
            let detail = self.cases.get_mut(&source.id).ok_or(CaseError::NotFound(source.id))?;
            let source_findings = detail.findings.clone();
            detail.case = source.clone();
            detail.timeline.push(CaseTimelineEvent {
                id: Id::new(),
                tenant_id: tenant,
                case_id: source.id,
                kind: TimelineKind::Merged,
                actor: actor.to_string(),
                note: format!("已合并入案件 {}（承接 {} 项 finding）", plan.target.code, source_findings.len()),
                detail: serde_json::json!({ "merged_into": plan.target.id, "target_code": plan.target.code }),
                automated: false,
                at: now,
                seq,
            });
        }
        Ok(())
    }
    /// 用纯函数计划执行拆分，并把子案登记进管理器。
    ///
    /// 子案的 finding 归属直接来自 [`SubCaseSpec`]；父案保留全部 finding（总案视角），
    /// `CaseSplitPlan::unassigned_findings` 列出未被子案覆盖的项。
    ///
    /// # Errors
    /// 见 [`plan_split`]；子案登记冲突时返回 [`CaseError::Duplicate`]。
    pub fn split(
        &mut self,
        tenant: TenantId,
        parent_id: Id,
        specs: &[SubCaseSpec],
        actor: &str,
        now: Timestamp,
    ) -> Result<CaseSplitPlan, CaseError> {
        let parent = self.detail_for(tenant, parent_id)?.case.clone();
        let plan = plan_split(tenant, &parent, specs, now)?;
        for (index, child) in plan.children.iter().enumerate() {
            let findings = specs.get(index).map(|s| s.finding_ids.clone()).unwrap_or_default();
            let seq = 0u64;
            let event = CaseTimelineEvent {
                id: Id::new(),
                tenant_id: tenant,
                case_id: child.id,
                kind: TimelineKind::Split,
                actor: actor.to_string(),
                note: format!("由案件 {} 拆分而来", parent.code),
                detail: serde_json::json!({ "parent_case": parent.id, "parent_code": parent.code }),
                automated: false,
                at: now,
                seq,
            };
            self.register(child.clone(), findings, vec![event])?;
        }
        let seq = self.next_seq(parent_id);
        let detail = self.cases.get_mut(&parent_id).ok_or(CaseError::NotFound(parent_id))?;
        detail.case = plan.parent.clone();
        detail.timeline.push(CaseTimelineEvent {
            id: Id::new(),
            tenant_id: tenant,
            case_id: parent_id,
            kind: TimelineKind::Split,
            actor: actor.to_string(),
            note: format!("拆分为 {} 个子案", plan.children.len()),
            detail: serde_json::json!({
                "children": plan.children.iter().map(|c| c.id).collect::<Vec<_>>(),
                "unassigned_findings": plan.unassigned_findings,
            }),
            automated: false,
            at: now,
            seq,
        });
        Ok(plan)
    }
    /// 从外部把案件置为"已超 SLA"（由 [`crate::sla`] 计算后回写，避免这里重复实现时钟）。
    ///
    /// 回写是**可审计动作**：时间线上留一条 `sla-marked` 记录（操作者 `system`），
    /// 否则"SLA 截止被改过"在案件时间线上无从体现。
    ///
    /// # Errors
    /// 案件不存在、跨租户时返回错误。
    pub fn mark_sla(
        &mut self,
        tenant: TenantId,
        case_id: Id,
        due_at: Timestamp,
        breached: bool,
        now: Timestamp,
    ) -> Result<(), CaseError> {
        self.detail_for(tenant, case_id)?;
        let seq = self.next_seq(case_id);
        let detail = self.cases.get_mut(&case_id).ok_or(CaseError::NotFound(case_id))?;
        detail.case.sla_due_at = Some(due_at);
        detail.case.sla_breached = breached;
        detail.case.updated_at = now;
        detail.timeline.push(CaseTimelineEvent {
            id: Id::new(),
            tenant_id: tenant,
            case_id,
            kind: TimelineKind::SlaMarked,
            actor: "system".to_string(),
            note: format!("SLA 回写：截止 {}，违约 {}", due_at.to_rfc3339(), if breached { "是" } else { "否" }),
            detail: serde_json::json!({ "sla_due_at": due_at.to_rfc3339(), "sla_breached": breached }),
            automated: true,
            at: now,
            seq,
        });
        Ok(())
    }
    /// 取某租户案件的**克隆**详情（避免借用与后续可变操作冲突）。
    ///
    /// # Errors
    /// 案件不存在、跨租户时返回错误。
    pub fn snapshot(&self, tenant: TenantId, case_id: Id) -> Result<CaseDetail, CaseError> {
        Ok(self.detail_for(tenant, case_id)?.clone())
    }
    /// 内部：租户校验后取引用。
    pub(crate) fn detail_for(&self, tenant: TenantId, case_id: Id) -> Result<&CaseDetail, CaseError> {
        let detail = self.cases.get(&case_id).ok_or(CaseError::NotFound(case_id))?;
        if detail.case.tenant_id != tenant {
            return Err(CaseError::TenantViolation {
                expected: tenant.to_string(),
                actual: detail.case.tenant_id.to_string(),
            });
        }
        Ok(detail)
    }
    /// 下一个时间线序号（同刻稳定排序用）。
    pub(crate) fn next_seq(&self, case_id: Id) -> u64 {
        self.cases.get(&case_id).map_or(0, |d| d.timeline.last().map_or(0, |e| e.seq.saturating_add(1)))
    }
    /// 生成案件编号。
    pub(crate) fn next_code(&mut self, tenant: TenantId, now: Timestamp) -> String {
        let year = chrono::Datelike::year(&now.as_datetime());
        let slot = self.code_seq.entry(tenant).or_insert(0);
        *slot = slot.saturating_add(1);
        Case::make_code(year, *slot)
    }
    /// 登记外部案件编号（保证内存序列不倒退）。
    pub(crate) fn bump_seq(&mut self, tenant: TenantId, code: &str) {
        let parsed = code.rsplit('-').next().and_then(|s| s.trim_start_matches('S').parse::<u32>().ok());
        if let Some(seq) = parsed {
            let slot = self.code_seq.entry(tenant).or_insert(0);
            if seq > *slot {
                *slot = seq;
            }
        }
    }
}

/// 允许的状态迁移（与 [`Case::can_transition_to`] 同语义，额外允许 `new → containing`）。
///
/// `new → containing` 是刻意放开的：真实应急里"先处置再调查"很常见（已知勒索样本直接隔离），
/// 强迫先进入 `investigating` 只会让操作员绕过系统。
#[must_use]
pub fn allowed_transitions(state: CaseState) -> Vec<CaseState> {
    match state {
        CaseState::New => vec![CaseState::Investigating, CaseState::Containing],
        CaseState::Investigating => vec![CaseState::Containing, CaseState::Resolved],
        CaseState::Containing => vec![CaseState::Resolved, CaseState::Investigating],
        CaseState::Resolved => vec![CaseState::Closed, CaseState::Investigating],
        CaseState::Closed => Vec::new(),
    }
}

/// 应用状态迁移的公共副作用（关闭时间、解决说明保留）。
pub(crate) fn apply_transition(case: &mut Case, next: CaseState, now: Timestamp) {
    case.state = next;
    case.updated_at = now;
    if next == CaseState::Closed {
        case.closed_at = Some(now);
    } else {
        // 从 closed 迁出（当前状态机不允许，此处仅防御性重置）。
        case.closed_at = None;
    }
}
