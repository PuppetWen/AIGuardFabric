//! 由 `case.rs` 拆分：`impl_CaseSeverityPolicy`/`impl_CaseSeverityPolicy` 等 11 项（纯搬移，逻辑不变）。
use super::*;

impl Default for CaseSeverityPolicy {
    fn default() -> Self {
        Self { multi_entity_threshold: 3, escalate_on_spread: true, high_repeat_threshold: 50 }
    }
}

impl CaseSeverityPolicy {
    /// 由事件簇推导案件等级（**只升不降**）。
    #[must_use]
    pub fn derive(&self, cluster: &EventCluster, affected_entities: usize) -> Severity {
        let base = cluster.severity;
        if !self.escalate_on_spread {
            return base;
        }
        let spread = affected_entities >= self.multi_entity_threshold;
        let repeated = cluster.occurrences >= self.high_repeat_threshold;
        if spread || repeated { bump(base) } else { base }
    }
}

/// 等级提升一级（`Critical` 为上限）。
pub(crate) fn bump(severity: Severity) -> Severity {
    match severity {
        Severity::Info => Severity::Low,
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High | Severity::Critical => Severity::Critical,
    }
}

impl TimelineKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::StateChanged => "state-changed",
            Self::Assigned => "assigned",
            Self::Comment => "comment",
            Self::EvidenceAdded => "evidence-added",
            Self::Escalated => "escalated",
            Self::Merged => "merged",
            Self::Split => "split",
            Self::Closed => "closed",
            Self::SlaMarked => "sla-marked",
        }
    }

    /// 映射到 `agf-core` 的持久化事件类型（合并/拆分/SLA 回写归入状态变更）。
    #[must_use]
    pub const fn to_core_kind(&self) -> CaseEventKind {
        match self {
            Self::Created => CaseEventKind::Created,
            Self::StateChanged | Self::Merged | Self::Split | Self::SlaMarked => CaseEventKind::StateChanged,
            Self::Assigned => CaseEventKind::Assigned,
            Self::Comment => CaseEventKind::Comment,
            Self::EvidenceAdded => CaseEventKind::EvidenceAdded,
            Self::Escalated => CaseEventKind::Escalated,
            Self::Closed => CaseEventKind::Closed,
        }
    }
}

impl CaseTimelineEvent {
    /// 是否由自动化（剧本）产生。
    #[must_use]
    pub const fn is_automated(&self) -> bool {
        self.automated
    }

    /// 一行式描述。
    #[must_use]
    pub fn render(&self) -> String {
        let tag = if self.automated { "自动" } else { "人工" };
        format!("[{}][{}] {} {}：{}", self.at.to_rfc3339(), tag, self.kind.as_str(), self.actor, self.note)
    }
}

impl CaseDetail {
    /// 是否已关闭。
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self.case.state, CaseState::Closed)
    }

    /// 是否缺少负责人（可运营性检查）。
    #[must_use]
    pub fn is_unassigned(&self) -> bool {
        self.case.owner.as_ref().is_none_or(|o| o.trim().is_empty())
    }

    /// 是否已超 SLA（用案件自带 `sla_breached`，避免在这里重复算时钟）。
    #[must_use]
    pub const fn is_overdue(&self) -> bool {
        self.case.sla_breached
    }

    /// 时间线条目数。
    #[must_use]
    pub fn timeline_len(&self) -> usize {
        self.timeline.len()
    }
}

impl SubCaseSpec {
    /// 构造。
    #[must_use]
    pub fn new(title: impl Into<String>, severity: Severity) -> Self {
        Self {
            title: title.into(),
            summary: String::new(),
            severity,
            finding_ids: Vec::new(),
            asset_ids: Vec::new(),
            owner: None,
        }
    }
}

impl CaseSplitPlan {
    /// 子案数。
    #[must_use]
    pub fn child_count(&self) -> usize {
        self.children.len()
    }
}

impl CaseMergePlan {
    /// 合并涉及的案件总数（目标 + 源）。
    #[must_use]
    pub fn involved(&self) -> usize {
        self.sources.len() + 1
    }
}

/// 合并计划：纯函数（可测），只做校验与重算，不动任何状态。
///
/// # Errors
/// - `target` 不属于 `tenant`，或任一源案件不属于 `tenant` → [`CaseError::TenantViolation`]；
/// - 目标或源案件已 `closed` → [`CaseError::StateConflict`]（归档案件不可再参与合并）；
/// - 目标与源为同一案件、或源列表为空 → [`CaseError::InvalidInput`]。
pub fn plan_merge(
    tenant: TenantId,
    target: &Case,
    sources: &[Case],
    now: Timestamp,
) -> Result<CaseMergePlan, CaseError> {
    if target.tenant_id != tenant {
        return Err(CaseError::TenantViolation { expected: tenant.to_string(), actual: target.tenant_id.to_string() });
    }
    if target.state == CaseState::Closed {
        return Err(CaseError::StateConflict { state: "closed", action: "merge" });
    }
    if sources.is_empty() {
        return Err(CaseError::InvalidInput("合并至少需要一个源案件".to_string()));
    }
    let mut merged = target.clone();
    merged.severity = target.severity;
    let mut closed_sources = Vec::with_capacity(sources.len());
    let mut unmoved: Vec<Id> = Vec::new();

    for source in sources {
        if source.tenant_id != tenant {
            return Err(CaseError::TenantViolation {
                expected: tenant.to_string(),
                actual: source.tenant_id.to_string(),
            });
        }
        if source.id == target.id {
            return Err(CaseError::InvalidInput("源案件不能是目标案件自身".to_string()));
        }
        if source.state == CaseState::Closed {
            return Err(CaseError::StateConflict { state: "closed", action: "merge-as-source" });
        }
        if source.severity.weight() > merged.severity.weight() {
            merged.severity = source.severity;
        }
        for id in &source.alert_ids {
            if !merged.alert_ids.contains(id) {
                merged.alert_ids.push(*id);
            }
        }
        for id in &source.asset_ids {
            if !merged.asset_ids.contains(id) {
                merged.asset_ids.push(*id);
            }
        }
        for id in &source.finding_ids {
            if merged.finding_ids.contains(id) {
                unmoved.push(*id);
            } else {
                merged.finding_ids.push(*id);
            }
        }
        for collaborator in &source.collaborators {
            if !merged.collaborators.contains(collaborator) {
                merged.collaborators.push(collaborator.clone());
            }
        }
        merged.security_incident |= source.security_incident;
        let mut closed = source.clone();
        closed.state = CaseState::Closed;
        closed.closed_at = Some(now);
        closed.updated_at = now;
        let note = format!("已合并入案件 {}", merged.code);
        closed.resolution = Some(match closed.resolution.clone() {
            Some(existing) if !existing.is_empty() => format!("{existing}；{note}"),
            _ => note,
        });
        closed_sources.push(closed);
    }
    merged.updated_at = now;
    unmoved.sort();
    unmoved.dedup();
    Ok(CaseMergePlan { target: merged, sources: closed_sources, unmoved_findings: unmoved })
}

/// 拆分计划：纯函数（可测）。
///
/// 语义：父案件保留（作为"总案"），按 `specs` 生成子案；finding 按规格分配，
/// **未出现在任何规格里的 finding 明确列在 `unassigned_findings`** 并保留在父案上。
///
/// # Errors
/// 父案件不属于 `tenant`、为空标题规格、规格数为 0、子案标题重复时返回错误。
pub fn plan_split(
    tenant: TenantId,
    parent: &Case,
    specs: &[SubCaseSpec],
    now: Timestamp,
) -> Result<CaseSplitPlan, CaseError> {
    if parent.tenant_id != tenant {
        return Err(CaseError::TenantViolation { expected: tenant.to_string(), actual: parent.tenant_id.to_string() });
    }
    if specs.is_empty() {
        return Err(CaseError::InvalidInput("拆分至少需要一个子案规格".to_string()));
    }
    if parent.state == CaseState::Closed {
        return Err(CaseError::StateConflict { state: "closed", action: "split" });
    }
    let mut seen_titles: BTreeSet<String> = BTreeSet::new();
    for spec in specs {
        let title = spec.title.trim();
        if title.is_empty() {
            return Err(CaseError::InvalidInput("子案标题不能为空".to_string()));
        }
        if !seen_titles.insert(title.to_lowercase()) {
            return Err(CaseError::InvalidInput(format!("子案标题重复: {title}")));
        }
    }

    let mut children = Vec::with_capacity(specs.len());
    let mut assigned: Vec<Id> = Vec::new();
    for (index, spec) in specs.iter().enumerate() {
        let mut child = parent.clone();
        child.id = Id::new();
        child.code = format!("{}-S{}", parent.code, index + 1);
        child.title = spec.title.trim().to_string();
        child.summary = spec.summary.clone();
        child.severity = spec.severity;
        child.state = CaseState::New;
        child.owner = spec.owner.clone();
        child.collaborators = Vec::new();
        child.finding_ids = spec.finding_ids.clone();
        child.asset_ids = spec.asset_ids.clone();
        child.resolution = None;
        child.closed_at = None;
        child.sla_due_at = None;
        child.sla_breached = false;
        child.tags = parent.tags.clone();
        child.tags.push(format!("split-from:{}", parent.code));
        child.created_at = now;
        child.updated_at = now;
        assigned.extend(spec.finding_ids.iter().copied());
        children.push(child);
    }
    let assigned_set: BTreeSet<Id> = assigned.iter().copied().collect();
    let unassigned: Vec<Id> = parent.finding_ids.iter().copied().filter(|id| !assigned_set.contains(id)).collect();

    let mut new_parent = parent.clone();
    // 父案等级不降低（仍涵盖全部子案）。
    // 摘要**一律**写明拆分事实：空摘要时直接以"已拆分为 N 个子案"起头，
    // 否则在原有摘要后追加，避免拆分这件事在父案上无从体现。
    new_parent.summary = if new_parent.summary.trim().is_empty() {
        format!("已拆分为 {} 个子案", children.len())
    } else {
        format!("{}（已拆分为 {} 个子案）", new_parent.summary, children.len())
    };
    new_parent.updated_at = now;
    new_parent.tags.push(format!("split-into:{}", children.len()));

    Ok(CaseSplitPlan {
        parent: new_parent,
        children,
        assigned_findings: assigned_set.into_iter().collect(),
        unassigned_findings: unassigned,
    })
}
