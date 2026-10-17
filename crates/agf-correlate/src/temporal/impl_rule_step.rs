//! 由 `temporal.rs` 拆分：`GraphRule`/`GroupBy`/`RuleStep`/`TemporalOutcome`/`TemporalRule`/`TemporalScanner` 的实现（纯搬移，逻辑不变）。
use super::*;

impl RuleStep {
    /// 构造必需步。
    #[must_use]
    pub fn required(name: impl Into<String>, min_events: u32) -> Self {
        Self { name: name.into(), min_events, ..Self::default() }
    }

    /// 构造可选步。
    #[must_use]
    pub fn optional(name: impl Into<String>, min_events: u32) -> Self {
        Self { name: name.into(), min_events, optional: true, ..Self::default() }
    }

    /// 限定事件类别。
    #[must_use]
    pub fn with_categories(mut self, categories: &[&str]) -> Self {
        self.categories = categories.iter().map(|c| (*c).to_string()).collect();
        self
    }

    /// 限定事件动作。
    #[must_use]
    pub fn with_actions(mut self, actions: &[&str]) -> Self {
        self.actions = actions.iter().map(|a| (*a).to_string()).collect();
        self
    }

    /// 限定规则键。
    #[must_use]
    pub fn with_rule_keys(mut self, keys: &[&str]) -> Self {
        self.rule_keys = keys.iter().map(|k| (*k).to_string()).collect();
        self
    }

    /// 事件是否满足本步。
    #[must_use]
    pub fn matches(&self, event: &Event) -> bool {
        if !self.categories.is_empty() && !self.categories.iter().any(|c| c == event.category.as_str()) {
            return false;
        }
        if !self.actions.is_empty()
            && !self.actions.iter().any(|a| a == event.action.as_str() || a == &event.action_raw)
        {
            return false;
        }
        if !self.rule_keys.is_empty() && !self.rule_keys.iter().any(|k| event.ai.rule_keys.contains(k)) {
            return false;
        }
        true
    }
}

impl TemporalRule {
    /// 构造。
    #[must_use]
    pub fn new(
        key: impl Into<String>,
        name: impl Into<String>,
        window_secs: i64,
        steps: Vec<RuleStep>,
        severity: Severity,
    ) -> Self {
        Self { key: key.into(), name: name.into(), window_secs, order_required: false, steps, severity }
    }

    /// 要求顺序。
    #[must_use]
    pub const fn ordered(mut self) -> Self {
        self.order_required = true;
        self
    }

    /// 在滑动窗口中寻找满足计数、顺序和租户边界的事件子序列。
    #[must_use]
    pub fn evaluate(&self, events: &[Event]) -> TemporalOutcome {
        super::evaluate::evaluate(self, events)
    }

    /// 自动处理时只返回以当前事件为证据的链，避免无关新事件重复触发旧链。
    #[must_use]
    pub fn evaluate_containing(&self, events: &[Event], anchor: Id) -> TemporalOutcome {
        super::evaluate::evaluate_containing(self, events, Some(anchor))
    }
}

impl TemporalOutcome {
    /// 置信度（命中步数占比，落在 `0.0..=1.0`）。
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn confidence(&self) -> f32 {
        self.hit_steps as f32 / self.total_steps.max(1) as f32
    }

    /// 证据摘要（可读，写入告警描述）。
    #[must_use]
    pub fn summary(&self) -> String {
        let mut s = format!(
            "时序规则 {}：命中 {}/{} 步，跨度 {}s（窗口 {}s）",
            self.rule_key, self.hit_steps, self.total_steps, self.span_secs, self.window_secs
        );
        if !self.missing_steps.is_empty() {
            s.push_str(&format!("，缺失步骤：{}", self.missing_steps.join("、")));
        }
        if !self.order_ok {
            s.push_str("，顺序不符");
        }
        if !self.window_ok {
            s.push_str("，超出窗口");
        }
        s
    }
}

impl GroupBy {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Entity => "entity",
            Self::Source => "source",
            Self::Session => "session",
            Self::None => "none",
        }
    }
}

impl Default for TemporalScanner {
    fn default() -> Self {
        Self { aligner: EntityAligner::new(), group_by: GroupBy::Entity }
    }
}

impl TemporalScanner {
    /// 构造。
    #[must_use]
    pub fn new(group_by: GroupBy) -> Self {
        Self { aligner: EntityAligner::new(), group_by }
    }

    /// 计算一条事件的归组键（`None` 表示不参与归组）。
    #[must_use]
    pub fn group_key(&self, tenant: TenantId, event: &Event) -> Option<String> {
        if event.tenant_id != tenant {
            return None;
        }
        match self.group_by {
            GroupBy::None => Some("all".to_string()),
            GroupBy::Source => Some(format!("source|{}", event.source_id)),
            GroupBy::Session => event.ai.session_id.as_deref().map(|s| format!("session|{s}")),
            GroupBy::Entity => {
                let ents = self.aligner.extract(event);
                ents.strongest()
                    .map(|entity| crate::entity::entity_alignment_key(tenant, entity.kind, &entity.canonical))
            }
        }
    }

    /// 把事件按"归组键"分组（同组内按时间升序）。
    #[must_use]
    pub fn partition(&self, tenant: TenantId, events: &[Event]) -> BTreeMap<String, Vec<Event>> {
        let mut out: BTreeMap<String, Vec<Event>> = BTreeMap::new();
        for e in events {
            if let Some(k) = self.group_key(tenant, e) {
                out.entry(k).or_default().push(e.clone());
            }
        }
        for v in out.values_mut() {
            v.sort_by_key(|e| e.time);
        }
        out
    }

    /// 按规则集扫描全部事件，返回命中列表（可多组多规则命中）。
    #[must_use]
    pub fn scan(&self, tenant: TenantId, events: &[Event], rules: &[TemporalRule]) -> Vec<TemporalScanHit> {
        let groups = self.partition(tenant, events);
        let mut hits = Vec::new();
        for (group, group_events) in groups {
            for rule in rules {
                let outcome = rule.evaluate(&group_events);
                if outcome.matched {
                    hits.push(TemporalScanHit {
                        group: group.clone(),
                        rule_key: rule.key.clone(),
                        severity: rule.severity,
                        outcome,
                    });
                }
            }
        }
        hits.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.rule_key.cmp(&b.rule_key)));
        hits
    }
}

impl GraphRule {
    /// 构造。
    #[must_use]
    pub fn new(
        key: impl Into<String>,
        from_kind: EntityKind,
        to_kind: EntityKind,
        max_hops: usize,
        severity: Severity,
    ) -> Self {
        let key = key.into();
        Self { name: key.clone(), key, from_kind, to_kind, max_hops, severity }
    }
}
