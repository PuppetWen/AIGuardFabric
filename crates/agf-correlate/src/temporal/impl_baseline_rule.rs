//! 由 `temporal.rs` 拆分：`impl_BaselineRule`/`impl_CorrelationInput` 等 5 项（纯搬移，逻辑不变）。
use super::*;

impl BaselineRule {
    /// 构造（默认 `z=3.0`、`min_samples=5`）。
    #[must_use]
    pub fn new(key: impl Into<String>, metric: impl Into<String>, severity: Severity) -> Self {
        let key = key.into();
        Self { name: key.clone(), key, metric: metric.into(), z_threshold: 3.0, min_samples: 5, severity }
    }

    /// 调整 Z 阈值。
    #[must_use]
    pub const fn with_z(mut self, z: f32) -> Self {
        self.z_threshold = z;
        self
    }

    /// 调整最小样本数。
    #[must_use]
    pub const fn with_min_samples(mut self, n: u32) -> Self {
        self.min_samples = n;
        self
    }
}

impl CorrelationInput {
    /// 由事件构造（自动做实体对齐与时间窗口推导）。
    #[must_use]
    pub fn from_events(tenant: TenantId, mut events: Vec<Event>) -> Self {
        events.retain(|event| event.tenant_id == tenant);
        events.sort_by_key(|e| e.time);
        let window = match (events.first(), events.last()) {
            (Some(a), Some(b)) => TimeRange::new(a.time, b.time),
            _ => TimeRange::last_secs(0),
        };
        let alignment = CrossSourceAlignment::from_events(tenant, &EntityAligner::new(), &events);
        Self { tenant, events, window, alignment, rule_keys: Vec::new(), metrics: BTreeMap::new() }
    }

    /// 追加规则键。
    #[must_use]
    pub fn with_rule_keys(mut self, keys: &[&str]) -> Self {
        self.rule_keys = keys.iter().map(|k| (*k).to_string()).collect();
        self
    }

    /// 追加指标。
    #[must_use]
    pub fn with_metric(mut self, name: impl Into<String>, value: f64) -> Self {
        self.metrics.insert(name.into(), value);
        self
    }

    /// 涉及的事件 id。
    #[must_use]
    pub fn event_ids(&self) -> Vec<Id> {
        self.events.iter().map(|e| e.id).collect()
    }
}

impl CorrelationRule {
    /// 规则键。
    #[must_use]
    pub fn key(&self) -> &str {
        match self {
            Self::Match { key, .. } | Self::Temporal(TemporalRule { key, .. }) => key,
            Self::Graph(g) => &g.key,
            Self::Baseline(b) => &b.key,
        }
    }

    /// 建议等级。
    #[must_use]
    pub const fn severity(&self) -> Severity {
        match self {
            Self::Match { severity, .. } => *severity,
            Self::Temporal(t) => t.severity,
            Self::Graph(g) => g.severity,
            Self::Baseline(b) => b.severity,
        }
    }

    /// 形态文本。
    #[must_use]
    pub const fn shape(&self) -> &'static str {
        match self {
            Self::Match { .. } => "match",
            Self::Temporal(_) => "temporal",
            Self::Graph(_) => "graph",
            Self::Baseline(_) => "baseline",
        }
    }
}

impl CorrelationHit {
    /// 是否达到"高危"分级。
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.8
    }
}

/// 判定一个规则（四形态统一入口）。
///
/// 图与基线形态需要额外上下文：图形态用 `input.alignment`，基线形态用
/// [`BaselineDetector`] 的画像——因此基线与图形态在 `CorrelateService` 里
/// 分别走 [`CorrelationRule::Baseline`] + [`crate::baseline::BaselineDetector`]
/// 与 [`crate::graph::CorrelationGraph`]；本函数对这两种形态返回 `None`，
/// 由上层显式分派（避免在这里塞入两个可选依赖参数）。
#[must_use]
pub fn evaluate_simple(rule: &CorrelationRule, input: &CorrelationInput) -> Option<CorrelationHit> {
    match rule {
        CorrelationRule::Match { key, name, rule_keys, severity } => {
            let hit_keys: Vec<String> =
                input.rule_keys.iter().filter(|k| rule_keys.is_empty() || rule_keys.contains(k)).cloned().collect();
            if hit_keys.is_empty() {
                return None;
            }
            Some(CorrelationHit {
                rule_key: key.clone(),
                shape: "match".to_string(),
                severity: *severity,
                confidence: 1.0,
                evidence: hit_keys.clone(),
                summary: format!("{name}：命中规则 {}", hit_keys.join("、")),
            })
        }
        CorrelationRule::Temporal(rule) => {
            let outcome = rule.evaluate(&input.events);
            if !outcome.matched {
                return None;
            }
            Some(CorrelationHit {
                rule_key: rule.key.clone(),
                shape: "temporal".to_string(),
                severity: rule.severity,
                confidence: outcome.confidence(),
                evidence: outcome.matched_event_ids.iter().map(ToString::to_string).collect(),
                summary: outcome.summary(),
            })
        }
        CorrelationRule::Graph(_) | CorrelationRule::Baseline(_) => None,
    }
}
