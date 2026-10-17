//! 由 `aggregate.rs` 拆分：`EventCluster`/`ReduceReport` 的实现（纯搬移，逻辑不变）。
use super::*;

impl EventCluster {
    /// 新建空簇（供持久化重建；正常路径由聚合器内部构造）。
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        entity_key: Option<String>,
        category: impl Into<String>,
        representative_title: impl Into<String>,
        severity: Severity,
        at: Timestamp,
    ) -> Self {
        let category = category.into();
        let representative_title = representative_title.into();
        let id = agf_core::ids::deterministic_id(
            NS_CLUSTER,
            &format!(
                "{tenant_id}|{}|{}|{}",
                entity_key.as_deref().unwrap_or("-"),
                category,
                normalize_title(&representative_title)
            ),
        );
        Self {
            id,
            tenant_id,
            entity_key,
            category,
            representative_title,
            severity,
            first_seen_at: at,
            last_seen_at: at,
            occurrences: 0,
            dedup_count: 0,
            dedup_keys: BTreeSet::new(),
            truncated: false,
            alert_ids: Vec::new(),
            event_ids: Vec::new(),
            rule_keys: BTreeSet::new(),
            tags: BTreeSet::new(),
            suppressed: false,
            suppress_rule: None,
            suppress_reason: None,
            suppressed_by: None,
        }
    }

    /// 是否落在与给定时间的聚合窗内（以首见时间为锚）。
    #[must_use]
    pub fn within_window(&self, at: Timestamp, window_secs: i64) -> bool {
        at.since_secs(&self.first_seen_at) <= window_secs
    }

    /// 把一条输入并入本簇（含上限保护）。
    pub fn absorb(&mut self, input: &AlertInput, max_alerts: usize) {
        self.occurrences = self.occurrences.saturating_add(1);
        if input.at.is_at_or_after(&self.last_seen_at) {
            self.last_seen_at = input.at;
        }
        if input.severity.weight() > self.severity.weight() {
            self.severity = input.severity;
        }
        let fingerprint = input.dedup_key();
        if self.dedup_keys.contains(&fingerprint) {
            return;
        }
        if self.dedup_keys.len() >= max_alerts {
            self.truncated = true;
            return;
        }
        self.dedup_keys.insert(fingerprint);
        self.dedup_count = self.dedup_count.saturating_add(1);
        if let Some(id) = input.alert_id {
            if !self.alert_ids.contains(&id) {
                self.alert_ids.push(id);
            }
        }
        for id in &input.event_ids {
            if !self.event_ids.contains(id) {
                self.event_ids.push(*id);
            }
        }
        for key in &input.rule_keys {
            self.rule_keys.insert(key.clone());
        }
        for tag in &input.tags {
            self.tags.insert(tag.clone());
        }
    }

    /// 簇内平均每条去重告警被重复了多少次（`occurrences / dedup_count`）。
    #[must_use]
    pub fn repeat_factor(&self) -> f64 {
        if self.dedup_count == 0 {
            return 0.0;
        }
        self.occurrences as f64 / self.dedup_count as f64
    }

    /// 可读摘要（写入案件摘要/通知正文）。
    #[must_use]
    pub fn summary(&self) -> String {
        use std::fmt::Write as _;
        let entity = self.entity_key.as_deref().unwrap_or("无实体");
        let mut s = format!(
            "簇 {}｜{}｜{}｜原始 {} 条 / 去重 {} 条｜等级 {}",
            self.id,
            entity,
            self.category,
            self.occurrences,
            self.dedup_count,
            self.severity.as_str()
        );
        if self.suppressed {
            let _ = write!(s, "｜已抑制（{}）", self.suppress_reason.as_deref().unwrap_or("未说明"));
        }
        s
    }

    /// 是否值得升级为案件（未被抑制且有实际内容）。
    #[must_use]
    pub const fn is_actionable(&self) -> bool {
        !self.suppressed && self.occurrences > 0
    }
}

impl ReduceReport {
    /// 去重降噪率（`0.0..=1.0`）：`1 - 运营单元数 / 原始条数`。
    ///
    /// 无输入时返回 `0.0`（**不是 1.0**）：没有告警不等于"降噪 100%"，
    /// 报出 1.0 会让上层误以为规则非常有效。
    #[must_use]
    pub fn noise_reduction_ratio(&self) -> f64 {
        if self.raw_alerts == 0 {
            return 0.0;
        }
        1.0 - self.deduped_alerts as f64 / self.raw_alerts as f64
    }

    /// 可行动簇（未抑制）。
    #[must_use]
    pub fn actionable(&self) -> Vec<&EventCluster> {
        self.clusters.iter().filter(|c| c.is_actionable()).collect()
    }

    /// 被抑制簇。
    #[must_use]
    pub fn suppressed(&self) -> Vec<&EventCluster> {
        self.clusters.iter().filter(|c| c.suppressed).collect()
    }

    /// 可行动簇中的最高等级。
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.actionable().iter().map(|c| c.severity).max()
    }

    /// 影响面：涉及的全部实体键（稳定顺序）。
    #[must_use]
    pub fn affected_entities(&self) -> Vec<String> {
        self.actionable().iter().filter_map(|c| c.entity_key.clone()).collect::<BTreeSet<_>>().into_iter().collect()
    }
}
