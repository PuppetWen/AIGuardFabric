//! 由 `aggregate.rs` 拆分：`impl_SimilarityPolicy`/`normalize_title` 等 9 项（纯搬移，逻辑不变）。
use super::*;

impl SimilarityPolicy {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Jaccard => "jaccard",
            Self::Prefix => "prefix",
        }
    }
}

/// 标题归一化：小写、折叠空白、把 ASCII 标点折成空格、去首尾空白。
///
/// 返回可能为空的 `String`；空标题在 Jaccard/Exact 策略下判为"不相似"，
/// 避免"一堆没有标题的告警被并成一个巨簇"。
#[must_use]
pub fn normalize_title(title: &str) -> String {
    let mut out = String::with_capacity(title.len());
    let mut pending_space = false;
    for ch in title.trim().chars() {
        if ch.is_whitespace() || ch.is_ascii_punctuation() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        for lower in ch.to_lowercase() {
            out.push(lower);
        }
    }
    out
}

/// 把归一化标题切成字符 2-gram 集合（去掉空白；长度不足 2 时退化为单字符）。
#[must_use]
pub fn char_bigrams(normalized: &str) -> BTreeSet<String> {
    let chars: Vec<char> = normalized.chars().filter(|c| !c.is_whitespace()).collect();
    let mut out = BTreeSet::new();
    match chars.len() {
        0 => {}
        1 => {
            out.insert(chars[0].to_string());
        }
        _ => {
            for pair in chars.windows(2) {
                out.insert(pair.iter().collect::<String>());
            }
        }
    }
    out
}

/// 字符 2-gram Jaccard 相似度，落在 `0.0..=1.0`。
///
/// 任一侧没有有效字符时返回 `0.0`：宁可判为"不相似"，也不要让空标题互相合并。
#[must_use]
pub fn jaccard_similarity(a: &str, b: &str) -> f64 {
    let sa = char_bigrams(a);
    let sb = char_bigrams(b);
    if sa.is_empty() || sb.is_empty() {
        return 0.0;
    }
    let inter = sa.intersection(&sb).count();
    let union = sa.union(&sb).count();
    if union == 0 {
        return 0.0;
    }
    // 计数为 usize，转 f64 精确无损（值域远小于 2^53）。
    inter as f64 / union as f64
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            window_secs: 300,
            similarity_threshold: 0.75,
            similarity: SimilarityPolicy::Jaccard,
            entity_scoped: true,
            max_alerts_per_cluster: 5_000,
            max_open_clusters: 10_000,
        }
    }
}

impl AggregationConfig {
    /// 默认配置。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置时间窗（秒）。
    #[must_use]
    pub const fn with_window_secs(mut self, secs: i64) -> Self {
        self.window_secs = secs;
        self
    }

    /// 设置相似度阈值（越界值由 [`Self::validate`] 报错，不静默截断）。
    #[must_use]
    pub const fn with_similarity_threshold(mut self, threshold: f64) -> Self {
        self.similarity_threshold = threshold;
        self
    }

    /// 设置相似度策略。
    #[must_use]
    pub const fn with_similarity(mut self, policy: SimilarityPolicy) -> Self {
        self.similarity = policy;
        self
    }

    /// 关闭实体分簇。
    #[must_use]
    pub const fn without_entity_scope(mut self) -> Self {
        self.entity_scoped = false;
        self
    }

    /// 校验配置。
    ///
    /// # Errors
    /// 时间窗非正、相似度阈值越界、簇容量为 0 时返回 [`AggregateError::InvalidConfig`]。
    pub fn validate(&self) -> Result<(), AggregateError> {
        if self.window_secs <= 0 {
            return Err(AggregateError::InvalidConfig(format!("window_secs 必须为正，当前 {}", self.window_secs)));
        }
        if !(0.0..=1.0).contains(&self.similarity_threshold) {
            return Err(AggregateError::InvalidConfig(format!(
                "similarity_threshold 必须落在 0.0..=1.0，当前 {}",
                self.similarity_threshold
            )));
        }
        if self.max_alerts_per_cluster == 0 {
            return Err(AggregateError::InvalidConfig("max_alerts_per_cluster 必须为正".to_string()));
        }
        if self.max_open_clusters == 0 {
            return Err(AggregateError::InvalidConfig("max_open_clusters 必须为正".to_string()));
        }
        Ok(())
    }
}

impl AlertInput {
    /// 构造（最小必需字段）。
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        category: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        at: Timestamp,
    ) -> Self {
        Self {
            tenant_id,
            entity_key: None,
            category: category.into(),
            severity,
            title: title.into(),
            alert_id: None,
            event_ids: Vec::new(),
            rule_keys: Vec::new(),
            at,
            tags: Vec::new(),
        }
    }

    /// 设置实体键。
    #[must_use]
    pub fn with_entity(mut self, entity_key: impl Into<String>) -> Self {
        self.entity_key = Some(entity_key.into());
        self
    }

    /// 关联告警 id。
    #[must_use]
    pub const fn with_alert_id(mut self, id: Id) -> Self {
        self.alert_id = Some(id);
        self
    }

    /// 追加事件 id。
    #[must_use]
    pub fn with_event(mut self, id: Id) -> Self {
        self.event_ids.push(id);
        self
    }

    /// 追加规则键。
    #[must_use]
    pub fn with_rule_key(mut self, key: impl Into<String>) -> Self {
        self.rule_keys.push(key.into());
        self
    }

    /// 追加标签。
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// 由已落地的 [`Alert`] 投影。
    ///
    /// `entity_key` 需由调用方提供（[`Alert`] 只存 `affected_hosts`，不含对齐键）。
    #[must_use]
    pub fn from_alert(alert: &Alert, entity_key: Option<&str>) -> Self {
        Self {
            tenant_id: alert.tenant_id,
            entity_key: entity_key.map(ToString::to_string),
            category: alert.domain.map_or_else(|| "unknown".to_string(), |d| d.as_str().to_string()),
            severity: alert.severity,
            title: alert.title.clone(),
            alert_id: Some(alert.id),
            event_ids: alert.event_ids.clone(),
            rule_keys: alert.tags.clone(),
            at: alert.last_seen_at,
            tags: alert.tags.clone(),
        }
    }

    /// 去重指纹：`租户|实体|类目|归一标题|标签`。
    ///
    /// 完全相同的指纹意味着"同一条告警又响了一次"，只累加计数、不新增记录。
    /// **标签参与指纹**：标签携带来源/规则等区分信息，两条标题相同但标签不同的告警
    /// 是两个去重键（这也是单簇去重键上限 [`AggregationConfig::max_alerts_per_cluster`]
    /// 与截断标记 [`EventCluster::truncated`] 的语义前提）；
    /// 标签先排序去重，声明顺序不同不产生新指纹。
    #[must_use]
    pub fn dedup_key(&self) -> String {
        let entity = self.entity_key.as_deref().unwrap_or("-");
        let category = if self.category.trim().is_empty() { "-" } else { self.category.trim() };
        let mut tags: Vec<&str> = self.tags.iter().map(String::as_str).collect();
        tags.sort_unstable();
        tags.dedup();
        format!("{}|{}|{}|{}|{}", self.tenant_id, entity, category, normalize_title(&self.title), tags.join(","))
    }
}

impl SuppressionKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Severity => "severity",
            Self::Category => "category",
            Self::RuleKey => "rule-key",
        }
    }
}

impl SuppressionRule {
    /// 构造空规则（需再补充约束条件）。
    #[must_use]
    pub fn new(key: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { key: key.into(), reason: reason.into(), enabled: true, ..Self::default() }
    }

    /// 设置父标题子串约束。
    #[must_use]
    pub fn parent_titles(mut self, titles: &[&str]) -> Self {
        self.parent_title_contains = titles.iter().map(|t| (*t).to_string()).collect();
        self
    }

    /// 设置子标题子串约束。
    #[must_use]
    pub fn child_titles(mut self, titles: &[&str]) -> Self {
        self.child_title_contains = titles.iter().map(|t| (*t).to_string()).collect();
        self
    }

    /// 设置父类目约束。
    #[must_use]
    pub fn parent_categories(mut self, categories: &[&str]) -> Self {
        self.parent_categories = categories.iter().map(|c| (*c).to_string()).collect();
        self
    }

    /// 设置子类目约束。
    #[must_use]
    pub fn child_categories(mut self, categories: &[&str]) -> Self {
        self.child_categories = categories.iter().map(|c| (*c).to_string()).collect();
        self
    }

    /// 设置父最低等级。
    #[must_use]
    pub const fn parent_min_severity(mut self, severity: Severity) -> Self {
        self.parent_min_severity = Some(severity);
        self
    }

    /// 设置子最高等级。
    #[must_use]
    pub const fn child_max_severity(mut self, severity: Severity) -> Self {
        self.child_max_severity = Some(severity);
        self
    }

    /// 要求父子命中同一规则键。
    #[must_use]
    pub const fn require_shared_rule_key(mut self) -> Self {
        self.shared_rule_key = true;
        self
    }

    /// 要求父子同类目。
    #[must_use]
    pub const fn require_same_category(mut self) -> Self {
        self.same_category = true;
        self
    }

    /// 要求父子同实体。
    #[must_use]
    pub const fn require_same_entity(mut self) -> Self {
        self.same_entity = true;
        self
    }

    /// 校验规则。
    ///
    /// # Errors
    /// `key`/`reason` 为空，或完全没有约束条件时返回 [`AggregateError::InvalidRule`]。
    pub fn validate(&self) -> Result<(), AggregateError> {
        if self.key.trim().is_empty() {
            return Err(AggregateError::InvalidRule("抑制规则 key 不能为空".to_string()));
        }
        if self.reason.trim().is_empty() {
            return Err(AggregateError::InvalidRule(format!(
                "抑制规则 {} 缺少 reason（必须说明抑制原因，禁止无理由静默告警）",
                self.key
            )));
        }
        let has_constraint = !self.parent_title_contains.is_empty()
            || !self.parent_categories.is_empty()
            || self.parent_min_severity.is_some()
            || !self.child_title_contains.is_empty()
            || !self.child_categories.is_empty()
            || self.child_max_severity.is_some()
            || self.shared_rule_key
            || self.same_category
            || self.same_entity;
        if !has_constraint {
            return Err(AggregateError::InvalidRule(format!(
                "抑制规则 {} 没有任何约束条件，会压制全部告警（拒绝加载）",
                self.key
            )));
        }
        Ok(())
    }

    /// 某簇是否满足"父"侧条件。
    #[must_use]
    pub fn matches_parent(&self, cluster: &EventCluster) -> bool {
        if !self.parent_title_contains.is_empty()
            && !self.parent_title_contains.iter().any(|t| cluster.representative_title.contains(t.as_str()))
        {
            return false;
        }
        if !self.parent_categories.is_empty() && !self.parent_categories.contains(&cluster.category) {
            return false;
        }
        self.parent_min_severity.is_none_or(|min| cluster.severity.weight() >= min.weight())
    }

    /// 某簇是否满足"子"侧条件。
    #[must_use]
    pub fn matches_child(&self, cluster: &EventCluster) -> bool {
        if !self.child_title_contains.is_empty()
            && !self.child_title_contains.iter().any(|t| cluster.representative_title.contains(t.as_str()))
        {
            return false;
        }
        if !self.child_categories.is_empty() && !self.child_categories.contains(&cluster.category) {
            return false;
        }
        self.child_max_severity.is_none_or(|max| cluster.severity.weight() <= max.weight())
    }

    /// 判定抑制类型（仅用于审计展示）。
    #[must_use]
    pub fn kind(&self) -> SuppressionKind {
        if self.shared_rule_key {
            SuppressionKind::RuleKey
        } else if self.parent_min_severity.is_some() || self.child_max_severity.is_some() {
            SuppressionKind::Severity
        } else {
            SuppressionKind::Category
        }
    }
}
