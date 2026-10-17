//! 由 `aggregate.rs` 拆分：`AlertAggregator` 的实现（纯搬移，逻辑不变）。
use super::*;

impl AlertAggregator {
    /// 构造（立即校验配置与规则）。
    ///
    /// # Errors
    /// 配置非法或任一抑制规则非法时返回错误。
    pub fn new(config: AggregationConfig, rules: Vec<SuppressionRule>) -> Result<Self, AggregateError> {
        config.validate()?;
        for rule in &rules {
            rule.validate()?;
        }
        Ok(Self { config, rules, state: ClusterState::default() })
    }

    /// 默认配置 + 无抑制规则。
    ///
    /// # Errors
    /// 默认配置理论恒合法；返回 `Result` 以统一上层写法。
    pub fn with_defaults() -> Result<Self, AggregateError> {
        Self::new(AggregationConfig::default(), Vec::new())
    }

    /// 已产出的簇总数（含被抑制）。
    #[must_use]
    pub fn cluster_count(&self) -> usize {
        self.state.open.len() + self.state.closed.len()
    }

    /// 只读状态（供对账/调试）。
    #[must_use]
    pub const fn state(&self) -> &ClusterState {
        &self.state
    }

    /// 摄入一条告警：相同指纹只累加计数，不新增记录。
    ///
    /// 返回簇的**快照**（`Clone`）而非引用：避免把 `&self` 生命周期绑到可变状态上，
    /// 调用方可以在拿到结论后继续 `ingest`/`flush`。簇体量小（去重键受配置上限约束），
    /// 这个克隆是刻意的可读性取舍。
    ///
    /// # Errors
    /// 仅当内部状态不一致（不应发生）时返回错误；正常路径恒 `Ok`。
    pub fn ingest(&mut self, input: AlertInput) -> Result<EventCluster, AggregateError> {
        let fingerprint = input.dedup_key();
        let window = self.config.window_secs;
        let max = self.config.max_alerts_per_cluster;

        // ① 已知指纹 **且仍在窗内** → 只累加计数（去重路径，不新建）。
        //
        // 窗外同指纹不算"又响了一次"：时间窗以首见时间为锚（见模块文档），跨窗的同指纹
        // 告警是新事件，必须新建簇，否则持续噪声会形成一个永不关闭的巨簇。
        if self.state.seen.contains_key(&fingerprint) {
            let mut hit: Option<String> = None;
            for (key, cluster) in &mut self.state.open {
                if cluster.dedup_keys.contains(&fingerprint) && cluster.within_window(input.at, window) {
                    cluster.absorb(&input, max);
                    hit = Some(key.clone());
                    break;
                }
            }
            if hit.is_none() {
                for (index, cluster) in self.state.closed.iter_mut().enumerate() {
                    if cluster.dedup_keys.contains(&fingerprint) && cluster.within_window(input.at, window) {
                        cluster.absorb(&input, max);
                        hit = Some(format!("#closed:{index}"));
                        break;
                    }
                }
            }
            if let Some(key) = hit {
                self.apply_suppression();
                return self
                    .cluster_snapshot(&key)
                    .ok_or_else(|| AggregateError::InvalidConfig(format!("内部状态不一致：簇 {key} 不存在")));
            }
        }

        // ② 新指纹（或窗外同指纹）→ 找同窗内相似簇并入，或新建簇。
        // 先把待并入簇 key 算出来（只读借用在此结束）。
        let existing = self.find_similar_cluster(&input);
        let key = match existing {
            Some(key) => key,
            None => {
                let base =
                    format!("{}|{}|{}", input.tenant_id, input.entity_key.as_deref().unwrap_or("-"), fingerprint);
                // 同指纹但窗外 ⇒ 旧簇在 `open` 里占着这个 key，**不能被覆盖**（否则丢簇），
                // 因此追加实例序号另立一个簇。
                let mut key = base.clone();
                let mut ordinal = 2u32;
                while self.state.open.contains_key(&key) && ordinal < u32::MAX {
                    key = format!("{base}#{ordinal}");
                    ordinal = ordinal.saturating_add(1);
                }
                let cluster = EventCluster::new(
                    input.tenant_id,
                    input.entity_key.clone(),
                    input.category.clone(),
                    input.title.clone(),
                    input.severity,
                    input.at,
                );
                self.state.open.insert(key.clone(), cluster);
                key
            }
        };
        {
            let cluster = self
                .state
                .open
                .get_mut(&key)
                .ok_or_else(|| AggregateError::InvalidConfig(format!("内部状态不一致：开放簇 {key} 不存在")))?;
            cluster.absorb(&input, max);
        }
        self.state.seen.insert(fingerprint, key.clone());
        // 抑制判定在每次摄入后增量重算（幂等）：`report` 是只读视图，
        // 调用方不必先 `flush` 才能看到"父告警已压制子告警"。
        self.apply_suppression();
        self.cluster_snapshot(&key)
            .ok_or_else(|| AggregateError::InvalidConfig(format!("内部状态不一致：开放簇 {key} 不存在")))
    }

    /// 按内部 key 取簇快照（`#closed:<index>` 表示已刷新簇）。
    pub(crate) fn cluster_snapshot(&self, key: &str) -> Option<EventCluster> {
        if let Some(index) = key.strip_prefix("#closed:").and_then(|s| s.parse::<usize>().ok()) {
            return self.state.closed.get(index).cloned();
        }
        self.state.open.get(key).cloned()
    }

    /// 批量摄入。
    ///
    /// # Errors
    /// 同 [`AlertAggregator::ingest`]。
    pub fn ingest_many(&mut self, inputs: &[AlertInput]) -> Result<(), AggregateError> {
        for input in inputs {
            self.ingest(input.clone())?;
        }
        Ok(())
    }

    /// 查找可并入的开放簇 key。
    pub(crate) fn find_similar_cluster(&self, input: &AlertInput) -> Option<String> {
        let normalized = normalize_title(&input.title);
        let mut best: Option<(String, f64)> = None;
        for (key, cluster) in &self.state.open {
            if cluster.tenant_id != input.tenant_id {
                // 租户隔离硬边界：跨租户绝不聚合。
                continue;
            }
            if self.config.entity_scoped && cluster.entity_key != input.entity_key {
                continue;
            }
            if cluster.category != input.category {
                // 类目不同不聚合（空类目只与空类目合并）。
                continue;
            }
            if !cluster.within_window(input.at, self.config.window_secs) {
                continue;
            }
            let score = match self.config.similarity {
                SimilarityPolicy::Prefix => 1.0,
                SimilarityPolicy::Exact => {
                    if normalize_title(&cluster.representative_title) == normalized {
                        1.0
                    } else {
                        0.0
                    }
                }
                SimilarityPolicy::Jaccard => {
                    jaccard_similarity(&normalize_title(&cluster.representative_title), &normalized)
                }
            };
            if score >= self.config.similarity_threshold && best.as_ref().is_none_or(|(_, b)| score > *b) {
                best = Some((key.clone(), score));
            }
        }
        best.map(|(key, _)| key)
    }

    /// 刷新：把时间窗外的开放簇移入 `closed` 并执行抑制判定；返回本次刷新的簇数。
    pub fn flush(&mut self, now: Timestamp) -> usize {
        let window = self.config.window_secs;
        let expired: Vec<String> =
            self.state.open.iter().filter(|(_, c)| !c.within_window(now, window)).map(|(k, _)| k.clone()).collect();
        let mut moved = Vec::with_capacity(expired.len());
        for key in expired {
            if let Some(cluster) = self.state.open.remove(&key) {
                moved.push(cluster);
            }
        }
        let count = moved.len();
        self.state.closed.extend(moved);
        self.apply_suppression();
        count
    }

    /// 对全部簇（开放 + 已刷新）执行抑制判定。
    ///
    /// 抑制是**幂等**的：已抑制的簇不会被重新指派来源（重复调用不产生新状态）。
    pub(crate) fn apply_suppression(&mut self) {
        let mut updates: Vec<(Id, String, String, Id)> = Vec::new();
        {
            let all: Vec<&EventCluster> = self.state.open.values().chain(self.state.closed.iter()).collect();
            for rule in &self.rules {
                if !rule.enabled {
                    continue;
                }
                for child in &all {
                    if child.suppressed {
                        continue;
                    }
                    for parent in &all {
                        if parent.id == child.id {
                            continue;
                        }
                        // 租户隔离：跨租户绝不抑制（硬边界）。
                        if parent.tenant_id != child.tenant_id {
                            continue;
                        }
                        if !rule.matches_parent(parent) || !rule.matches_child(child) {
                            continue;
                        }
                        if rule.same_category && parent.category != child.category {
                            continue;
                        }
                        if rule.same_entity && (parent.entity_key.is_none() || parent.entity_key != child.entity_key) {
                            continue;
                        }
                        if rule.shared_rule_key && !parent.rule_keys.iter().any(|k| child.rule_keys.contains(k)) {
                            continue;
                        }
                        updates.push((child.id, rule.key.clone(), rule.reason.clone(), parent.id));
                        break;
                    }
                }
            }
        }
        for (child_id, rule_key, reason, parent_id) in updates {
            for cluster in self.state.open.values_mut().chain(self.state.closed.iter_mut()) {
                if cluster.id == child_id && !cluster.suppressed {
                    cluster.suppressed = true;
                    cluster.suppress_rule = Some(rule_key.clone());
                    cluster.suppress_reason = Some(reason.clone());
                    cluster.suppressed_by = Some(parent_id);
                    break;
                }
            }
        }
    }

    /// 产出降噪报告（要求调用方声明租户）。
    ///
    /// # Errors
    /// 存在不属于 `tenant` 的簇时返回 [`AggregateError::TenantViolation`]。
    pub fn report(&self, tenant: TenantId, now: Timestamp) -> Result<ReduceReport, AggregateError> {
        let mut clusters: Vec<EventCluster> = Vec::with_capacity(self.cluster_count());
        for cluster in self.state.open.values().chain(self.state.closed.iter()) {
            if cluster.tenant_id != tenant {
                return Err(AggregateError::TenantViolation {
                    expected: tenant.to_string(),
                    actual: cluster.tenant_id.to_string(),
                });
            }
            clusters.push(cluster.clone());
        }
        clusters.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.first_seen_at.cmp(&b.first_seen_at))
                .then_with(|| a.id.cmp(&b.id))
        });
        let raw_alerts = clusters.iter().map(|c| c.occurrences).sum();
        let deduped_alerts = clusters.len() as u64;
        let suppressed_alerts = clusters.iter().filter(|c| c.suppressed).count() as u64;
        Ok(ReduceReport {
            tenant_id: tenant,
            raw_alerts,
            deduped_alerts,
            suppressed_alerts,
            clusters,
            generated_at: now,
        })
    }
}
