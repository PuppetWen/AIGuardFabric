//! 由 `baseline.rs` 拆分：`BaselineDetector`/`BaselineDeviation`/`BaselineProfile`/`DeviationKind` 的实现（纯搬移，逻辑不变）。
use super::*;

impl BaselineProfile {
    /// 新建空画像（调用方通常直接用 [`BaselineDetector::observe`] 自动建档）。
    #[must_use]
    pub fn new(tenant: TenantId, entity_key: impl Into<String>, metric: impl Into<String>, at: Timestamp) -> Self {
        let dt = at.as_datetime();
        Self {
            tenant_id: tenant,
            entity_key: entity_key.into(),
            metric: metric.into(),
            hour_of_day: u8::try_from(chrono::Timelike::hour(&dt)).unwrap_or(0),
            day_of_week: u8::try_from(chrono::Datelike::weekday(&dt).num_days_from_monday()).unwrap_or(0),
            samples: 0,
            mean: 0.0,
            m2: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
            updated_at: at,
        }
    }

    /// 画像键（`租户|实体|指标|小时|星期`）。
    #[must_use]
    pub fn profile_key(tenant: TenantId, entity_key: &str, metric: &str, hour_of_day: u8, day_of_week: u8) -> String {
        format!("{tenant}|{entity_key}|{metric}|{hour_of_day}|{day_of_week}")
    }

    /// 本画像的键。
    #[must_use]
    pub fn key(&self) -> String {
        Self::profile_key(self.tenant_id, &self.entity_key, &self.metric, self.hour_of_day, self.day_of_week)
    }

    /// 标准差（样本数 < 2 时为 0）。
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn stddev(&self) -> f64 {
        if self.samples < 2 {
            return 0.0;
        }
        (self.m2 / (self.samples - 1) as f64).sqrt()
    }

    /// Welford 在线更新（数值稳定，只遍历一次）。
    pub fn observe(&mut self, value: f64, at: Timestamp) {
        self.samples = self.samples.saturating_add(1);
        let delta = value - self.mean;
        self.mean += delta / self.samples as f64;
        self.m2 += delta * (value - self.mean);
        if value < self.min {
            self.min = value;
        }
        if value > self.max {
            self.max = value;
        }
        self.updated_at = at;
    }

    /// 观测值相对画像的 Z 分数（标准差为 0 时返回 `None`，由调用方走极值兜底）。
    #[must_use]
    pub fn z_score(&self, value: f64) -> Option<f64> {
        let sd = self.stddev();
        if sd <= f64::EPSILON || !sd.is_finite() {
            return None;
        }
        Some((value - self.mean) / sd)
    }

    /// 是否已有足够样本。
    #[must_use]
    pub const fn is_warm(&self, min_samples: u32) -> bool {
        self.samples >= min_samples as u64
    }
}

impl DeviationKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Spike => "spike",
            Self::Drop => "drop",
            Self::OutOfRange => "out-of-range",
            Self::Normal => "normal",
            Self::InsufficientData => "insufficient-data",
        }
    }

    /// 是否属于"判定成立"的偏离（`Normal` / `InsufficientData` 都不算）。
    #[must_use]
    pub const fn is_deviation(&self) -> bool {
        matches!(self, Self::Spike | Self::Drop | Self::OutOfRange)
    }
}

impl BaselineDeviation {
    /// 可读摘要。
    #[must_use]
    pub fn summary(&self) -> String {
        let z = self.z_score.map_or_else(|| "n/a".to_string(), |z| format!("{z:.2}"));
        format!(
            "指标 {} 观测 {:.4}，基线均值 {:.4}±{:.4}（z={}，样本 {}，历史区间 [{:.4}, {:.4}]）→ {}",
            self.metric,
            self.observed,
            self.mean,
            self.stddev,
            z,
            self.samples,
            self.range.0,
            self.range.1,
            self.kind.as_str()
        )
    }

    /// 是否达到告警条件（偏离成立）。
    #[must_use]
    pub const fn should_alert(&self) -> bool {
        self.kind.is_deviation()
    }
}

impl Default for BaselineDetector {
    fn default() -> Self {
        Self { profiles: BTreeMap::new(), slot_by_time: true, default_min_samples: 5 }
    }
}

impl BaselineDetector {
    /// 构造（默认分时段、`min_samples = 5`）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 关闭时段分槽（全时段共享画像，样本积累更快但灵敏度下降）。
    #[must_use]
    pub const fn global_slots(mut self) -> Self {
        self.slot_by_time = false;
        self
    }

    /// 已建档的画像数。
    #[must_use]
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// 读取画像（供接口/调试）。
    #[must_use]
    pub fn profile(&self, key: &str) -> Option<&BaselineProfile> {
        self.profiles.get(key)
    }

    /// 由实体键 + 观测时间推导画像键。
    #[must_use]
    pub fn slot_key(&self, tenant: TenantId, entity_key: &str, metric: &str, at: Timestamp) -> String {
        let (hour, dow) = if self.slot_by_time {
            let dt = at.as_datetime();
            (
                u8::try_from(chrono::Timelike::hour(&dt)).unwrap_or(0),
                u8::try_from(chrono::Datelike::weekday(&dt).num_days_from_monday()).unwrap_or(0),
            )
        } else {
            (0, 0)
        };
        BaselineProfile::profile_key(tenant, entity_key, metric, hour, dow)
    }

    /// 学习一个观测值（自动建档）。
    pub fn observe(&mut self, tenant: TenantId, entity_key: &str, metric: &str, value: f64, at: Timestamp) {
        let key = self.slot_key(tenant, entity_key, metric, at);
        let (hour, dow) = {
            let dt = at.as_datetime();
            if self.slot_by_time {
                (
                    u8::try_from(chrono::Timelike::hour(&dt)).unwrap_or(0),
                    u8::try_from(chrono::Datelike::weekday(&dt).num_days_from_monday()).unwrap_or(0),
                )
            } else {
                (0, 0)
            }
        };
        let profile = self.profiles.entry(key).or_insert_with(|| BaselineProfile::new(tenant, entity_key, metric, at));
        profile.hour_of_day = hour;
        profile.day_of_week = dow;
        profile.observe(value, at);
    }

    /// 判定一个观测值是否偏离基线。
    ///
    /// **不修改画像**（判定与学习解耦：先判定后学习，避免"异常值污染基线"）。
    #[must_use]
    pub fn evaluate(
        &self,
        rule: &BaselineRule,
        tenant: TenantId,
        entity_key: &str,
        value: f64,
        at: Timestamp,
    ) -> BaselineDeviation {
        let key = self.slot_key(tenant, entity_key, &rule.metric, at);
        let min_samples = rule.min_samples;
        let Some(profile) = self.profiles.get(&key) else {
            return BaselineDeviation {
                rule_key: rule.key.clone(),
                entity_key: entity_key.to_string(),
                metric: rule.metric.clone(),
                observed: value,
                mean: 0.0,
                stddev: 0.0,
                z_score: None,
                range: (0.0, 0.0),
                kind: DeviationKind::InsufficientData,
                confidence: 0.0,
                samples: 0,
            };
        };
        if !profile.is_warm(min_samples) {
            return BaselineDeviation {
                rule_key: rule.key.clone(),
                entity_key: entity_key.to_string(),
                metric: rule.metric.clone(),
                observed: value,
                mean: profile.mean,
                stddev: profile.stddev(),
                z_score: profile.z_score(value),
                range: (profile.min, profile.max),
                kind: DeviationKind::InsufficientData,
                confidence: 0.0,
                samples: profile.samples,
            };
        }

        let z = profile.z_score(value);
        let threshold = f64::from(rule.z_threshold.max(0.1));
        let (kind, confidence) = match z {
            Some(z) if z.abs() > threshold => {
                let conf = ((z.abs() / (2.0 * threshold)).min(1.0)) as f32;
                (if z > 0.0 { DeviationKind::Spike } else { DeviationKind::Drop }, conf)
            }
            Some(_) => (DeviationKind::Normal, 0.0),
            None => {
                // 标准差为 0：用极值兜底（"平时恒定值，今天变了"）
                if (value - profile.mean).abs() > f64::EPSILON {
                    (DeviationKind::OutOfRange, 1.0)
                } else {
                    (DeviationKind::Normal, 0.0)
                }
            }
        };
        // 未偏离时统一用 `Normal` 表达"有结论：正常"，样本不足另用 `InsufficientData`。
        BaselineDeviation {
            rule_key: rule.key.clone(),
            entity_key: entity_key.to_string(),
            metric: rule.metric.clone(),
            observed: value,
            mean: profile.mean,
            stddev: profile.stddev(),
            z_score: z,
            range: (profile.min, profile.max),
            kind,
            confidence,
            samples: profile.samples,
        }
    }

    /// 批量判定（同一实体多指标）。
    #[must_use]
    pub fn evaluate_many(
        &self,
        rules: &[BaselineRule],
        tenant: TenantId,
        entity_key: &str,
        observations: &BTreeMap<String, f64>,
        at: Timestamp,
    ) -> Vec<BaselineDeviation> {
        rules
            .iter()
            .filter_map(|rule| observations.get(&rule.metric).map(|v| self.evaluate(rule, tenant, entity_key, *v, at)))
            .filter(BaselineDeviation::should_alert)
            .collect()
    }
}
