//! 基线偏离关联（§4.6「基线关联」）。
//!
//! 有些风险**不看单条事件、也不看序列**，只看"和平时不一样"：
//! 某个 Agent 平时每天外传 2 MB，今天 500 MB；某个服务账号平时只在 09:00-18:00 调用工具，
//! 凌晨 03:00 突然出现。本模块提供：
//!
//! 1. [`BaselineProfile`]：按 `实体 + 指标 + 时段槽位` 维护的滚动统计画像（均值/标准差/极值/样本数）；
//! 2. [`BaselineDetector`]：在线学习（`observe`）+ 判定（`evaluate`），并支持**冷启动降级**——
//!    样本数不足 `min_samples` 时**不判定为偏离**而是标记 [`DeviationKind::InsufficientData`]，
//!    避免"刚上线就把所有事件判成异常"；
//! 3. [`BaselineDeviation`]：可读的偏离结论（Z 分数、观测值、基线区间、置信度）。
//!
//! ## 统计口径
//!
//! | 项 | 口径 |
//! |---|---|
//! | 时段槽位 | `hour_of_day`（0-23）+ `day_of_week`（0=周一 … 6=周日），可分别关闭 |
//! | 均值/方差 | Welford 在线算法（数值稳定，无第二次遍历） |
//! | Z 分数 | `(观测 - 均值) / 标准差`；标准差为 0 时用"是否越出历史极值"兜底 |
//! | 置信度 | `min(1.0, |z| / (2 * 阈值))`，观测值越远超阈值越接近 1 |
//!
//! ## 降级行为
//!
//! | 能力 | 未实现/不可用时 | 锚点 |
//! |---|---|---|
//! | 画像持久化（跨进程存活） | 内存画像；生产由 `agf-storage` 落 `baseline_profiles` 表 | `TODO(correlate-baseline-persist)` |
//! | 季节性分解（STL/傅里叶） | 只用"小时 + 星期"两级槽位近似周期性 | `TODO(correlate-baseline-seasonality)` |
//! | 分位数/尾部建模（EVT） | 只用均值±Z，极端分布下灵敏度有限 | `TODO(correlate-baseline-quantile)` |

pub(crate) use std::collections::BTreeMap;

pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use crate::temporal::BaselineRule;

#[cfg(test)]
pub(crate) use agf_core::enums::Severity;

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 基线画像（`实体 + 指标 + 时段槽位` 的滚动统计）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineProfile {
    /// 租户。
    pub tenant_id: TenantId,
    /// 实体对齐键（见 [`crate::entity::entity_alignment_key`]）。
    pub entity_key: String,
    /// 指标名。
    pub metric: String,
    /// 小时槽位（0-23）。
    pub hour_of_day: u8,
    /// 星期槽位（0=周一 … 6=周日）。
    pub day_of_week: u8,
    /// 样本数。
    pub samples: u64,
    /// 均值。
    pub mean: f64,
    /// 总体二阶矩（Welford 的 `m2`，用于求标准差）。
    pub m2: f64,
    /// 历史最小值。
    pub min: f64,
    /// 历史最大值。
    pub max: f64,
    /// 最近更新。
    pub updated_at: Timestamp,
}

/// 基线偏离类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviationKind {
    /// Z 分数正向超阈值（突增）。
    Spike,
    /// Z 分数负向超阈值（骤降/静默）。
    Drop,
    /// 标准差为 0 但观测值等于/越出历史极值（"平时都是 0，突然不是 0"）。
    OutOfRange,
    /// 观测值落在基线区间内（**不是异常**）。
    Normal,
    /// 样本不足，无法判定（**不是异常**）。
    InsufficientData,
}

/// 一次基线判定结论。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineDeviation {
    /// 规则键。
    pub rule_key: String,
    /// 实体对齐键。
    pub entity_key: String,
    /// 指标名。
    pub metric: String,
    /// 观测值。
    pub observed: f64,
    /// 基线均值。
    pub mean: f64,
    /// 基线标准差。
    pub stddev: f64,
    /// Z 分数（不可计算时为 `None`）。
    pub z_score: Option<f64>,
    /// 历史区间 `[min, max]`。
    pub range: (f64, f64),
    /// 偏离类型。
    pub kind: DeviationKind,
    /// 置信度（`0.0..=1.0`）。
    pub confidence: f32,
    /// 判定所用样本数。
    pub samples: u64,
}

/// 基线检测器：在线学习 + 判定。
#[derive(Debug, Clone)]
pub struct BaselineDetector {
    /// 画像表（键 = `租户|实体|指标|小时|星期`）。
    profiles: BTreeMap<String, BaselineProfile>,
    /// 是否按"小时 + 星期"分槽（关闭则全时段共用一份画像）。
    pub slot_by_time: bool,
    /// 建档时的默认最小样本数（仅作说明与默认值来源；实际判定门槛取
    /// [`BaselineRule::min_samples`]，规则自带默认值 5）。
    pub default_min_samples: u32,
}

mod impl_baseline_profile;
#[cfg(test)]
mod tests;
