//! 规则/时序/图/基线四种关联的**统一规则模型**（§4.6）。
//!
//! 四种关联形态共享同一套"输入 = 跨源实体对齐后的事件"语义，因此放在一个模块里定义，
//! 避免上层（`agf-api`）面对四个平行的规则体系：
//!
//! | 形态 | 看到的东西 | 典型噪声抑制场景 |
//! |---|---|---|
//! | [`CorrelationRule::Match`] | 单事件特征 | 同源重复告警（真正的去重交给聚合层） |
//! | [`CorrelationRule::Temporal`] | 一段时间内的**序列** | "先外传再封禁"这类多步攻击链，单步不算 |
//! | [`CorrelationRule::Graph`] | 实体之间的**关系路径** | 沿攻击链传播（同一 C2 的多个 Agent） |
//! | [`CorrelationRule::Baseline`] | 与**历史基线**的偏离 | 低频但异常（平时 0 次，今天 500 次） |
//!
//! ## 判定语义
//!
//! - 归组键（`group_by`）默认 [`GroupBy::Entity`]：同一实体（主机/用户/IP）的事件才算同一条链；
//! - 时序步 [`TemporalStep`] 的 `optional = true` 表示"有则加强、无则不影响命中"；
//! - 命中结论 [`CorrelationHit::confidence`] 由"命中步数 / 总步数 + 平均证据强度"合成，
//!   落在 `0.0..=1.0`，供上层做分级（`>= 0.8` 高危、`>= 0.5` 可疑）；
//! - `order_required = true` 但事件时间戳完全相同（同一秒）时按输入顺序判定，
//!   这是刻意行为：日志里同秒事件无法区分先后，按接入顺序视为先后更符合直觉。
//!
//! ## 降级行为
//!
//! | 能力 | 未实现/不可用时 | 锚点 |
//! |---|---|---|
//! | 跨租户关联（供应链同源） | **不做**：本 crate 全程单租户，跨租户必须显式租户映射 | `TODO(correlate-cross-tenant)` |
//! | 流式增量匹配（滑动窗口状态机） | 当前对**给定窗口内的事件切片**做批量判定；流式由 `agf-runtime` 周期调用本模块 | `TODO(correlate-stream-window)` |

pub(crate) use std::collections::BTreeMap;
pub(crate) use std::collections::BTreeSet;

pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::event::Event;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::time::TimeRange;
#[cfg(test)]
pub(crate) use agf_core::time::Timestamp;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use crate::entity::CrossSourceAlignment;
pub(crate) use crate::entity::EntityAligner;
pub(crate) use crate::entity::EntityKind;

#[cfg(test)]
pub(crate) use agf_core::enums::IngestProtocol;

#[cfg(test)]
pub(crate) use agf_core::event::EventAction;
#[cfg(test)]
pub(crate) use agf_core::event::EventCategory;

#[allow(unused_imports)]
pub use impl_baseline_rule::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 规则中的一步（时序/图/基线的通用"步"描述）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RuleStep {
    /// 步骤名（出现在证据描述里）。
    pub name: String,
    /// 必须命中的事件类别（空 = 不限）。
    #[serde(default)]
    pub categories: Vec<String>,
    /// 必须命中的事件动作（空 = 不限）。
    #[serde(default)]
    pub actions: Vec<String>,
    /// 命中的规则键（空 = 不限）。
    #[serde(default)]
    pub rule_keys: Vec<String>,
    /// 该步的最少事件数。
    #[serde(default)]
    pub min_events: u32,
    /// 可选步（缺失不影响整体命中）。
    #[serde(default)]
    pub optional: bool,
}

/// 时序关联规则（§4.6「时序关联」）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemporalRule {
    /// 稳定键。
    pub key: String,
    /// 名称。
    pub name: String,
    /// 时间窗口（秒）：所有步必须落在同一次窗口内。
    pub window_secs: i64,
    /// 是否要求按步骤顺序发生（默认 `false`：只要求共现）。
    #[serde(default)]
    pub order_required: bool,
    /// 步骤序列。
    pub steps: Vec<RuleStep>,
    /// 命中后的建议严重等级。
    pub severity: Severity,
}

/// 时序判定结论。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemporalOutcome {
    /// 规则键。
    pub rule_key: String,
    /// 是否整体命中。
    pub matched: bool,
    /// 命中的步数。
    pub hit_steps: usize,
    /// 总步数。
    pub total_steps: usize,
    /// 缺失的必需步名。
    pub missing_steps: Vec<String>,
    /// 命中的事件 id（去重）。
    pub matched_event_ids: Vec<Id>,
    /// 事件跨度（秒）。
    pub span_secs: i64,
    /// 窗口上限（秒）。
    pub window_secs: i64,
    /// 顺序约束是否满足。
    pub order_ok: bool,
    /// 窗口约束是否满足。
    pub window_ok: bool,
}

/// 事件归组方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupBy {
    /// 按实体归组（默认，推荐）：同主机/用户/IP 才算一条链。
    Entity,
    /// 按日志源归组。
    Source,
    /// 按会话归组（`ai.session_id`）。
    Session,
    /// 全部事件一组（最宽松，噪声最大）。
    None,
}

/// 时序扫描器：切窗口 + 归组 + 逐组判定规则。
#[derive(Debug, Clone)]
pub struct TemporalScanner {
    /// 实体对齐器（决定归组键）。
    pub aligner: EntityAligner,
    /// 归组方式。
    pub group_by: GroupBy,
}

/// 一次时序命中。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemporalScanHit {
    /// 归组键。
    pub group: String,
    /// 规则键。
    pub rule_key: String,
    /// 建议等级。
    pub severity: Severity,
    /// 判定细节。
    pub outcome: TemporalOutcome,
}

/// 图关联规则：沿实体关系路径判定（§4.6「图关联」）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphRule {
    /// 稳定键。
    pub key: String,
    /// 名称。
    pub name: String,
    /// 起点实体类型。
    pub from_kind: EntityKind,
    /// 终点实体类型。
    pub to_kind: EntityKind,
    /// 最大跳数。
    pub max_hops: usize,
    /// 建议等级。
    pub severity: Severity,
}

/// 基线关联规则：与历史画像比对（§4.6「基线关联」）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineRule {
    /// 稳定键。
    pub key: String,
    /// 名称。
    pub name: String,
    /// 指标名（如 `outbound_bytes` / `tool_calls`）。
    pub metric: String,
    /// 触发偏离的标准差倍数（默认 3.0）。
    pub z_threshold: f32,
    /// 需要多少历史样本才能启用（默认 5）。
    pub min_samples: u32,
    /// 建议等级。
    pub severity: Severity,
}

/// 一次跨源关联的完整输入（供 [`CorrelationRule`] 判定与 `CorrelateService` 编排使用）。
#[derive(Debug, Clone)]
pub struct CorrelationInput {
    /// 租户。
    pub tenant: TenantId,
    /// 事件切片（应已按时间升序）。
    pub events: Vec<Event>,
    /// 时间窗口。
    pub window: TimeRange,
    /// 跨源实体对齐结果（由 [`crate::entity::CrossSourceAlignment`] 生成）。
    pub alignment: CrossSourceAlignment,
    /// 命中的规则键集合（来自规则引擎，供 `Match` 形态判定）。
    pub rule_keys: Vec<String>,
    /// 观察到的指标值（供基线形态判定）。
    pub metrics: BTreeMap<String, f64>,
}

/// 四种关联形态的统一规则。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CorrelationRule {
    /// 单事件特征匹配（最基础形态；去重降噪交给聚合层）。
    Match {
        /// 稳定键。
        key: String,
        /// 名称。
        name: String,
        /// 需要命中的规则键（任一）。
        rule_keys: Vec<String>,
        /// 建议等级。
        severity: Severity,
    },
    /// 时序关联。
    Temporal(TemporalRule),
    /// 图关联。
    Graph(GraphRule),
    /// 基线关联。
    Baseline(BaselineRule),
}

/// 关联命中的统一结论。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrelationHit {
    /// 规则键。
    pub rule_key: String,
    /// 规则形态。
    pub shape: String,
    /// 建议等级。
    pub severity: Severity,
    /// 置信度（`0.0..=1.0`）。
    pub confidence: f32,
    /// 命中证据（事件 id / 实体对齐键 / 指标值）。
    pub evidence: Vec<String>,
    /// 可读摘要。
    pub summary: String,
}

mod evaluate;
mod impl_baseline_rule;
mod impl_rule_step;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod window_tests;
