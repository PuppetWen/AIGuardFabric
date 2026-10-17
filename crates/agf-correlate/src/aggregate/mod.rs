//! 告警聚合、去重与抑制（§4.6「告警降噪」）。
//!
//! 一个真实的 SOC 里大多数告警是"同一个原因反复响"：同一台主机、同一类风险、几分钟内
//! 几百条。本模块把这种噪声压成**事件簇**（event cluster）——一个可被案件升级的运营单元：
//!
//! | 能力 | 语义 | 关键配置 |
//! |---|---|---|
//! | 聚合 | 同实体 + 同类目 + 时间窗内 + 标题相似 → 合并为一个簇 | [`AggregationConfig::entity_scoped`]、[`AggregationConfig::window_secs`]、[`AggregationConfig::similarity_threshold`] |
//! | 去重 | 完全相同的告警只累加计数、不新增记录 | [`AlertInput::dedup_key`] 生成的指纹 |
//! | 抑制 | 父告警压制子告警（"已隔离成功"压制后续"外传尝试"） | [`SuppressionRule`] 列表 |
//! | 降噪 | 输出合并前后计数与降噪率，用于验证规则有效性 | [`ReduceReport::noise_reduction_ratio`] |
//!
//! ## 语义细节（**刻意行为，不是 bug**）
//!
//! - **跨租户绝不聚合并绝不抑制**：租户隔离是本模块的硬边界，即使实体键恰好同名也不会合并
//!   （见 [`AlertAggregator::find_similar_cluster`] 的租户守卫与 `cross_tenant_alerts_never_merge` 测试）。
//! - **相似度策略**：默认 [`SimilarityPolicy::Jaccard`]，对归一化标题做字符 2-gram 集合的
//!   Jaccard 相似度。选字符 2-gram 而非"按空格分词"，是因为中文告警标题没有空格分隔，
//!   而字符 2-gram 对中英文都给出稳定相似度。`Exact` 策略用于"一条都不能错并"的严格场景。
//! - **类目不同不聚合**：类目为空视为"未知类目"，与任何非空类目都不合并；只有双方类目都为空
//!   时才允许合并。宁可少聚合，也不要跨类目错并（错并会让调查员错过真实链路）。
//! - **时间窗以首条告警为锚**：不用"最后一条"滑窗，否则持续噪声会形成一个永不关闭的巨簇，
//!   案件影响面永远无法定稿。
//!
//! ## 降级行为
//!
//! | 能力 | 未实现/不可用时 | 锚点 |
//! |---|---|---|
//! | 跨租户聚合（供应链同源告警） | **不做**：本 crate 全程单租户，跨租户合并需要显式租户映射与授权 | `TODO(correlate-aggregate-cross-tenant)` |
//! | 语义向量相似度（embedding 判同因） | 不做：只用可复现的字符 2-gram Jaccard；向量需要外部模型与网络 | `TODO(correlate-aggregate-embedding)` |
//! | 簇的持久化与增量续算 | 内存态：生产由 `agf-storage` 落 `alert_clusters` 表并按窗口续算 | `TODO(correlate-aggregate-persist)` |
//! | 抑制规则从策略表加载 | 本模块只接受显式传入的 [`SuppressionRule`]；不读数据库、不读配置中心 | `TODO(correlate-aggregate-policy-load)` |

pub(crate) use std::collections::BTreeMap;
pub(crate) use std::collections::BTreeSet;

pub(crate) use agf_core::alert::Alert;

pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;
pub(crate) use agf_core::ids::TenantScoped;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

#[cfg(test)]
pub(crate) use agf_core::enums::AlertState;
#[cfg(test)]
pub(crate) use agf_core::enums::RiskDomain;

#[allow(unused_imports)]
pub use impl_similarity_policy::*;
#[allow(unused_imports)]
pub use reduce_once::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 簇 id 命名空间（确定性 id 用）。
pub const NS_CLUSTER: &str = "aiguardfabric.correlate.cluster";

/// 标题相似度策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SimilarityPolicy {
    /// 严格相等：归一化标题必须完全一致才合并（零误并，但降噪率最低）。
    Exact,
    /// 字符 2-gram Jaccard 相似度（默认）：对中英文都稳定。
    Jaccard,
    /// 同实体同类目即合并（降噪率最高，误并风险最大，仅用于低价值噪声源）。
    Prefix,
}

/// 聚合配置（全部字段**必有默认值**，见 [`AggregationConfig::default`]）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AggregationConfig {
    /// 聚簇与其**首条**告警的时间偏移上限（秒），默认 300。
    pub window_secs: i64,
    /// 标题相似度阈值（`0.0..=1.0`），默认 0.75。
    pub similarity_threshold: f64,
    /// 相似度策略，默认 [`SimilarityPolicy::Jaccard`]。
    pub similarity: SimilarityPolicy,
    /// 是否按实体键分簇（默认 true）。关闭后退化为"同类目 + 同标题"，仅建议用于无实体信息的源。
    pub entity_scoped: bool,
    /// 单簇保留的去重键上限（防御性），默认 5 000；超限后只继续累加 `occurrences`。
    pub max_alerts_per_cluster: usize,
    /// 单租户开放簇上限，默认 10 000（仅作容量登记，超出不自动淘汰，由上层调度 flush）。
    pub max_open_clusters: usize,
}

/// 聚合/抑制过程中的错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AggregateError {
    /// 配置非法。
    #[error("聚合配置非法: {0}")]
    InvalidConfig(String),
    /// 抑制规则非法。
    #[error("抑制规则非法: {0}")]
    InvalidRule(String),
    /// 跨租户访问被拒绝（租户隔离硬边界）。
    #[error("租户隔离拒绝: 期望租户 {expected}，实际 {actual}")]
    TenantViolation {
        /// 调用方声明的租户。
        expected: String,
        /// 数据实际所属租户。
        actual: String,
    },
}

/// 进入聚合流水线的告警输入（是 [`Alert`] 的**投影**：只保留聚合所需的最小字段）。
///
/// 之所以不直接吃 `Alert`：聚合层需要"一条原始告警"的语义，而 [`Alert`] 自身是
/// "已被聚合过的告警"（带 `dedup_count`）。分开可以让上下行都保持诚实。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertInput {
    /// 租户（硬边界）。
    pub tenant_id: TenantId,
    /// 实体对齐键（见 [`crate::entity::entity_alignment_key`]）；`None` = 无实体信息。
    pub entity_key: Option<String>,
    /// 风险类目（域 / 规则分类的文本形式）。
    pub category: String,
    /// 严重等级。
    pub severity: Severity,
    /// 标题。
    pub title: String,
    /// 来源告警 id（若已在告警表中落地）。
    pub alert_id: Option<Id>,
    /// 来源事件 id（证据）。
    pub event_ids: Vec<Id>,
    /// 命中的规则键。
    pub rule_keys: Vec<String>,
    /// 发生时间。
    pub at: Timestamp,
    /// 标签。
    pub tags: Vec<String>,
}

/// 抑制类型（审计展示用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuppressionKind {
    /// 父告警等级更高，压制低等级子告警（默认形态）。
    Severity,
    /// 同类目下的父子抑制（如"已隔离"压制"再次外传尝试"）。
    Category,
    /// 命中同一规则簇的重复抑制。
    RuleKey,
}

/// 抑制规则：当存在满足"父"条件的簇时，压制满足"子"条件的簇。
///
/// 字段都是可选过滤条件；但一条规则**至少要有一个约束**（否则会压制一切），
/// 由 [`SuppressionRule::validate`] 强制。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressionRule {
    /// 规则键（审计用）。
    pub key: String,
    /// 人类可读原因（写入被抑制簇的 `suppress_reason`）。
    pub reason: String,
    /// 父簇必须命中的标题子串（空 = 不限）。
    #[serde(default)]
    pub parent_title_contains: Vec<String>,
    /// 父簇必须命中的类目（空 = 不限）。
    #[serde(default)]
    pub parent_categories: Vec<String>,
    /// 父簇的最低等级（`None` = 不限）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_min_severity: Option<Severity>,
    /// 子簇必须命中的标题子串（空 = 不限）。
    #[serde(default)]
    pub child_title_contains: Vec<String>,
    /// 子簇必须命中的类目（空 = 不限）。
    #[serde(default)]
    pub child_categories: Vec<String>,
    /// 子簇的最高等级（`None` = 不限）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_max_severity: Option<Severity>,
    /// 要求父子命中同一规则键（交集非空）。
    #[serde(default)]
    pub shared_rule_key: bool,
    /// 要求父子同类目。
    #[serde(default)]
    pub same_category: bool,
    /// 要求父子同实体键（任一为空则不满足）。
    #[serde(default)]
    pub same_entity: bool,
    /// 是否启用（默认 true）。
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

const fn default_enabled() -> bool {
    true
}

/// 聚合后的事件簇（可升级为案件的运营单元）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventCluster {
    /// 簇 id（确定性：同租户同实体同类目同标题 → 同 id，便于跨进程对账）。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 实体对齐键（`None` = 无实体信息）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_key: Option<String>,
    /// 类目。
    pub category: String,
    /// 代表标题（簇内首次出现的标题）。
    pub representative_title: String,
    /// 最高严重等级（簇等级只升不降）。
    pub severity: Severity,
    /// 首见时间。
    pub first_seen_at: Timestamp,
    /// 最后时间。
    pub last_seen_at: Timestamp,
    /// 原始告警条数（含重复）。
    pub occurrences: u64,
    /// 去重后的告警数（降噪核心指标）。
    pub dedup_count: u64,
    /// 去重指纹集合（受 `max_alerts_per_cluster` 限制）。
    pub dedup_keys: BTreeSet<String>,
    /// 去重键明细是否被截断。
    pub truncated: bool,
    /// 来源告警 id。
    pub alert_ids: Vec<Id>,
    /// 来源事件 id（证据，去重、稳定顺序）。
    pub event_ids: Vec<Id>,
    /// 命中过的规则键。
    pub rule_keys: BTreeSet<String>,
    /// 全部标签。
    pub tags: BTreeSet<String>,
    /// 是否被抑制。
    pub suppressed: bool,
    /// 命中的抑制规则键。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppress_rule: Option<String>,
    /// 抑制原因（人类可读）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppress_reason: Option<String>,
    /// 抑制来源簇 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed_by: Option<Id>,
}

/// 实体聚类状态（开放簇 + 已刷新簇 + 指纹索引）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClusterState {
    /// 尚未刷新的开放簇（key 由租户 + 实体 + 指纹拼成）。
    pub open: BTreeMap<String, EventCluster>,
    /// 已刷新并完成抑制判定的簇。
    pub closed: Vec<EventCluster>,
    /// 去重指纹 → 落位簇 key（重复告警只计数不新增，靠它命中）。
    pub seen: BTreeMap<String, String>,
}

/// 降噪报告。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReduceReport {
    /// 租户。
    pub tenant_id: TenantId,
    /// 原始告警条数。
    pub raw_alerts: u64,
    /// 去重聚合后的**运营单元数**（即事件簇数）：相似标题/同指纹被合成一个簇后，
    /// 上层真正要处理的就是簇本身；簇内到底装了多少个去重键见各簇的 `dedup_count`。
    pub deduped_alerts: u64,
    /// 被抑制的簇数（计入 `deduped_alerts`，但标记为不可行动）。
    pub suppressed_alerts: u64,
    /// 产出的事件簇（等级降序）。
    pub clusters: Vec<EventCluster>,
    /// 生成时间。
    pub generated_at: Timestamp,
}

/// 告警聚合器：摄入 → 聚簇 → 抑制 → 产出事件簇。
///
/// ## 租户隔离
///
/// 聚合器自身不携带租户：它在 [`AlertAggregator::ingest`] 中按输入租户分簇，在跨租户比较
/// （抑制判定）时显式校验租户一致；[`AlertAggregator::report`] 要求调用方声明租户，
/// 只接受该租户的簇，不匹配则返回 [`AggregateError::TenantViolation`]（不静默过滤——
/// 静默过滤会掩盖上层的租户串联错误）。
#[derive(Debug, Clone)]
pub struct AlertAggregator {
    /// 配置。
    pub config: AggregationConfig,
    /// 抑制规则。
    pub rules: Vec<SuppressionRule>,
    state: ClusterState,
}

mod impl_alert_aggregator;
mod impl_event_cluster;
mod impl_similarity_policy;
mod reduce_once;
#[cfg(test)]
mod tests;
