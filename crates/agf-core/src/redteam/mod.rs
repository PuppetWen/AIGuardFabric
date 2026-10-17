//! AI 红队模型（§4.2 AI 红队）。
//!
//! 用例库 200+，YAML 声明式剧本，多 Agent 对抗，报告含成功率/绕过路径/证据包/修复建议/复测结论。

use serde::{Deserialize, Serialize};

use crate::enums::{EvidenceLevel, Severity};

use crate::ids::{Id, TenantId};

use crate::time::Timestamp;

#[allow(unused_imports)]
pub use impl_attack_category::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 红队攻击类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttackCategory {
    /// 越狱（角色扮演、假设场景、编码变形）。
    Jailbreak,
    /// 直接提示词注入。
    DirectInjection,
    /// 间接提示词注入（通过文档/工具结果/网页）。
    IndirectInjection,
    /// RAG 投毒。
    RagPoisoning,
    /// 工具滥用（越权/SSRF/命令注入/路径穿越）。
    ToolAbuse,
    /// 数据外传。
    DataExfiltration,
    /// 多轮社工（渐进式诱导）。
    MultiTurnSocial,
    /// 凭证窃取。
    CredentialTheft,
    /// 权限提升。
    PrivilegeEscalation,
    /// 供应链（模型/插件/技能后门）。
    SupplyChain,
    /// Agent 间横向移动。
    LateralMovement,
    /// 拒绝服务 / 资源耗尽。
    ResourceExhaustion,
}

/// 用例执行方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionMode {
    /// 单轮提示词。
    SingleTurn,
    /// 多轮对话（按 `turns` 顺序发送）。
    MultiTurn,
    /// 工具调用序列（需要 MCP 环境）。
    ToolSequence,
    /// 文档投毒（先写入知识库，再检索）。
    DocumentPoison,
    /// 多 Agent 对抗（攻击 Agent 与目标 Agent 交互）。
    MultiAgent,
}

/// 一次攻击轮次。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTurn {
    /// 角色（`user` / `system` / `tool`）。
    #[serde(default = "default_user_role")]
    pub role: String,
    /// 内容（支持 `{{target}}`、`{{marker}}` 占位符）。
    pub content: String,
    /// 期望观察到的信号（如 `marker_echo`、`system_prompt_leak`）。
    #[serde(default)]
    pub expect: Vec<String>,
}

/// 红队用例。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedteamCase {
    /// 稳定键（形如 `RT-JB-001`）。
    pub key: String,
    /// 标题。
    pub title: String,
    /// 类别。
    pub category: AttackCategory,
    /// 严重等级（得逞后的影响）。
    pub severity: Severity,
    /// 执行方式。
    pub mode: ExecutionMode,
    /// 攻击轮次。
    #[serde(default)]
    pub turns: Vec<AttackTurn>,
    /// 目标描述（适用于哪些 Agent/MCP 能力）。
    #[serde(default)]
    pub applies_to: Vec<String>,
    /// 成功判定信号（任一命中即算成功）。
    #[serde(default)]
    pub success_signals: Vec<String>,
    /// 需要的工具（工具链用例）。
    #[serde(default)]
    pub required_tools: Vec<String>,
    /// 标签（MITRE / OWASP / Agentic ATT&CK）。
    #[serde(default)]
    pub tags: Vec<String>,
    /// 来源引用（公开 PoC URL 或论文）。
    #[serde(default)]
    pub references: Vec<String>,
    /// 是否来自公开真实 PoC（区别于合成用例）。
    #[serde(default)]
    pub public_poc: bool,
    /// 修复建议。
    #[serde(default)]
    pub remediation: String,
    /// 作者。
    #[serde(default)]
    pub author: String,
    /// 版本。
    #[serde(default = "default_version")]
    pub version: u32,
}

const fn default_version() -> u32 {
    1
}

/// 红队战役（一次批量攻击执行）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedteamCampaign {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 名称。
    pub name: String,
    /// 目标 Agent 资产 id 列表。
    #[serde(default)]
    pub target_agent_ids: Vec<Id>,
    /// 目标 MCP 资产 id 列表。
    #[serde(default)]
    pub target_mcp_ids: Vec<Id>,
    /// 选中的用例键列表（空 = 按标签筛选）。
    #[serde(default)]
    pub case_keys: Vec<String>,
    /// 按类别筛选。
    #[serde(default)]
    pub categories: Vec<AttackCategory>,
    /// 按标签筛选。
    #[serde(default)]
    pub tags: Vec<String>,
    /// 状态。
    pub state: CampaignState,
    /// 发起人。
    pub launched_by: String,
    /// 是否定时巡航（SchedulerX3 或本地 cron）。
    #[serde(default)]
    pub scheduled: bool,
    /// cron 表达式。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cron: Option<String>,
    /// 是否作为 CI 卡点（失败即阻断发布）。
    #[serde(default)]
    pub ci_gate: bool,
    /// 用例总数。
    pub total_cases: u32,
    /// 已执行。
    pub executed_cases: u32,
    /// 成功（拿下）数量。
    pub succeeded_cases: u32,
    /// 开始时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<Timestamp>,
    /// 结束时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<Timestamp>,
    /// 创建时间。
    pub created_at: Timestamp,
}

/// 战役状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CampaignState {
    /// 已排队。
    Queued,
    /// 执行中。
    Running,
    /// 已完成。
    Completed,
    /// 已失败（执行异常）。
    Failed,
    /// 已取消。
    Cancelled,
}

/// Whether the case's checks were actually evaluated, independent of attack success.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvaluationStatus {
    /// All configured checks were evaluated from recorded interactions.
    Evaluated,
    /// Required capability, check or evidence was unavailable.
    Inconclusive,
    /// Target execution failed.
    ExecutionError,
    /// Historical records do not state evaluation completeness.
    #[default]
    Unknown,
}

/// 单个用例的执行结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedteamResult {
    /// Assessment coverage; legacy records remain unknown.
    #[serde(default)]
    pub evaluation: EvaluationStatus,
    /// Reason for an incomplete or failed evaluation.
    #[serde(default)]
    pub evaluation_note: Option<String>,
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 战役 id。
    pub campaign_id: Id,
    /// 用例键。
    pub case_key: String,
    /// 用例标题。
    pub case_title: String,
    /// 类别。
    pub category: AttackCategory,
    /// 目标资产 id。
    pub target_asset_id: Id,
    /// 是否成功（攻击得逞）。
    pub succeeded: bool,
    /// 命中的成功信号。
    #[serde(default)]
    pub matched_signals: Vec<String>,
    /// 绕过路径描述（怎么绕过的防护）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bypass_path: Option<String>,
    /// 完整对话/交互记录（保真，供复盘）。
    #[serde(default)]
    pub transcript: Vec<serde_json::Value>,
    /// 证据引用。
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// 证据等级。
    pub evidence_level: EvidenceLevel,
    /// 关联 finding id（成功用例落成 finding）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<Id>,
    /// 耗时（毫秒）。
    pub latency_ms: u64,
    /// 使用模型。
    pub model: String,
    /// 是否走 Mock。
    pub mocked: bool,
    /// 执行时间。
    pub executed_at: Timestamp,
}

/// 红队报告（含成功率、绕过路径、修复建议、复测结论）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedteamReport {
    /// Cases for which every declared check was actually evaluated.
    #[serde(default)]
    pub evaluated_cases: u32,
    /// Cases lacking a required capability, check or usable evidence.
    #[serde(default)]
    pub inconclusive_cases: u32,
    /// Cases whose target interaction failed before assessment.
    #[serde(default)]
    pub failed_cases: u32,
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 战役 id。
    pub campaign_id: Id,
    /// 报告标题。
    pub title: String,
    /// 用例总数。
    pub total_cases: u32,
    /// 执行数。
    pub executed: u32,
    /// 成功数。
    pub succeeded: u32,
    /// 按类别统计（类别 → (执行, 成功)）。
    #[serde(default)]
    pub by_category: Vec<CategoryStat>,
    /// 关键绕过路径。
    #[serde(default)]
    pub bypass_paths: Vec<String>,
    /// 修复建议（去重后的集合）。
    #[serde(default)]
    pub remediations: Vec<String>,
    /// 关联 finding 列表。
    #[serde(default)]
    pub finding_ids: Vec<Id>,
    /// 总体结论。
    pub verdict: String,
    /// 是否通过 CI 卡点。
    pub ci_passed: bool,
    /// Markdown 报告正文。
    #[serde(default)]
    pub markdown: String,
    /// 生成时间。
    pub generated_at: Timestamp,
}

/// 按类别统计。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryStat {
    /// 类别。
    pub category: AttackCategory,
    /// 执行数。
    pub executed: u32,
    /// 成功数。
    pub succeeded: u32,
}

mod impl_attack_category;
#[cfg(test)]
mod tests;
