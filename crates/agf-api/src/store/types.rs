//! 扫描任务状态与扫描任务实体（`ScanJobState` / `ScanJob`）。

use super::*;

/// 扫描任务状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScanJobState {
    /// 已排队。
    Queued,
    /// 执行中。
    Running,
    /// 成功。
    Succeeded,
    /// 失败。
    Failed,
    /// 已取消。
    Cancelled,
}

impl ScanJobState {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// 是否终态。
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }

    /// 解析。
    ///
    /// # Errors
    /// 未知状态名。
    pub fn parse(raw: &str) -> DomainResult<Self> {
        match raw {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(DomainError::Validation(format!("未知扫描任务状态: {other}"))),
        }
    }
}

/// 扫描任务（长任务句柄：`POST /scans` 返回 `task_id`，`GET /scans/{task_id}` 查询）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanJob {
    /// 任务 id（对外即 `task_id`）。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 任务名。
    pub name: String,
    /// 状态。
    pub state: ScanJobState,
    /// 目标数。
    pub targets: usize,
    /// 扫描域。
    pub domains: Vec<String>,
    /// 进度（0-100）。
    pub progress: u8,
    /// 是否启用 LLM 研判。
    pub use_llm_judge: bool,
    /// 命中的规则计数（规则键 → 次数）。
    pub rule_hits: BTreeMap<String, usize>,
    /// 产出发现数。
    pub finding_count: usize,
    /// 风险评分。
    pub risk_score: Option<u8>,
    /// Committed findings produced by this task; empty until successful completion.
    #[serde(default)]
    pub finding_ids: Vec<Id>,
    /// Whether an actual secondary judgement used the offline mock.
    #[serde(default)]
    pub llm_mocked: Option<bool>,
    /// Completed model judgements.
    #[serde(default)]
    pub judgement_count: usize,
    /// Failed requested judgements; rule results were retained.
    #[serde(default)]
    pub judgement_failures: usize,
    /// 最高严重等级。
    pub max_severity: String,
    /// 摘要行。
    pub summary: String,
    /// 耗时（毫秒）。
    pub elapsed_ms: u64,
    /// 失败原因。
    pub error: Option<String>,
    /// 发起人。
    pub requested_by: String,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 开始时间。
    pub started_at: Option<Timestamp>,
    /// 结束时间。
    pub finished_at: Option<Timestamp>,
}
