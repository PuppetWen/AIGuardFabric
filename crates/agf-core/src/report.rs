//! 报表与报告模型（§4.4 报告自动生成、§4.7 报表）。

use serde::{Deserialize, Serialize};

use crate::ids::{Id, TenantId, TenantScoped};
use crate::time::{Date, TimeRange, Timestamp};

/// 报表类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportKind {
    /// 安全态势总览。
    Posture,
    /// 风险发现报告。
    Findings,
    /// 红队报告。
    Redteam,
    /// 合规报告（等保/ISO/内部规范映射）。
    Compliance,
    /// 资产盘点报告。
    AssetInventory,
    /// 变更漂移报告。
    Drift,
    /// 计费账单。
    Billing,
    /// 事件复盘报告。
    Incident,
    /// 自定义（基于模板）。
    Custom,
}

impl ReportKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Posture => "posture",
            Self::Findings => "findings",
            Self::Redteam => "redteam",
            Self::Compliance => "compliance",
            Self::AssetInventory => "asset-inventory",
            Self::Drift => "drift",
            Self::Billing => "billing",
            Self::Incident => "incident",
            Self::Custom => "custom",
        }
    }

    /// 全部类型。
    #[must_use]
    pub const fn all() -> [Self; 9] {
        [
            Self::Posture,
            Self::Findings,
            Self::Redteam,
            Self::Compliance,
            Self::AssetInventory,
            Self::Drift,
            Self::Billing,
            Self::Incident,
            Self::Custom,
        ]
    }
}

/// 输出格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    /// Markdown。
    Markdown,
    /// PDF。
    Pdf,
    /// HTML。
    Html,
    /// CSV（明细）。
    Csv,
    /// JSON（机器消费）。
    Json,
}

impl ReportFormat {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Markdown => "markdown",
            Self::Pdf => "pdf",
            Self::Html => "html",
            Self::Csv => "csv",
            Self::Json => "json",
        }
    }

    /// 文件扩展名。
    #[must_use]
    pub const fn extension(&self) -> &'static str {
        match self {
            Self::Markdown => "md",
            Self::Pdf => "pdf",
            Self::Html => "html",
            Self::Csv => "csv",
            Self::Json => "json",
        }
    }
}

/// 报告生成状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportState {
    /// 排队中（长任务，返回 `task_id`）。
    Queued,
    /// 生成中。
    Running,
    /// 已完成。
    Completed,
    /// 失败。
    Failed,
}

impl ReportState {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    /// 是否终态。
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

/// 报告定义/实例。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 类型。
    pub kind: ReportKind,
    /// 标题。
    pub title: String,
    /// 状态。
    pub state: ReportState,
    /// 数据窗口。
    pub range: TimeRange,
    /// 输出格式。
    pub format: ReportFormat,
    /// 渲染模板 key（Handlebars/Tera）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_key: Option<String>,
    /// 过滤条件（资产/部门/等级）。
    #[serde(default)]
    pub filters: serde_json::Value,
    /// 渲染后的正文（Markdown / HTML）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// 产物引用（对象存储 key）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<String>,
    /// 产物体积（字节）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_bytes: Option<u64>,
    /// 内容哈希（防篡改）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    /// 是否由大模型生成（AI 报告）。
    #[serde(default)]
    pub ai_generated: bool,
    /// 使用的模型。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// 是否 Mock 模型生成。
    #[serde(default)]
    pub mocked: bool,
    /// 失败原因。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// 生成人。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<Id>,
    /// 定时生成计划 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule_id: Option<Id>,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 完成时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<Timestamp>,
}

impl TenantScoped for Report {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl Report {
    /// 生成建议文件名（不含目录）。
    #[must_use]
    pub fn suggested_filename(&self) -> String {
        let day = Date::today().to_iso();
        let slug: String = self.title.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).take(48).collect();
        format!("{}-{}-{}.{}", self.kind.as_str(), day, slug.trim_matches('_'), self.format.extension())
    }

    /// 是否已完成且产物可用。
    #[must_use]
    pub fn is_downloadable(&self) -> bool {
        self.state == ReportState::Completed && self.artifact_ref.is_some()
    }
}

/// 报表计划（定时生成）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSchedule {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 名称。
    pub name: String,
    /// 类型。
    pub kind: ReportKind,
    /// 格式。
    pub format: ReportFormat,
    /// cron 表达式。
    pub cron: String,
    /// 时间窗口长度（秒；相对生成时刻往前推）。
    pub window_secs: i64,
    /// 收件渠道 id。
    #[serde(default)]
    pub channel_ids: Vec<Id>,
    /// 收件人。
    #[serde(default)]
    pub recipients: Vec<String>,
    /// 是否启用。
    pub enabled: bool,
    /// 上次生成时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_generated_at: Option<Timestamp>,
    /// 创建时间。
    pub created_at: Timestamp,
}

impl TenantScoped for ReportSchedule {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl ReportSchedule {
    /// 依据当前时刻计算报告数据窗口。
    #[must_use]
    pub fn window_at(&self, now: Timestamp) -> TimeRange {
        TimeRange::new(now.offset_secs(-self.window_secs), now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(kind: ReportKind, format: ReportFormat, title: &str) -> Report {
        let now = Timestamp::now();
        Report {
            id: Id::new(),
            tenant_id: TenantId::default_tenant(),
            kind,
            title: title.to_string(),
            state: ReportState::Queued,
            range: TimeRange::last_day(),
            format,
            template_key: None,
            filters: serde_json::Value::Null,
            body: None,
            artifact_ref: None,
            artifact_bytes: None,
            content_hash: None,
            ai_generated: false,
            model: None,
            mocked: false,
            error: None,
            created_by: None,
            schedule_id: None,
            created_at: now,
            completed_at: None,
        }
    }

    #[test]
    fn filename_slugifies_and_uses_extension() {
        let r = report(ReportKind::Posture, ReportFormat::Pdf, "2026 Q1 安全态势 总览");
        let name = r.suggested_filename();
        assert!(name.starts_with("posture-"));
        assert!(name.ends_with(".pdf"));
        assert!(!name.contains(' '), "文件名不应含空格: {name}");
        assert!(!name.contains("__"), "连续下划线应被压缩: {name}");
    }

    #[test]
    fn downloadable_requires_completed_and_artifact() {
        let mut r = report(ReportKind::Findings, ReportFormat::Markdown, "发现报告");
        assert!(!r.is_downloadable());
        r.state = ReportState::Completed;
        assert!(!r.is_downloadable(), "无产物不可下载");
        r.artifact_ref = Some("reports/2026/x.md".into());
        assert!(r.is_downloadable());
        r.state = ReportState::Failed;
        assert!(!r.is_downloadable());
    }

    #[test]
    fn report_states_terminal() {
        assert!(!ReportState::Queued.is_terminal());
        assert!(!ReportState::Running.is_terminal());
        assert!(ReportState::Completed.is_terminal());
        assert!(ReportState::Failed.is_terminal());
    }

    #[test]
    fn kinds_and_formats_complete() {
        assert_eq!(ReportKind::all().len(), 9);
        for k in ReportKind::all() {
            assert!(!k.as_str().is_empty());
        }
        assert_eq!(ReportFormat::Markdown.extension(), "md");
        assert_eq!(ReportFormat::Csv.extension(), "csv");
        assert_eq!(ReportFormat::Pdf.as_str(), "pdf");
    }

    #[test]
    fn schedule_window_is_backwards_from_now() {
        let now = Timestamp::now();
        let s = ReportSchedule {
            id: Id::new(),
            tenant_id: TenantId::default_tenant(),
            name: "周报".into(),
            kind: ReportKind::Posture,
            format: ReportFormat::Html,
            cron: "0 8 * * 1".into(),
            window_secs: 604_800,
            channel_ids: vec![],
            recipients: vec![],
            enabled: true,
            last_generated_at: None,
            created_at: now,
        };
        let w = s.window_at(now);
        assert_eq!(w.duration_secs(), 604_800);
        assert_eq!(w.to.unix_secs(), now.unix_secs());
    }
}
