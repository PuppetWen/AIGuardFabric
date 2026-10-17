//! 报表格式 / 状态标签与报表 ID 别名。

use super::*;

/// 报表格式标签（供前端展示）。
#[must_use]
pub const fn format_label(format: ReportFormat) -> &'static str {
    format.as_str()
}

/// 报表状态标签。
#[must_use]
pub const fn report_state_label(state: ReportState) -> &'static str {
    state.as_str()
}

/// 报表 ID 类型别名（对外文档用）。
pub type ReportId = Id;
