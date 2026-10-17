//! 由 `cms.rs` 拆分：`parse_alarm_histories` 函数（纯搬移，逻辑不变）。
use super::*;

/// 把 `DescribeAlertHistoryList` 响应解析为领域结构（兼容两种数组形态与字符串数字）。
#[must_use]
pub fn parse_alarm_histories(response: &RpcResponse) -> Vec<CmsAlarmHistory> {
    json_array(response.body.get("AlarmHistoryList").unwrap_or(&response.body), &["AlarmHistory", "AlarmHistories"])
        .into_iter()
        .map(|item| CmsAlarmHistory {
            alarm_id: json_str(item, "AlarmId").or_else(|| json_str(item, "RuleId")).unwrap_or_default(),
            rule_name: json_str(item, "RuleName").or_else(|| json_str(item, "Name")).unwrap_or_default(),
            resource_id: json_str(item, "InstanceId")
                .or_else(|| json_str(item, "InstanceName"))
                .or_else(|| json_str(item, "ResourceId"))
                .unwrap_or_default(),
            level: json_str(item, "Level").unwrap_or_else(|| "INFO".to_string()),
            state: json_str(item, "State").unwrap_or_else(|| "ALARM".to_string()),
            content: json_str(item, "Content").or_else(|| json_str(item, "Value")).unwrap_or_default(),
            at: json_i64(item, "AlertTime")
                .or_else(|| json_i64(item, "AlarmTime"))
                .or_else(|| json_i64(item, "Timestamp"))
                .and_then(|ms| Timestamp::from_unix_millis(ms).ok())
                .unwrap_or_else(Timestamp::now),
        })
        .collect()
}
