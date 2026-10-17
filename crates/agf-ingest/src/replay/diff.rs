//! 回放差分与渲染：可比较字段抽取、前后事件字段级 diff 与文本报告渲染。

use super::*;

/// 事件的可比较字段视图（仅纳入归一化后会变化的字段，避免噪声）。
#[must_use]
pub fn comparable_fields(event: &Event) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    out.insert("event.time".to_string(), Value::from(event.time.to_rfc3339()));
    out.insert("event.severity".to_string(), Value::from(event.severity.as_str()));
    out.insert("event.category".to_string(), Value::from(event.category.as_str()));
    out.insert("event.action".to_string(), Value::from(event.action.as_str()));
    if !event.action_raw.is_empty() {
        out.insert("event.action_raw".to_string(), Value::from(event.action_raw.clone()));
    }
    if let Some(v) = &event.host.name {
        out.insert("host.name".to_string(), Value::from(v.clone()));
    }
    if let Some(v) = &event.network.source_ip {
        out.insert("network.source_ip".to_string(), Value::from(v.clone()));
    }
    if let Some(v) = &event.network.destination_ip {
        out.insert("network.destination_ip".to_string(), Value::from(v.clone()));
    }
    if let Some(v) = &event.user.name {
        out.insert("user.name".to_string(), Value::from(v.clone()));
    }
    if let Some(v) = &event.parser_name {
        out.insert("parser_name".to_string(), Value::from(v.clone()));
    }
    if !event.vendor.is_empty() {
        out.insert("vendor".to_string(), Value::from(event.vendor.clone()));
    }
    if !event.product.is_empty() {
        out.insert("product".to_string(), Value::from(event.product.clone()));
    }
    out.insert("message".to_string(), Value::from(event.message.clone()));
    out
}

/// 计算两次归一化结果的字段差分。
#[must_use]
pub fn diff_events(before: &Event, after: &Event) -> Vec<FieldDiff> {
    let b = comparable_fields(before);
    let a = comparable_fields(after);
    let keys: BTreeSet<&String> = b.keys().chain(a.keys()).collect();
    keys.into_iter()
        .map(|key| FieldDiff { path: key.clone(), before: b.get(key).cloned(), after: a.get(key).cloned() })
        .filter(|d| d.before != d.after)
        .collect()
}

/// 把报告渲染为 Markdown（运维复盘/上线评审用）。
#[must_use]
pub fn render_report(report: &ReplayReport) -> String {
    let mut out = String::new();
    out.push_str("# 原始日志回放报告\n\n");
    out.push_str(&format!(
        "- 检查条数：{}\n- 新解析成功：{}\n- 仍失败：{}\n- 差分条数：{}\n- 耗时：{} μs\n\n",
        report.replayed,
        report.newly_parsed,
        report.failed,
        report.diffs.len(),
        report.elapsed_micros
    ));
    if !report.parser_used.is_empty() {
        out.push_str("## 解析器使用\n\n| 解析器 | 次数 |\n|---|---|\n");
        for (key, count) in &report.parser_used {
            out.push_str(&format!("| {key} | {count} |\n"));
        }
        out.push('\n');
    }
    if !report.failures.is_empty() {
        out.push_str("## 失败明细\n\n| 原始日志 | 原因 |\n|---|---|\n");
        for failure in &report.failures {
            out.push_str(&format!("| {} | {} |\n", failure.raw_id, failure.reason));
        }
        out.push('\n');
    }
    if !report.diffs.is_empty() {
        out.push_str("## 差分明细\n\n");
        for diff in &report.diffs {
            out.push_str(&format!(
                "### {} → {}\n\n- 原始日志：{}\n- 解析器：{}\n\n",
                diff.previous_event.map(|v| v.to_string()).unwrap_or_else(|| "<无>".to_string()),
                diff.new_event.map(|v| v.to_string()).unwrap_or_else(|| "<无>".to_string()),
                diff.raw_id,
                diff.parser_key.clone().unwrap_or_else(|| "<无>".to_string())
            ));
            for change in &diff.changes {
                out.push_str(&format!(
                    "- `{0}`: {1} → {2}\n",
                    change.path,
                    change.before.clone().unwrap_or(Value::Null),
                    change.after.clone().unwrap_or(Value::Null)
                ));
            }
            out.push('\n');
        }
    }
    out
}

/// 把原始日志协议转换为总线主题后缀（回放监控用）。
#[must_use]
pub fn protocol_label(protocol: IngestProtocol) -> &'static str {
    protocol.as_str()
}
