//! Type-specific detail tables. Snapshot data is distinguished from time-window events.
use super::*;
use agf_core::{error::DomainResult, ids::TenantId};
use serde_json::Value;

pub(super) async fn append(
    state: &AppState,
    tenant: TenantId,
    kind: ReportKind,
    range: &TimeRange,
    out: &mut String,
) -> DomainResult<()> {
    out.push_str("\n## 7. 分类明细\n\n");
    let within = |at: Timestamp| at >= range.from && at < range.to;
    match kind {
        ReportKind::AssetInventory => {
            out.push_str("以下为生成时的资产快照，包含窗口之前创建且仍在台账中的资产。\n\n");
            table(
                out,
                state.store.asset_list_all_durable(tenant).await?,
                &[
                    ("name", "资产"),
                    ("kind", "类型"),
                    ("department", "部门"),
                    ("owner", "负责人"),
                    ("data_class", "分级"),
                    ("lifecycle", "生命周期"),
                ],
            )?;
        }
        ReportKind::Incident => {
            out.push_str("### 告警（窗口内首次发生）\n\n");
            table(
                out,
                state
                    .store
                    .alert_list_durable(tenant, None, None)
                    .await?
                    .into_iter()
                    .filter(|r| within(r.first_seen_at))
                    .collect(),
                &[("title", "标题"), ("severity", "等级"), ("state", "状态"), ("first_seen_at", "首次发生")],
            )?;
            out.push_str("\n### 案件（窗口内创建）\n\n");
            table(
                out,
                state.store.case_list_durable(tenant).await?.into_iter().filter(|r| within(r.created_at)).collect(),
                &[("code", "编号"), ("title", "标题"), ("severity", "等级"), ("state", "状态")],
            )?;
        }
        ReportKind::Redteam => table(
            out,
            state.store.campaign_list_durable(tenant).await?.into_iter().filter(|r| within(r.created_at)).collect(),
            &[
                ("name", "战役"),
                ("state", "状态"),
                ("executed_cases", "已执行"),
                ("succeeded_cases", "攻击成功"),
                ("ci_gate", "CI门禁"),
            ],
        )?,
        ReportKind::Billing => {
            let rows: Vec<_> =
                crate::gateway_quota::usage(state, tenant).await?.into_iter().filter(|r| within(r.at)).collect();
            let cost: u64 = rows.iter().map(|r| r.cost_micro).fold(0, u64::saturating_add);
            out.push_str(&format!(
                "调用 {} 次；费用合计 {} 微人民币（1 CNY = 1,000,000 微人民币），以配置的端点单价计量。\n\n",
                rows.len(),
                cost
            ));
            table(
                out,
                rows,
                &[
                    ("model", "模型"),
                    ("prompt_tokens", "输入Token"),
                    ("completion_tokens", "输出Token"),
                    ("cost_micro", "微人民币（CNY）"),
                    ("at", "时间"),
                ],
            )?;
        }
        ReportKind::Drift => {
            let changes = state.store.asset_changes_in_range(tenant, range).await?;
            table(
                out,
                changes,
                &[
                    ("asset_id", "资产"),
                    ("change_kind", "变更"),
                    ("field", "字段"),
                    ("risky", "风险漂移"),
                    ("detected_at", "时间"),
                ],
            )?;
        }
        ReportKind::Posture | ReportKind::Findings | ReportKind::Compliance | ReportKind::Custom => {
            if kind == ReportKind::Compliance {
                out.push_str("本报告列出可用于内部审计的风险证据；不替代第三方合规认证。\n\n");
            }
            table(
                out,
                state
                    .store
                    .finding_list_all_durable(tenant)
                    .await?
                    .into_iter()
                    .filter(|r| within(r.first_seen_at))
                    .collect(),
                &[
                    ("title", "发现"),
                    ("domain", "安全域"),
                    ("severity", "等级"),
                    ("state", "状态"),
                    ("first_seen_at", "首次发现"),
                    ("fix", "修复建议"),
                ],
            )?;
        }
    }
    Ok(())
}

fn cell(value: &Value) -> String {
    let text = match value {
        Value::String(s) => s.clone(),
        Value::Null => "—".into(),
        other => other.to_string(),
    };
    text.replace('|', "\\|").replace(['\r', '\n'], " ").chars().take(240).collect()
}

fn table<T: Serialize>(out: &mut String, rows: Vec<T>, columns: &[(&str, &str)]) -> DomainResult<()> {
    out.push_str(&format!("共 {} 条；下表最多展示 200 条。\n\n", rows.len()));
    out.push('|');
    for (_, label) in columns {
        out.push_str(&format!(" {label} |"));
    }
    out.push_str("\n|");
    for _ in columns {
        out.push_str("---|");
    }
    out.push('\n');
    for row in rows.into_iter().take(200) {
        let value = serde_json::to_value(row)?;
        out.push('|');
        for (key, _) in columns {
            out.push_str(&format!(" {} |", cell(&value[*key])));
        }
        out.push('\n');
    }
    Ok(())
}
