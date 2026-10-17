//! Campaign inputs are saved before spawning; terminal evidence is committed atomically.
use super::*;
use crate::store::CampaignRecord;
use agf_core::{
    ids::{Id, TenantId},
    redteam::RedteamCase,
};

pub(super) async fn execute(state: &AppState, tenant: TenantId, id: Id) -> Result<CampaignRecord, DomainError> {
    let result = run(state, tenant, id).await;
    match result {
        Ok(record) => Ok(record),
        Err(error) => {
            tracing::warn!(task_id=%id,error=%error,"Campaign execution failed");
            state
                .store
                .campaign_transition_durable(
                    tenant,
                    id,
                    CampaignState::Failed,
                    Some(
                        "Campaign execution failed before committing evidence; inspect service health and retest."
                            .into(),
                    ),
                )
                .await
        }
    }
}

async fn run(state: &AppState, tenant: TenantId, id: Id) -> Result<CampaignRecord, DomainError> {
    let mut record = state.store.campaign_transition_durable(tenant, id, CampaignState::Running, None).await?;
    if record.terminal() {
        return Ok(record);
    }
    let cases: Vec<&RedteamCase> = record.cases.iter().collect();
    let (outcomes, model) = if record.execution_mode.as_deref() == Some("agent-http") {
        super::agent_live_execution::run(state, &record, &cases).await?
    } else if record.execution_mode.as_deref() == Some("mcp-http") {
        super::mcp_live_execution::run(state, &record, &cases).await?
    } else if record.execution_mode.as_deref() == Some("simulator") {
        let target = RedteamSimulator::new(record.target_name.clone(), record.guard_strength);
        let (_, outcomes, _) = tokio::time::timeout(
            remaining(&record),
            CampaignRunner::new().run(
                tenant,
                &record.campaign.name,
                &cases,
                &target,
                &record.campaign.launched_by,
                record.campaign.ci_gate,
            ),
        )
        .await
        .map_err(|_| DomainError::PreconditionFailed("Campaign timed out".into()))??;
        (outcomes, None)
    } else {
        return Err(DomainError::Validation("Campaign execution mode is unknown".into()));
    };
    record.campaign.state = CampaignState::Completed;
    record.campaign.executed_cases = u32::try_from(outcomes.len()).unwrap_or(u32::MAX);
    record.campaign.succeeded_cases =
        u32::try_from(outcomes.iter().filter(|o| o.succeeded).count()).unwrap_or(u32::MAX);
    record.campaign.finished_at = Some(Timestamp::now());
    let mut report = CampaignRunner::build_report(tenant, &record.campaign, &cases, &outcomes);
    let breaches = outcomes.iter().filter(|o| o.succeeded && o.severity >= record.severity_threshold).count();
    report.ci_passed = !record.campaign.ci_gate
        || (breaches == 0 && report.evaluated_cases > 0 && report.evaluated_cases == record.campaign.total_cases);
    if model.is_none() {
        report.verdict = format!(
            "模拟执行完成；{} 项模拟攻击得逞，{} 项达到 {} 门槛。此结论不证明任何真实资产的防护能力。",
            record.campaign.succeeded_cases,
            breaches,
            record.severity_threshold.as_str()
        );
    } else {
        report.verdict.push_str(&format!(" {} 项达到 {} CI 门槛。", breaches, record.severity_threshold.as_str()));
    }
    if report.inconclusive_cases + report.failed_cases > 0 {
        report.verdict.push_str(&format!(
            " {} 项无法判定，{} 项执行失败；未完成的判定不能放行。",
            report.inconclusive_cases, report.failed_cases
        ));
    }
    record.results=outcomes.iter().zip(&cases).map(|(outcome,case)|{
        let mut result=outcome.to_result(tenant,id);
        if let Some(model) = &model {
            result.model=model.clone();
        } else {
            // Simulated successes never create confirmed findings or link invented IDs to inventory assets.
            result.evidence_level=agf_core::enums::EvidenceLevel::Unknown;
            result.transcript=case.turns.iter().map(|turn|serde_json::json!({"role":turn.role,"content":turn.content,"simulated":true})).collect();
            result.transcript.push(serde_json::json!({"role":"simulator","content":"Deterministic simulation; no external target was contacted.","signals":result.matched_signals,"guard_strength":record.guard_strength}));
        }
        result.evidence_refs=vec![format!("campaign:{id}/results/{}",result.id)];
        result
    }).collect();
    if let Some(parent) = record.retest_of {
        let previous = state
            .store
            .campaign_get_durable(tenant, parent)
            .await?
            .ok_or_else(|| DomainError::NotFound { entity: "redteam-campaign", id: parent.to_string() })?;
        let mut resolved = vec![];
        let mut persistent = vec![];
        let mut regressed = vec![];
        let mut unassessed = vec![];
        for result in &record.results {
            if let Some(old) = previous.results.iter().find(|old| old.case_key == result.case_key) {
                if !old.is_evaluated() || !result.is_evaluated() {
                    unassessed.push(result.case_key.clone());
                    continue;
                }
                match (old.succeeded, result.succeeded) {
                    (true, false) => resolved.push(result.case_key.clone()),
                    (true, true) => persistent.push(result.case_key.clone()),
                    (false, true) => regressed.push(result.case_key.clone()),
                    (false, false) => {}
                }
            }
        }
        let comparable = previous.campaign.state == CampaignState::Completed
            && previous.execution_mode == record.execution_mode
            && previous.campaign.target_agent_ids == record.campaign.target_agent_ids
            && previous.campaign.target_mcp_ids == record.campaign.target_mcp_ids;
        record.comparison = Some(
            serde_json::json!({"baseline":parent,"resolved":resolved,"persistent":persistent,"regressed":regressed,
            "comparable":comparable,"simulated":model.is_none(),"unassessed":unassessed}),
        );
    }
    report.markdown = render_markdown(&record.campaign, &outcomes, &report);
    if model.is_none() {
        report.markdown = report.markdown.replacen(
            "- 目标: <未指定>",
            &format!("- 模拟目标: {}", record.target_name.replace(['\n', '\r'], " ")),
            1,
        );
    }
    if !record.campaign.ci_gate {
        report.markdown = report.markdown.replacen("- CI 卡点: 通过", "- CI 卡点: 未启用", 1);
    }
    if model.is_none() {
        report.markdown.push_str(&format!("\n## 执行设置\n\n- 模式：simulator（模拟）\n- 模拟目标：{}\n- 防护参数：{}\n- CI 门槛：{}\n- CI 已启用：{}\n- 任务 ID：{}\n",
            record.target_name.replace(['\n','\r']," "),record.guard_strength,record.severity_threshold.as_str(),record.campaign.ci_gate,id));
    } else {
        report.markdown.push_str(&format!("\n## 执行设置\n\n- 模式：{}\n- 资产 ID：{}\n- 目标配置版本：{}\n- CI 门槛：{}\n- CI 已启用：{}\n- 任务 ID：{}\n",
            record.execution_mode.as_deref().unwrap_or("unknown"),
            record.campaign.target_agent_ids.first().or_else(|| record.campaign.target_mcp_ids.first())
                .map_or_else(||"<missing>".into(),ToString::to_string),
            record.target_profile_version.unwrap_or(0),record.severity_threshold.as_str(),record.campaign.ci_gate,id));
    }
    if let Some(comparison) = &record.comparison {
        report.markdown.push_str(&format!(
            "\n## 复测对比（{}）\n\n```json\n{}\n```\n",
            if model.is_none() { "模拟" } else { "真实目标" },
            serde_json::to_string_pretty(comparison)?
        ));
    }
    report.markdown.push_str(if model.is_none() {
        "\n逐用例证据及固定用例版本见本战役证据 JSON 包。模拟结果不写入风险发现或真实资产风险分。\n"
    } else {
        "\n逐用例结构化摘要、交互哈希及固定用例版本见本战役证据 JSON 包。未完成判定的用例不能用于放行。\n"
    });
    record.report = Some(report);
    state.store.campaign_complete_durable(&record).await
}

pub(super) fn remaining(record: &CampaignRecord) -> std::time::Duration {
    let seconds =
        record.campaign.created_at.offset_secs(crate::store::CAMPAIGN_TIMEOUT).since_secs(&Timestamp::now()).max(0);
    std::time::Duration::from_secs(u64::try_from(seconds).unwrap_or(0))
}
