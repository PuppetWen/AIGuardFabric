//! Turn evaluated live red-team hits into reviewable findings without storing target secrets.
use super::*;
use agf_core::{enums::EvidenceLevel, ids::deterministic_id, risk::Evidence};
use sha2::{Digest, Sha256};

pub(super) fn prepare(record: &mut CampaignRecord) -> DomainResult<Vec<Finding>> {
    let Some(mode @ ("agent-http" | "mcp-http")) = record.execution_mode.as_deref() else {
        if record.results.iter().any(|result| result.finding_id.is_some()) {
            return Err(DomainError::Validation("Simulated results cannot link to a real finding".into()));
        }
        return Ok(Vec::new());
    };
    let assets = if mode == "agent-http" { &record.campaign.target_agent_ids } else { &record.campaign.target_mcp_ids };
    let mut findings = Vec::new();
    for result in &mut record.results {
        let observable = result.succeeded
            && result.is_evaluated()
            && !result.mocked
            && result.evidence_level >= EvidenceLevel::Partial;
        if !observable {
            if result.finding_id.is_some() {
                return Err(DomainError::Validation("Unobserved result cannot link to a finding".into()));
            }
            continue;
        }
        let case = record
            .cases
            .iter()
            .find(|case| case.key == result.case_key)
            .ok_or_else(|| DomainError::Validation("Red-team result has no case snapshot".into()))?;
        if result.category != case.category
            || !assets.contains(&result.target_asset_id)
            || result.evidence_refs.is_empty()
        {
            return Err(DomainError::Validation("Red-team result has mismatched evidence or asset".into()));
        }
        let id = deterministic_id(
            "agf.redteam-finding",
            &format!("{}:{}:{}", record.campaign.tenant_id, record.campaign.id, case.key),
        );
        if result.finding_id.is_some_and(|existing| existing != id) {
            return Err(DomainError::Validation("Red-team finding ID does not match the result".into()));
        }
        let mut finding = Finding::new(
            record.campaign.tenant_id,
            case.category.domain(),
            case.severity,
            format!("asset:{}", result.target_asset_id),
            format!("红队命中：{}", case.title),
            "真实目标响应命中了本用例的受保护哨兵；需审核其来源、暴露范围及复现证据。",
            &case.remediation,
        );
        finding.id = id;
        finding.asset_id = Some(result.target_asset_id);
        finding.category = case.category.as_str().into();
        finding.source_origin = "redteam-observed".into();
        finding.evidence_level = result.evidence_level;
        finding.evidence_refs.clone_from(&result.evidence_refs);
        finding.description = format!(
            "战役 {} 的用例 {} 在 {} 目标上命中；原始请求、响应和哨兵不写入发现。请从战役证据包核对交互哈希。",
            record.campaign.id, case.key, mode
        );
        finding.confidence = 0.8;
        let evidence_summary = serde_json::json!({
            "campaign_id":record.campaign.id,
            "result_id":result.id,
            "case_key":case.key,
            "asset_id":result.target_asset_id,
            "signals":result.matched_signals,
            "evidence_refs":result.evidence_refs,
        });
        let digest = Sha256::digest(serde_json::to_vec(&evidence_summary)?);
        finding.evidence.push(Evidence::new(
            "EV-REDTEAM-1",
            if mode == "agent-http" { "model-output" } else { "tool-output" },
            "真实目标交互的脱敏摘要；原始内容仅以战役证据哈希核对。",
            hex::encode(digest),
        ));
        result.finding_id = Some(id);
        findings.push(finding);
    }
    Ok(findings)
}
