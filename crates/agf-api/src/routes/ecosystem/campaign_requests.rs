//! Explicit campaign inputs; unsupported options cannot silently turn into simulation.
use super::*;
use crate::store::CampaignRecord;
use agf_core::{
    enums::Severity,
    ids::Id,
    redteam::{RedteamCampaign, RedteamCase},
};
use agf_scan::redteam::{AgentHttpTarget, McpHttpTarget};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignPartition {
    pub index: u32,
    pub total: u32,
}
impl CampaignPartition {
    fn owns(&self, key: &str) -> bool {
        let hash = Sha256::digest(key.as_bytes()).iter().take(8).fold(0u64, |n, b| (n << 8) | u64::from(*b));
        hash % u64::from(self.total) == u64::from(self.index)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignBody {
    pub name: String,
    #[serde(default)]
    pub scheduled: bool,
    #[serde(default)]
    pub partition: Option<CampaignPartition>,
    #[serde(default)]
    pub case_keys: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub target_name: Option<String>,
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub target_profile_id: Option<Id>,
    #[serde(default)]
    pub target_profile_version: Option<u64>,
    #[serde(default)]
    pub guard_strength: Option<u8>,
    #[serde(default)]
    pub max_cases: Option<usize>,
    #[serde(default)]
    pub ci_gate: bool,
    #[serde(default = "default_severity")]
    #[schema(value_type = String)]
    pub severity_threshold: Severity,
    #[serde(default = "simulator")]
    pub execution_mode: String,
}
fn default_severity() -> Severity {
    Severity::High
}
fn simulator() -> String {
    "simulator".into()
}

pub(super) fn prepare(
    state: &AppState,
    principal: &Principal,
    body: CampaignBody,
) -> ApiResult<Option<CampaignRecord>> {
    validate(&body)?;
    let categories = body.categories.iter().map(|s| parse_attack_category(s)).collect::<Result<Vec<_>, _>>()?;
    if body.case_keys.iter().any(|key| !state.redteam_cases.cases().iter().any(|case| case.key == *key)) {
        return Err(DomainError::Validation("One or more case keys do not exist".into()).into());
    }
    let selected = state.redteam_cases.select(&body.case_keys, &categories, &body.tags, &[]);
    let selected = selected
        .into_iter()
        .filter(|case| body.partition.as_ref().is_none_or(|p| p.owns(&case.key)))
        .collect::<Vec<_>>();
    if body.scheduled && selected.len() > body.max_cases.unwrap_or(500) {
        return Err(
            DomainError::Validation("Scheduled partition exceeds max_cases; increase the shard count".into()).into()
        );
    }
    if selected.is_empty() && body.scheduled && body.partition.is_some() {
        return Ok(None);
    }
    let cases = selected.into_iter().take(body.max_cases.unwrap_or(500)).cloned().collect::<Vec<_>>();
    if cases.is_empty() {
        return Err(DomainError::Validation("No cases match the selection".into()).into());
    }
    if cases.iter().any(|c| c.validate().is_err()) {
        return Err(DomainError::Validation("Selected case is invalid".into()).into());
    }
    if body.execution_mode == "agent-http"
        && (cases.len() != body.case_keys.len() || cases.iter().any(|case| !AgentHttpTarget::supports_case(case)))
    {
        return Err(DomainError::Validation(
            "Select at most 20 distinct Agent HTTP compatible cases; every case must have a supported oracle".into(),
        )
        .into());
    }
    if body.execution_mode == "mcp-http"
        && (cases.len() != body.case_keys.len() || cases.iter().any(|case| !McpHttpTarget::supports_case(case)))
    {
        return Err(DomainError::Validation(
            "Select only the supported MCP read-only canary cases; other tool sequences are not executable".into(),
        )
        .into());
    }
    Ok(Some(record(principal, body, cases)))
}

pub(super) fn validate(body: &CampaignBody) -> ApiResult<()> {
    if body.name.trim().is_empty()
        || body.name.len() > 200
        || !matches!(body.execution_mode.as_str(), "simulator" | "agent-http" | "mcp-http")
        || (body.execution_mode == "simulator"
            && (body.target_profile_id.is_some() || body.target_profile_version.is_some()))
        || (matches!(body.execution_mode.as_str(), "agent-http" | "mcp-http")
            && (body.target_profile_id.is_none()
                || body.target_profile_version.is_none_or(|version| version == 0)
                || body.target_name.is_some()
                || body.guard_strength.is_some()
                || body.max_cases.is_none_or(|count| count > 20)
                || body.case_keys.is_empty()
                || body.case_keys.len() > 20
                || !body.categories.is_empty()
                || !body.tags.is_empty()
                || body.partition.is_some()))
        || body.partition.as_ref().is_some_and(|p| p.total == 0 || p.total > 256 || p.index >= p.total)
        || body.guard_strength.is_some_and(|v| v > 100)
        || body.max_cases.is_some_and(|v| v == 0 || v > 500)
        || body.case_keys.len() > 500
        || body.categories.len() > 12
        || body.tags.len() > 32
        || body.case_keys.iter().chain(&body.categories).chain(&body.tags).any(|v| v.is_empty() || v.len() > 200)
        || body.target_name.as_ref().is_some_and(|v| v.trim().is_empty() || v.len() > 200)
    {
        return Err(DomainError::Validation("Use a name up to 200 bytes. Simulator accepts guard strength 0–100 and no target profile. Real Agent/MCP modes require a target ID/version, explicit supported case keys, at most 20 cases, and no simulator settings.".into()).into());
    }
    Ok(())
}

pub(super) fn record(principal: &Principal, body: CampaignBody, cases: Vec<RedteamCase>) -> CampaignRecord {
    let mut categories: Vec<_> = cases.iter().map(|c| c.category).collect();
    categories.sort_by_key(AttackCategory::as_str);
    categories.dedup();
    let campaign = RedteamCampaign {
        id: Id::new(),
        tenant_id: principal.tenant,
        name: body.name.trim().into(),
        target_agent_ids: vec![],
        target_mcp_ids: vec![],
        case_keys: cases.iter().map(|c| c.key.clone()).collect(),
        categories,
        tags: body.tags,
        state: CampaignState::Queued,
        launched_by: principal.display(),
        scheduled: body.scheduled,
        cron: None,
        ci_gate: body.ci_gate,
        total_cases: u32::try_from(cases.len()).unwrap_or(u32::MAX),
        executed_cases: 0,
        succeeded_cases: 0,
        started_at: None,
        finished_at: None,
        created_at: Timestamp::now(),
    };
    CampaignRecord {
        campaign,
        request_fingerprint: None,
        execution_mode: Some(body.execution_mode),
        target_name: body.target_name.unwrap_or_else(|| "local-simulator".into()),
        target_profile_id: body.target_profile_id,
        target_profile_version: body.target_profile_version,
        severity_threshold: body.severity_threshold,
        guard_strength: body.guard_strength.unwrap_or(30),
        cases,
        results: vec![],
        report: None,
        retest_of: None,
        comparison: None,
        error: None,
    }
}
