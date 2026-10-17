//! Immutable execution inputs and atomically committed campaign evidence.
use super::*;
use agf_core::redteam::{CampaignState, RedteamCase};
use serde::{Deserialize, Serialize};

pub(crate) const CAMPAIGN_TIMEOUT: i64 = 600;
pub(crate) const CAMPAIGN_INTERRUPTED: &str = "Campaign expired or was interrupted. Retest to start a new run.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignRecord {
    pub campaign: RedteamCampaign,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_fingerprint: Option<String>,
    #[serde(default)]
    pub execution_mode: Option<String>,
    #[serde(default)]
    pub target_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_profile_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_profile_version: Option<u64>,
    #[serde(default = "default_threshold")]
    pub severity_threshold: Severity,
    #[serde(default)]
    pub guard_strength: u8,
    #[serde(default)]
    pub cases: Vec<RedteamCase>,
    #[serde(default)]
    pub results: Vec<RedteamResult>,
    #[serde(default)]
    pub report: Option<RedteamReport>,
    #[serde(default)]
    pub retest_of: Option<Id>,
    #[serde(default)]
    pub comparison: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<String>,
}

fn default_threshold() -> Severity {
    Severity::Critical
}

impl CampaignRecord {
    pub fn legacy(campaign: RedteamCampaign, results: Vec<RedteamResult>, report: Option<RedteamReport>) -> Self {
        // Historical execution mode and inputs are unknown; never retrofit simulated/live provenance.
        Self {
            campaign,
            request_fingerprint: None,
            execution_mode: None,
            target_name: String::new(),
            target_profile_id: None,
            target_profile_version: None,
            severity_threshold: default_threshold(),
            guard_strength: 0,
            cases: vec![],
            results,
            report,
            retest_of: None,
            comparison: None,
            error: None,
        }
    }

    pub fn terminal(&self) -> bool {
        matches!(self.campaign.state, CampaignState::Completed | CampaignState::Failed | CampaignState::Cancelled)
    }

    pub(crate) fn expire(&mut self) {
        if !self.terminal() && Timestamp::now() >= self.campaign.created_at.offset_secs(CAMPAIGN_TIMEOUT) {
            self.campaign.state = CampaignState::Failed;
            self.campaign.finished_at = Some(Timestamp::now());
            self.error = Some(CAMPAIGN_INTERRUPTED.into());
        }
    }

    pub fn view(&self) -> DomainResult<serde_json::Value> {
        let mut value = serde_json::to_value(&self.campaign)?;
        let complete = self.campaign.state == CampaignState::Completed;
        value["execution_mode"] = serde_json::to_value(&self.execution_mode)?;
        value["target_name"] = serde_json::to_value(&self.target_name)?;
        value["target_profile_id"] = serde_json::to_value(self.target_profile_id)?;
        value["target_profile_version"] = serde_json::to_value(self.target_profile_version)?;
        value["severity_threshold"] = serde_json::to_value(self.severity_threshold)?;
        value["guard_strength"] =
            serde_json::to_value((self.execution_mode.as_deref() == Some("simulator")).then_some(self.guard_strength))?;
        value["retest_of"] = serde_json::to_value(self.retest_of)?;
        value["comparison"] = serde_json::to_value(&self.comparison)?;
        value["error"] = serde_json::to_value(&self.error)?;
        value["ci_passed"] = serde_json::to_value(
            self.report.as_ref().filter(|_| complete && self.campaign.ci_gate).map(|r| r.ci_passed),
        )?;
        let evaluated = self.results.iter().filter(|row| row.is_evaluated()).count();
        let succeeded = self.results.iter().filter(|row| row.is_evaluated() && row.succeeded).count();
        let failed = self
            .results
            .iter()
            .filter(|row| row.evaluation == agf_core::redteam::EvaluationStatus::ExecutionError)
            .count();
        value["evaluated_cases"] = serde_json::to_value(complete.then_some(evaluated))?;
        value["failed_cases"] = serde_json::to_value(complete.then_some(failed))?;
        value["inconclusive_cases"] =
            serde_json::to_value(complete.then_some(self.results.len().saturating_sub(evaluated + failed)))?;
        // Compatibility field: this counts evaluated cases without an observed success, not proven blocking.
        value["blocked"] =
            serde_json::to_value((complete && evaluated > 0).then_some(evaluated.saturating_sub(succeeded)))?;
        value["success_rate"] = serde_json::to_value((evaluated > 0).then(|| {
            f64::from(u32::try_from(succeeded).unwrap_or(0)) / f64::from(u32::try_from(evaluated).unwrap_or(1))
        }))?;
        Ok(value)
    }
}
