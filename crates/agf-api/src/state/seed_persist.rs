//! Commit trusted demo tasks through the same SQL read paths used by the console.

use super::*;
use crate::store::CampaignRecord;
use agf_core::redteam::CampaignState;

impl AppState {
    /// Persist completed demo tasks after synchronous fixture construction.
    /// Pending synthetic tasks stay process-local: no worker owns them after a restart.
    pub async fn seed_durable_demo_tasks(&self) -> DomainResult<(usize, usize)> {
        if !self.store.has_database() {
            return Ok((0, 0));
        }
        let tenant = self.default_tenant;
        let mut scans = 0;
        for job in self.store.scan_list(tenant)? {
            if !job.state.is_terminal() || self.store.scan_get_durable(tenant, job.id).await?.is_some() {
                continue;
            }
            match self.store.scan_insert_durable(&job).await {
                Ok(_) => scans += 1,
                Err(DomainError::Conflict(_)) => {
                    let same =
                        self.store.scan_get_durable(tenant, job.id).await?.is_some_and(|saved| saved.name == job.name);
                    if !same {
                        return Err(DomainError::Conflict("演示扫描 ID 与现有任务冲突".into()));
                    }
                }
                Err(error) => return Err(error),
            }
        }

        let mut campaigns = 0;
        for campaign in self.store.campaign_list(tenant)? {
            if campaign.state != CampaignState::Completed {
                continue;
            }
            let mut record = CampaignRecord::legacy(
                campaign.clone(),
                self.store.campaign_results(tenant, campaign.id)?,
                self.store.campaign_report(tenant, campaign.id)?,
            );
            record.cases = self.redteam_cases.cases().to_vec();
            record.execution_mode = Some("simulator".into());
            record.target_name = "demo-offline-agent".into();
            record.guard_strength = 35;
            if self.store.campaign_seed_completed_durable(&record).await? {
                campaigns += 1;
            }
        }
        Ok((scans, campaigns))
    }
}
