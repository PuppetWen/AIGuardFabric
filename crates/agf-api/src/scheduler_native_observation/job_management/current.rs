use super::super::{authority::Submission, binding, proof, records::BindingRecord, scope, util};
use super::{
    codec,
    model::{Operation, State},
};
use crate::state::AppState;
use agf_alicloud::schedulerx3::native_observation::CurrentGuard;
use agf_core::error::DomainResult;

pub(super) struct Guard<'a> {
    pub(super) state: &'a AppState,
    pub(super) submission: &'a Submission,
    pub(super) row: &'a Operation,
}
#[async_trait::async_trait]
impl CurrentGuard for Guard<'_> {
    async fn validate(&self) -> DomainResult<()> {
        self.submission.authorize(self.state).await?;
        let tenant = self.row.tenant;
        if scope::current(self.state, tenant).await?.as_ref() != Some(&self.row.target) {
            return Err(util::stale());
        }
        let journal = codec::journal(self.state, tenant).await?;
        let Some(active) = journal.active else {
            return Err(util::stale());
        };
        if (active.request_id, active.claim_id) != (self.row.request_id, self.row.claim_id)
            || active.expires_at <= agf_core::time::Timestamp::now()
        {
            return Err(util::stale());
        }
        let row = super::views::load_operation(self.state, tenant, self.row.request_id).await?;
        if row.state != State::Started || !same_claim(&row, self.row)? {
            return Err(util::stale());
        }
        let binding: BindingRecord =
            super::super::store::get(self.state, tenant, &util::binding_key(tenant)).await?.unwrap_or_default();
        binding::validate(&binding, tenant)?;
        proof::restore(self.state, &binding, tenant)?;
        if binding.version != self.row.preview.as_ref().ok_or_else(util::corrupt)?.input.expected_binding_version {
            return Err(util::stale());
        }
        self.submission.budget()
    }
}
pub(super) fn same_claim(left: &Operation, right: &Operation) -> DomainResult<bool> {
    let normalized = |row: &Operation| -> DomainResult<serde_json::Value> {
        let mut row = row.clone();
        row.state = State::Started;
        row.finished_at = None;
        row.write = None;
        row.readback = agf_alicloud::schedulerx3::managed_jobs::Readback::Unknown;
        row.detail_bytes = 0;
        row.readback_at = None;
        row.readback_fingerprint = None;
        Ok(serde_json::to_value(row)?)
    };
    Ok(normalized(left)? == normalized(right)?)
}
pub(super) struct ReadGuard<'a> {
    pub(super) state: &'a AppState,
    pub(super) submission: &'a Submission,
    pub(super) row: &'a Operation,
}
#[async_trait::async_trait]
impl CurrentGuard for ReadGuard<'_> {
    async fn validate(&self) -> DomainResult<()> {
        self.submission.authorize(self.state).await?;
        if scope::current(self.state, self.row.tenant).await?.as_ref() != Some(&self.row.target) {
            return Err(util::stale());
        }
        self.submission.budget()
    }
}
