use super::super::{claim, scope::SourceTarget, util};
use super::{
    identity,
    input::{AdmissionInput, Outcome},
};
use agf_core::{
    credential::SecretMaterial,
    error::DomainResult,
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(in super::super) const EXECUTION: &str = "scheduler-native-callback-execution";
pub(in super::super) const BATCH: &str = "scheduler-native-callback-batch";
pub(in super::super) const PROGRESS: &str = "scheduler-native-callback-progress";
pub(in super::super) const PENDING: &str = "scheduler-native-callback-pending";
pub(in super::super) const REQUEST: &str = "scheduler-native-callback-request";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Owner {
    pub key_id: Id,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Context {
    pub tenant: TenantId,
    pub kind: String,
    pub app_id: String,
    pub job_id: String,
    pub job_execution_id: String,
    pub partition_total: u16,
    pub binding_version: u64,
    pub adoption_version: u64,
    pub target: SourceTarget,
    pub owner: Owner,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum State {
    Admitted,
    Running,
    Succeeded,
    Failed,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fact {
    pub id: Id,
    pub batch_id: Id,
    pub request_id: Id,
    pub claim_id: Id,
    pub input_hash: String,
    pub context: Context,
    pub partition_index: u16,
    pub submitted_at: Timestamp,
    pub admitted_at: Timestamp,
    pub start_expires_at: Timestamp,
    pub started_at: Option<Timestamp>,
    pub execution_expires_at: Option<Timestamp>,
    pub finished_at: Option<Timestamp>,
    pub state: State,
    pub outcome: Option<Outcome>,
    pub outcome_hash: Option<String>,
    pub seal: Option<ProgressSeal>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Terminal {
    pub ok: bool,
    pub skipped: bool,
    pub degraded: bool,
    pub outcome_hash: String,
    pub finished_at: Timestamp,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Partition {
    pub fact_id: Id,
    pub claim_id: Id,
    pub terminal: Option<Terminal>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Batch {
    pub id: Id,
    pub context: Context,
    pub admitted_at: Timestamp,
    pub partitions: BTreeMap<u16, Partition>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Progress {
    pub tenant: TenantId,
    pub kind: String,
    pub batch: Batch,
    pub seal: ProgressSeal,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProgressSeal {
    pub hash: String,
    pub secret: SecretMaterial,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RequestIndex {
    pub tenant: TenantId,
    pub request_id: Id,
    pub fact_id: Id,
    pub input_hash: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    pub tenant: TenantId,
    pub fact_id: Id,
    pub claim_id: Id,
    pub hash: String,
    pub secret: SecretMaterial,
}
impl Context {
    pub(super) fn input(&self, request_id: Id, partition_index: u16) -> AdmissionInput {
        AdmissionInput {
            request_id,
            kind: self.kind.clone(),
            app_id: self.app_id.clone(),
            job_id: self.job_id.clone(),
            job_execution_id: self.job_execution_id.clone(),
            partition_index,
            partition_total: self.partition_total,
            binding_version: self.binding_version,
            configuration_version: self.target.configuration_version,
            source_fingerprint: self.target.fingerprint.clone(),
        }
    }
    pub(super) fn validate(&self, tenant: TenantId) -> DomainResult<()> {
        self.input(self.owner.key_id, 0).validate().map_err(|_| util::corrupt())?;
        claim::validate_target(&self.target, tenant)?;
        if self.tenant != tenant
            || self.owner.key_id.is_nil()
            || self.adoption_version == 0
            || self.adoption_version > self.binding_version
            || self.target.mocked
        {
            return Err(util::corrupt());
        }
        Ok(())
    }
}
impl Fact {
    pub(super) fn validate(&self, tenant: TenantId, id: Id) -> DomainResult<()> {
        self.context.validate(tenant)?;
        let input = self.context.input(self.request_id, self.partition_index);
        if self.id != id
            || self.id != identity::fact(tenant, &input)?
            || self.batch_id != identity::batch(tenant, &input)?
            || self.claim_id.is_nil()
            || self.request_id.is_nil()
            || self.input_hash != identity::input_hash(&input)?
            || self.submitted_at > self.admitted_at
            || self.start_expires_at != self.admitted_at.offset_secs(110)
        {
            return Err(util::corrupt());
        }
        match self.state {
            State::Admitted
                if self.started_at.is_none()
                    && self.execution_expires_at.is_none()
                    && self.finished_at.is_none()
                    && self.outcome.is_none()
                    && self.outcome_hash.is_none() => {}
            State::Running | State::Succeeded | State::Failed => {
                let started = self.started_at.ok_or_else(util::corrupt)?;
                if started < self.admitted_at
                    || started >= self.start_expires_at
                    || self.execution_expires_at != Some(started.offset_secs(300))
                {
                    return Err(util::corrupt());
                }
                if self.state == State::Running {
                    if self.finished_at.is_some() || self.outcome.is_some() || self.outcome_hash.is_some() {
                        return Err(util::corrupt());
                    }
                } else {
                    let outcome = self.outcome.as_ref().ok_or_else(util::corrupt)?;
                    outcome.validate().map_err(|_| util::corrupt())?;
                    if self.finished_at.is_none_or(|at| at < started)
                        || self.outcome_hash.as_deref() != Some(identity::outcome_hash(outcome)?.as_str())
                        || (self.state == State::Succeeded) != outcome.ok
                    {
                        return Err(util::corrupt());
                    }
                }
            }
            State::Admitted => return Err(util::corrupt()),
        }
        util::bound(self, 64 * 1024)?;
        Ok(())
    }
}
impl Batch {
    pub(super) fn validate(&self, tenant: TenantId) -> DomainResult<()> {
        self.context.validate(tenant)?;
        if self.id != identity::batch(tenant, &self.context.input(self.context.owner.key_id, 0))?
            || self.partitions.len() > usize::from(self.context.partition_total)
            || !super::input::unique_ids(self.partitions.values().map(|item| item.fact_id))
            || !super::input::unique_ids(self.partitions.values().map(|item| item.claim_id))
        {
            return Err(util::corrupt());
        }
        for (index, item) in &self.partitions {
            if *index >= self.context.partition_total
                || item.claim_id.is_nil()
                || item.fact_id != identity::fact(tenant, &self.context.input(self.context.owner.key_id, *index))?
            {
                return Err(util::corrupt());
            }
            if let Some(terminal) = &item.terminal {
                if terminal.finished_at < self.admitted_at || !util::digest(&terminal.outcome_hash) {
                    return Err(util::corrupt());
                }
            }
        }
        util::bound(self, 1024 * 1024)?;
        Ok(())
    }
}
