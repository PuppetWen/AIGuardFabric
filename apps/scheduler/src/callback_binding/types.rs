use super::identity::{Identity, Kind, digest, positive_id};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};

pub(crate) fn invalid() -> DomainError {
    DomainError::Parse("平台回调响应身份或结构无效".into())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SourceTarget {
    pub(crate) tenant: TenantId,
    pub(crate) configuration_id: Id,
    pub(crate) configuration_version: u64,
    pub(crate) scope_id: Id,
    pub(crate) fingerprint: String,
    pub(crate) region: String,
    pub(crate) rpc_origin: String,
    pub(crate) configured_account_id: Option<String>,
    pub(crate) account_identity_verified: bool,
    pub(crate) cluster_id: String,
    pub(crate) app_name: String,
    pub(crate) mocked: bool,
    pub(crate) transport_mode: String,
}
impl SourceTarget {
    pub(crate) fn check(&self, tenant: TenantId, test_loopback: bool) -> DomainResult<()> {
        if self.tenant != tenant
            || self.configuration_id.is_nil()
            || self.scope_id.is_nil()
            || self.configuration_version == 0
            || !digest(&self.fingerprint)
            || self.mocked
            || !(self.transport_mode == "live" || (test_loopback && self.transport_mode == "loopback_test"))
            || [&self.region, &self.rpc_origin, &self.cluster_id, &self.app_name]
                .iter()
                .any(|s| s.is_empty() || s.len() > 512 || s.contains('\0'))
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NativeState {
    pub(crate) tenant_id: TenantId,
    pub(crate) configured: bool,
    pub(crate) enabled: bool,
    pub(crate) source_target: Option<SourceTarget>,
    pub(crate) bindings: Binding,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Binding {
    pub(crate) version: u64,
    pub(crate) adoption_version: u64,
    pub(crate) locally_enabled: bool,
    pub(crate) source_current: bool,
    pub(crate) source_target: Option<SourceTarget>,
    pub(crate) items: Vec<Mapping>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Mapping {
    pub(crate) kind: Kind,
    pub(crate) job_id: String,
    pub(crate) eligibility: String,
    pub(crate) adopted_proof: Option<Proof>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Proof {
    pub(crate) adoption_version: u64,
    pub(crate) source_target: SourceTarget,
    pub(crate) app_id: String,
    pub(crate) job_id: String,
    pub(crate) kind: Kind,
    pub(crate) http_job: bool,
    pub(crate) enabled: bool,
}
pub(crate) struct Context {
    pub(crate) source: SourceTarget,
    pub(crate) binding_version: u64,
    pub(crate) adoption_version: u64,
}
impl NativeState {
    pub(crate) fn context(self, tenant: TenantId, identity: &Identity, test_loopback: bool) -> DomainResult<Context> {
        identity.validate()?;
        let source = self.source_target.ok_or_else(invalid)?;
        source.check(tenant, test_loopback)?;
        let binding = self.bindings;
        if self.tenant_id != tenant
            || !self.configured
            || !self.enabled
            || !binding.locally_enabled
            || !binding.source_current
            || binding.source_target.as_ref() != Some(&source)
            || binding.version == 0
            || binding.adoption_version == 0
            || binding.adoption_version > binding.version
            || binding.items.len() > 6
        {
            return Err(invalid());
        }
        let kind = identity.kind;
        let job_id = &identity.job;
        let mut matches = binding.items.into_iter().filter(|item| item.kind == kind && &item.job_id == job_id);
        let mapping = matches.next().ok_or_else(invalid)?;
        if matches.next().is_some() || mapping.eligibility != "eligible" {
            return Err(invalid());
        }
        let proof = mapping.adopted_proof.ok_or_else(invalid)?;
        if proof.source_target != source
            || proof.app_id != identity.app
            || proof.job_id != identity.job
            || proof.kind != identity.kind
            || proof.adoption_version != binding.adoption_version
            || !proof.http_job
            || !proof.enabled
        {
            return Err(invalid());
        }
        Ok(Context { source, binding_version: binding.version, adoption_version: binding.adoption_version })
    }
}

#[derive(Serialize)]
pub(crate) struct Admission<'a> {
    pub(crate) request_id: Id,
    pub(crate) kind: Kind,
    pub(crate) app_id: &'a str,
    pub(crate) job_id: &'a str,
    pub(crate) job_execution_id: &'a str,
    pub(crate) partition_index: u32,
    pub(crate) partition_total: u32,
    pub(crate) binding_version: u64,
    pub(crate) configuration_version: u64,
    pub(crate) source_fingerprint: &'a str,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Artifact {
    pub(crate) sha256: String,
    pub(crate) bytes: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Outcome {
    pub(crate) ok: bool,
    pub(crate) skipped: bool,
    pub(crate) degraded: bool,
    pub(crate) artifacts: Vec<Artifact>,
}
impl Outcome {
    pub(crate) fn check(&self) -> DomainResult<()> {
        if self.artifacts.len() > 64
            || (self.skipped && !self.artifacts.is_empty())
            || self.artifacts.iter().any(|a| !digest(&a.sha256))
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Receipt {
    pub(crate) fact_id: Id,
    pub(crate) claim_id: Id,
    pub(crate) request_id: Id,
    pub(crate) tenant_id: TenantId,
    pub(crate) kind: Kind,
    pub(crate) app_id: String,
    pub(crate) job_id: String,
    pub(crate) job_execution_id: String,
    pub(crate) partition_index: u32,
    pub(crate) partition_total: u32,
    pub(crate) binding_version: u64,
    pub(crate) adoption_version: u64,
    pub(crate) original_target: SourceTarget,
    pub(crate) submitted_at: Timestamp,
    pub(crate) start_lease_expires_at: Timestamp,
    pub(crate) started_at: Option<Timestamp>,
    pub(crate) execution_lease_expires_at: Option<Timestamp>,
    pub(crate) finished_at: Option<Timestamp>,
    pub(crate) state: String,
    pub(crate) may_confirm_start: bool,
    pub(crate) may_execute: bool,
    pub(crate) outcome: Option<Outcome>,
    pub(crate) completion_state: String,
    pub(crate) source_current: bool,
}
impl Receipt {
    pub(crate) fn check(
        &self,
        tenant: TenantId,
        identity: &Identity,
        context: &Context,
        test_loopback: bool,
    ) -> DomainResult<()> {
        self.original_target.check(tenant, test_loopback)?;
        if self.fact_id.is_nil()
            || self.claim_id.is_nil()
            || self.request_id.is_nil()
            || self.tenant_id != tenant
            || self.kind != identity.kind
            || self.app_id != identity.app
            || self.job_id != identity.job
            || !positive_id(&self.app_id)
            || !positive_id(&self.job_id)
            || self.job_execution_id != identity.execution
            || self.partition_index != identity.partition.index
            || self.partition_total != identity.partition.total
            || self.binding_version != context.binding_version
            || self.adoption_version != context.adoption_version
            || self.original_target != context.source
            || self.start_lease_expires_at < self.submitted_at
            || !matches!(self.state.as_str(), "admitted" | "running" | "succeeded" | "failed" | "uncertain")
            || !matches!(self.completion_state.as_str(), "admitted" | "pending_audit" | "complete")
        {
            return Err(invalid());
        }
        if let Some(outcome) = &self.outcome {
            outcome.check()?;
        }
        if self.may_confirm_start && (self.may_execute || self.state != "admitted" || self.started_at.is_some()) {
            return Err(invalid());
        }
        if self.started_at.is_some() != self.execution_lease_expires_at.is_some()
            || self.started_at.is_some_and(|started| {
                started < self.submitted_at
                    || started > self.start_lease_expires_at
                    || self.execution_lease_expires_at != Some(started.offset_secs(300))
            })
        {
            return Err(invalid());
        }
        if self.completion_state == "complete"
            && (self.outcome.is_none()
                || self.finished_at.is_none()
                || !matches!(self.state.as_str(), "succeeded" | "failed")
                || self.started_at.is_none())
        {
            return Err(invalid());
        }
        if self.completion_state == "complete"
            && self.outcome.as_ref().is_some_and(|outcome| outcome.ok != (self.state == "succeeded"))
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) fn same_claim(&self, original: &Self) -> bool {
        self.fact_id == original.fact_id
            && self.claim_id == original.claim_id
            && self.request_id == original.request_id
            && self.tenant_id == original.tenant_id
            && self.kind == original.kind
            && self.app_id == original.app_id
            && self.job_id == original.job_id
            && self.job_execution_id == original.job_execution_id
            && self.partition_index == original.partition_index
            && self.partition_total == original.partition_total
            && self.binding_version == original.binding_version
            && self.adoption_version == original.adoption_version
            && self.original_target == original.original_target
            && self.submitted_at == original.submitted_at
            && self.start_lease_expires_at == original.start_lease_expires_at
            && (original.started_at.is_none() || self.started_at == original.started_at)
            && (original.execution_lease_expires_at.is_none()
                || self.execution_lease_expires_at == original.execution_lease_expires_at)
            && (original.finished_at.is_none() || self.finished_at == original.finished_at)
    }
}
