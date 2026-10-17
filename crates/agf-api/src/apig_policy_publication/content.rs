//! One authenticated package binds the full baseline, signed source and exact managed intent.
use super::{
    contract::Scope,
    input::PolicyRevision,
    records::{Action, Fence, Prepared},
    util,
};
use crate::state::AppState;
use agf_alicloud::apig::policy_driver::{self as driver, ManagedLimit, Observation, PreparedUpdate};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    policy::Policy,
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Package {
    schema: u8,
    proof: Proof,
    baseline: Value,
    source_policies: Vec<Policy>,
    action: Action,
    source_publication_id: Option<Id>,
    managed_limit: ManagedLimit,
    previous_limit: u32,
    desired_limit: u32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Proof {
    pub scope: Scope,
    pub fence: Fence,
    pub state_version: u64,
    pub observation_id: Id,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub baseline_observed_at: Timestamp,
    pub acknowledge_unknown_operation_id: Option<Id>,
}
impl Proof {
    fn from_prepared(row: &Prepared) -> Self {
        Self {
            scope: row.scope.clone(),
            fence: row.fence.clone(),
            state_version: row.state_version,
            observation_id: row.observation_id,
            created_at: row.created_at,
            expires_at: row.expires_at,
            baseline_observed_at: row.baseline_observed_at,
            acknowledge_unknown_operation_id: row.acknowledge_unknown_operation_id,
        }
    }
}

pub(super) struct Content {
    pub plaintext: String,
    pub package_hash: String,
    pub update: PreparedUpdate,
    pub source_policies: Vec<Policy>,
    pub source_policy_versions: Vec<PolicyRevision>,
    pub previous_limit: u32,
    pub desired_limit: u32,
    pub managed_limit: ManagedLimit,
}

pub(super) struct Intent {
    pub action: Action,
    pub source_publication_id: Option<Id>,
    pub managed_limit: ManagedLimit,
    pub desired_limit: u32,
}

pub(super) fn generate(
    state: &AppState,
    scope: &Scope,
    baseline: &Observation,
    policies: Vec<Policy>,
    intent: Intent,
    proof: Proof,
) -> DomainResult<Content> {
    if baseline.binding() != &scope.target.binding {
        return Err(util::corrupt());
    }
    let package = Package {
        schema: 1,
        proof,
        baseline: baseline.exported_evidence(),
        source_policies: policies,
        action: intent.action,
        source_publication_id: intent.source_publication_id,
        managed_limit: intent.managed_limit,
        previous_limit: driver::current_limit(baseline, intent.managed_limit)?,
        desired_limit: intent.desired_limit,
    };
    validated(state, scope, package)
}

pub(super) fn restore(state: &AppState, tenant: TenantId, prepared: &Prepared) -> DomainResult<Content> {
    if (prepared.tenant, prepared.scope.tenant) != (tenant, tenant) || prepared.request_id.is_nil() {
        return Err(util::corrupt());
    }
    let plaintext = util::decrypt_content(
        state,
        tenant,
        body_id(tenant, prepared.request_id),
        &prepared.body,
        &prepared.body_hash,
    )?;
    if plaintext.len() != prepared.body_bytes {
        return Err(util::corrupt());
    }
    let package: Package = serde_json::from_str(&plaintext)?;
    if serde_json::to_value(&package.proof)? != serde_json::to_value(Proof::from_prepared(prepared))?
        || package.action != prepared.action
        || package.source_publication_id != prepared.source_publication_id
        || package.managed_limit != prepared.managed_limit
        || package.previous_limit != prepared.previous_limit
        || package.desired_limit != prepared.desired_limit
    {
        return Err(util::corrupt());
    }
    let content = validated(state, &prepared.scope, package)?;
    let baseline = driver::restore_evidence(
        &prepared.scope.target.binding,
        &serde_json::from_str::<Package>(&plaintext)?.baseline,
    )?;
    if baseline.fingerprint() != prepared.baseline_fingerprint
        || baseline.config_hash() != prepared.baseline_config_hash
        || content.update.desired_hash() != prepared.desired_hash
        || content.update.desired_config_bytes()? != prepared.desired_bytes
        || content.source_policy_versions != prepared.source_policy_versions
    {
        return Err(util::corrupt());
    }
    Ok(content)
}

fn validated(state: &AppState, scope: &Scope, package: Package) -> DomainResult<Content> {
    if package.schema != 1
        || package.proof.scope != *scope
        || package.source_policies.len() != 1
        || (package.action == Action::Rollback) != package.source_publication_id.is_some()
        || package.source_publication_id.is_some_and(|id| id.is_nil())
    {
        return Err(util::corrupt());
    }
    let signer = crate::policy_store::signer(state)?;
    for policy in &package.source_policies {
        if policy.tenant_id != scope.tenant
            || policy.id.is_nil()
            || policy.version == 0
            || policy.deleted_at.is_some()
            || !policy.enabled
            || policy.content_hash != policy.compute_hash()
        {
            return Err(util::corrupt());
        }
        signer.verify(policy)?;
    }
    let baseline = driver::restore_evidence(&scope.target.binding, &package.baseline)?;
    if driver::current_limit(&baseline, package.managed_limit)? != package.previous_limit {
        return Err(util::corrupt());
    }
    let update = driver::prepare_limit(&baseline, package.managed_limit, package.desired_limit)?;
    let plaintext = serde_json::to_string(&package)?;
    util::bound(&package, super::MAX_CONTENT_BYTES)?;
    let source_policy_versions =
        package.source_policies.iter().map(|row| PolicyRevision { policy_id: row.id, version: row.version }).collect();
    Ok(Content {
        package_hash: util::hash(plaintext.as_bytes()),
        plaintext,
        update,
        source_policies: package.source_policies,
        source_policy_versions,
        previous_limit: package.previous_limit,
        desired_limit: package.desired_limit,
        managed_limit: package.managed_limit,
    })
}

pub(super) fn body_id(tenant: TenantId, request: Id) -> Id {
    util::content_id(tenant, request, "intent")
}

pub(super) fn selected_quota(
    state: &AppState,
    scope: &Scope,
    selection: &crate::policy_store::TrustedPolicySelection,
    values: &super::records::Values,
) -> DomainResult<super::SourceLimit> {
    let policy = selection.policies.first().filter(|_| selection.policies.len() == 1).ok_or_else(util::corrupt)?;
    let quota_id = policy.quota_id.ok_or_else(|| DomainError::PreconditionFailed("所选来源不是quota策略".into()))?;
    let payload = values
        .get(&(crate::quota_definitions::KIND.into(), crate::model_routes::tenant_record_id(scope.tenant)))
        .cloned()
        .flatten()
        .ok_or_else(util::stale)?;
    let quota = crate::quota_definitions::parse_versioned_registry(payload, quota_id)?.ok_or_else(util::stale)?;
    super::derive_source_limit(scope.tenant, policy, &quota, &crate::policy_store::signer(state)?)
}
