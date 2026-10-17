//! Signed policy revisions, history and success audit commit together; runtime reads durable state.
use crate::{Principal, model_routes::tenant_record_id, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    policy::Policy,
    time::Timestamp,
};
use agf_runtime::{
    engine::{EngineConfig, RuntimeEngine},
    signature::PolicySigner,
};
use base64::Engine as _;

mod authenticated_rejection;
pub(crate) use authenticated_rejection::AuthenticatedRejection;
mod authority;
mod change;
mod mutation;
mod offline;
mod offline_authority;
mod publication;
mod publication_authority;
mod registry;
mod sql;
mod validation;
pub(crate) use authority::AccessLease;
pub(crate) use publication::{
    PublicationDependencyEvidence, TrustedPolicySelection, parse_publication_snapshot, publication_candidates,
    quota_publication_evidence, validate_publication_dependencies,
};
pub(crate) use publication_authority::{
    AuthorizedSubmission, Grant, OfflinePublicationProof, PublicationAuthorization, authorize_publication,
};

const KIND: &str = "signed-policy-registry";

pub fn signer(state: &AppState) -> DomainResult<PolicySigner> {
    let key = base64::engine::general_purpose::STANDARD
        .decode(&state.config.security.master_key_b64)
        .map_err(|_| DomainError::Config("策略签名需要有效的 AGF_MASTER_KEY_BASE64".into()))?;
    PolicySigner::new(key, "agf-master")
}

async fn registry(state: &AppState, tenant: TenantId) -> DomainResult<registry::Registry> {
    let signer = signer(state)?;
    if let Some(rows) = state.configurations.get::<registry::Registry>(tenant, KIND, tenant_record_id(tenant)).await? {
        rows.validate(tenant, &signer)?;
        return Ok(rows);
    }
    let original = state.store.policy_list(tenant)?;
    state
        .configurations
        .mutate::<registry::Registry, _>(tenant, KIND, tenant_record_id(tenant), |rows| {
            rows.initialize(tenant, original, &signer)
        })
        .await
}

pub async fn list(state: &AppState, tenant: TenantId) -> DomainResult<Vec<Policy>> {
    let mut rows =
        registry(state, tenant).await?.entries.into_values().filter(|row| row.deleted_at.is_none()).collect::<Vec<_>>();
    rows.sort_by_key(|row| (row.priority, row.id));
    Ok(rows)
}
pub async fn get(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Option<Policy>> {
    Ok(list(state, tenant).await?.into_iter().find(|row| row.id == id))
}
pub async fn history(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Vec<Policy>> {
    let rows = registry(state, tenant).await?;
    let mut versions = rows.history.get(&id).cloned().unwrap_or_default();
    if let Some(current) = rows.entries.get(&id) {
        versions.push(current.clone());
    }
    Ok(versions)
}

/// Trusted internal upserts keep their unconditional, same-name update contract.
pub async fn save(state: &AppState, tenant: TenantId, mut policy: Policy) -> DomainResult<Policy> {
    policy.tenant_id = tenant;
    mutation::execute(state, mutation::Submission::internal(tenant), change::Change::Save(Box::new(policy))).await
}
/// Trusted internal deletion retains its existing signature; management uses explicit CAS.
pub async fn delete(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<()> {
    mutation::execute(state, mutation::Submission::internal(tenant), change::Change::Delete { id, expected: None })
        .await?;
    Ok(())
}

pub(crate) async fn create_audited(
    state: &AppState,
    principal: &Principal,
    policy: Policy,
    submitted_at: Timestamp,
    lease: Option<AccessLease>,
) -> DomainResult<Policy> {
    mutation::execute(
        state,
        mutation::Submission::management(principal, submitted_at, lease),
        change::Change::Create(Box::new(policy)),
    )
    .await
}
pub(crate) async fn update_audited(
    state: &AppState,
    principal: &Principal,
    policy: Policy,
    expected: u64,
    submitted_at: Timestamp,
    lease: Option<AccessLease>,
) -> DomainResult<Policy> {
    mutation::execute(
        state,
        mutation::Submission::management(principal, submitted_at, lease),
        change::Change::Update { policy: Box::new(policy), expected },
    )
    .await
}
pub(crate) async fn delete_audited(
    state: &AppState,
    principal: &Principal,
    id: Id,
    expected: u64,
    submitted_at: Timestamp,
    lease: Option<AccessLease>,
) -> DomainResult<()> {
    mutation::execute(
        state,
        mutation::Submission::management(principal, submitted_at, lease),
        change::Change::Delete { id, expected: Some(expected) },
    )
    .await?;
    Ok(())
}
pub(crate) async fn restore_audited(
    state: &AppState,
    principal: &Principal,
    id: Id,
    version: u32,
    expected: u64,
    submitted_at: Timestamp,
    lease: Option<AccessLease>,
) -> DomainResult<Policy> {
    let policy = history(state, principal.tenant, id)
        .await?
        .into_iter()
        .find(|row| row.version == version)
        .ok_or_else(|| DomainError::NotFound { entity: "policy-version", id: format!("{id}/{version}") })?;
    mutation::execute(
        state,
        mutation::Submission::management(principal, submitted_at, lease),
        change::Change::Restore { policy: Box::new(policy), version, expected },
    )
    .await
}
