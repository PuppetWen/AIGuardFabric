//! Both current revisions and a rollback bundle's original references remain real prerequisites.
use super::{
    MAX_AGENT_IDS, MAX_GUARDS,
    contract::Scope,
    input::PolicyRevision,
    records::{Fence, POLICY, Values},
    util,
};
use crate::{
    cloud_store,
    model_routes::tenant_record_id,
    policy_store::{self, TrustedPolicySelection},
    state::AppState,
};
use agf_core::{
    asset::Asset,
    error::DomainResult,
    ids::{Id, TenantId},
    policy::Policy,
};
use agf_storage::configuration::ConfigurationGuard;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn expected(revisions: &[PolicyRevision]) -> DomainResult<BTreeMap<Id, u32>> {
    let values = revisions.iter().map(|row| (row.policy_id, row.version)).collect::<BTreeMap<_, _>>();
    if values.len() != revisions.len() {
        return Err(util::corrupt());
    }
    Ok(values)
}

/// Read only the durable registry. Extracted versions are provisional until the full trusted reader verifies it.
pub(super) async fn current_versions(
    state: &AppState,
    tenant: TenantId,
    source: &[PolicyRevision],
) -> DomainResult<Vec<PolicyRevision>> {
    let payload = state.configurations.get::<Value>(tenant, POLICY, tenant_record_id(tenant)).await?;
    let mut revisions = Vec::with_capacity(source.len());
    for row in source {
        let version = payload
            .as_ref()
            .and_then(|value| value["entries"].get(row.policy_id.to_string()))
            .and_then(|value| value["version"].as_u64())
            .and_then(|version| u32::try_from(version).ok())
            .filter(|version| *version > 0)
            .ok_or_else(util::stale)?;
        revisions.push(PolicyRevision { policy_id: row.policy_id, version });
    }
    policy_store::parse_publication_snapshot(state, tenant, payload, &expected(&revisions)?)?;
    Ok(revisions)
}

pub(super) async fn prepare(
    state: &AppState,
    scope: &Scope,
    revisions: &[PolicyRevision],
    source: &[Policy],
) -> DomainResult<(TrustedPolicySelection, Fence)> {
    let tenant = scope.tenant;
    let payload = state.configurations.get::<Value>(tenant, POLICY, tenant_record_id(tenant)).await?;
    let current = policy_store::parse_publication_snapshot(state, tenant, payload, &expected(revisions)?)?;
    let selection = combined(current, source, tenant)?;
    let mut values = Values::new();
    for key in &selection.guards {
        values.insert((key.kind.to_owned(), key.id), state.configurations.get(tenant, key.kind, key.id).await?);
    }
    let mut assets = BTreeMap::new();
    for id in &selection.agent_ids {
        if let Some(asset) = state.store.asset_get_durable(tenant, *id).await? {
            assets.insert(*id, asset);
        }
    }
    let dependencies = policy_store::validate_publication_dependencies(tenant, &selection, &values, &assets)?;
    Ok((selection, Fence { policies: revisions.to_vec(), dependencies }))
}

pub(super) fn combined(
    mut current: TrustedPolicySelection,
    source: &[Policy],
    tenant: TenantId,
) -> DomainResult<TrustedPolicySelection> {
    let mut guards = current.guards.into_iter().map(|key| ((key.kind, key.id), key)).collect::<BTreeMap<_, _>>();
    let mut agents = current.agent_ids.into_iter().collect::<BTreeSet<_>>();
    for policy in source {
        if policy.tenant_id != tenant {
            return Err(util::corrupt());
        }
        if policy.quota_id.is_some() {
            let key = (crate::quota_definitions::KIND, tenant_record_id(tenant));
            guards.insert(key, ConfigurationGuard { kind: key.0, id: key.1 });
        }
        if let Some(id) = policy.degrade_endpoint_id {
            let key = (crate::model_gateway::ENDPOINT_KIND, id);
            guards.insert(key, ConfigurationGuard { kind: key.0, id: key.1 });
        }
        agents.extend(policy.scope_agent_ids.iter().copied());
    }
    if guards.len() + 2 > MAX_GUARDS || agents.len() > MAX_AGENT_IDS {
        return Err(util::capacity());
    }
    current.policies.extend_from_slice(source);
    current.guards = guards.into_values().collect();
    current.agent_ids = agents.into_iter().collect();
    Ok(current)
}

pub(super) fn guards(
    scope: Option<&Scope>,
    selection: Option<&TrustedPolicySelection>,
) -> Vec<ConfigurationGuard<'static>> {
    let mut keys = Vec::new();
    if let Some(scope) = scope {
        keys.push(ConfigurationGuard { kind: cloud_store::KIND, id: scope.target.configuration_id });
    }
    if let Some(selection) = selection {
        keys.extend(selection.guards.iter().map(|key| ConfigurationGuard { kind: key.kind, id: key.id }));
        if let Some(scope) = scope {
            keys.push(ConfigurationGuard { kind: POLICY, id: tenant_record_id(scope.tenant) });
        }
    }
    keys
}

pub(super) fn validate_locked(
    state: &AppState,
    scope: &Scope,
    fence: Option<&Fence>,
    source: &[Policy],
    values: &Values,
    assets: &BTreeMap<Id, Asset>,
) -> DomainResult<()> {
    let cloud: crate::integration_store::Stored = util::read(values, cloud_store::KIND, scope.target.configuration_id)?
        .filter(|row: &crate::integration_store::Stored| row.enabled)
        .ok_or_else(util::stale)?;
    if super::scope::from_row(state, scope.tenant, &cloud)? != *scope {
        return Err(util::stale());
    }
    if let Some(fence) = fence {
        let registry = values.get(&(POLICY.to_owned(), tenant_record_id(scope.tenant))).cloned().flatten();
        let current =
            policy_store::parse_publication_snapshot(state, scope.tenant, registry, &expected(&fence.policies)?)?;
        let selected = combined(current, source, scope.tenant)?;
        let actual = policy_store::validate_publication_dependencies(scope.tenant, &selected, values, assets)?;
        if actual != fence.dependencies {
            return Err(util::stale());
        }
        let actual_keys = selected.guards.iter().map(|key| (key.kind.to_owned(), key.id)).collect::<BTreeSet<_>>();
        if actual_keys.iter().any(|key| !values.contains_key(key)) {
            return Err(util::stale());
        }
    }
    Ok(())
}
