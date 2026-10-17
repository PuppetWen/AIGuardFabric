//! Freeze resource identity at binding time; sender payloads cannot select tenants or assets.
use crate::{cloud_inventory, cloud_store, integration_store, source_store, state::AppState};
use agf_alicloud::agentteams::relations;
use agf_core::{
    enums::IngestProtocol,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
    source::{CollectionMode, LogSource},
    time::Timestamp,
};
use agf_ingest::pipeline::AgentTeamsBindingGuard;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const KIND: &str = "agentteams-audit-source";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub asset_id: Id,
    pub teams: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Binding {
    pub version: u64,
    pub binding_id: Id,
    pub source_id: Id,
    pub scope_id: Id,
    pub cloud_version: u64,
    pub source_updated_at: Timestamp,
    pub inventory_updated_at: Timestamp,
    pub bound_at: Timestamp,
    pub enabled: bool,
    pub mocked: bool,
    pub members: BTreeMap<String, Member>,
    pub teams: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct Context {
    pub cloud: integration_store::Stored,
    pub snapshot: cloud_inventory::Snapshot,
    pub scope_id: Id,
}

pub async fn context(state: &AppState, tenant: TenantId) -> DomainResult<Option<Context>> {
    let Some(cloud) = cloud_store::load(state, tenant, cloud_inventory::NAME).await?.filter(|cfg| cfg.enabled) else {
        return Ok(None);
    };
    let Some(snapshot) = cloud_inventory::load(state, tenant).await? else {
        return Ok(None);
    };
    if snapshot.version != cloud.version || snapshot.mocked != (state.config.mock_mode || cloud.mock) {
        return Err(super::stale());
    }
    let scope_id = scope(tenant, &snapshot);
    Ok(Some(Context { cloud, snapshot, scope_id }))
}

pub(super) fn scope(tenant: TenantId, snapshot: &cloud_inventory::Snapshot) -> Id {
    let identity =
        format!("{tenant}:{}:{}:{}:{}", snapshot.version, snapshot.region, snapshot.instance_id, snapshot.mocked);
    deterministic_id("agf.agentteams.scope", &identity)
}

pub fn eligible(record: &source_store::Record) -> bool {
    record.native_receiver.is_none()
        && record
            .source
            .as_ref()
            .is_some_and(|source| source.protocol == IngestProtocol::Webhook && source.mode == CollectionMode::Push)
}

pub async fn load(state: &AppState, tenant: TenantId, source_id: Id) -> DomainResult<Option<Binding>> {
    state.configurations.get(tenant, KIND, source_id).await
}

pub fn current(binding: &Binding, context: &Context, source: &LogSource) -> bool {
    binding.enabled
        && source.enabled
        && source.protocol == IngestProtocol::Webhook
        && source.mode == CollectionMode::Push
        && binding.source_id == source.id
        && binding.cloud_version == context.cloud.version
        && binding.mocked == context.snapshot.mocked
        && binding.scope_id == context.scope_id
        && binding.source_updated_at == source.updated_at
        && binding.inventory_updated_at == context.snapshot.checked_at
        && resources(&context.snapshot)
            .is_ok_and(|resources| resources.members == binding.members && resources.teams == binding.teams)
}

pub async fn verified(
    state: &AppState,
    tenant: TenantId,
    source_id: Id,
    wanted: Id,
) -> DomainResult<(Binding, LogSource, AgentTeamsBindingGuard)> {
    if !crate::tenant_directory::get(state, tenant).await?.enabled {
        return Err(DomainError::Forbidden("租户已停用".into()));
    }
    let binding = load(state, tenant, source_id).await?.ok_or_else(super::stale)?;
    let context = context(state, tenant).await?.ok_or_else(super::stale)?;
    let record = source_store::load(state, tenant, source_id).await?;
    if !eligible(&record) {
        return Err(super::stale());
    }
    let source = record.source.ok_or_else(super::stale)?;
    if binding.binding_id != wanted || !current(&binding, &context, &source) {
        return Err(super::stale());
    }
    let guard = AgentTeamsBindingGuard {
        tenant_id: tenant,
        source_id,
        binding_id: binding.binding_id,
        binding_version: binding.version,
        cloud_config_id: context.cloud.id,
        cloud_version: binding.cloud_version,
        scope_id: binding.scope_id,
        source_updated_at: binding.source_updated_at,
        inventory_updated_at: binding.inventory_updated_at,
    };
    Ok((binding, source, guard))
}

pub fn make(context: &Context, source: &LogSource, version: u64) -> DomainResult<Binding> {
    let Resources { members, teams } = resources(&context.snapshot)?;
    Ok(Binding {
        version,
        binding_id: Id::new(),
        source_id: source.id,
        scope_id: context.scope_id,
        cloud_version: context.cloud.version,
        source_updated_at: source.updated_at,
        inventory_updated_at: context.snapshot.checked_at,
        bound_at: Timestamp::now(),
        enabled: true,
        mocked: context.snapshot.mocked,
        members,
        teams,
    })
}

pub(super) struct Resources {
    pub members: BTreeMap<String, Member>,
    pub teams: BTreeSet<String>,
}
pub(super) fn resources(snapshot: &cloud_inventory::Snapshot) -> DomainResult<Resources> {
    let relationships = relations::parse_inventory(&snapshot.instance_id, &snapshot.teams, &snapshot.workers)
        .map_err(|_| DomainError::PreconditionFailed("团队关系未验证，请重新完成云资源盘点".into()))?;
    relationships.require_complete()?;
    if !relationships.workers.iter().eq(snapshot.assets.keys()) {
        return Err(DomainError::PreconditionFailed("Worker 资产映射不完整，请重新完成云资源盘点".into()));
    }
    let mut members = BTreeMap::new();
    let teams = relationships.teams.keys().cloned().collect();
    for (name, asset_id) in &snapshot.assets {
        let membership = relationships
            .teams
            .iter()
            .filter(|(_, team)| team.workers.as_ref().is_some_and(|workers| workers.contains_key(name)))
            .map(|(name, _)| name.clone())
            .collect();
        members.insert(name.clone(), Member { asset_id: *asset_id, teams: membership });
    }
    Ok(Resources { members, teams })
}

pub async fn save(
    state: &AppState,
    principal: &crate::Principal,
    source_id: Id,
    input: super::contract::BindInput,
) -> DomainResult<Binding> {
    super::binding_write::save(state, principal, source_id, input).await
}
