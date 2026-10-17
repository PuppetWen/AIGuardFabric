use super::*;
use crate::{
    cloud_inventory::Snapshot,
    integration_store::{Stored, decrypt},
};
use agf_alicloud::agentteams::{orchestration::inventory_fingerprint, relations};
use agf_core::{
    agent::OnboardingMode,
    cloud::{AgentTeam, AgentTeamMember},
    ids::deterministic_id,
};

#[derive(Debug, Clone)]
pub(super) struct Current {
    pub(super) source: model::Source,
    pub(super) team: AgentTeam,
    pub(super) assets: Vec<Id>,
}
pub(super) fn capture(
    state: &AppState,
    tenant: TenantId,
    team_name: &str,
    cfg: &Stored,
    saved: &Stored,
) -> DomainResult<Current> {
    if tenant.as_uuid().is_nil()
        || team_name.is_empty()
        || team_name.len() > 256
        || team_name.trim() != team_name
        || team_name.chars().any(char::is_control)
        || cfg.id != crate::integration_store::id(tenant, crate::cloud_inventory::NAME)
        || cfg.name != crate::cloud_inventory::NAME
        || !cfg.enabled
        || cfg.version == 0
        || saved.id != cfg.id
        || saved.name != cfg.name
        || saved.version != cfg.version
    {
        return Err(denied());
    }
    // Verify the current connection AEAD as well as the encrypted inventory.
    decrypt(state, tenant, cfg)?;
    let snapshot: Snapshot =
        serde_json::from_value(decrypt(state, tenant, saved)?.settings.get("snapshot").cloned().ok_or_else(denied)?)?;
    if !(state.config.mock_mode || cfg.mock) || !snapshot.mocked || snapshot.version != cfg.version {
        return Err(denied());
    }
    let relationship = relations::parse_inventory(&snapshot.instance_id, &snapshot.teams, &snapshot.workers)?;
    relationship.require_complete()?;
    let members = relationship.teams.get(team_name).and_then(|team| team.workers.as_ref()).ok_or_else(denied)?;
    let mut agents = Vec::new();
    let mut assets = Vec::new();
    for (name, role) in members {
        if name.is_empty() || name.len() > 512 || name.trim() != name || name.chars().any(char::is_control) {
            return Err(denied());
        }
        let asset_id = *snapshot.assets.get(name).ok_or_else(denied)?;
        if asset_id.is_nil() || snapshot.assets.values().filter(|id| **id == asset_id).count() != 1 {
            return Err(denied());
        }
        assets.push(asset_id);
        agents.push(AgentTeamMember {
            cloud_agent_id: name.clone(),
            name: name.clone(),
            models: vec![],
            tools: vec![],
            role_names: role.iter().cloned().collect(),
            asset_id: Some(asset_id),
            status: "observed_membership".into(),
        });
    }
    let team = AgentTeam {
        id: deterministic_id(KIND, &format!("{tenant}/{team_name}")),
        tenant_id: tenant,
        cloud_team_id: team_name.into(),
        name: team_name.into(),
        description: String::new(),
        agents,
        roles: vec![],
        orchestration: vec![],
        onboarding: OnboardingMode::ObserveOnly,
        synced: false,
        cloud_updated_at: None,
        created_at: snapshot.checked_at,
        updated_at: snapshot.checked_at,
    };
    let source = model::Source {
        tenant,
        configuration_version: cfg.version,
        evidence_hash: hash(&(
            cfg.id,
            &cfg.name,
            cfg.version,
            cfg.enabled,
            state.config.mock_mode || cfg.mock,
            &cfg.private,
        ))?,
        region: snapshot.region,
        instance_id: snapshot.instance_id,
        inventory_fingerprint: inventory_fingerprint(&team),
    };
    Ok(Current { source, team, assets })
}
pub(super) async fn current(state: &AppState, tenant: TenantId, team: &str) -> DomainResult<Current> {
    let id = crate::integration_store::id(tenant, crate::cloud_inventory::NAME);
    let cfg = state.configurations.get::<Stored>(tenant, crate::cloud_store::KIND, id).await?.ok_or_else(denied)?;
    let saved = state.configurations.get::<Stored>(tenant, "cloud-inventory", id).await?.ok_or_else(denied)?;
    capture(state, tenant, team, &cfg, &saved)
}
pub(super) fn live_asset(tenant: TenantId, id: Id, asset: Option<&agf_core::asset::Asset>) -> DomainResult<()> {
    if asset.is_none_or(|asset| {
        asset.id != id
            || asset.tenant_id != tenant
            || asset.kind != agf_core::enums::AssetKind::Agent
            || !asset.is_live()
    }) {
        return Err(denied());
    }
    Ok(())
}
