//! Execute only explicitly selected, supported cases against a version-pinned Agent target.
use super::*;
use crate::store::CampaignRecord;
use agf_core::{
    enums::AssetKind,
    ids::{Id, TenantId},
    redteam::RedteamCase,
};
use agf_scan::redteam::{AgentHttpTarget, RedteamOutcome};

pub(super) async fn run(
    state: &AppState,
    record: &CampaignRecord,
    cases: &[&RedteamCase],
) -> Result<(Vec<RedteamOutcome>, Option<String>), DomainError> {
    let tenant = record.campaign.tenant_id;
    let id = record.target_profile_id.ok_or_else(|| DomainError::Validation("Agent target is missing".into()))?;
    let profile = super::agent_targets::load(state, tenant, id).await?;
    if !profile.enabled
        || Some(profile.version) != record.target_profile_version
        || record.campaign.target_agent_ids.as_slice() != [profile.asset_id]
    {
        return Err(DomainError::Conflict("Agent target changed or was disabled; no request was sent".into()));
    }
    let asset = state.store.asset_get_durable(tenant, profile.asset_id).await?;
    if !asset.is_some_and(|row| row.kind == AssetKind::Agent && row.is_live()) {
        return Err(DomainError::NotFound { entity: "agent-asset", id: profile.asset_id.to_string() });
    }
    let token = profile
        .secret
        .as_ref()
        .map(|material| super::agent_targets::unseal(state, tenant, id, material))
        .transpose()?;
    let canary = super::agent_targets::unseal(state, tenant, id, &profile.canary)?;
    let target =
        AgentHttpTarget::new(profile.name, profile.asset_id, &profile.url, profile.model.clone(), token, canary)?;
    let guard_state = state.clone();
    let campaign_id = record.campaign.id;
    let profile_version = profile.version;
    let asset_id = profile.asset_id;
    let target = target.with_request_guard(move || {
        let state = guard_state.clone();
        Box::pin(async move { ensure_active(&state, tenant, campaign_id, id, profile_version, asset_id).await })
    });
    let mut outcomes = Vec::with_capacity(cases.len());
    for case in cases {
        ensure_active(state, tenant, campaign_id, id, profile_version, asset_id).await?;
        let (_, mut observed, _) = tokio::time::timeout(
            super::campaign_execution::remaining(record),
            CampaignRunner::new().run(
                tenant,
                &record.campaign.name,
                &[*case],
                &target,
                &record.campaign.launched_by,
                record.campaign.ci_gate,
            ),
        )
        .await
        .map_err(|_| DomainError::PreconditionFailed("Campaign timed out".into()))??;
        outcomes.append(&mut observed);
    }
    Ok((outcomes, Some(profile.model)))
}

async fn ensure_active(
    state: &AppState,
    tenant: TenantId,
    campaign_id: Id,
    profile_id: Id,
    version: u64,
    asset_id: Id,
) -> Result<(), DomainError> {
    let current = state.store.campaign_get_durable(tenant, campaign_id).await?;
    if !current.is_some_and(|row| row.campaign.state == CampaignState::Running) {
        return Err(DomainError::Conflict("Campaign was cancelled or expired".into()));
    }
    let profile = super::agent_targets::load(state, tenant, profile_id).await?;
    if !profile.enabled || profile.version != version || profile.asset_id != asset_id {
        return Err(DomainError::Conflict("Agent target changed during the campaign".into()));
    }
    let asset = state.store.asset_get_durable(tenant, asset_id).await?;
    if !asset.is_some_and(|row| row.kind == AssetKind::Agent && row.is_live()) {
        return Err(DomainError::Conflict("Agent asset was disabled during the campaign".into()));
    }
    Ok(())
}
