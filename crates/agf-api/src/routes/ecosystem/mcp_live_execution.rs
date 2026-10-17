//! Execute only the dedicated canary case against a version-pinned MCP target.
use super::*;
use crate::store::CampaignRecord;
use agf_core::{
    enums::AssetKind,
    ids::{Id, TenantId},
    redteam::RedteamCase,
};
use agf_scan::redteam::{McpHttpTarget, RedteamOutcome};

pub(super) async fn run(
    state: &AppState,
    record: &CampaignRecord,
    cases: &[&RedteamCase],
) -> Result<(Vec<RedteamOutcome>, Option<String>), DomainError> {
    let tenant = record.campaign.tenant_id;
    let id = record.target_profile_id.ok_or_else(|| DomainError::Validation("MCP target is missing".into()))?;
    let profile = super::mcp_targets::load(state, tenant, id).await?;
    if !profile.enabled
        || Some(profile.version) != record.target_profile_version
        || record.campaign.target_mcp_ids.as_slice() != [profile.asset_id]
    {
        return Err(DomainError::Conflict("MCP target changed or was disabled; no request was sent".into()));
    }
    let asset = state.store.asset_get_durable(tenant, profile.asset_id).await?;
    if !asset.is_some_and(|row| row.kind == AssetKind::McpServer && row.is_live()) {
        return Err(DomainError::NotFound { entity: "mcp-asset", id: profile.asset_id.to_string() });
    }
    let token = profile
        .secret
        .as_ref()
        .map(|material| super::agent_targets::unseal(state, tenant, id, material))
        .transpose()?;
    let canary = super::agent_targets::unseal(state, tenant, id, &profile.canary)?;
    let mut target = McpHttpTarget::new(
        profile.name,
        profile.asset_id,
        &profile.url,
        profile.tool_name.clone(),
        profile.argument_name,
        token,
        canary,
    )?;
    if let (Some(name), Some(argument)) = (&profile.detail_tool_name, &profile.detail_argument_name) {
        target = target.with_detail_tool(name.clone(), argument.clone())?;
    }
    let guard_state = state.clone();
    let campaign_id = record.campaign.id;
    let profile_version = profile.version;
    let asset_id = profile.asset_id;
    let target = target.with_request_guard(move || {
        let state = guard_state.clone();
        Box::pin(async move { ensure_active(&state, tenant, campaign_id, id, profile_version, asset_id).await })
    });
    let meter_state = state.clone();
    let target = target.with_tool_meter(move |tool| {
        let state = meter_state.clone();
        Box::pin(async move { super::mcp_tool_meter::reserve(&state, tenant, campaign_id, id, tool).await })
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
    Ok((outcomes, Some(format!("mcp-http:{}", profile.tool_name))))
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
    let profile = super::mcp_targets::load(state, tenant, profile_id).await?;
    if !profile.enabled || profile.version != version || profile.asset_id != asset_id {
        return Err(DomainError::Conflict("MCP target changed during the campaign".into()));
    }
    let asset = state.store.asset_get_durable(tenant, asset_id).await?;
    if !asset.is_some_and(|row| row.kind == AssetKind::McpServer && row.is_live()) {
        return Err(DomainError::Conflict("MCP asset was disabled during the campaign".into()));
    }
    Ok(())
}
