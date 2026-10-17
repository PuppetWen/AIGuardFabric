//! Snapshot the case inputs used for a reviewed playbook; later edits cannot change its targets.
use super::*;

pub(super) async fn context(state: &AppState, tenant: TenantId, case: &Case) -> ApiResult<(TriggerInput, RunContext)> {
    let domain = first_finding_domain(state, tenant, case).await?.unwrap_or_default();
    let mut trigger = TriggerInput::new(case.severity);
    if let Ok(parsed) = agf_core::enums::RiskDomain::parse(&domain) {
        trigger = trigger.with_domain(parsed);
    }
    if let Some(asset) = case.asset_ids.first() {
        if let Some(asset) = state.store.asset_get_durable(tenant, *asset).await? {
            trigger = trigger.with_asset_kind(asset.kind);
        }
    }
    let mut ctx = RunContext::new(tenant, case.severity).with_case(case.id).with_domain(domain);
    for asset_id in &case.asset_ids {
        ctx = ctx.with_asset(*asset_id);
    }
    ctx.rule_keys = case.tags.clone();
    for id in &case.finding_ids {
        if let Some(finding) = state.store.finding_get_durable(tenant, *id).await? {
            ctx.rule_keys.extend(finding.rule_keys);
        }
    }
    ctx.rule_keys.sort();
    ctx.rule_keys.dedup();
    trigger.rule_keys = ctx.rule_keys.clone();
    ctx.finding_ids = case.finding_ids.clone();
    ctx.alert_id = case.alert_ids.first().copied();
    ctx = ctx.with_param("case_code", case.code.clone()).with_param("case_state", case.state.as_str());
    if let Some(owner) = &case.owner {
        ctx = ctx.with_param("owner", owner.clone());
    }
    if let Some(alert) = ctx.alert_id {
        ctx = ctx.with_param("alert_id", alert.to_string());
    }
    Ok((trigger, ctx))
}
