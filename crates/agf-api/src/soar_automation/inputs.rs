//! Derive targets only from the selected tenant's alert, never from a text search.
use super::*;
use agf_core::case::ContainmentAction;
use agf_correlate::playbook::{RunContext, TriggerInput};

#[derive(Debug, Clone, Serialize)]
pub struct Preview {
    pub matches: bool,
    pub active: bool,
    pub requires_approval: bool,
    pub context: RunContext,
    pub steps: Vec<String>,
}

pub async fn preview(state: &AppState, tenant: TenantId, alert: &Alert, book: &Playbook) -> DomainResult<Preview> {
    workflow::validate(book)?;
    if alert.tenant_id != tenant {
        return Err(DomainError::Forbidden("告警租户不匹配".into()));
    }
    let mut context = RunContext::new(tenant, alert.severity)
        .with_alert(alert.id)
        .with_domain(alert.domain.map_or("", |domain| domain.as_str()))
        .with_param("alert_id", alert.id.to_string())
        .with_param("alert_title", alert.title.clone());
    context.asset_ids = alert.asset_ids.clone();
    context.finding_ids = alert.finding_ids.clone();
    for id in &alert.finding_ids {
        if let Some(finding) = state.store.finding_get_durable(tenant, *id).await? {
            context.rule_keys.extend(finding.rule_keys);
        }
    }
    context.rule_keys.sort();
    context.rule_keys.dedup();
    let mut kinds = Vec::new();
    for id in &alert.asset_ids {
        if let Some(asset) = state.store.asset_get_durable(tenant, *id).await? {
            kinds.push(Some(asset.kind));
        }
    }
    if kinds.is_empty() {
        kinds.push(None);
    }
    let mut matched = false;
    for kind in kinds {
        let trigger = TriggerInput {
            domain: alert.domain,
            severity: alert.severity,
            rule_keys: context.rule_keys.clone(),
            asset_kind: kind,
        };
        matched |= workflow::matches(book, &trigger, &context)?;
    }
    let targets_linked = book
        .steps
        .iter()
        .filter(|step| {
            matches!(step.action, Some(ContainmentAction::IsolateHost | ContainmentAction::DeactivateExternalUser))
        })
        .all(|step| {
            step.params
                .get("asset_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| Id::parse(value).ok())
                .is_some_and(|id| alert.asset_ids.contains(&id))
        });
    Ok(Preview {
        matches: matched && targets_linked,
        active: alert.is_active(),
        requires_approval: book.needs_human_approval(),
        context,
        steps: book.steps.iter().map(|step| step.name.clone()).collect(),
    })
}
