use super::*;
use crate::store::asset_transaction::AssetTransaction;

pub(super) async fn change<F>(
    state: &AppState,
    submission: &Submission,
    key: &str,
    apply: F,
) -> DomainResult<RuleDefinition>
where
    F: FnOnce(Option<RuleDefinition>) -> DomainResult<RuleDefinition> + Send,
{
    let tenant = submission.principal.tenant;
    let db = state.store.database().ok_or_else(|| DomainError::Internal("Rule publication database missing".into()))?;
    let tx = AssetTransaction::begin(db, tenant).await?;
    tx.tenant_enabled().await?;
    tx.configuration_lock(KIND, record(tenant)).await?;
    let mut registry = tx.configuration::<Registry>(KIND, record(tenant)).await?.unwrap_or_default();
    let builtin = state.rules.rules.iter().find(|rule| rule.key == key).cloned();
    let rule = revise(&mut registry, key, builtin, submission.principal.display(), apply)?;
    let payload = serde_json::to_value(&registry)?;
    submission.authorize(state).await?;
    tx.configure(KIND, record(tenant), Some(payload)).await?;
    tx.audit(audit(submission, &rule)).await?;
    submission.authorize(state).await?;
    submission.budget()?;
    tx.commit(&state.store).await?;
    Ok(rule)
}
