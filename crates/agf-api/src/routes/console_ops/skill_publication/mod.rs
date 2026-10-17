//! A reviewed Skill, its history and success audit commit before websocket publication.
use crate::{
    AppState,
    rule_store::publication::{Submission, expired},
};
use agf_asset::service::AssetBackend;
use agf_core::{
    asset::{Asset, AssetChange},
    audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget},
    error::{DomainError, DomainResult},
    ids::Id,
};
mod offline;

pub(super) async fn save<F>(
    state: &AppState,
    submission: &Submission,
    id: Id,
    action: &'static str,
    apply: F,
) -> DomainResult<Asset>
where
    F: FnOnce(Option<Asset>) -> DomainResult<(Asset, Option<AssetChange>)> + Send,
{
    tokio::time::timeout_at(submission.deadline, async {
        submission.authorize(state).await?;
        if state.store.database().is_some() {
            Box::pin(sql(state, submission, id, action, apply)).await
        } else {
            offline::save(state, submission, id, action, apply).await
        }
    })
    .await
    .map_err(|_| expired())?
}

async fn sql<F>(
    state: &AppState,
    submission: &Submission,
    id: Id,
    action: &'static str,
    apply: F,
) -> DomainResult<Asset>
where
    F: FnOnce(Option<Asset>) -> DomainResult<(Asset, Option<AssetChange>)> + Send,
{
    let tenant = submission.principal.tenant;
    let db =
        state.store.database().ok_or_else(|| DomainError::Internal("Skill publication database missing".into()))?;
    let tx = crate::store::asset_transaction::AssetTransaction::begin(db, tenant).await?;
    tx.tenant_enabled().await?;
    let current = tx.find(tenant, id).await?;
    let (asset, change) = apply(current.clone())?;
    crate::store::skill_publication_offline::validate(tenant, id, &asset, change.as_ref())?;
    let changed = change.is_some()
        || current.as_ref().map(serde_json::to_value).transpose()? != Some(serde_json::to_value(&asset)?);
    submission.authorize(state).await?;
    if changed {
        tx.upsert(tenant, &asset).await?;
        if let Some(change) = &change {
            tx.record_change(tenant, change).await?;
        }
    }
    tx.audit(audit(submission, &asset, action)).await?;
    submission.authorize(state).await?;
    let saved =
        tx.find(tenant, id).await?.ok_or_else(|| DomainError::NotFound { entity: "skill", id: id.to_string() })?;
    submission.budget()?;
    tx.commit(&state.store).await?;
    Ok(saved)
}

fn audit(submission: &Submission, asset: &Asset, action: &'static str) -> AuditLog {
    AppState::audit_entry(
        submission.principal.tenant,
        AuditAction::Update,
        AuditOutcome::Success,
        AppState::audit_actor(&submission.principal, action),
        AuditTarget::new("asset", Some(asset.id.to_string()), Some(asset.name.clone())),
        action,
    )
}
