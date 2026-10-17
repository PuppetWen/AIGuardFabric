//! The blacklist registry and its success audit publish at one boundary.
use super::{Entry, KIND, Rules, Submission, tenant_record_id};
use crate::{AppState, policy_store::OfflinePublicationProof, store::asset_transaction::AssetTransaction};
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget},
    error::{DomainError, DomainResult},
    time::Timestamp,
};
use agf_storage::configuration::OfflineGuardedMutation;
use serde_json::json;

pub(super) enum Change {
    Add(Entry),
    Update { id: String, enabled: Option<bool>, expected_version: u64 },
}
impl Change {
    fn apply(&self, rows: &mut Rules) -> DomainResult<Entry> {
        match self {
            Self::Add(entry) => {
                if rows.rules.len() >= 2048 {
                    return Err(DomainError::Validation("最多保存 2048 条黑名单规则".into()));
                }
                rows.rules.push(entry.clone());
                Ok(entry.clone())
            }
            Self::Update { id, enabled, expected_version } => {
                let row = rows
                    .rules
                    .iter_mut()
                    .find(|row| row.rule.id == *id)
                    .ok_or_else(|| DomainError::NotFound { entity: "blacklist", id: id.clone() })?;
                if row.version != *expected_version {
                    return Err(DomainError::Conflict("黑名单已被其他人修改，请重新加载后确认".into()));
                }
                row.version =
                    row.version.checked_add(1).ok_or_else(|| DomainError::Conflict("黑名单版本已达上限".into()))?;
                row.updated_at = Timestamp::now();
                if let Some(enabled) = enabled {
                    row.enabled = *enabled;
                }
                let result = row.clone();
                if enabled.is_none() {
                    rows.rules.retain(|row| row.rule.id != *id);
                }
                Ok(result)
            }
        }
    }
    fn audit(&self, submission: &Submission, entry: &Entry) -> AuditLog {
        let message = match self {
            Self::Add(_) => "新增黑名单",
            Self::Update { enabled: Some(_), .. } => "变更黑名单启停",
            Self::Update { enabled: None, .. } => "删除黑名单",
        };
        let mut log = AppState::audit_entry(
            submission.principal.tenant,
            AuditAction::Configure,
            AuditOutcome::Success,
            AppState::audit_actor(&submission.principal, "blacklist"),
            AuditTarget::new("blacklist", Some(entry.rule.id.clone()), None),
            message,
        );
        if let Self::Update { expected_version, .. } = self {
            log.before = Some(json!({"version":expected_version}));
        }
        log.after = Some(json!({"version":entry.version,"enabled":entry.enabled,
            "deleted":matches!(self, Self::Update { enabled: None, .. })}));
        log
    }
}

pub(super) async fn execute(state: &AppState, submission: &Submission, change: Change) -> DomainResult<Entry> {
    tokio::time::timeout_at(submission.deadline, async {
        submission.authorize(state).await?;
        if state.store.database().is_some() {
            Box::pin(sql(state, submission, change)).await
        } else {
            offline(state, submission, change).await
        }
    })
    .await
    .map_err(|_| super::expired())?
}

async fn offline(state: &AppState, submission: &Submission, change: Change) -> DomainResult<Entry> {
    let authorization = submission.borrowed();
    let proof = OfflinePublicationProof::prepare(state, &authorization).await?;
    let (_, entry, _) = state.configurations.mutate_offline_guarded_audited(
        submission.principal.tenant,
        OfflineGuardedMutation {
            kind: KIND,
            id: tenant_record_id(submission.principal.tenant),
            guards: &[],
            security: Some(OfflinePublicationProof::security(&authorization)?),
        },
        |_, rows: &mut Rules| {
            let entry = change.apply(rows)?;
            let audit = change.audit(submission, &entry);
            budget(rows)?;
            Ok((entry, audit))
        },
        |audit, locked| {
            proof.check(state, &authorization, locked)?;
            submission.budget()?;
            state.store.audit_append(audit)
        },
    )?;
    Ok(entry)
}

async fn sql(state: &AppState, submission: &Submission, change: Change) -> DomainResult<Entry> {
    let tenant = submission.principal.tenant;
    let db = state.store.database().ok_or_else(|| DomainError::PreconditionFailed("缺少配置数据库".into()))?;
    let tx = AssetTransaction::begin(db, tenant).await?;
    tx.tenant_enabled().await?;
    let id = tenant_record_id(tenant);
    tx.configuration_lock(KIND, id).await?;
    let mut rows = tx.configuration::<Rules>(KIND, id).await?.unwrap_or_default();
    let entry = change.apply(&mut rows)?;
    let audit = change.audit(submission, &entry);
    budget(&rows)?;
    submission.authorize(state).await?;
    tx.configure(KIND, id, Some(serde_json::to_value(rows)?)).await?;
    tx.audit(audit).await?;
    // Recheck original JWT/session, current permissions and deadline after the audit-tail wait.
    submission.authorize(state).await?;
    submission.budget()?;
    tx.commit(&state.store).await?;
    Ok(entry)
}

fn budget(rows: &Rules) -> DomainResult<()> {
    if serde_json::to_vec(rows)?.len() > 16 * 1024 * 1024 {
        return Err(DomainError::PreconditionFailed("黑名单配置超过 16 MiB 编码预算".into()));
    }
    Ok(())
}
