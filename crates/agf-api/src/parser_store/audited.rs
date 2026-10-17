//! API revisions publish only when their success audit can be appended.
use super::*;
use crate::Principal;
use agf_core::audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget};
use agf_storage::configuration::AuditedMutation;

pub async fn save_audited(
    state: &AppState,
    principal: &Principal,
    id: Option<Id>,
    input: Input,
    action: AuditAction,
) -> DomainResult<Record> {
    let (stable_id, input) = prepare(state, id, input).await?;
    let audit = entry(principal, stable_id, input.definition.name.clone(), action);
    let (row, sealed) = state
        .configurations
        .mutate_bounded_audited_with(
            principal.tenant,
            KIND,
            stable_id,
            AuditedMutation { limit: None, audit },
            |row| revise(row, principal.tenant, id, stable_id, input),
            |audit| state.store.audit_append(audit).map(Some),
        )
        .await?;
    refresh_projection(state, sealed);
    Ok(row)
}

pub async fn delete_audited(
    state: &AppState,
    principal: &Principal,
    id: Id,
    expected_version: u32,
) -> DomainResult<()> {
    let prior = custom(state, principal.tenant, id).await?;
    let current = prior.current.as_ref().ok_or_else(|| missing(id))?;
    let audit = entry(principal, id, current.parser.definition.name.clone(), AuditAction::Delete);
    let (_, sealed) = state
        .configurations
        .mutate_bounded_audited_with::<Record, _, _>(
            principal.tenant,
            KIND,
            id,
            AuditedMutation { limit: None, audit },
            |row| {
                let current = row.current.as_ref().filter(|_| !row.deleted).ok_or_else(|| missing(id))?;
                if current.parser.definition.version != expected_version {
                    return Err(DomainError::Conflict("模板版本已变更，请重新加载".into()));
                }
                row.deleted = true;
                Ok(())
            },
            |audit| state.store.audit_append(audit).map(Some),
        )
        .await?;
    refresh_projection(state, sealed);
    Ok(())
}

fn entry(principal: &Principal, id: Id, name: String, action: AuditAction) -> AuditLog {
    AppState::audit_entry(
        principal.tenant,
        action,
        AuditOutcome::Success,
        AppState::audit_actor(principal, "parser"),
        AuditTarget::new("parser", Some(id.to_string()), Some(name)),
        "解析模板配置已变更",
    )
}

fn refresh_projection(state: &AppState, sealed: Option<AuditLog>) {
    // Offline audits were already appended by the synchronous callback, without a second append.
    if state.store.database().is_some() {
        if let Some(sealed) = sealed {
            if let Err(error) = state.store.hydrate_audit(&sealed) {
                tracing::warn!(%error, "已提交的解析模板审计内存投影刷新失败");
            }
        }
    }
}
