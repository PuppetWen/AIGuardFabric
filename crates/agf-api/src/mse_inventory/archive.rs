//! Explicit local archival frees the bounded ledger while preserving permanent no-redispatch facts.
use super::{
    archive_store,
    contract::{ArchiveInput, Archived, Record, Run, SyncInput},
    guard, scope,
};
use crate::{Principal, state::AppState};
use agf_core::{
    audit::{AuditAction, AuditOutcome, AuditTarget},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_storage::configuration::BatchDecision;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const KIND: &str = "mse-inventory-archive";

pub(super) async fn get(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Option<Run>> {
    let value = state.configurations.get::<Archived>(tenant, KIND, id).await?;
    value.map(|archived| as_run(tenant, id, &archived)).transpose()
}
pub(super) fn as_run(tenant: TenantId, id: Id, archived: &Archived) -> DomainResult<Run> {
    if archived.run.request_id != id
        || archived.run.scope.cloud_id != crate::integration_store::id(tenant, super::NAME)
        || !terminal(&archived.run)
        || archived.run.archived
    {
        return Err(DomainError::Conflict("MSE 归档事实的身份或终态不一致；该编号不能重派".into()));
    }
    let mut run = archived.run.clone();
    run.original_status = Some(run.status.clone());
    run.status = "archived".into();
    run.archived = true;
    run.archived_at = Some(archived.archived_at);
    Ok(run)
}
pub(super) fn terminal(run: &Run) -> bool {
    run.finished_at.is_some()
        && matches!(run.status.as_str(), "succeeded" | "failed" | "cancelled" | "interrupted" | "superseded")
}
pub(super) fn archivable(row: &Record, run: &Run) -> bool {
    terminal(run) && row.active.as_ref().is_none_or(|active| active.run_id != run.request_id)
}
pub(super) async fn replay(state: &AppState, principal: &Principal, input: &SyncInput) -> DomainResult<Option<Run>> {
    let Some(run) = get(state, principal.tenant, input.request_id).await? else {
        return Ok(None);
    };
    let current = match scope::load(state, principal.tenant).await {
        Ok((_, scope)) => scope,
        Err(DomainError::PreconditionFailed(_) | DomainError::Validation(_) | DomainError::Conflict(_)) => {
            return Err(archived_conflict());
        }
        Err(error) => return Err(error),
    };
    let hash = scope::hash(&json!({"input":input,"scope":current}))?;
    if run.request_hash != hash {
        return Err(archived_conflict());
    }
    Ok(Some(run))
}
pub(super) fn archived_conflict() -> DomainError {
    DomainError::Conflict("该MSE请求编号已归档；参数或配置范围不匹配，永久禁止重派，请使用新编号".into())
}
pub(super) async fn save(state: &AppState, principal: &Principal, input: ArchiveInput) -> DomainResult<Value> {
    if input.request_ids.is_empty()
        || input.request_ids.len() > 100
        || input.request_ids.iter().any(Id::is_nil)
        || input.request_ids.iter().copied().collect::<BTreeSet<_>>().len() != input.request_ids.len()
    {
        return Err(DomainError::Validation("MSE 归档需1至100个唯一非空UUID".into()));
    }
    let submitted_at = Timestamp::now();
    guard::authorize(state, principal, submitted_at).await?;
    let row=archive_store::mutate(state,principal,None,&input.request_ids,submitted_at,|row,existing| {
        if row.generation!=input.expected_generation {return Err(DomainError::Conflict("MSE 请求台账已变化；请重新读取再明确归档".into()));}
        let mut related=BTreeMap::new();
        let now=Timestamp::now();
        for id in &input.request_ids {
            if let Some(archived)=existing.get(id).and_then(Option::as_ref) {
                as_run(principal.tenant,*id,archived)?;
                if row.runs.contains_key(id) {return Err(archived_conflict());}
                continue;
            }
            let run=row.runs.get(id).ok_or_else(||DomainError::NotFound{entity:"MSE inventory run",id:id.to_string()})?;
            if !archivable(row,run) {return Err(DomainError::PreconditionFailed("仅可归档已结束且非active的请求；租约过期的running请求须先显式取消".into()));}
            related.insert(*id,serde_json::to_value(Archived{run:run.clone(),archived_at:now})?);
        }
        if related.is_empty() {return Ok(BatchDecision::Unchanged);}
        let count=related.len() as u64;
        row.generation=row.generation.checked_add(1).ok_or_else(scope::stale)?;
        row.archived_count=row.archived_count.checked_add(count).ok_or_else(scope::stale)?;
        for id in related.keys() {row.runs.remove(id);}
        let mut audit=crate::AppState::audit_entry(principal.tenant,AuditAction::Update,AuditOutcome::Success,
            crate::AppState::audit_actor(principal,"mse-inventory-archive"),
            AuditTarget::new("mse-inventory",Some(crate::integration_store::id(principal.tenant,super::NAME).to_string()),None),
            "显式归档已结束MSE请求；保留永久领取事实、当前快照和资产");
        audit.after=Some(json!({"generation":row.generation,"archived_count":row.archived_count,"request_ids":related.keys().collect::<Vec<_>>() }));
        Ok(BatchDecision::Write{related,audit:Some(Box::new(audit))})
    }).await?;
    Ok(json!({"generation":row.generation,"archivedCount":row.archived_count,"archivedRequestIds":input.request_ids}))
}
