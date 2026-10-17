//! Short transactions protect resource state, its indexes and the audit chain.
use super::{
    KIND, PREVIEWS, RUNS, context,
    contract::{Operation, Preview, Record, Scope},
};
use crate::{
    Principal, cloud_store, integration_store::Stored, state::AppState, store::asset_transaction::AssetTransaction,
};
use agf_core::{
    audit::{AuditAction, AuditOutcome, AuditTarget},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
};

type OfflineLocks = Mutex<BTreeMap<TenantId, Arc<tokio::sync::Mutex<()>>>>;
static OFFLINE_LOCKS: OnceLock<OfflineLocks> = OnceLock::new();
fn offline_lock(tenant: TenantId) -> DomainResult<Arc<tokio::sync::Mutex<()>>> {
    let mut rows = OFFLINE_LOCKS
        .get_or_init(Mutex::default)
        .lock()
        .map_err(|_| DomainError::Internal("团队内存锁不可用".into()))?;
    Ok(rows.entry(tenant).or_default().clone())
}

pub(super) async fn list(state: &AppState, tenant: TenantId) -> DomainResult<Vec<Record>> {
    state.configurations.list(tenant, KIND).await
}
pub(super) async fn get(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Record> {
    Ok(state.configurations.get(tenant, KIND, id).await?.unwrap_or_default())
}
pub(super) async fn preview(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Preview> {
    for row in list(state, tenant).await? {
        if let Some(value) = row.previews.get(&id) {
            return Ok(value.clone());
        }
    }
    Err(DomainError::NotFound { entity: "team preview", id: id.to_string() })
}
pub(super) async fn operation(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Operation> {
    for row in list(state, tenant).await? {
        if let Some(value) = row.operations.get(&id) {
            return Ok(value.clone());
        }
    }
    Err(DomainError::NotFound { entity: "team operation", id: id.to_string() })
}
pub(super) fn idle(row: &Record) -> DomainResult<()> {
    if row.active.as_ref().is_some_and(|lease| lease.expires_at > Timestamp::now()) {
        return Err(DomainError::Conflict("该团队已有操作进行中，请刷新回执".into()));
    }
    Ok(())
}
pub(super) fn owns(row: &Record, id: Id, claim: Id) -> DomainResult<()> {
    if row
        .active
        .as_ref()
        .is_none_or(|lease| lease.run != id || lease.claim != claim || lease.expires_at <= Timestamp::now())
    {
        return Err(DomainError::Conflict("操作租约失效，禁止继续发送变更；请重新观察".into()));
    }
    Ok(())
}
pub(super) fn bounded(row: &Record) -> DomainResult<()> {
    if row.previews.len() > 100 || row.operations.len() > 100 || serde_json::to_vec(row)?.len() > 1_900_000 {
        return Err(DomainError::PreconditionFailed(
            "该团队操作台账已达容量上限，请导出归档后联系管理员；已有回执保留".into(),
        ));
    }
    Ok(())
}
pub(super) async fn guard(tx: &AssetTransaction<'_>, scope: &Scope) -> DomainResult<()> {
    tx.tenant_enabled().await?;
    let current = tx.configuration::<Stored>(cloud_store::KIND, scope.cloud_id).await?;
    if current.is_none_or(|cfg| !cfg.enabled || cfg.version != scope.configuration_version) {
        return Err(super::stale());
    }
    let snapshot = tx.configuration::<Stored>("cloud-inventory", scope.cloud_id).await?;
    if snapshot.is_none_or(|row| row.updated_at != scope.inventory_at || row.version != scope.configuration_version) {
        return Err(super::stale());
    }
    Ok(())
}
pub(super) async fn save_indexes(tx: &AssetTransaction<'_>, row: &Record) -> DomainResult<()> {
    for preview in row.previews.values() {
        if tx.configuration::<Preview>(PREVIEWS, preview.id).await?.is_some_and(|old| {
            let different_team = old.record_id != row.id;
            let different_content = old.request_hash != preview.request_hash;
            different_team || different_content
        }) {
            return Err(DomainError::Conflict("同一预览请求编号不能用于不同团队或内容".into()));
        }
        tx.configure(PREVIEWS, preview.id, Some(serde_json::to_value(preview)?)).await?;
    }
    for operation in row.operations.values() {
        if tx.configuration::<Operation>(RUNS, operation.id).await?.is_some_and(|old| {
            let different_team = old.record_id != row.id;
            let different_content = old.request_hash != operation.request_hash;
            different_team || different_content
        }) {
            return Err(DomainError::Conflict("同一确认请求编号不能用于不同团队或内容".into()));
        }
        tx.configure(RUNS, operation.id, Some(serde_json::to_value(operation)?)).await?;
    }
    tx.configure(KIND, row.id, Some(serde_json::to_value(row)?)).await
}
pub(super) async fn modify<F>(
    state: &AppState,
    principal: &Principal,
    scope: &Scope,
    team: &str,
    note: &str,
    apply: F,
) -> DomainResult<Record>
where
    F: FnOnce(&mut Record) -> DomainResult<()> + Send,
{
    let tenant = principal.tenant;
    let id = context::record_id(tenant, scope, team)?;
    let audit = AppState::audit_entry(
        tenant,
        AuditAction::Configure,
        AuditOutcome::Success,
        AppState::audit_actor(principal, "agentteams-team-management"),
        AuditTarget::new(KIND, Some(id.to_string()), None),
        note,
    );
    if let Some(db) = state.store.database() {
        let tx = AssetTransaction::begin(db, tenant).await?;
        guard(&tx, scope).await?;
        tx.configuration_lock(KIND, id).await?;
        let mut row = tx.configuration::<Record>(KIND, id).await?.unwrap_or_default();
        row.id = id;
        row.team_name = team.into();
        apply(&mut row)?;
        bounded(&row)?;
        save_indexes(&tx, &row).await?;
        tx.audit(audit).await?;
        tx.commit(&state.store).await?;
        return Ok(row);
    }
    // Offline mode is explicitly one process. A tenant lock includes the global request lookup.
    let lock = offline_lock(tenant)?;
    let _guard = lock.lock().await;
    let current = context::load(state, tenant).await?;
    if !context::same_scope(scope, &current.scope) || scope.inventory_at != current.scope.inventory_at {
        return Err(super::stale());
    }
    let previous = get(state, tenant, id).await?;
    let mut candidate = previous.clone();
    candidate.id = id;
    candidate.team_name = team.into();
    apply(&mut candidate)?;
    bounded(&candidate)?;
    for other in list(state, tenant).await?.iter().filter(|row| row.id != id) {
        if candidate.previews.keys().any(|key| other.previews.contains_key(key))
            || candidate.operations.keys().any(|key| other.operations.contains_key(key))
        {
            return Err(DomainError::Conflict("同一请求编号不能跨团队复用".into()));
        }
    }
    let (row, _) = state
        .configurations
        .mutate_audited(tenant, KIND, id, audit.clone(), |row: &mut Record| {
            if serde_json::to_value(&*row)? != serde_json::to_value(&previous)? {
                return Err(super::stale());
            }
            *row = candidate;
            Ok(())
        })
        .await?;
    state.store.audit_append_durable(audit).await?;
    Ok(row)
}
