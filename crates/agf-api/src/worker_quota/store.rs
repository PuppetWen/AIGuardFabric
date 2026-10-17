//! Short publication transactions only; never keep resource locks while calling the cloud.
use super::{
    context::Resolved,
    contract::{Binding, Operation},
};
use crate::{Principal, integration_store::Stored, state::AppState};
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget},
    error::{DomainError, DomainResult},
    ids::Id,
};
use agf_storage::{AuditRepo, TenantTransaction};
use serde_json::Value;

pub(super) fn audit(principal: &Principal, asset: Id, note: &str, success: bool) -> AuditLog {
    AppState::audit_entry(
        principal.tenant,
        AuditAction::Configure,
        if success { AuditOutcome::Success } else { AuditOutcome::Failure },
        AppState::audit_actor(principal, "agentteams-worker-quota"),
        AuditTarget::new(super::KIND, Some(asset.to_string()), None),
        note,
    )
}

pub(super) struct Commit<'a> {
    pub asset: Id,
    pub expected: u64,
    pub resolved: Option<&'a Resolved>,
    pub audit: AuditLog,
    pub operation: Option<&'a Operation>,
}

pub(super) async fn modify<F>(
    state: &AppState,
    principal: &Principal,
    commit: Commit<'_>,
    apply: F,
) -> DomainResult<Binding>
where
    F: FnOnce(&mut Binding) -> DomainResult<()> + Send,
{
    let Commit { asset, expected, resolved, audit, operation } = commit;
    let tenant = principal.tenant;
    if let Some(db) = state.store.database() {
        let mut tx = db.db().begin_tenant(tenant).await?;
        let enabled: bool =
            sqlx::query_scalar("SELECT agf_agentteams_lock_tenant()").fetch_one(&mut *tx).await.map_err(sql_error)?;
        if !enabled {
            return Err(DomainError::Forbidden("租户已停用".into()));
        }
        if let Some(resolved) = resolved {
            check_resources(&mut tx, resolved).await?;
        }
        lock(&mut tx, super::KIND, asset).await?;
        let mut row: Binding = configuration(&mut tx, super::KIND, asset, true)
            .await?
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default();
        if row.version != expected {
            return Err(super::stale());
        }
        apply(&mut row)?;
        let changed_alert = if let Some(resolved) = resolved {
            super::alerts::sql(&mut tx, &mut row, resolved, operation).await?
        } else {
            None
        };
        if let Some(operation) = operation {
            lock(&mut tx, super::RUNS, operation.id).await?;
            sqlx::query(
                "INSERT INTO console_configurations(tenant_id,kind,id,payload) VALUES($1,$2,$3,$4)
                ON CONFLICT(tenant_id,kind,id) DO UPDATE SET payload=excluded.payload,updated_at=now(),deleted_at=NULL",
            )
            .bind(tenant.as_uuid())
            .bind(super::RUNS)
            .bind(operation.id.as_uuid())
            .bind(serde_json::to_value(operation)?)
            .execute(&mut *tx)
            .await
            .map_err(sql_error)?;
        }
        sqlx::query(
            "INSERT INTO console_configurations(tenant_id,kind,id,payload) VALUES($1,$2,$3,$4)
            ON CONFLICT(tenant_id,kind,id) DO UPDATE SET payload=excluded.payload,updated_at=now(),deleted_at=NULL",
        )
        .bind(tenant.as_uuid())
        .bind(super::KIND)
        .bind(asset.as_uuid())
        .bind(serde_json::to_value(&row)?)
        .execute(&mut *tx)
        .await
        .map_err(sql_error)?;
        let sealed = AuditRepo::append_log(&mut tx, audit).await?;
        tx.commit().await?;
        if let Some(alert) = changed_alert {
            if let Err(error) = state.store.hydrate_alert(&alert) {
                tracing::warn!(%error,"Committed Worker quota alert cache refresh failed");
            }
        }
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(%error, "Committed Worker quota audit cache refresh failed");
        }
        return Ok(row);
    }
    // Explicit single-process offline mode; it cannot promise cross-store durable transactions.
    if !crate::tenant_directory::get(state, tenant).await?.enabled {
        return Err(DomainError::Forbidden("租户已停用".into()));
    }
    if let Some(resolved) = resolved {
        let fresh = super::context::resolve(state, tenant, asset, resolved.quota.quota.id).await?;
        if fresh.cloud.cloud.version != resolved.cloud.cloud.version
            || fresh.cloud.scope_id != resolved.cloud.scope_id
            || fresh.cloud.snapshot.checked_at != resolved.cloud.snapshot.checked_at
            || fresh.quota.version != resolved.quota.version
        {
            return Err(super::stale());
        }
    }
    let (saved, _) = state
        .configurations
        .mutate_audited::<Binding, _>(tenant, super::KIND, asset, audit.clone(), |row| {
            if row.version != expected {
                return Err(super::stale());
            }
            apply(row)?;
            if let Some(resolved) = resolved {
                super::alerts::memory(state, tenant, row, resolved, operation)?;
            }
            Ok(())
        })
        .await?;
    state.store.audit_append_durable(audit).await?;
    if let Some(operation) = operation {
        state.configurations.put(tenant, super::RUNS, operation.id, operation).await?;
    }
    Ok(saved)
}

async fn check_resources(tx: &mut TenantTransaction<'_>, resolved: &Resolved) -> DomainResult<()> {
    let cloud: Stored = configuration(tx, crate::cloud_store::KIND, resolved.cloud.cloud.id, false)
        .await?
        .map(serde_json::from_value)
        .transpose()?
        .ok_or_else(super::stale)?;
    if !cloud.enabled || cloud.version != resolved.cloud.cloud.version {
        return Err(super::stale());
    }
    let inventory: Stored = configuration(tx, "cloud-inventory", cloud.id, false)
        .await?
        .map(serde_json::from_value)
        .transpose()?
        .ok_or_else(super::stale)?;
    if inventory.version != cloud.version || inventory.updated_at != resolved.cloud.snapshot.checked_at {
        return Err(super::stale());
    }
    let registry_id = crate::model_routes::tenant_record_id(tx.tenant());
    lock(tx, crate::quota_definitions::KIND, registry_id).await?;
    let payload =
        configuration(tx, crate::quota_definitions::KIND, registry_id, false).await?.ok_or_else(super::stale)?;
    let quota = crate::quota_definitions::parse_versioned_registry(payload, resolved.quota.quota.id)?
        .ok_or_else(super::stale)?;
    if quota.version != resolved.quota.version || !super::context::supported(&quota, resolved.asset) {
        return Err(super::stale());
    }
    let asset: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT id FROM assets WHERE id=$1 AND kind='agent' AND deleted_at IS NULL
         AND lifecycle IN ('trial','production') FOR SHARE",
    )
    .bind(resolved.asset.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map_err(sql_error)?;
    if asset.is_none() {
        return Err(super::stale());
    }
    Ok(())
}

async fn lock(tx: &mut TenantTransaction<'_>, kind: &str, id: Id) -> DomainResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("{}:{kind}:{id}", tx.tenant()))
        .execute(&mut **tx)
        .await
        .map_err(sql_error)?;
    Ok(())
}

async fn configuration(tx: &mut TenantTransaction<'_>, kind: &str, id: Id, write: bool) -> DomainResult<Option<Value>> {
    let sql = if write {
        "SELECT payload FROM console_configurations WHERE kind=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE"
    } else {
        "SELECT payload FROM console_configurations WHERE kind=$1 AND id=$2 AND deleted_at IS NULL FOR SHARE"
    };
    sqlx::query_scalar(sql).bind(kind).bind(id.as_uuid()).fetch_optional(&mut **tx).await.map_err(sql_error)
}

fn sql_error(error: sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("agentteams_worker_quota", &error)
}
