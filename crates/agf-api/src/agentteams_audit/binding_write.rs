//! Bind configuration and its audit atomically while resource revision locks are held.
use super::{
    binding::{self, Binding, Context, KIND},
    contract::BindInput,
};
use crate::{Principal, source_store, state::AppState};
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget},
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};
use agf_storage::{AuditRepo, TenantTransaction};
use serde_json::Value;

pub(super) async fn save(
    state: &AppState,
    principal: &Principal,
    source_id: Id,
    input: BindInput,
) -> DomainResult<Binding> {
    let tenant = principal.tenant;
    if !crate::tenant_directory::get(state, tenant).await?.enabled {
        return Err(DomainError::Forbidden("租户已停用".into()));
    }
    let record = source_store::load(state, tenant, source_id).await?;
    let source = record.source.as_ref().ok_or_else(super::stale)?;
    let context = if input.enabled {
        if !binding::eligible(&record) || !source.enabled {
            return Err(DomainError::PreconditionFailed("请选择已启用的 API Webhook 日志源".into()));
        }
        Some(
            binding::context(state, tenant)
                .await?
                .ok_or_else(|| DomainError::PreconditionFailed("请先启用 AgentTeams 连接并完成资源盘点".into()))?,
        )
    } else {
        None
    };
    let replacement = context.as_ref().map(|ctx| binding::make(ctx, source, 0)).transpose()?;
    let audit = audit(principal, source_id, input.enabled);
    if let Some(db) = state.store.database() {
        let mut tx = db.db().begin_tenant(tenant).await?;
        let enabled: bool =
            sqlx::query_scalar("SELECT agf_agentteams_lock_tenant()").fetch_one(&mut *tx).await.map_err(sql_error)?;
        if !enabled {
            return Err(DomainError::Forbidden("租户已停用".into()));
        }
        if let Some(context) = &context {
            check_context(&mut tx, context, source_id, source.updated_at).await?;
        }
        // Serialize creation too, when there is no binding row to lock yet.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("{tenant}:{KIND}:{source_id}"))
            .execute(&mut *tx)
            .await
            .map_err(sql_error)?;
        let previous = configuration(&mut tx, KIND, source_id, true)
            .await?
            .map(serde_json::from_value::<Binding>)
            .transpose()?
            .unwrap_or_default();
        let saved = revision(previous, replacement, input)?;
        sqlx::query(
            "INSERT INTO console_configurations(tenant_id,kind,id,payload) VALUES($1,$2,$3,$4)
            ON CONFLICT(tenant_id,kind,id) DO UPDATE SET payload=excluded.payload,updated_at=now(),deleted_at=NULL",
        )
        .bind(tenant.as_uuid())
        .bind(KIND)
        .bind(source_id.as_uuid())
        .bind(serde_json::to_value(&saved)?)
        .execute(&mut *tx)
        .await
        .map_err(sql_error)?;
        let sealed = AuditRepo::append_log(&mut tx, audit).await?;
        tx.commit().await?;
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(%error, "Binding audit cache refresh failed");
        }
        return Ok(saved);
    }
    // Explicit offline mode has process-local configuration and no cross-process durability.
    let (saved, _) = state
        .configurations
        .mutate_audited::<Binding, _>(tenant, KIND, source_id, audit.clone(), |row| {
            *row = revision(row.clone(), replacement, input)?;
            Ok(())
        })
        .await?;
    state.store.audit_append_durable(audit).await?;
    Ok(saved)
}

fn revision(previous: Binding, replacement: Option<Binding>, input: BindInput) -> DomainResult<Binding> {
    if previous.version != input.expected_version {
        return Err(DomainError::Conflict("绑定版本已改变，请刷新后重试".into()));
    }
    if !input.enabled && previous.version == 0 {
        return Err(DomainError::PreconditionFailed("该日志源尚未绑定".into()));
    }
    let mut saved = replacement.unwrap_or(previous);
    saved.version = input.expected_version.checked_add(1).ok_or_else(super::stale)?;
    saved.enabled = input.enabled;
    Ok(saved)
}

async fn check_context(
    tx: &mut TenantTransaction<'_>,
    context: &Context,
    source: Id,
    updated_at: Timestamp,
) -> DomainResult<()> {
    let cloud = configuration(tx, crate::cloud_store::KIND, context.cloud.id, false).await?.ok_or_else(super::stale)?;
    if cloud["version"].as_u64() != Some(context.cloud.version) || cloud["enabled"] != true {
        return Err(super::stale());
    }
    let row = configuration(tx, source_store::KIND, source, false).await?.ok_or_else(super::stale)?;
    let record: source_store::Record = serde_json::from_value(row)?;
    if !binding::eligible(&record)
        || record.source.as_ref().is_none_or(|row| !row.enabled || row.updated_at != updated_at)
    {
        return Err(super::stale());
    }
    let inventory = configuration(tx, "cloud-inventory", context.cloud.id, false).await?.ok_or_else(super::stale)?;
    if inventory["version"].as_u64() != Some(context.cloud.version)
        || serde_json::from_value::<Timestamp>(inventory["updated_at"].clone())? != context.snapshot.checked_at
    {
        return Err(super::stale());
    }
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

fn audit(principal: &Principal, source: Id, enabled: bool) -> AuditLog {
    AuditLog {
        id: Id::new(),
        tenant_id: principal.tenant,
        sequence: 0,
        action: AuditAction::Configure,
        outcome: AuditOutcome::Success,
        actor: AppState::audit_actor(principal, "agentteams-audit-binding"),
        target: AuditTarget::new(KIND, Some(source.to_string()), None),
        before: None,
        after: None,
        changed_fields: vec!["binding".into()],
        request_id: crate::error::current_request_id(),
        error: None,
        note: if enabled {
            "绑定完整盘点和日志源版本；上传者仅可声明已盘点成员"
        } else {
            "停用 AgentTeams 审计绑定"
        }
        .into(),
        prev_hash: String::new(),
        entry_hash: String::new(),
        at: Timestamp::now(),
    }
}
fn sql_error(error: sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("agentteams_binding", &error)
}
