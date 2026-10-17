//! One guarded tenant transaction claims business identities before writing events/outbox.
use super::{agentteams_audit::*, *};
use agf_storage::{Store, TenantTransaction, map_sqlx_err};

pub(super) async fn persist(
    store: &Store,
    guard: &AgentTeamsBindingGuard,
    items: &[AgentTeamsIngestItem],
    outbox: bool,
) -> DomainResult<AgentTeamsIngestResult> {
    validate_items(guard, items)?;
    let guard = guard.clone();
    let items = items.to_vec();
    store.with_tenant(guard.tenant_id, move |tx| Box::pin(async move {
        lock_binding(tx, &guard).await?;
        let mut result = AgentTeamsIngestResult::default();
        for item in &items {
            if !claim(tx, &item.audit).await? {
                result.deduped += 1;
                continue;
            }
            agf_storage::EventRepo::insert_raw(tx, &item.write.raw).await?;
            let event = item.write.event.as_ref().ok_or_else(|| DomainError::Validation("Missing audit event".into()))?;
            agf_storage::EventRepo::insert(tx, event).await?;
            if outbox {
                sqlx::query("INSERT INTO event_delivery_outbox (tenant_id,event_id,payload) VALUES ($1,$2,$3) ON CONFLICT (tenant_id,event_id) DO NOTHING")
                    .bind(guard.tenant_id.as_uuid()).bind(event.id.as_uuid()).bind(serde_json::to_value(event)?)
                    .execute(&mut **tx).await.map_err(|error| map_sqlx_err("agentteams_enqueue", &error))?;
            }
            result.accepted += 1;
        }
        Ok(result)
    })).await
}

async fn claim(tx: &mut TenantTransaction<'_>, audit: &AgentTeamsAuditRecord) -> DomainResult<bool> {
    let inserted = sqlx::query(
        "INSERT INTO agentteams_audit
        (tenant_id,scope_id,external_event_id,content_hash,id,source_id,binding_id,event_time,received_at,kind,payload)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        ON CONFLICT (tenant_id,scope_id,external_event_id) DO NOTHING",
    )
    .bind(audit.tenant_id.as_uuid())
    .bind(audit.scope_id.as_uuid())
    .bind(&audit.external_event_id)
    .bind(&audit.content_hash)
    .bind(audit.id.as_uuid())
    .bind(audit.source_id.as_uuid())
    .bind(audit.binding_id.as_uuid())
    .bind(audit.event_time.as_datetime())
    .bind(audit.received_at.as_datetime())
    .bind(&audit.kind)
    .bind(serde_json::to_value(audit)?)
    .execute(&mut **tx)
    .await
    .map_err(|error| map_sqlx_err("agentteams_claim", &error))?
    .rows_affected();
    if inserted > 0 {
        return Ok(true);
    }
    let previous: String = sqlx::query_scalar(
        "SELECT content_hash FROM agentteams_audit WHERE tenant_id=$1 AND scope_id=$2 AND external_event_id=$3",
    )
    .bind(audit.tenant_id.as_uuid())
    .bind(audit.scope_id.as_uuid())
    .bind(&audit.external_event_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| map_sqlx_err("agentteams_duplicate", &error))?;
    if previous != audit.content_hash {
        return Err(DomainError::Conflict("AgentTeams event ID already has different content".into()));
    }
    Ok(false)
}

async fn configuration(
    tx: &mut TenantTransaction<'_>,
    guard: &AgentTeamsBindingGuard,
    kind: &str,
    id: Id,
) -> DomainResult<Value> {
    sqlx::query_scalar("SELECT payload FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NULL FOR SHARE")
        .bind(guard.tenant_id.as_uuid()).bind(kind).bind(id.as_uuid())
        .fetch_optional(&mut **tx).await.map_err(|error| map_sqlx_err("agentteams_binding_guard", &error))?
        .ok_or_else(|| DomainError::Conflict("AgentTeams source, binding or inventory was removed; refresh binding".into()))
}

fn same_time(value: &Value, expected: Timestamp) -> bool {
    serde_json::from_value::<Timestamp>(value.clone()).is_ok_and(|actual| actual == expected)
}

async fn lock_binding(tx: &mut TenantTransaction<'_>, guard: &AgentTeamsBindingGuard) -> DomainResult<()> {
    // The restricted function can only read/lock the current tenant. All writes retain RLS.
    let enabled: bool = sqlx::query_scalar("SELECT agf_agentteams_lock_tenant()")
        .fetch_one(&mut **tx)
        .await
        .map_err(|error| map_sqlx_err("agentteams_tenant_guard", &error))?;
    if !enabled {
        return Err(DomainError::Forbidden("AgentTeams event tenant is disabled or deleted".into()));
    }
    // Do not acquire ConfigStore or asset-governance advisory locks after these row locks.
    let cloud = configuration(tx, guard, "cloud-integration", guard.cloud_config_id).await?;
    let source = configuration(tx, guard, "log-source", guard.source_id).await?;
    let inventory = configuration(tx, guard, "cloud-inventory", guard.cloud_config_id).await?;
    let binding = configuration(tx, guard, "agentteams-audit-source", guard.source_id).await?;
    let source_data = &source["source"];
    if cloud["enabled"] != true
        || cloud["version"].as_u64() != Some(guard.cloud_version)
        || source_data["enabled"] != true
        || source_data["protocol"] != "webhook"
        || source_data["mode"] != "push"
        || !source["native_receiver"].is_null()
        || !same_time(&source_data["updated_at"], guard.source_updated_at)
        || inventory["enabled"] != true
        || inventory["version"].as_u64() != Some(guard.cloud_version)
        || !same_time(&inventory["updated_at"], guard.inventory_updated_at)
        || binding["enabled"] != true
        || binding["version"].as_u64() != Some(guard.binding_version)
        || binding["cloud_version"].as_u64() != Some(guard.cloud_version)
        || !same_time(&binding["source_updated_at"], guard.source_updated_at)
        || !same_time(&binding["inventory_updated_at"], guard.inventory_updated_at)
        || serde_json::from_value::<Id>(binding["binding_id"].clone()).ok() != Some(guard.binding_id)
        || serde_json::from_value::<Id>(binding["scope_id"].clone()).ok() != Some(guard.scope_id)
    {
        return Err(DomainError::Conflict(
            "AgentTeams source, inventory or configuration changed; refresh binding".into(),
        ));
    }
    Ok(())
}
