//! Internal conservative expiry maintenance never obtains permission to execute or reveal a model result.
use super::{authority, records::*, reducer, sql, store};
use crate::{model_routes::tenant_record_id, state::AppState, store::asset_transaction::AssetTransaction};
use agf_core::{
    audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget},
    error::DomainResult,
    ids::{Id, TenantId, deterministic_id},
    time::Timestamp,
};
use serde_json::json;
use std::collections::BTreeMap;

// No public route. Called by authenticated admission and the service's owned expiry task only.
pub(super) async fn expire(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<bool> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(110);
    tokio::time::timeout_at(deadline, transaction(state, tenant, id, deadline)).await.map_err(|_| {
        agf_core::error::DomainError::Timeout("Conservative expiry local publication budget expired".into())
    })?
}

async fn transaction(state: &AppState, tenant: TenantId, id: Id, deadline: tokio::time::Instant) -> DomainResult<bool> {
    let tx = AssetTransaction::begin(authority::database(state)?, tenant).await?;
    // A disabled tenant or revoked original key must not hold concurrency forever.
    // No tenant_enabled(), original model grant, or provider execution permission is synthesized.
    let key = tenant_record_id(tenant);
    let gateway = store::read(&tx, GATEWAY, key).await?.ok_or_else(store::missing)?;
    let runtime = store::read(&tx, RUNTIME, key).await?.ok_or_else(store::missing)?;
    let mut active = store::active(state, &tx, tenant).await?;
    let fact: Fact =
        store::decode(state, tenant, id, FACT, store::read(&tx, FACT, id).await?.ok_or_else(store::missing)?)?;
    if fact.origin.tenant != tenant || fact.attempt != id || fact.usage_id != usage_id(tenant, id) {
        return Err(store::missing());
    }
    let reducer::Decision::Write(candidate) =
        reducer::conservative(&fact, gateway, runtime, Timestamp::now().unix_secs())?
    else {
        tx.commit(&state.store).await?;
        return Ok(false);
    };
    active.items.remove(&id);
    let writes = BTreeMap::from([
        ((GATEWAY, key), candidate.gateway.ok_or_else(store::missing)?),
        ((RUNTIME, key), candidate.runtime.ok_or_else(store::missing)?),
        ((ACTIVE, key), store::encoded(state, tenant, key, ACTIVE, &active)?),
        ((FACT, id), store::encoded(state, tenant, id, FACT, &candidate.fact)?),
    ]);
    let mut audit = AppState::audit_entry(
        tenant,
        AuditAction::Execute,
        AuditOutcome::Failure,
        AuditActor::system("gateway-conservative-expiry"),
        AuditTarget::new("gateway-attempt-expiry", Some(id.to_string()), None),
        "",
    );
    audit.id = deterministic_id("agf.gateway-expiry.audit.v1", &format!("{tenant}:{id}"));
    audit.request_id = Some(id.to_string());
    audit.after = Some(
        json!({"attemptId":id,"originalActorId":fact.origin.subject,"chargeState":"conservative","newProviderPermission":false}),
    );
    sql::budget(tenant, &writes, &audit)?;
    for ((kind, id), value) in writes {
        tx.configure(kind, id, Some(value)).await?;
    }
    tx.audit(audit).await?;
    authority::budget(deadline)?;
    tx.commit(&state.store).await?;
    Ok(true)
}

pub(super) async fn due_ids(state: &AppState, tenant: TenantId, limit: usize) -> DomainResult<Vec<Id>> {
    due_rotated(state, tenant, limit, 0).await
}

pub(super) async fn due_rotated(
    state: &AppState,
    tenant: TenantId,
    limit: usize,
    offset: usize,
) -> DomainResult<Vec<Id>> {
    if limit > 16 {
        return Err(store::missing());
    }
    let key = tenant_record_id(tenant);
    let active: ActiveAttempts = state
        .configurations
        .get::<serde_json::Value>(tenant, ACTIVE, key)
        .await?
        .map(|value| store::decode(state, tenant, key, ACTIVE, value))
        .transpose()?
        .unwrap_or_default();
    if active.items.len() > 512 {
        return Err(store::missing());
    }
    let now = Timestamp::now();
    let due = active.items.into_iter().filter(|(_, expires)| *expires <= now).map(|(id, _)| id).collect::<Vec<_>>();
    if due.is_empty() {
        return Ok(Vec::new());
    }
    // A corrupt old fact must not permanently hide later expired facts in this tenant.
    Ok(due.iter().copied().cycle().skip(offset % due.len()).take(limit.min(due.len())).collect())
}

pub(super) async fn due(state: &AppState, tenant: TenantId) -> DomainResult<()> {
    for id in due_ids(state, tenant, 16).await? {
        expire(state, tenant, id).await?;
    }
    Ok(())
}
