//! Terminal publication: immutable outcome, both ledgers, usage, rejection and the real audit commit together.
use super::{
    authority::{self, Submission},
    codec,
    records::*,
    reducer, store,
};
use crate::{model_routes::tenant_record_id, state::AppState, store::asset_transaction::AssetTransaction};
use agf_core::{
    audit::{AuditAction, AuditActor, AuditLog, AuditOutcome, AuditTarget},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) async fn publish_known(
    state: &AppState,
    submission: &Submission<'_>,
    id: Id,
    headers: &axum::http::HeaderMap,
) -> DomainResult<bool> {
    tokio::time::timeout_at(submission.deadline, transaction(state, submission, id, headers)).await.map_err(|_| {
        DomainError::Timeout("Known gateway result remains pending after local publication timeout".into())
    })?
}

async fn transaction(
    state: &AppState,
    submission: &Submission<'_>,
    id: Id,
    headers: &axum::http::HeaderMap,
) -> DomainResult<bool> {
    let tenant = submission.principal.tenant;
    let before = super::stage::readonly_fact(state, tenant, id).await?.ok_or_else(store::missing)?;
    submission.models(state, &before.origin).await?;
    let original: Pending = state
        .configurations
        .get::<agf_core::credential::SecretMaterial>(tenant, PENDING, id)
        .await?
        .map(|row| codec::decode(state, tenant, id, PENDING, &row))
        .transpose()?
        .ok_or_else(store::missing)?;
    reducer::validate(&before, &original)?;
    let tx = AssetTransaction::begin(authority::database(state)?, tenant).await?;
    tx.tenant_enabled().await?;
    // E's canonical source locks precede all journal/ledger row locks, even during recovery.
    let cache_current = if let Some(cache) = &original.outcome.semantic {
        super::semantic::lock_fences(&tx, &before, cache).await?
    } else {
        false
    };
    let key = tenant_record_id(tenant);
    let gateway = store::read(&tx, GATEWAY, key).await?;
    let runtime = store::read(&tx, RUNTIME, key).await?;
    let mut active = store::active(state, &tx, tenant).await?;
    let fact: Fact =
        store::decode(state, tenant, id, FACT, store::read(&tx, FACT, id).await?.ok_or_else(store::missing)?)?;
    if fact.attempt != id {
        return Err(store::missing());
    }
    submission.models(state, &fact.origin).await?;
    let pending: Pending =
        store::decode(state, tenant, id, PENDING, store::read(&tx, PENDING, id).await?.ok_or_else(store::missing)?)?;
    if codec::hash(&pending)? != codec::hash(&original)? {
        return Err(store::missing());
    }
    let decision = reducer::reduce(&fact, &pending, gateway, runtime, Timestamp::now().unix_secs())?;
    let reducer::Decision::Write(candidate) = decision else {
        tx.commit(&state.store).await?;
        if let Err(error) = super::meter_projection::hydrate(state, tenant).await {
            tracing::warn!(%error, "Committed gateway usage projection was not refreshed");
        }
        return Ok(false);
    };
    let mut audit = audit(&fact, &pending)?;
    let mut writes = BTreeMap::new();
    if let Some(value) = candidate.gateway {
        writes.insert((GATEWAY, key), value);
    }
    if let Some(value) = candidate.runtime {
        writes.insert((RUNTIME, key), value);
    }
    for usage in super::components::usage_rows(&pending.outcome) {
        if store::read(&tx, crate::gateway_quota::USAGE, usage.id).await?.is_some() {
            return Err(store::missing());
        }
        writes.insert((crate::gateway_quota::USAGE, usage.id), serde_json::to_value(usage)?);
    }
    if let Some(rejection) = &pending.outcome.rejection {
        if store::read(&tx, REJECTION, id).await?.is_some() {
            return Err(store::missing());
        }
        writes.insert(
            (REJECTION, id),
            serde_json::to_value(GatewayRejectionFact {
                tenant,
                attempt: id,
                actor: fact.origin.subject,
                rejection: rejection.clone(),
                audit_id: audit.id,
                outcome_hash: codec::hash(&pending.outcome)?,
            })?,
        );
    }
    active.items.remove(&id);
    writes.insert((ACTIVE, key), store::encoded(state, tenant, key, ACTIVE, &active)?);
    writes.insert((FACT, id), store::encoded(state, tenant, id, FACT, &candidate.fact)?);
    super::meter_projection::append(state, &tx, &pending, &mut writes).await?;
    let cache = if let Some(cache) = &pending.outcome.semantic {
        Some(super::semantic::admit(state, &tx, submission, headers, &fact, cache, cache_current).await?)
    } else {
        None
    };
    if let Some(after) = audit.after.as_mut() {
        after["cacheAdmission"] = match &cache {
            Some(publication) => serde_json::to_value(&publication.disposition)?,
            None => serde_json::to_value(super::semantic::Disposition::Absent)?,
        };
    }
    budget(tenant, &writes, &audit)?;
    for ((kind, id), value) in writes {
        tx.configure(kind, id, Some(value)).await?;
    }
    tx.audit(audit).await?;
    if let Some(publication) = &cache {
        publication.revalidate().await?;
    }
    submission.models(state, &fact.origin).await?;
    if let Some(safety) = fact.charge.as_ref().and_then(|charge| charge.agent_safety.as_ref()) {
        safety.current(state).await?;
    }
    authority::budget(submission.deadline)?;
    tx.commit(&state.store).await?;
    if let Err(error) = super::meter_projection::hydrate(state, tenant).await {
        tracing::warn!(%error, "Committed gateway usage projection was not refreshed");
    }
    Ok(true)
}

fn audit(fact: &Fact, pending: &Pending) -> DomainResult<AuditLog> {
    let failed = pending.outcome.rejection.is_some()
        || matches!(pending.outcome.evidence, Evidence::SentUsageUnknown | Evidence::SentUsagePartial)
        || pending
            .outcome
            .components
            .iter()
            .any(|row| matches!(row.evidence, Evidence::SentUsageUnknown | Evidence::SentUsagePartial));
    let mut entry = AppState::audit_entry(
        fact.origin.tenant,
        AuditAction::Execute,
        if failed { AuditOutcome::Failure } else { AuditOutcome::Success },
        AuditActor {
            id: Some(fact.origin.subject),
            kind: fact.origin.kind.as_str().into(),
            name: format!("{}:{}", fact.origin.kind.as_str(), fact.origin.subject),
            source_ip: fact.origin.source_ip.clone(),
            user_agent: None,
            session_id: fact.origin.session.clone(),
        },
        AuditTarget::new("gateway-attempt", Some(fact.attempt.to_string()), None),
        "",
    );
    entry.id = reducer::audit_id(fact);
    entry.request_id = Some(fact.attempt.to_string());
    entry.after = Some(
        json!({"attemptId":fact.attempt,"evidence":pending.outcome.evidence,"outcomeHash":codec::hash(&pending.outcome)?,
        "rejection":pending.outcome.rejection,"usageId":pending.outcome.usage.as_ref().map(|row|row.id),"mocked":pending.outcome.usage.as_ref().map(|row|row.mocked),"components":pending.outcome.components.iter().map(|row|json!({"usageId":row.usage_id,"evidence":row.evidence,"costMicro":row.usage.as_ref().map(|usage|usage.cost_micro)})).collect::<Vec<_>>()}),
    );
    Ok(entry)
}

#[derive(Serialize)]
struct Write<'a> {
    tenant: TenantId,
    kind: &'a str,
    id: Id,
    delete: bool,
    payload: &'a Value,
}
pub(super) fn budget(tenant: TenantId, writes: &BTreeMap<(&str, Id), Value>, audit: &AuditLog) -> DomainResult<()> {
    let mut rows = Vec::new();
    if audit.tenant_id != tenant || writes.len() > 100 {
        return Err(store::missing());
    }
    for ((kind, id), value) in writes {
        if id.is_nil() || serde_json::to_vec(value)?.len() > 1024 * 1024 {
            return Err(store::missing());
        }
        rows.push(Write { tenant, kind, id: *id, delete: false, payload: value });
    }
    let mut sealed = audit.clone();
    sealed.sequence = i64::MAX;
    sealed.prev_hash = "0".repeat(64);
    sealed.entry_hash = "0".repeat(64);
    if serde_json::to_vec(&(rows, sealed))?.len() > 8 * 1024 * 1024 {
        return Err(store::missing());
    }
    Ok(())
}
