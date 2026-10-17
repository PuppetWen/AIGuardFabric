//! Bounded coverage evidence, not a migration or a second authoritative billing ledger.
use super::{codec, components, records::*, reducer, store};
use crate::AppState;
use agf_aigw::meter::CommittedMeterProjection;
use agf_core::{
    credential::SecretMaterial,
    error::DomainResult,
    ids::{Id, TenantId},
    model::UsageRecord,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) const ROWS: usize = 512;
pub(super) const BYTES: usize = 8 * 1024 * 1024;
pub(super) struct Witness {
    pub(super) checkpoint: Option<SecretMaterial>,
    pub(super) retired_checkpoint: bool,
    pub(super) usages: Vec<(Id, Value)>,
    pub(super) facts: Vec<(Id, Value)>,
}

pub(super) fn verify(
    state: &AppState,
    tenant: TenantId,
    checkpoint: &CommittedMeterProjection,
    witness: &Witness,
) -> DomainResult<()> {
    if witness.usages.len() > ROWS
        || witness.facts.len() > ROWS
        || serde_json::to_vec(&(&witness.usages, &witness.facts))?.len() > BYTES
    {
        return Err(store::missing());
    }
    let mut usages = BTreeMap::new();
    for (id, value) in &witness.usages {
        let row: UsageRecord = serde_json::from_value(value.clone()).map_err(|_| store::missing())?;
        if id.is_nil() || row.id != *id || row.tenant_id != tenant || usages.insert(*id, row).is_some() {
            return Err(store::missing());
        }
    }
    let mut reconstructed = CommittedMeterProjection::new(tenant)?;
    let mut fact_ids = BTreeSet::new();
    for (id, value) in &witness.facts {
        let secret: SecretMaterial = serde_json::from_value(value.clone()).map_err(|_| store::missing())?;
        let fact: Fact = codec::decode(state, tenant, *id, FACT, &secret)?;
        if !fact_ids.insert(*id)
            || id.is_nil()
            || fact.attempt != *id
            || fact.origin.tenant != tenant
            || fact.usage_id != usage_id(tenant, *id)
        {
            return Err(store::missing());
        }
        let Phase::Settled { ref audit_id, .. } = fact.phase else { continue };
        if *audit_id != reducer::audit_id(&fact) {
            return Err(store::missing());
        }
        let mut rows = Vec::new();
        if let Some(row) = usages.remove(&fact.usage_id) {
            rows.push(row);
        }
        if let Some(anchor) = fact.charge.as_ref().and_then(|charge| charge.embedding.as_ref()) {
            if anchor.usage_id != components::embedding_id(tenant, *id) {
                return Err(store::missing());
            }
            if let Some(row) = usages.remove(&anchor.usage_id) {
                rows.push(row);
            }
        }
        if let Some(charge) = &fact.charge {
            for (ordinal, anchor) in charge.chats.iter().enumerate().skip(1) {
                if anchor.usage_id != super::chat_components::usage_id(tenant, *id, ordinal) {
                    return Err(store::missing());
                }
                if let Some(row) = usages.remove(&anchor.usage_id) {
                    rows.push(row);
                }
            }
            // Committed usage still displays verified lower bounds; it is not a complete invoice.
            if charge.state == ChargeState::Conservative {
                state.meter.mark_committed_projection_incomplete();
            }
        }
        // Reconstruct only a bounded numerical witness using the same checked owner arithmetic.
        // Its display groups and revision are not installed, and it grants no execution authority.
        reconstructed = reconstructed.append(&rows)?;
    }
    if !usages.is_empty()
        || reconstructed.revision() != checkpoint.revision()
        || serde_json::to_value(&reconstructed)?["total"] != serde_json::to_value(checkpoint)?["total"]
    {
        return Err(store::missing());
    }
    Ok(())
}

pub(super) fn absent(state: &AppState, tenant: TenantId, witness: &Witness) -> DomainResult<()> {
    if witness.retired_checkpoint || !witness.usages.is_empty() {
        return Err(store::missing());
    }
    for (id, value) in &witness.facts {
        let secret = serde_json::from_value(value.clone()).map_err(|_| store::missing())?;
        let fact: Fact = codec::decode(state, tenant, *id, FACT, &secret)?;
        if fact.attempt != *id || fact.origin.tenant != tenant || matches!(fact.phase, Phase::Settled { .. }) {
            return Err(store::missing());
        }
    }
    Ok(())
}

pub(super) async fn read(state: &AppState, tenant: TenantId, id: Id, kind: &str) -> DomainResult<Witness> {
    if let Some(database) = state.store.database() {
        let mut tx = database.db().begin_tenant(tenant).await?;
        // All rows, including tombstones, are sampled by one RLS statement/snapshot. A prefix
        // or oversized collection never proves coverage. No locks, writes or initialization.
        let (checkpoint, retired_checkpoint, usages, facts): (Option<Value>, bool, Option<Value>, Option<Value>) = sqlx::query_as(
            "WITH u AS MATERIALIZED (SELECT id,payload FROM console_configurations WHERE tenant_id=$1 AND kind='model-usage' ORDER BY id LIMIT 513),
             f AS MATERIALIZED (SELECT id,payload FROM console_configurations WHERE tenant_id=$1 AND kind='gateway-attempt-fact-v1' ORDER BY id LIMIT 513),
             bounds AS (SELECT (SELECT count(*)<=512 FROM u) AND (SELECT count(*)<=512 FROM f)
                AND coalesce((SELECT sum(octet_length(payload::text)::bigint) FROM u),0)
                  +coalesce((SELECT sum(octet_length(payload::text)::bigint) FROM f),0)<=8388608 AS fits)
             SELECT (SELECT payload FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NULL),
               EXISTS(SELECT 1 FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NOT NULL),
               CASE WHEN fits THEN coalesce((SELECT jsonb_agg(jsonb_build_array(id,payload) ORDER BY id) FROM u),'[]'::jsonb) END,
               CASE WHEN fits THEN coalesce((SELECT jsonb_agg(jsonb_build_array(id,payload) ORDER BY id) FROM f),'[]'::jsonb) END FROM bounds"
        ).bind(tenant.as_uuid()).bind(kind).bind(id.as_uuid()).fetch_one(&mut *tx).await
            .map_err(|error| agf_storage::map_sqlx_err("gateway_meter_coverage", &error))?;
        tx.commit().await?;
        return Ok(Witness {
            checkpoint: checkpoint.map(serde_json::from_value).transpose().map_err(|_| store::missing())?,
            retired_checkpoint,
            usages: serde_json::from_value(usages.ok_or_else(store::missing)?).map_err(|_| store::missing())?,
            facts: serde_json::from_value(facts.ok_or_else(store::missing)?).map_err(|_| store::missing())?,
        });
    }
    // Memory has no tombstones. Separate bounded snapshots can only fail closed on races;
    // this worker is SQL-only, and ordinary post-commit hydrate never fabricates missing rows.
    let checkpoint = state.configurations.get(tenant, kind, id).await?;
    let usages: Vec<UsageRecord> = bounded(state, tenant, "model-usage").await?;
    let secrets: Vec<SecretMaterial> = bounded(state, tenant, FACT).await?;
    let prefix = format!("agf.gateway-settlement.preview.v1:{FACT}:{tenant}:");
    let facts = secrets
        .into_iter()
        .map(|secret| {
            let id =
                Id::parse(secret.aad.as_deref().and_then(|aad| aad.strip_prefix(&prefix)).ok_or_else(store::missing)?)?;
            Ok((id, serde_json::to_value(secret)?))
        })
        .collect::<DomainResult<Vec<_>>>()?;
    let usages =
        usages.into_iter().map(|row| Ok((row.id, serde_json::to_value(row)?))).collect::<DomainResult<Vec<_>>>()?;
    Ok(Witness { checkpoint, retired_checkpoint: false, usages, facts })
}
async fn bounded<T: serde::de::DeserializeOwned>(
    state: &AppState,
    tenant: TenantId,
    kind: &str,
) -> DomainResult<Vec<T>> {
    match state.configurations.list_bounded(tenant, kind, ROWS, BYTES).await? {
        agf_storage::configuration::BoundedConfigurationList::Complete(rows) => Ok(rows),
        _ => Err(store::missing()),
    }
}
