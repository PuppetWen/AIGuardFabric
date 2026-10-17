//! Read one event's authoritative analysis inputs in one tenant transaction.
use super::{AnalysisResult, AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    event::Event,
    ids::{Id, TenantId},
};
use agf_storage::{Store, TenantTransaction};
use serde::de::DeserializeOwned;

pub(super) enum Input {
    Duplicate(AnalysisResult),
    Event { event: Box<Event>, detection: crate::rule_store::Registry, correlation: crate::correlation::Registry },
}

/// Caller first verifies that configuration and event storage share this exact Store.
/// All business reads use the unchanged tenant role/RLS; this phase writes no evidence.
pub(super) async fn load(
    state: &AppState,
    store: &std::sync::Arc<Store>,
    reference: &Event,
    check_deferred: bool,
) -> DomainResult<Input> {
    if !state.configurations.uses_database(store) {
        return Err(DomainError::Config("Analysis input configuration authority differs from the event store".into()));
    }
    let tenant = reference.tenant_id;
    let id = reference.id;
    let time = reference.time;
    store
        .with_tenant(tenant, move |tx| {
            Box::pin(async move {
                if check_deferred && super::retry::deferred_in_transaction(tx, id).await? {
                    return Err(DomainError::RateLimited("Analysis is paused, quarantined or awaiting retry".into()));
                }
                let receipt: Option<serde_json::Value> = sqlx::query_scalar(
                    "SELECT jsonb_build_object('duplicate',true,'finding_ids',finding_ids,'alert_ids',alert_ids)
            FROM event_analysis_receipts WHERE event_id=$1",
                )
                .bind(id.as_uuid())
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("analysis_completed", &e))?;
                if let Some(receipt) = receipt {
                    return serde_json::from_value(receipt).map(Input::Duplicate).map_err(Into::into);
                }
                let value: Option<serde_json::Value> =
                    sqlx::query_scalar("SELECT to_jsonb(e) FROM events e WHERE id=$1 AND time=$2")
                        .bind(id.as_uuid())
                        .bind(time.as_datetime())
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(|e| agf_storage::map_sqlx_err("analysis_event", &e))?;
                let event: Event = serde_json::from_value(
                    value.ok_or_else(|| DomainError::NotFound { entity: "committed-event", id: id.to_string() })?,
                )?;
                let detection =
                    configuration(tx, tenant, crate::rule_store::KIND, crate::rule_store::record(tenant)).await?;
                let correlation = configuration(
                    tx,
                    tenant,
                    crate::correlation::registry::KIND,
                    crate::correlation::registry::record(tenant),
                )
                .await?;
                Ok(Input::Event { event: Box::new(event), detection, correlation })
            })
        })
        .await
}

pub(super) async fn configuration<T: DeserializeOwned + Default>(
    tx: &mut TenantTransaction<'_>,
    tenant: TenantId,
    kind: &str,
    id: Id,
) -> DomainResult<T> {
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT payload FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NULL",
    )
    .bind(tenant.as_uuid())
    .bind(kind)
    .bind(id.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| {
        tracing::error!(%error, "Analysis configuration read failed");
        DomainError::DependencyUnavailable {
            dependency: "postgres".into(),
            cause: "配置未能保存，请检查数据库连接与迁移状态".into(),
        }
    })?;
    value.map(serde_json::from_value).transpose().map(Option::unwrap_or_default).map_err(Into::into)
}

/// At most one ready pull: canonical rows and both registries share tenant authority.
/// A snapshot is scoped to this attempt, never retained for the next batch.
pub(super) const BATCH_LIMIT: usize = 32;

pub(super) struct Snapshot {
    pub detection: crate::rule_store::Registry,
    pub correlation: crate::correlation::Registry,
}

impl Snapshot {
    pub(super) fn identity(&self) -> DomainResult<serde_json::Value> {
        serde_json::to_value((&self.detection, &self.correlation)).map_err(Into::into)
    }
}

pub(super) enum BatchItem {
    Duplicate(AnalysisResult),
    Event(Box<Event>),
}

pub(super) struct BatchInput {
    pub items: Vec<BatchItem>,
    pub snapshot: Option<Snapshot>,
}

/// `None` requires the original ordered path, including its per-event error precedence.
pub(super) async fn load_batch(
    state: &AppState,
    store: &std::sync::Arc<Store>,
    references: &[Event],
    check_deferred: bool,
) -> DomainResult<Option<BatchInput>> {
    let Some(first) = references.first() else { return Ok(None) };
    let tenant = first.tenant_id;
    let mut unique = std::collections::HashSet::new();
    if references.len() > BATCH_LIMIT
        || !state.configurations.uses_database(store)
        || references.iter().any(|event| event.tenant_id != tenant || !unique.insert(event.id))
    {
        return Ok(None);
    }
    // This uses the platform pool; do not hold the only tenant pool connection here.
    if !crate::tenant_directory::get(state, tenant).await?.enabled {
        return Err(DomainError::Forbidden("Event tenant is disabled".into()));
    }
    let ids: Vec<_> = references.iter().map(|e| e.id.as_uuid()).collect();
    let times: Vec<_> = references.iter().map(|e| e.time.as_datetime()).collect();
    store
        .with_tenant(tenant, move |tx| {
            Box::pin(async move {
                let rows: Vec<(bool, Option<serde_json::Value>, Option<serde_json::Value>)> = sqlx::query_as(
                    "SELECT $3 AND EXISTS(SELECT 1 FROM event_analysis_retries f WHERE f.event_id=i.id
                AND f.resolved_at IS NULL AND (f.available_at>now() OR f.paused OR f.attempts>=8)),
             CASE WHEN r.event_id IS NOT NULL THEN jsonb_build_object('duplicate',true,
                'finding_ids',r.finding_ids,'alert_ids',r.alert_ids) END,
             to_jsonb(e) FROM UNNEST($1::uuid[],$2::timestamptz[]) WITH ORDINALITY i(id,time,ord)
             LEFT JOIN event_analysis_receipts r ON r.event_id=i.id
             LEFT JOIN events e ON e.id=i.id AND e.time=i.time ORDER BY i.ord",
                )
                .bind(ids)
                .bind(times)
                .bind(check_deferred)
                .fetch_all(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("analysis_batch_inputs", &e))?;
                let mut items = Vec::with_capacity(rows.len());
                let mut has_new = false;
                for (deferred, receipt, canonical) in rows {
                    if deferred {
                        return Ok(None);
                    }
                    if let Some(receipt) = receipt {
                        // A receipt wins even when the reference time or current registry is invalid.
                        items.push(BatchItem::Duplicate(serde_json::from_value(receipt)?));
                    } else {
                        let Some(canonical) = canonical else { return Ok(None) };
                        let Ok(event) = serde_json::from_value(canonical) else { return Ok(None) };
                        items.push(BatchItem::Event(Box::new(event)));
                        has_new = true;
                    }
                }
                let snapshot = if has_new { Some(snapshot(tx, tenant).await?) } else { None };
                Ok(Some(BatchInput { items, snapshot }))
            })
        })
        .await
}

pub(super) async fn snapshot(tx: &mut TenantTransaction<'_>, tenant: TenantId) -> DomainResult<Snapshot> {
    Ok(Snapshot {
        detection: configuration(tx, tenant, crate::rule_store::KIND, crate::rule_store::record(tenant)).await?,
        correlation: configuration(
            tx,
            tenant,
            crate::correlation::registry::KIND,
            crate::correlation::registry::record(tenant),
        )
        .await?,
    })
}
