//! Automatic normalized-event analysis. SQL commits precede every broker acknowledgement.
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    event::Event,
    ids::Id,
};
use agf_storage::Store;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[cfg(test)]
mod batch_tests;
pub mod broker_quarantine;
mod commit;
mod context;
mod detect;
mod notifications;
mod retry;
mod worker;
mod worker_batch;
pub use worker::{process_delivery, process_or_defer_delivery, recover_pending, run_loop};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub duplicate: bool,
    pub finding_ids: Vec<Id>,
    pub alert_ids: Vec<Id>,
}

fn database(state: &AppState) -> DomainResult<Arc<Store>> {
    state.ingest_sink.database().ok_or_else(|| {
        DomainError::PreconditionFailed("Automatic event analysis requires the shared SQL event store".into())
    })
}

/// Load the canonical committed event: broker payloads cannot inject or alter evidence.
pub async fn process(state: &AppState, reference: &Event) -> DomainResult<AnalysisResult> {
    process_inner(state, reference, false).await
}

pub(super) async fn process_broker(state: &AppState, reference: &Event) -> DomainResult<AnalysisResult> {
    process_inner(state, reference, true).await
}

/// Analyze a bounded, ordered set of references, honoring the broker retry gates.
/// Effectful, mixed-authority or otherwise ineligible batches retain single-event processing.
pub async fn process_batch(state: &AppState, references: &[Event]) -> DomainResult<Vec<AnalysisResult>> {
    if references.len() > context::BATCH_LIMIT {
        return Err(DomainError::Validation("Analysis batch exceeds 32 references".into()));
    }
    if let Ok(Some(results)) = try_empty_batch(state, references, true).await {
        return Ok(results);
    }
    let mut results = Vec::with_capacity(references.len());
    for reference in references {
        results.push(process_broker(state, reference).await?);
    }
    Ok(results)
}

pub(super) async fn try_empty_batch(
    state: &AppState,
    references: &[Event],
    check_deferred: bool,
) -> DomainResult<Option<Vec<AnalysisResult>>> {
    let store = database(state)?;
    let Some(input) = context::load_batch(state, &store, references, check_deferred).await? else {
        return Ok(None);
    };
    let Some(snapshot) = input.snapshot else {
        return Ok(Some(
            input
                .items
                .into_iter()
                .filter_map(|item| match item {
                    context::BatchItem::Duplicate(result) => Some(result),
                    context::BatchItem::Event(_) => None,
                })
                .collect(),
        ));
    };
    if !crate::correlation::registry::active_from_registry(snapshot.correlation.clone()).is_empty() {
        return Ok(None);
    }
    let tenant = references[0].tenant_id;
    let registry_identity = snapshot.identity()?;
    let pack = crate::rule_store::pack_from_registry(state, tenant, snapshot.detection)?;
    let mut events = Vec::new();
    for item in &input.items {
        if let context::BatchItem::Event(event) = item {
            // Every new canonical event runs all normal detectors, in delivery order.
            if !detect::scan(state, event, &pack).await?.is_empty() {
                return Ok(None);
            }
            tokio::task::yield_now().await;
            events.push((**event).clone());
        }
    }
    // Recheck outside the tenant transaction so pool_max=1 remains supported.
    if !crate::tenant_directory::get(state, tenant).await?.enabled {
        return Ok(None);
    }
    let Some(completed) =
        commit::save_empty_batch(&store, &events, &pack.report.pack_fingerprint, registry_identity, check_deferred)
            .await?
    else {
        return Ok(None);
    };
    let mut completed = completed.into_iter();
    let mut results = Vec::with_capacity(input.items.len());
    for item in input.items {
        results.push(match item {
            context::BatchItem::Duplicate(result) => result,
            context::BatchItem::Event(_) => {
                completed.next().ok_or_else(|| DomainError::Internal("Incomplete analysis batch result".into()))?
            }
        });
    }
    Ok(Some(results))
}

async fn process_inner(state: &AppState, reference: &Event, check_deferred: bool) -> DomainResult<AnalysisResult> {
    let store = database(state)?;
    let shared_authority = state.configurations.uses_database(&store);
    // Retain the original lookup path when configuration belongs to memory or another Store.
    if !shared_authority && check_deferred && retry::deferred(state, reference.tenant_id, reference.id).await? {
        return Err(DomainError::RateLimited("Analysis is paused, quarantined or awaiting retry".into()));
    }
    if !crate::tenant_directory::get(state, reference.tenant_id).await?.enabled {
        return Err(DomainError::Forbidden("Event tenant is disabled".into()));
    }
    let tenant = reference.tenant_id;
    let id = reference.id;
    let (event, pack, loaded_correlations) = if shared_authority {
        match context::load(state, &store, reference, check_deferred).await? {
            context::Input::Duplicate(result) => return Ok(result),
            context::Input::Event { event, detection, correlation } => {
                // The read transaction has committed before rule compilation, scanning or effect writes.
                let pack = crate::rule_store::pack_from_registry(state, tenant, detection)?;
                let correlations = crate::correlation::registry::active_from_registry(correlation);
                (*event, pack, Some(correlations))
            }
        }
    } else {
        let id = reference.id;
        let receipt: Option<serde_json::Value> = store
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        "SELECT jsonb_build_object('duplicate',true,'finding_ids',finding_ids,'alert_ids',alert_ids)
                FROM event_analysis_receipts WHERE event_id=$1",
                    )
                    .bind(id.as_uuid())
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(|e| agf_storage::map_sqlx_err("analysis_completed", &e))
                })
            })
            .await?;
        if let Some(receipt) = receipt {
            return serde_json::from_value(receipt).map_err(Into::into);
        }
        let event_time = reference.time;
        let value: Option<serde_json::Value> = store
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT to_jsonb(e) FROM events e WHERE id=$1 AND time=$2")
                        .bind(id.as_uuid())
                        .bind(event_time.as_datetime())
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(|e| agf_storage::map_sqlx_err("analysis_event", &e))
                })
            })
            .await?;
        let event: Event = serde_json::from_value(
            value.ok_or_else(|| DomainError::NotFound { entity: "committed-event", id: id.to_string() })?,
        )?;
        let pack = crate::rule_store::pack(state, tenant).await?;
        (event, pack, None)
    };
    let findings = detect::scan(state, &event, &pack).await?;
    let correlations = match loaded_correlations {
        Some(correlations) => correlations,
        None => crate::correlation::registry::active(state, tenant).await?,
    };
    let result = commit::save(&store, &event, &pack.report.pack_fingerprint, &findings, &correlations).await?;
    if !result.duplicate {
        for finding in &findings {
            state.store.hydrate_finding(finding)?;
        }
        for id in &result.finding_ids {
            state.store.finding_get_durable(tenant, *id).await?;
        }
        for id in &result.alert_ids {
            state.store.alert_get_durable(tenant, *id).await?;
        }
        if !result.alert_ids.is_empty() {
            state.publish(crate::state::WsEvent {
                kind: "alert".into(), tenant_id: tenant, at: agf_core::time::Timestamp::now(),
                payload: serde_json::json!({"event_id":id,"alert_ids":result.alert_ids,"finding_ids":result.finding_ids}),
            });
        }
    }
    Ok(result)
}
