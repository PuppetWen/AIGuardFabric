//! Queue visibility does not equate an empty queue with a verified broker connection.
use super::*;

pub(super) async fn status(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "sources", "read")?;
    let Some(store) = state.ingest_sink.database() else {
        return Ok(Json(serde_json::json!({"storage":"memory", "workerEnabled":false, "pending":null, "failed":null})));
    };
    let (pending, failed) = agf_ingest::bus::EventOutbox::new(store.clone(), principal.tenant).pending().await?;
    let analysis: serde_json::Value = store.with_tenant(principal.tenant, |tx| Box::pin(async move {
        sqlx::query_scalar("SELECT jsonb_build_object(
            'pending',(SELECT count(*) FROM events e WHERE NOT EXISTS (SELECT 1 FROM event_analysis_receipts r WHERE r.event_id=e.id)),
            'retrying',(SELECT count(*) FROM event_analysis_retries WHERE resolved_at IS NULL AND NOT paused AND attempts<8),
            'quarantined',(SELECT count(*) FROM event_analysis_retries WHERE resolved_at IS NULL AND NOT paused AND attempts>=8),
            'paused',(SELECT count(*) FROM event_analysis_retries WHERE resolved_at IS NULL AND paused),
            'processed',(SELECT count(*) FROM event_analysis_receipts),
            'lastProcessedAt',(SELECT max(processed_at) FROM event_analysis_receipts))")
            .fetch_one(&mut **tx).await.map_err(|e| agf_storage::map_sqlx_err("analysis_status", &e))
    })).await?;
    let can_inspect = super::broker_operations::can_inspect(&state, &principal);
    let broker: serde_json::Value = if can_inspect {
        store
            .with_tenant(TenantId::default_tenant(), |tx| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        "SELECT jsonb_build_object(
                'quarantined',count(*) FILTER (WHERE state='quarantined'),
                'retrying',count(*) FILTER (WHERE state='retrying')) FROM broker_quarantine",
                    )
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(|e| agf_storage::map_sqlx_err("broker_quarantine_status", &e))
                })
            })
            .await?
    } else {
        serde_json::Value::Null
    };
    Ok(Json(
        serde_json::json!({"storage":"sql", "workerEnabled":state.config.nats.enabled, "pending":pending, "failed":failed,"analysis":analysis,
            "canInspectBroker":can_inspect,"broker":broker}),
    ))
}
