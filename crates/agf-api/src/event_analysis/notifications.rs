//! Persist notification jobs after analysis, with a separate recoverable receipt stage.
use super::{AppState, database};
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId},
};

pub(super) async fn drain(state: &AppState, tenant: TenantId) -> DomainResult<usize> {
    let store = database(state)?;
    let rows: Vec<(uuid::Uuid, serde_json::Value)> = store
        .with_tenant(tenant, |tx| {
            Box::pin(async move {
                sqlx::query_as(
                    "SELECT event_id,alert_ids FROM event_analysis_receipts
            WHERE notification_enqueued_at IS NULL ORDER BY processed_at,event_id LIMIT 32",
                )
                .fetch_all(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("analysis_notifications", &e))
            })
        })
        .await?;
    let count = rows.len();
    let mut empty_ids = Vec::new();
    let mut pending = Vec::new();
    // Validate every selected receipt before changing any of them; malformed JSON must remain an error.
    for (event_id, value) in rows {
        let ids: Vec<Id> = serde_json::from_value(value)?;
        if ids.is_empty() {
            empty_ids.push(event_id);
        } else {
            pending.push((event_id, ids));
        }
    }
    if !empty_ids.is_empty() {
        store
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "WITH empty AS (
                        SELECT event_id FROM event_analysis_receipts
                        WHERE event_id=ANY($1) AND notification_enqueued_at IS NULL AND alert_ids='[]'::jsonb
                        ORDER BY processed_at,event_id LIMIT 32
                    ) UPDATE event_analysis_receipts r SET notification_enqueued_at=now()
                    FROM empty e WHERE r.event_id=e.event_id
                    AND r.notification_enqueued_at IS NULL AND r.alert_ids='[]'::jsonb",
                    )
                    .bind(empty_ids)
                    .execute(&mut **tx)
                    .await
                    .map_err(|e| agf_storage::map_sqlx_err("analysis_empty_notifications", &e))?;
                    Ok(())
                })
            })
            .await?;
    }
    if pending.is_empty() {
        return Ok(count);
    }
    let channels = state
        .configurations
        .list::<crate::notification_config::StoredChannel>(tenant, crate::notification_config::KIND)
        .await?;
    for (event_id, ids) in pending {
        for id in ids {
            if let Some(alert) = state.store.alert_get_durable(tenant, id).await? {
                if alert.is_active() {
                    crate::notification_outbox::enqueue(
                        state,
                        tenant,
                        channels.clone(),
                        "alert",
                        id,
                        &alert.title,
                        &alert.description,
                        alert.severity,
                    )
                    .await?;
                }
            }
        }
        store
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    sqlx::query("UPDATE event_analysis_receipts SET notification_enqueued_at=now() WHERE event_id=$1")
                        .bind(event_id)
                        .execute(&mut **tx)
                        .await
                        .map_err(|e| agf_storage::map_sqlx_err("analysis_notification_receipt", &e))?;
                    Ok(())
                })
            })
            .await?;
    }
    Ok(count)
}
