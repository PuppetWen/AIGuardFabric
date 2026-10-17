//! Tenant-scoped SQL delivery leases. Mark delivered only after the broker acknowledges storage.
use super::EventBus;
use agf_core::{
    error::{DomainError, DomainResult},
    event::Event,
    ids::{Id, TenantId},
};
use agf_storage::Store;
use futures::{StreamExt, stream};
use sqlx::Row;
use std::{sync::Arc, time::Duration};

/// Durable delivery queue for one tenant. Multiple workers coordinate through SQL leases.
#[derive(Debug, Clone)]
pub struct EventOutbox {
    store: Arc<Store>,
    tenant: TenantId,
}

/// Result of one bounded delivery attempt.
#[derive(Debug, Default, serde::Serialize)]
pub struct DeliveryReport {
    /// Rows acquired from the durable queue.
    pub claimed: usize,
    /// Publications confirmed by the broker.
    pub delivered: usize,
    /// Failed attempts scheduled for retry.
    pub failed: usize,
}

impl EventOutbox {
    /// Bind delivery to an explicit tenant.
    #[must_use]
    pub fn new(store: Arc<Store>, tenant: TenantId) -> Self {
        Self { store, tenant }
    }

    /// Claim at most 128 records for 120 seconds. Up to 16 sends await individual
    /// broker acknowledgements concurrently, each bounded to five seconds.
    pub async fn drain_once(&self, bus: &dyn EventBus) -> DomainResult<DeliveryReport> {
        let enabled: Option<bool> =
            sqlx::query_scalar("SELECT enabled FROM tenants WHERE id=$1 AND deleted_at IS NULL")
                .bind(self.tenant.as_uuid())
                .fetch_optional(self.store.db().pool())
                .await
                .map_err(db_error)?;
        if enabled != Some(true) {
            return Ok(DeliveryReport::default());
        }
        let lease = Id::new();
        let mut tx = self.store.db().begin_tenant(self.tenant).await?;
        let rows = sqlx::query(
            "WITH pending AS (
            SELECT event_id FROM event_delivery_outbox WHERE delivered_at IS NULL AND deleted_at IS NULL
            AND available_at<=now() AND (lease_until IS NULL OR lease_until<now())
            ORDER BY available_at, event_id FOR UPDATE SKIP LOCKED LIMIT 128
        ) UPDATE event_delivery_outbox q SET lease_id=$1, lease_until=now()+interval '120 seconds',
            attempts=attempts+1, updated_at=now() FROM pending p WHERE q.event_id=p.event_id
            RETURNING q.event_id, q.payload, q.attempts",
        )
        .bind(lease.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await?;
        let mut report = DeliveryReport { claimed: rows.len(), ..Default::default() };
        if rows.is_empty() {
            return Ok(report);
        }
        let mut pending = Vec::with_capacity(rows.len());
        for row in rows {
            let id: uuid::Uuid = row.try_get("event_id").map_err(db_error)?;
            let payload: serde_json::Value = row.try_get("payload").map_err(db_error)?;
            let attempts: i32 = row.try_get("attempts").map_err(db_error)?;
            pending.push((id, payload, attempts));
        }
        // Collect every outcome: one failed send must never cancel confirmed
        // siblings or cause an unconfirmed event to receive a delivered receipt.
        let receipts: Vec<_> = stream::iter(pending)
            .map(|(id, payload, attempts)| async move {
                let event = serde_json::from_value::<Event>(payload);
                let success = if let Ok(event) = event {
                    event.tenant_id == self.tenant
                        && event.id.as_uuid() == id
                        && matches!(tokio::time::timeout(Duration::from_secs(5), bus.publish(&event)).await, Ok(Ok(())))
                } else {
                    false
                };
                let backoff = 5_i64.saturating_mul(1_i64 << attempts.clamp(0, 6)).min(300);
                (id, success, backoff as f64)
            })
            .buffer_unordered(16)
            .collect()
            .await;
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "UPDATE event_delivery_outbox q SET
             delivered_at=CASE WHEN receipt.success THEN now() ELSE NULL END,
             available_at=now()+make_interval(secs=>receipt.backoff), lease_id=NULL, lease_until=NULL,
             last_error=CASE WHEN receipt.success THEN NULL ELSE 'Publication unconfirmed; retry scheduled' END,
             updated_at=now() FROM (",
        );
        query.push_values(&receipts, |mut row, (id, success, backoff)| {
            // Explicit casts also give a single-row VALUES table stable types.
            row.push_bind(*id)
                .push_unseparated("::uuid")
                .push_bind(*success)
                .push_unseparated("::boolean")
                .push_bind(*backoff)
                .push_unseparated("::double precision");
        });
        query
            .push(") AS receipt(event_id,success,backoff) WHERE q.event_id=receipt.event_id AND q.tenant_id=")
            .push_bind(self.tenant.as_uuid())
            .push(" AND q.lease_id=")
            .push_bind(lease.as_uuid())
            .push(" AND q.deleted_at IS NULL RETURNING (q.delivered_at IS NOT NULL) AS delivered");
        let mut tx = self.store.db().begin_tenant(self.tenant).await?;
        let recorded = query.build().fetch_all(&mut *tx).await.map_err(db_error)?;
        tx.commit().await?;
        // Only committed rows still owned by our lease count as receipts.
        for row in recorded {
            if row.try_get::<bool, _>("delivered").map_err(db_error)? {
                report.delivered += 1;
            } else {
                report.failed += 1;
            }
        }
        Ok(report)
    }

    /// Pending and failed-at-least-once rows, without exposing event payloads.
    pub async fn pending(&self) -> DomainResult<(i64, i64)> {
        let mut tx = self.store.db().begin_tenant(self.tenant).await?;
        let result = sqlx::query_as(
            "SELECT count(*), count(*) FILTER (WHERE last_error IS NOT NULL)
            FROM event_delivery_outbox WHERE delivered_at IS NULL AND deleted_at IS NULL",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await?;
        Ok(result)
    }

    /// Remove confirmed delivery receipts after seven days; pending events are retained.
    pub async fn prune(&self) -> DomainResult<()> {
        let mut tx = self.store.db().begin_tenant(self.tenant).await?;
        sqlx::query("DELETE FROM event_delivery_outbox WHERE delivered_at<now()-interval '7 days'")
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        tx.commit().await
    }
}

fn db_error(error: sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("event_delivery", &error)
}
