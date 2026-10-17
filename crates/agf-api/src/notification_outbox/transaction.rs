//! Append notifications inside the caller's tenant transaction, without sending them.
use super::*;
use agf_storage::{TenantTransaction, map_sqlx_err};

#[derive(Debug)]
pub(crate) struct EnqueueMessage<'a> {
    pub subject: &'a str,
    pub id: Id,
    pub title: &'a str,
    pub body: &'a str,
    pub severity: Severity,
}

pub(crate) async fn enqueue_transaction(
    state: &AppState,
    tx: &mut TenantTransaction<'_>,
    rows: Vec<StoredChannel>,
    message: EnqueueMessage<'_>,
) -> DomainResult<Vec<Id>> {
    let tenant = tx.tenant();
    let id = queue_id(tenant);
    let jobs =
        prepare_jobs(state, tenant, rows, message.subject, message.id, message.title, message.body, message.severity)?;
    let ids = jobs.iter().map(|job| job.id).collect();
    // Match ConfigStore::mutate's record lock; normal enqueue/claim/retry shares this lock.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("{tenant}:{KIND}:{id}"))
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("lock_notification_outbox", &e))?;
    let value: Option<Value> =
        sqlx::query_scalar("SELECT payload FROM console_configurations WHERE kind=$1 AND id=$2 AND deleted_at IS NULL")
            .bind(KIND)
            .bind(id.as_uuid())
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("read_notification_outbox", &e))?;
    let mut queue: Queue = value.map(serde_json::from_value).transpose()?.unwrap_or_default();
    insert_jobs(&mut queue, jobs, Timestamp::now())?;
    sqlx::query(
        "INSERT INTO console_configurations (tenant_id,kind,id,payload) VALUES ($1,$2,$3,$4)
        ON CONFLICT (tenant_id,kind,id) DO UPDATE SET payload=excluded.payload,updated_at=now(),deleted_at=NULL",
    )
    .bind(tenant.as_uuid())
    .bind(KIND)
    .bind(id.as_uuid())
    .bind(serde_json::to_value(queue)?)
    .execute(&mut **tx)
    .await
    .map_err(|e| map_sqlx_err("write_notification_outbox", &e))?;
    Ok(ids)
}
