//! Persistent bounded retries with safe diagnostics and operator-controlled recovery.
use super::{AppState, database};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};

// Arbitrary dependency errors can contain source events or credentials.
fn diagnostic(error: &DomainError) -> (&'static str, &'static str) {
    match error {
        DomainError::Parse(_) => {
            ("invalid_event", "Stored event schema is invalid; inspect evidence and parser compatibility")
        }
        DomainError::Validation(_) => {
            ("invalid_rule_or_window", "Check published rule parameters and correlation window limits")
        }
        DomainError::Config(_) => ("configuration", "Check rule and analysis configuration"),
        DomainError::DependencyUnavailable { .. } | DomainError::Timeout(_) => {
            ("dependency", "Check database availability, analysis timeout and service logs")
        }
        DomainError::Forbidden(_) | DomainError::TenantViolation { .. } => {
            ("authorization", "Check tenant status and analysis authorization")
        }
        DomainError::Crypto(_) => ("encryption", "Check the configured encryption key without replacing it"),
        _ => ("analysis_failed", "Inspect this event's ID in server logs; verify rule output and database health"),
    }
}

pub(super) async fn record(state: &AppState, tenant: TenantId, id: Id, error: &DomainError) -> DomainResult<()> {
    let (code, message) = diagnostic(error);
    database(state)?.with_tenant(tenant, move |tx| Box::pin(async move {
        sqlx::query("INSERT INTO event_analysis_retries(tenant_id,event_id,error_code,last_error)
            SELECT $1,$2,$3,$4 WHERE NOT EXISTS (SELECT 1 FROM event_analysis_receipts WHERE event_id=$2)
            ON CONFLICT (tenant_id,event_id) DO UPDATE SET attempts=event_analysis_retries.attempts+1,
            total_attempts=event_analysis_retries.total_attempts+1,version=event_analysis_retries.version+1,
            error_code=EXCLUDED.error_code,last_error=EXCLUDED.last_error,
            available_at=now()+make_interval(secs=>LEAST(300,10*power(2,LEAST(event_analysis_retries.attempts,5)))::integer),
            updated_at=now() WHERE NOT event_analysis_retries.paused AND event_analysis_retries.attempts<8
            AND event_analysis_retries.resolved_at IS NULL")
            .bind(tenant.as_uuid()).bind(id.as_uuid()).bind(code).bind(message).execute(&mut **tx).await
            .map_err(|e| agf_storage::map_sqlx_err("analysis_retry", &e))?;
        Ok(())
    })).await
}

/// Broker redelivery must respect a persisted pause, quarantine and retry backoff.
pub(super) async fn deferred(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<bool> {
    database(state)?.with_tenant(tenant, move |tx| Box::pin(async move { deferred_in_transaction(tx, id).await })).await
}

pub(super) async fn deferred_in_transaction(tx: &mut agf_storage::TenantTransaction<'_>, id: Id) -> DomainResult<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM event_analysis_retries WHERE event_id=$1
            AND resolved_at IS NULL AND (paused OR attempts>=8 OR available_at>now()))",
    )
    .bind(id.as_uuid())
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| agf_storage::map_sqlx_err("analysis_deferred", &e))
}

/// Transfer responsibility only after proving the referenced evidence exists durably in this tenant.
pub(super) async fn handoff(
    state: &AppState,
    event: &agf_core::event::Event,
    error: &DomainError,
) -> DomainResult<bool> {
    let tenant = event.tenant_id;
    let id = event.id;
    let time = event.time;
    let exists: bool = database(state)?
        .with_tenant(tenant, move |tx| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM events WHERE id=$1 AND time=$2)")
                    .bind(id.as_uuid())
                    .bind(time.as_datetime())
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(|e| agf_storage::map_sqlx_err("analysis_handoff_evidence", &e))
            })
        })
        .await?;
    if !exists {
        return Ok(false);
    }
    // An existing backoff, pause or quarantine already owns recovery. Redelivery must not consume another attempt.
    if !deferred(state, tenant, id).await? {
        record(state, tenant, id, error).await?;
    }
    Ok(true)
}
