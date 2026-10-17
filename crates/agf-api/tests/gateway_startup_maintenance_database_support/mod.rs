//! Owned database fixture failures are restored after both assertion panics and ordinary errors.
use crate::{common::*, gateway_settlement_database_support::*};
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
};
use base64::Engine as _;
use futures::FutureExt as _;
use std::{future::Future, panic::AssertUnwindSafe};

pub(crate) const CHECKPOINT: &str = "gateway-meter-checkpoint-v1";
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
pub(crate) async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL.lock().await
}
fn sql(error: &sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("owned_gateway_startup_fixture", error)
}

pub(crate) async fn with_corrupt_checkpoint<T, F: Future<Output = DomainResult<T>>>(
    owned: &Owned,
    run: F,
) -> DomainResult<T> {
    owned.ownership.verify(&owned.case.pool).await?;
    let h = &owned.case.h;
    let id = agf_api::model_routes::tenant_record_id(h.tenant);
    let original: SecretMaterial = h.state.configurations.get(h.tenant, CHECKPOINT, id).await?.ok_or_else(invalid)?;
    let mut bad = original.clone();
    let mut bytes = base64::engine::general_purpose::STANDARD.decode(&bad.ciphertext_b64).map_err(|_| invalid())?;
    *bytes.first_mut().ok_or_else(invalid)? ^= 1;
    bad.ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    h.state.configurations.put(h.tenant, CHECKPOINT, id, &bad).await?;
    let result = AssertUnwindSafe(run).catch_unwind().await;
    owned.ownership.verify(&owned.case.pool).await?;
    h.state.configurations.put(h.tenant, CHECKPOINT, id, &original).await?;
    finish(result)
}

pub(crate) async fn with_table_lock<T, F: Future<Output = DomainResult<T>>>(owned: &Owned, run: F) -> DomainResult<T> {
    owned.ownership.verify(&owned.case.pool).await?;
    let mut tx = owned.case.pool.begin().await.map_err(|error| sql(&error))?;
    // Exact-owned database only; this is a bounded wait fixture, not a production injector.
    sqlx::query("LOCK TABLE console_configurations IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await
        .map_err(|error| sql(&error))?;
    let result = AssertUnwindSafe(run).catch_unwind().await;
    tx.rollback().await.map_err(|error| sql(&error))?;
    finish(result)
}

pub(crate) async fn with_retired_tenant<T, F: Future<Output = DomainResult<T>>>(
    owned: &Owned,
    run: F,
) -> DomainResult<T> {
    owned.ownership.verify(&owned.case.pool).await?;
    let tenant = owned.case.h.tenant.as_uuid();
    let original: (bool, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT enabled,deleted_at FROM tenants WHERE id=$1")
            .bind(tenant)
            .fetch_one(&owned.case.pool)
            .await
            .map_err(|error| sql(&error))?;
    let rows = sqlx::query(
        "UPDATE tenants SET enabled=false,deleted_at=now(),version=version+1 WHERE id=$1 AND deleted_at IS NULL",
    )
    .bind(tenant)
    .execute(&owned.case.pool)
    .await
    .map_err(|error| sql(&error))?
    .rows_affected();
    if rows != 1 {
        return Err(invalid());
    }
    let result = AssertUnwindSafe(run).catch_unwind().await;
    owned.ownership.verify(&owned.case.pool).await?;
    sqlx::query("UPDATE tenants SET enabled=$2,deleted_at=$3,version=version+1 WHERE id=$1")
        .bind(tenant)
        .bind(original.0)
        .bind(original.1)
        .execute(&owned.case.pool)
        .await
        .map_err(|error| sql(&error))?;
    finish(result)
}
fn finish<T>(result: Result<DomainResult<T>, Box<dyn std::any::Any + Send>>) -> DomainResult<T> {
    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

pub(crate) async fn ledger(h: &Harness, kind: &str) -> DomainResult<Value> {
    h.state
        .configurations
        .get(h.tenant, kind, agf_api::model_routes::tenant_record_id(h.tenant))
        .await?
        .ok_or_else(invalid)
}
pub(crate) fn concurrency(ledger: &Value) -> DomainResult<i64> {
    let rows = ledger["counters"].as_object().ok_or_else(invalid)?;
    if rows.len() != 1 {
        return Err(invalid());
    }
    rows.values().next().and_then(|row| row["used"].as_i64()).ok_or_else(invalid)
}
pub(crate) async fn expiry_count(h: &Harness, id: agf_core::ids::Id) -> DomainResult<usize> {
    Ok(h.state
        .store
        .audit_chain_durable(h.tenant, 0, i64::MAX)
        .await?
        .into_iter()
        .filter(|row| {
            row.target.kind == "gateway-attempt-expiry" && row.target.id.as_deref() == Some(id.to_string().as_str())
        })
        .count())
}

pub(crate) async fn with_deleted_checkpoint<T, F: Future<Output = DomainResult<T>>>(
    owned: &Owned,
    run: F,
) -> DomainResult<T> {
    owned.ownership.verify(&owned.case.pool).await?;
    let h = &owned.case.h;
    let id = agf_api::model_routes::tenant_record_id(h.tenant);
    let original: SecretMaterial = h.state.configurations.get(h.tenant, CHECKPOINT, id).await?.ok_or_else(invalid)?;
    h.state.configurations.delete(h.tenant, CHECKPOINT, id).await?;
    let result = AssertUnwindSafe(run).catch_unwind().await;
    owned.ownership.verify(&owned.case.pool).await?;
    h.state.configurations.put(h.tenant, CHECKPOINT, id, &original).await?;
    finish(result)
}
