//! One immutable baseline per UTC day, committed with its diff under the discovery lock.
use super::*;
use agf_asset::drift::{DriftScanner, DriftSummary};
use agf_core::{asset::Asset, time::Date};
use agf_storage::AssetRepo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryRun {
    pub id: Id,
    pub date: String,
    pub baseline_date: Option<String>,
    pub initial_baseline: bool,
    pub snapshot_count: usize,
    pub summary: DriftSummary,
    pub completed_at: Timestamp,
}

/// The supplied day supports deterministic recovery/testing; callers use today's UTC date.
pub async fn run_for_date(state: &AppState, tenant: TenantId, date: Date) -> DomainResult<InventoryRun> {
    if date.as_naive() > Date::today().as_naive() {
        return Err(DomainError::Validation("Inventory date cannot be in the future".into()));
    }
    let db = database(state)?;
    let mut tx = db.db().begin_tenant(tenant).await?;
    crate::store::asset_transaction::lock_tenant(&mut tx).await?;
    let current: Option<Value> = sqlx::query_scalar("SELECT payload FROM asset_inventory_runs WHERE inventory_date=$1")
        .bind(date.as_naive())
        .fetch_optional(&mut *tx)
        .await
        .map_err(sql_error)?;
    if let Some(current) = current {
        return Ok(serde_json::from_value(current)?);
    }
    let previous: Option<Value> =
        sqlx::query_scalar("SELECT payload FROM asset_inventory_runs ORDER BY inventory_date DESC LIMIT 1")
            .fetch_optional(&mut *tx)
            .await
            .map_err(sql_error)?;
    let previous: Option<InventoryRun> = previous.map(serde_json::from_value).transpose()?;
    if previous.as_ref().is_some_and(|run| run.date >= date.to_iso()) {
        return Err(DomainError::Conflict("Cannot insert an inventory before the latest completed run".into()));
    }
    let assets = AssetRepo::list_all(&mut tx, 100_001).await?;
    if assets.len() > 100_000 {
        return Err(DomainError::PreconditionFailed(
            "Daily inventory supports at most 100000 assets per tenant".into(),
        ));
    }
    let before: Vec<Asset> = if let Some(previous) = &previous {
        let rows: Vec<Value> =
            sqlx::query_scalar("SELECT payload FROM asset_inventory_snapshots WHERE run_id=$1 ORDER BY asset_id")
                .bind(previous.id.as_uuid())
                .fetch_all(&mut *tx)
                .await
                .map_err(sql_error)?;
        rows.into_iter().map(serde_json::from_value).collect::<Result<_, _>>()?
    } else {
        vec![]
    };
    // First inventory establishes a baseline, without inventing an unauthorized-asset incident.
    let changes = if previous.is_some() { DriftScanner::new().diff(&before, &assets) } else { vec![] };
    let mut summary = DriftScanner::summarize(&changes);
    // Detailed rows are paginated; do not repeat the entire risky list in every history response.
    summary.risky_assets.clear();
    let run = InventoryRun {
        id: Id::new(),
        date: date.to_iso(),
        baseline_date: previous.as_ref().map(|r| r.date.clone()),
        initial_baseline: previous.is_none(),
        snapshot_count: assets.len(),
        summary,
        completed_at: Timestamp::now(),
    };
    sqlx::query("INSERT INTO asset_inventory_runs(tenant_id,id,inventory_date,payload) VALUES ($1,$2,$3,$4)")
        .bind(tenant.as_uuid())
        .bind(run.id.as_uuid())
        .bind(date.as_naive())
        .bind(serde_json::to_value(&run)?)
        .execute(&mut *tx)
        .await
        .map_err(sql_error)?;
    for chunk in assets.chunks(500) {
        sqlx::query(
            "INSERT INTO asset_inventory_snapshots(tenant_id,run_id,asset_id,payload)
            SELECT $1,$2,(value->>'id')::uuid,value FROM jsonb_array_elements($3)",
        )
        .bind(tenant.as_uuid())
        .bind(run.id.as_uuid())
        .bind(serde_json::to_value(chunk)?)
        .execute(&mut *tx)
        .await
        .map_err(sql_error)?;
    }
    for (index, chunk) in changes.chunks(500).enumerate() {
        let offset =
            i32::try_from(index * 500).map_err(|_| DomainError::Internal("Inventory change limit exceeded".into()))?;
        sqlx::query(
            "INSERT INTO asset_inventory_changes(tenant_id,run_id,position,payload)
            SELECT $1,$2,$3+ordinality::integer,value FROM jsonb_array_elements($4) WITH ORDINALITY",
        )
        .bind(tenant.as_uuid())
        .bind(run.id.as_uuid())
        .bind(offset)
        .bind(serde_json::to_value(chunk)?)
        .execute(&mut *tx)
        .await
        .map_err(sql_error)?;
    }
    // Daily reports are a separate ledger; do not duplicate discovery/lifecycle events in asset_changes.
    tx.commit().await?;
    Ok(run)
}

pub async fn list(state: &AppState, tenant: TenantId, page: u64) -> DomainResult<Value> {
    let mut tx = database(state)?.db().begin_tenant(tenant).await?;
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM asset_inventory_runs").fetch_one(&mut *tx).await.map_err(sql_error)?;
    let rows: Vec<Value> =
        sqlx::query_scalar("SELECT payload FROM asset_inventory_runs ORDER BY inventory_date DESC LIMIT 20 OFFSET $1")
            .bind(offset(page, 20)?)
            .fetch_all(&mut *tx)
            .await
            .map_err(sql_error)?;
    Ok(json!({"items":rows,"total":total,"page":page,"page_size":20}))
}

pub async fn changes(state: &AppState, tenant: TenantId, id: Id, page: u64) -> DomainResult<Value> {
    let mut tx = database(state)?.db().begin_tenant(tenant).await?;
    let run: Option<Value> = sqlx::query_scalar("SELECT payload FROM asset_inventory_runs WHERE id=$1")
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(sql_error)?;
    let run = run.ok_or_else(|| DomainError::NotFound { entity: "asset-inventory", id: id.to_string() })?;
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT c.payload || jsonb_build_object('asset_name',COALESCE(
            (SELECT name FROM assets WHERE id=(c.payload->>'asset_id')::uuid),
            c.payload->'old_value'->>'name',c.payload->'new_value'->>'name'))
        FROM asset_inventory_changes c WHERE run_id=$1 ORDER BY position LIMIT 50 OFFSET $2",
    )
    .bind(id.as_uuid())
    .bind(offset(page, 50)?)
    .fetch_all(&mut *tx)
    .await
    .map_err(sql_error)?;
    Ok(json!({"items":rows,"total":run["summary"]["total"],"page":page,"page_size":50,"run":run}))
}

fn offset(page: u64, size: u64) -> DomainResult<i64> {
    if !(1..=1_000_000).contains(&page) {
        return Err(DomainError::Validation("Page must be between 1 and 1000000".into()));
    }
    i64::try_from((page - 1) * size).map_err(|_| DomainError::Validation("Page is too large".into()))
}

fn sql_error(error: sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("asset_inventory", &error)
}
