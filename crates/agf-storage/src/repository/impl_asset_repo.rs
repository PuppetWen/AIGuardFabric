//! 由 `repository.rs` 拆分：`AssetRepo` 的实现（纯搬移，逻辑不变）。
use super::*;

use crate::db::{TenantTransaction, map_sqlx_err};
use agf_core::asset::{Asset, AssetChange, ChangeKind};
use agf_core::enums::{AssetKind, LifecycleState, RiskDomain};
use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::Id;
use agf_core::pagination::{Page, PageRequest};
use agf_core::time::Timestamp;
use std::collections::BTreeMap;

impl AssetRepo {
    /// 资产发现写入（幂等：按 `fingerprint` 更新或插入）。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn upsert(tx: &mut TenantTransaction<'_>, asset: &Asset) -> DomainResult<Id> {
        // Rediscovery of a removed fingerprint restores its stable ID and retained history.
        // The later UPDATE refreshes observed fields within this same transaction.
        sqlx::query("UPDATE assets SET deleted_at=NULL WHERE id=$1 AND tenant_id=$2 AND fingerprint=$3 AND deleted_at IS NOT NULL")
            .bind(asset.id.as_uuid())
            .bind(asset.tenant_id.as_uuid())
            .bind(&asset.fingerprint)
            .execute(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("revive_asset", &e))?;
        let updated = sqlx::query(
            r"UPDATE assets SET
                 name = $1, kind = $2, vendor = $3, version = $4, protocol = $5, endpoint = $6,
                 owner = COALESCE($7, owner), department = CASE WHEN $8::text = '' THEN NULL ELSE COALESCE($8, department) END,
                 data_class = $9, exposure_score = $10, runtime = $11, network_zone = $12,
                 cloud_resource_id = COALESCE($13, cloud_resource_id), tags = $14, attributes = $15,
                 dependencies = $16, last_seen_at = $17, updated_at = now()
               WHERE fingerprint = $18 AND deleted_at IS NULL
               RETURNING id",
        )
        .bind(&asset.name)
        .bind(asset.kind.as_str())
        .bind(&asset.vendor)
        .bind(&asset.version)
        .bind(asset.protocol.map(|p| p.as_str().to_string()))
        .bind(&asset.endpoint)
        .bind(&asset.owner)
        .bind(&asset.department)
        .bind(asset.data_class.as_str())
        .bind(i16::from(asset.exposure_score))
        .bind(&asset.runtime)
        .bind(&asset.network_zone)
        .bind(&asset.cloud_resource_id)
        .bind(serde_json::to_value(&asset.tags).unwrap_or(serde_json::Value::Null))
        .bind(serde_json::to_value(&asset.attributes).unwrap_or(serde_json::Value::Null))
        .bind(serde_json::to_value(&asset.dependencies).unwrap_or(serde_json::Value::Null))
        .bind(asset.last_seen_at.as_ref().map(Timestamp::as_datetime))
        .bind(&asset.fingerprint)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("update_asset_by_fp", &e))?;

        if let Some(row) = updated {
            let id: uuid::Uuid = row.try_get("id").map_err(|e| DomainError::Internal(e.to_string()))?;
            return Ok(Id::from_uuid(id));
        }

        sqlx::query(
            r"INSERT INTO assets (
                 id, tenant_id, kind, name, fingerprint, vendor, version, protocol, endpoint,
                 owner, department, data_class, lifecycle, discovery_source, exposure_score,
                 runtime, network_zone, cloud_resource_id, tags, attributes, dependencies,
                 risk_score, last_seen_at, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)",
        )
        .bind(asset.id.as_uuid())
        .bind(asset.tenant_id.as_uuid())
        .bind(asset.kind.as_str())
        .bind(&asset.name)
        .bind(&asset.fingerprint)
        .bind(&asset.vendor)
        .bind(&asset.version)
        .bind(asset.protocol.map(|p| p.as_str().to_string()))
        .bind(&asset.endpoint)
        .bind(&asset.owner)
        .bind(&asset.department)
        .bind(asset.data_class.as_str())
        .bind(asset.lifecycle.as_str())
        .bind(asset.discovery_source.as_str())
        .bind(i16::from(asset.exposure_score))
        .bind(&asset.runtime)
        .bind(&asset.network_zone)
        .bind(&asset.cloud_resource_id)
        .bind(serde_json::to_value(&asset.tags).unwrap_or(serde_json::Value::Null))
        .bind(serde_json::to_value(&asset.attributes).unwrap_or(serde_json::Value::Null))
        .bind(serde_json::to_value(&asset.dependencies).unwrap_or(serde_json::Value::Null))
        .bind(asset.risk_score.map(i16::from))
        .bind(asset.last_seen_at.as_ref().map(Timestamp::as_datetime))
        .bind(asset.created_at.as_datetime())
        .bind(asset.updated_at.as_datetime())
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("insert_asset", &e))?;
        Ok(asset.id)
    }

    /// 按 id 读取。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn get(tx: &mut TenantTransaction<'_>, id: Id) -> DomainResult<Option<Asset>> {
        let row = sqlx::query("SELECT * FROM assets WHERE id = $1 AND deleted_at IS NULL")
            .bind(id.as_uuid())
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("get_asset", &e))?;
        row.as_ref().map(row_to_asset).transpose()
    }

    /// 按指纹读取。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn get_by_fingerprint(tx: &mut TenantTransaction<'_>, fingerprint: &str) -> DomainResult<Option<Asset>> {
        let row = sqlx::query("SELECT * FROM assets WHERE fingerprint = $1 AND deleted_at IS NULL")
            .bind(fingerprint)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("get_asset_by_fp", &e))?;
        row.as_ref().map(row_to_asset).transpose()
    }

    /// 分页列出资产。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn list(
        tx: &mut TenantTransaction<'_>,
        req: &PageRequest,
        kind: Option<AssetKind>,
        min_exposure: Option<u8>,
    ) -> DomainResult<Page<Asset>> {
        let n = req.normalized();
        let kind_s = kind.map(|k| k.as_str().to_string());
        let exp = min_exposure.map(i32::from);
        let total: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM assets WHERE deleted_at IS NULL \
             AND ($1::text IS NULL OR kind = $1) AND ($2::int IS NULL OR exposure_score >= $2)",
        )
        .bind(kind_s.clone())
        .bind(exp)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("count_assets", &e))?;
        let rows = sqlx::query(
            "SELECT * FROM assets WHERE deleted_at IS NULL \
             AND ($1::text IS NULL OR kind = $1) AND ($2::int IS NULL OR exposure_score >= $2) \
             ORDER BY exposure_score DESC, updated_at DESC LIMIT $3 OFFSET $4",
        )
        .bind(kind_s)
        .bind(exp)
        .bind(n.limit())
        .bind(n.offset())
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("list_assets", &e))?;
        let items = rows.iter().map(row_to_asset).collect::<DomainResult<Vec<_>>>()?;
        Ok(Page::new(items, total, req))
    }

    /// 列出存活资产（拓扑构建）。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn list_all(tx: &mut TenantTransaction<'_>, limit: i64) -> DomainResult<Vec<Asset>> {
        let rows = sqlx::query("SELECT * FROM assets WHERE deleted_at IS NULL ORDER BY kind, name LIMIT $1")
            .bind(limit)
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("list_all_assets", &e))?;
        rows.iter().map(row_to_asset).collect()
    }

    /// 更新生命周期。
    ///
    /// # Errors
    /// 记录不存在或 SQL 失败。
    pub async fn set_lifecycle(tx: &mut TenantTransaction<'_>, id: Id, state: LifecycleState) -> DomainResult<()> {
        let affected =
            sqlx::query("UPDATE assets SET lifecycle = $1, updated_at = now() WHERE id = $2 AND deleted_at IS NULL")
                .bind(state.as_str())
                .bind(id.as_uuid())
                .execute(&mut **tx)
                .await
                .map_err(|e| map_sqlx_err("set_lifecycle", &e))?
                .rows_affected();
        if affected == 0 {
            return Err(DomainError::NotFound { entity: "asset", id: id.to_string() });
        }
        Ok(())
    }

    /// 软删除。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn soft_delete(tx: &mut TenantTransaction<'_>, id: Id) -> DomainResult<()> {
        let affected = sqlx::query(
            "UPDATE assets SET deleted_at = now(), updated_at = now() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id.as_uuid())
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("delete_asset", &e))?
        .rows_affected();
        if affected == 0 {
            return Err(DomainError::NotFound { entity: "asset", id: id.to_string() });
        }
        Ok(())
    }

    /// 写入变更记录。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn insert_change(tx: &mut TenantTransaction<'_>, change: &AssetChange) -> DomainResult<()> {
        sqlx::query(
            "INSERT INTO asset_changes (id, tenant_id, asset_id, kind, change_kind, field, old_value,
                new_value, risky, risk_note, domain, detected_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(change.id.as_uuid())
        .bind(change.tenant_id.as_uuid())
        .bind(change.asset_id.as_uuid())
        .bind(change.kind.as_str())
        .bind(change.change_kind.as_str())
        .bind(&change.field)
        .bind(&change.old_value)
        .bind(&change.new_value)
        .bind(change.risky)
        .bind(&change.risk_note)
        .bind(change.domain.map(|d| d.as_str().to_string()))
        .bind(change.detected_at.as_datetime())
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("insert_asset_change", &e))?;
        Ok(())
    }

    /// 变更历史。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn list_changes(
        tx: &mut TenantTransaction<'_>,
        asset_id: Id,
        limit: i64,
    ) -> DomainResult<Vec<AssetChange>> {
        let rows = sqlx::query("SELECT * FROM asset_changes WHERE asset_id = $1 ORDER BY detected_at DESC LIMIT $2")
            .bind(asset_id.as_uuid())
            .bind(limit)
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("list_asset_changes", &e))?;
        let tenant = tx.tenant();
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let kind_raw: String = r.try_get("kind").unwrap_or_default();
            let ck_raw: String = r.try_get("change_kind").unwrap_or_default();
            let domain_raw: Option<String> = r.try_get("domain").unwrap_or(None);
            out.push(AssetChange {
                id: uuid_col(&r, "id")?,
                tenant_id: tenant,
                asset_id: uuid_col(&r, "asset_id")?,
                kind: AssetKind::parse(&kind_raw).unwrap_or(AssetKind::Other),
                change_kind: match ck_raw.as_str() {
                    "added" => ChangeKind::Added,
                    "removed" => ChangeKind::Removed,
                    _ => ChangeKind::Modified,
                },
                field: r.try_get("field").unwrap_or(None),
                old_value: r.try_get("old_value").unwrap_or(None),
                new_value: r.try_get("new_value").unwrap_or(None),
                risky: r.try_get("risky").unwrap_or(false),
                risk_note: r.try_get("risk_note").unwrap_or(None),
                domain: domain_raw.and_then(|d| RiskDomain::parse(&d).ok()),
                detected_at: ts_col(&r, "detected_at"),
            });
        }
        Ok(out)
    }

    /// 写入当日首次观测快照；重复写入不会替换已有基线。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn snapshot(tx: &mut TenantTransaction<'_>, snapshot_date: &str, asset: &Asset) -> DomainResult<()> {
        let payload = serde_json::to_value(asset).unwrap_or(serde_json::Value::Null);
        let hash = agf_core::secret::content_hash(&payload.to_string());
        sqlx::query(
            "INSERT INTO asset_snapshots (id, tenant_id, snapshot_date, asset_id, kind, payload, content_hash)
             VALUES ($1,$2,$3::date,$4,$5,$6,$7)
             ON CONFLICT (tenant_id,snapshot_date,asset_id) DO NOTHING",
        )
        .bind(Id::new().as_uuid())
        .bind(tx.tenant().as_uuid())
        .bind(snapshot_date)
        .bind(asset.id.as_uuid())
        .bind(asset.kind.as_str())
        .bind(&payload)
        .bind(&hash)
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("insert_snapshot", &e))?;
        Ok(())
    }

    /// 指定日期的快照（`asset_id → content_hash`）。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn snapshots_on(
        tx: &mut TenantTransaction<'_>,
        snapshot_date: &str,
    ) -> DomainResult<BTreeMap<Id, String>> {
        let rows = sqlx::query("SELECT asset_id, content_hash FROM asset_snapshots WHERE snapshot_date = $1::date")
            .bind(snapshot_date)
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("list_snapshots", &e))?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    Id::from_uuid(r.try_get("asset_id").unwrap_or_else(|_| uuid::Uuid::nil())),
                    r.try_get::<String, _>("content_hash").unwrap_or_default(),
                )
            })
            .collect())
    }
}
