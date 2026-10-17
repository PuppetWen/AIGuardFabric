//! SQL aggregates use the same tenant-visible rows as inventory, including on a fresh API instance.
use super::*;

impl ApiStore {
    pub async fn asset_stats_durable(&self, tenant: TenantId) -> DomainResult<InventoryStats> {
        let Some(db) = &self.database else { return self.asset_stats(tenant) };
        db.with_tenant(tenant, |tx| Box::pin(async move {
            let value: serde_json::Value = sqlx::query_scalar(
                "WITH inventory AS (SELECT * FROM assets WHERE deleted_at IS NULL)
                SELECT jsonb_build_object(
                    'total',count(*),
                    'shadow',count(*) FILTER (WHERE lifecycle='trial' AND discovery_source<>'manual'),
                    'high_exposure',count(*) FILTER (WHERE exposure_score>=70),
                    'with_plaintext_secret',count(*) FILTER (WHERE attributes->'has_plaintext_secret'='true'::jsonb OR attributes->'hasPlaintextSecret'='true'::jsonb),
                    'avg_exposure',COALESCE(avg(exposure_score),0),
                    'by_kind',COALESCE((SELECT jsonb_object_agg(kind,n) FROM (SELECT kind,count(*) n FROM inventory GROUP BY kind) g),'{}'::jsonb),
                    'by_lifecycle',COALESCE((SELECT jsonb_object_agg(lifecycle,n) FROM (SELECT lifecycle,count(*) n FROM inventory GROUP BY lifecycle) g),'{}'::jsonb),
                    'by_source',COALESCE((SELECT jsonb_object_agg(discovery_source,n) FROM (SELECT discovery_source,count(*) n FROM inventory GROUP BY discovery_source) g),'{}'::jsonb)
                ) FROM inventory"
            ).fetch_one(&mut **tx).await.map_err(|e| agf_storage::map_sqlx_err("asset_statistics", &e))?;
            Ok(serde_json::from_value(value)?)
        })).await
    }

    pub async fn platform_snapshot_durable(&self, tenant: TenantId) -> DomainResult<PlatformSnapshot> {
        let Some(db) = &self.database else { return self.platform_snapshot(tenant) };
        db.with_tenant(tenant, |tx| Box::pin(async move {
            let value: serde_json::Value = sqlx::query_scalar(
                "SELECT jsonb_build_object(
                    'assets',(SELECT count(*) FROM assets WHERE deleted_at IS NULL),
                    'assets_production',(SELECT count(*) FROM assets WHERE deleted_at IS NULL AND lifecycle='production'),
                    'shadow_mcps',(SELECT count(*) FROM assets WHERE deleted_at IS NULL AND kind='mcp-server' AND lifecycle<>'production'),
                    'findings_open',(SELECT count(*) FROM findings WHERE deleted_at IS NULL AND state NOT IN ('fixed','false-positive')),
                    'findings_critical',(SELECT count(*) FROM findings WHERE deleted_at IS NULL AND severity='critical' AND state NOT IN ('false-positive','fixed')),
                    'alerts_active',(SELECT count(*) FROM alerts WHERE state IN ('open','acknowledged','escalated')),
                    'cases_open',(SELECT count(*) FROM cases WHERE state<>'closed'),
                    'scans',(SELECT count(*) FROM scan_jobs WHERE deleted_at IS NULL),
                    'policies',COALESCE((SELECT (SELECT count(*) FROM jsonb_each(payload->'entries') e WHERE e.value->>'deleted_at' IS NULL)
                        FROM console_configurations WHERE kind='signed-policy-registry' AND deleted_at IS NULL LIMIT 1),
                        (SELECT count(*) FROM policies WHERE deleted_at IS NULL)))"
            ).fetch_one(&mut **tx).await.map_err(|e| agf_storage::map_sqlx_err("platform_snapshot", &e))?;
            Ok(serde_json::from_value(value)?)
        })).await
    }

    /// Drift reports select the full time window, never silently trim each asset to its last 200 changes.
    pub async fn asset_changes_in_range(&self, tenant: TenantId, range: &TimeRange) -> DomainResult<Vec<AssetChange>> {
        let Some(db) = &self.database else {
            return Ok(self
                .lock()?
                .changes
                .iter()
                .filter(|row| row.tenant_id == tenant && row.detected_at >= range.from && row.detected_at < range.to)
                .cloned()
                .collect());
        };
        let range = *range;
        db.with_tenant(tenant, move |tx| Box::pin(async move {
            let rows: Vec<serde_json::Value> = sqlx::query_scalar(
                "SELECT to_jsonb(c) FROM asset_changes c WHERE detected_at >= $1 AND detected_at < $2 ORDER BY detected_at,id LIMIT 100001"
            ).bind(range.from.as_datetime()).bind(range.to.as_datetime()).fetch_all(&mut **tx).await
                .map_err(|e|agf_storage::map_sqlx_err("asset_change_window",&e))?;
            if rows.len()>100_000 {
                return Err(DomainError::Validation("More than 100000 asset changes; choose a shorter report window".into()));
            }
            Ok(rows.into_iter().map(serde_json::from_value).collect::<Result<_,_>>()?)
        })).await
    }
}
