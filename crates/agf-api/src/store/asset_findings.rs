//! Counts for one visible inventory page, sourced from current tenant findings.
use super::*;
use agf_core::risk::FindingState;

impl ApiStore {
    pub(crate) async fn asset_open_findings(&self, tenant: TenantId, ids: &[Id]) -> DomainResult<BTreeMap<Id, i64>> {
        if ids.len() > 200 {
            return Err(DomainError::Validation("Finding counts are limited to one 200-asset page".into()));
        }
        let mut counts: BTreeMap<Id, i64> = ids.iter().copied().map(|id| (id, 0)).collect();
        if ids.is_empty() {
            return Ok(counts);
        }
        let Some(db) = &self.database else {
            let memory = self.lock()?;
            for finding in memory.findings.values() {
                if finding.tenant_id != tenant
                    || finding.deleted_at.is_some()
                    || matches!(finding.state, FindingState::Fixed | FindingState::FalsePositive)
                {
                    continue;
                }
                if let Some(value) = finding.asset_id.and_then(|id| counts.get_mut(&id)) {
                    *value += 1;
                }
            }
            return Ok(counts);
        };
        let ids = ids.iter().map(Id::as_uuid).collect::<Vec<_>>();
        db.with_tenant(tenant, move |tx| {
            Box::pin(async move {
                let rows: Vec<(uuid::Uuid, i64)> = sqlx::query_as(
                    "SELECT asset_id,count(*) FROM findings WHERE asset_id=ANY($1) AND deleted_at IS NULL
                 AND state NOT IN ('fixed','false-positive') GROUP BY asset_id",
                )
                .bind(ids)
                .fetch_all(&mut **tx)
                .await
                .map_err(|error| agf_storage::map_sqlx_err("asset_open_findings", &error))?;
                for (id, count) in rows {
                    counts.insert(Id::from_uuid(id), count);
                }
                Ok(counts)
            })
        })
        .await
    }
}
