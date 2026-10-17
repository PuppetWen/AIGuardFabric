use super::asset_transaction::AssetTransaction;
use super::*;
use agf_asset::{
    discovery::DiscoveryBatch,
    drift::DriftReport,
    service::{AssetService, IngestStats, LifecycleTransition},
};

impl ApiStore {
    /// Read, change and record history while holding the same database lock as discovery.
    pub(crate) async fn asset_mutate_durable<F>(&self, tenant: TenantId, id: Id, mutate: F) -> DomainResult<Asset>
    where
        F: FnOnce(Option<Asset>) -> DomainResult<(Asset, Option<AssetChange>)> + Send,
    {
        self.asset_mutate_inner(tenant, id, None, mutate).await
    }

    /// Commit a reviewed asset change and its success audit in one SQL transaction.
    pub(crate) async fn asset_mutate_audited_durable<F>(
        &self,
        tenant: TenantId,
        id: Id,
        audit: AuditLog,
        mutate: F,
    ) -> DomainResult<Asset>
    where
        F: FnOnce(Option<Asset>) -> DomainResult<(Asset, Option<AssetChange>)> + Send,
    {
        self.asset_mutate_inner(tenant, id, Some(audit), mutate).await
    }

    async fn asset_mutate_inner<F>(
        &self,
        tenant: TenantId,
        id: Id,
        audit: Option<AuditLog>,
        mutate: F,
    ) -> DomainResult<Asset>
    where
        F: FnOnce(Option<Asset>) -> DomainResult<(Asset, Option<AssetChange>)> + Send,
    {
        if let Some(db) = &self.database {
            let backend = AssetTransaction::begin(db, tenant).await?;
            let current = backend.find(tenant, id).await?;
            let (asset, change) = mutate(current.clone())?;
            if change.is_none()
                && current.as_ref().map(serde_json::to_value).transpose()? == Some(serde_json::to_value(&asset)?)
            {
                return Ok(asset);
            }
            if asset.id != id {
                return Err(DomainError::Validation("An asset mutation cannot replace its ID".into()));
            }
            backend.upsert(tenant, &asset).await?;
            if let Some(change) = &change {
                validate_change(tenant, id, change)?;
                backend.record_change(tenant, change).await?;
            }
            if let Some(entry) = audit {
                backend.audit(entry).await?;
            }
            let saved = backend
                .find(tenant, id)
                .await?
                .ok_or_else(|| DomainError::NotFound { entity: "asset", id: id.to_string() })?;
            backend.commit(self).await?;
            return Ok(saved);
        }
        let asset = {
            let mut memory = self.lock()?;
            let current = memory.assets.get(&(tenant, id)).cloned();
            let (asset, change) = mutate(current.clone())?;
            if change.is_none()
                && current.as_ref().map(serde_json::to_value).transpose()? == Some(serde_json::to_value(&asset)?)
            {
                return Ok(asset);
            }
            if asset.tenant_id != tenant || asset.id != id {
                return Err(DomainError::Validation("Asset mutation changed its identity".into()));
            }
            if memory.assets.values().any(|existing| {
                existing.tenant_id == tenant && existing.id != id && existing.fingerprint == asset.fingerprint
            }) {
                return Err(DomainError::Conflict("Asset fingerprint belongs to a different canonical ID".into()));
            }
            if let Some(change) = &change {
                validate_change(tenant, id, change)?;
            }
            memory.assets.insert((tenant, id), asset.clone());
            if let Some(change) = change {
                memory.changes.push(change);
            }
            asset
        };
        if let Some(entry) = audit {
            self.audit_append_durable(entry).await?;
        }
        Ok(asset)
    }

    /// All discovered rows, change records and baseline snapshots commit before reporting success.
    pub async fn asset_ingest_durable(&self, tenant: TenantId, batch: &DiscoveryBatch) -> DomainResult<IngestStats> {
        self.asset_ingest_inner(tenant, batch, None).await
    }

    /// Commit a discovery batch and its success audit together in PostgreSQL mode.
    pub async fn asset_ingest_audited_durable(
        &self,
        tenant: TenantId,
        batch: &DiscoveryBatch,
        audit: AuditLog,
    ) -> DomainResult<IngestStats> {
        self.asset_ingest_inner(tenant, batch, Some(audit)).await
    }

    async fn asset_ingest_inner(
        &self,
        tenant: TenantId,
        batch: &DiscoveryBatch,
        audit: Option<AuditLog>,
    ) -> DomainResult<IngestStats> {
        if batch.tenant_id.is_some_and(|id| id != tenant) {
            return Err(DomainError::TenantViolation {
                tenant: tenant.to_string(),
                resource: "asset-discovery-batch".into(),
            });
        }
        if batch.assets.len() > 1000 {
            return Err(DomainError::Validation("Submit at most 1000 assets per discovery batch".into()));
        }
        let service = AssetService::new();
        let Some(db) = &self.database else {
            let result = service.ingest(self, tenant, batch).await?;
            if let Some(mut entry) = audit {
                entry.note = discovery_audit_note(&result);
                self.audit_append_durable(entry).await?;
            }
            return Ok(result);
        };
        let backend = AssetTransaction::begin(db, tenant).await?;
        let result = service.ingest(&backend, tenant, batch).await?;
        if let Some(mut entry) = audit {
            entry.note = discovery_audit_note(&result);
            backend.audit(entry).await?;
        }
        backend.commit(self).await?;
        Ok(result)
    }

    pub async fn asset_transition_durable(
        &self,
        tenant: TenantId,
        input: &LifecycleTransition,
        expected_updated_at: Option<Timestamp>,
        audit: AuditLog,
    ) -> DomainResult<Asset> {
        self.asset_mutate_audited_durable(tenant, input.asset_id, audit, |current| {
            check_version(current.clone(), expected_updated_at)?;
            let mut asset =
                current.ok_or_else(|| DomainError::NotFound { entity: "asset", id: input.asset_id.to_string() })?;
            let change = agf_asset::service::apply_review(&mut asset, input)?;
            Ok((asset, Some(change)))
        })
        .await
    }

    pub async fn asset_drift_durable(
        &self,
        tenant: TenantId,
        baseline: Option<&str>,
    ) -> DomainResult<(usize, DriftReport)> {
        let service = AssetService::new();
        let Some(db) = &self.database else {
            return service.snapshot_and_drift(self, tenant, baseline).await;
        };
        let backend = AssetTransaction::begin(db, tenant).await?;
        let result = service.snapshot_and_drift(&backend, tenant, baseline).await?;
        backend.commit(self).await?;
        Ok(result)
    }
}

fn discovery_audit_note(stats: &IngestStats) -> String {
    format!("导入发现批次：新增 {} 更新 {} 未变 {}", stats.created, stats.updated, stats.unchanged)
}

fn validate_change(tenant: TenantId, id: Id, change: &AssetChange) -> DomainResult<()> {
    if change.tenant_id != tenant || change.asset_id != id {
        return Err(DomainError::Validation("Asset history must belong to the mutated asset".into()));
    }
    Ok(())
}

fn check_version(asset: Option<Asset>, expected: Option<Timestamp>) -> DomainResult<()> {
    if expected.is_some_and(|value| asset.as_ref().is_none_or(|asset| asset.updated_at != value)) {
        return Err(DomainError::Conflict(
            "Asset changed since this form was opened; refresh and compare before saving".into(),
        ));
    }
    Ok(())
}
