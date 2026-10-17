//! 由 `service.rs` 拆分：`impl_InMemoryAssetBackend`/`impl_InMemoryAssetBackend` 等 3 项（纯搬移，逻辑不变）。
use super::*;

impl InMemoryAssetBackend {
    /// 新建。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 变更记录数。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn change_count(&self) -> DomainResult<usize> {
        self.changes.lock().map(|v| v.len()).map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))
    }

    /// 变更记录快照。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn changes(&self) -> DomainResult<Vec<AssetChange>> {
        self.changes.lock().map(|v| v.clone()).map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))
    }

    /// 资产总数。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn asset_count(&self) -> DomainResult<usize> {
        self.assets.lock().map(|m| m.len()).map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))
    }
}

#[async_trait]
impl AssetBackend for InMemoryAssetBackend {
    async fn find_by_fingerprint(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<Option<Asset>> {
        let map = self.assets.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        Ok(map.iter().find(|((t, _), a)| *t == tenant && a.fingerprint == fingerprint).map(|(_, a)| a.clone()))
    }

    async fn find(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Asset>> {
        let map = self.assets.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        Ok(map.get(&(tenant, id)).cloned())
    }

    async fn list_all(&self, tenant: TenantId) -> DomainResult<Vec<Asset>> {
        let map = self.assets.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        Ok(map.iter().filter(|((t, _), _)| *t == tenant).map(|(_, a)| a.clone()).collect())
    }

    async fn upsert(&self, tenant: TenantId, asset: &Asset) -> DomainResult<Id> {
        let mut map = self.assets.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        map.insert((tenant, asset.id), asset.clone());
        Ok(asset.id)
    }

    async fn record_change(&self, _tenant: TenantId, change: &AssetChange) -> DomainResult<()> {
        let mut v = self.changes.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        v.push(change.clone());
        Ok(())
    }

    async fn snapshot(&self, tenant: TenantId, date: &str, asset: &Asset) -> DomainResult<()> {
        let mut map = self.snapshots.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        let hash = asset_content_hash(
            asset.kind,
            asset.endpoint.as_deref(),
            asset.protocol,
            asset.version.as_deref(),
            asset.vendor.as_deref(),
            asset.data_class,
            asset.lifecycle,
            &asset.dependencies,
            asset.discovery_source,
        );
        map.entry((tenant, date.to_string(), asset.id)).or_insert(hash);
        Ok(())
    }

    async fn snapshot_hashes(&self, tenant: TenantId, date: &str) -> DomainResult<BTreeMap<Id, String>> {
        let map = self.snapshots.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        Ok(map
            .iter()
            .filter(|((t, d, _), _)| *t == tenant && d == date)
            .map(|((_, _, id), h)| (*id, h.clone()))
            .collect())
    }
}

/// 便捷：把发现结果直接转成"待评审"资产列表（不落库，供预览）。
#[must_use]
pub fn preview_assets(batch: &DiscoveryBatch, tenant: TenantId) -> Vec<DiscoveredAsset> {
    batch
        .assets
        .clone()
        .into_iter()
        .map(|mut d| {
            d.discovered_at = Timestamp::now();
            let _ = tenant;
            d
        })
        .collect()
}
