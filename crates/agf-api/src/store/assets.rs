//! 资产台账读写：写入/查询/生命周期/变更/快照/统计。

use super::*;

impl ApiStore {
    /// Refresh an asset cache from authoritative storage without enqueuing another SQL write.
    pub(crate) fn remember_asset(&self, asset: &Asset) -> DomainResult<()> {
        let mut memory = self.lock()?;
        if asset.deleted_at.is_some() {
            memory.assets.remove(&(asset.tenant_id, asset.id));
        } else {
            memory.assets.insert((asset.tenant_id, asset.id), asset.clone());
        }
        Ok(())
    }
    // ---------------------------------------------------------------- 资产

    /// 写入/更新资产（按 id 覆盖，调用方负责指纹去重）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn asset_upsert(&self, asset: &Asset) -> DomainResult<Id> {
        let mut mem = self.lock()?;
        mem.assets.insert((asset.tenant_id, asset.id), asset.clone());
        drop(mem);
        self.journal(PgWrite::AssetUpsert { asset: Box::new(asset.clone()) });
        Ok(asset.id)
    }

    /// 按 id 读取资产。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn asset_get(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Asset>> {
        Ok(self.lock()?.assets.get(&(tenant, id)).cloned())
    }

    /// 按指纹读取资产。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn asset_find_by_fingerprint(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<Option<Asset>> {
        Ok(self
            .lock()?
            .assets
            .iter()
            .find(|((t, _), a)| *t == tenant && a.fingerprint == fingerprint)
            .map(|(_, a)| a.clone()))
    }

    /// 列出全部资产。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn asset_list_all(&self, tenant: TenantId) -> DomainResult<Vec<Asset>> {
        Ok(self.lock()?.assets.iter().filter(|((t, _), _)| *t == tenant).map(|(_, a)| a.clone()).collect())
    }

    /// 分页列出资产（支持类型/最低暴露面过滤与 `q` 全文过滤）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn asset_list(
        &self,
        tenant: TenantId,
        req: &PageRequest,
        kind: Option<agf_core::enums::AssetKind>,
        min_exposure: Option<u8>,
    ) -> DomainResult<Page<Asset>> {
        let needle = req.q.as_deref().map(str::to_lowercase);
        let items: Vec<Asset> = self
            .lock()?
            .assets
            .iter()
            .filter(|((t, _), _)| *t == tenant)
            .map(|(_, a)| a.clone())
            .filter(|a| kind.is_none_or(|k| a.kind == k))
            .filter(|a| min_exposure.is_none_or(|m| a.exposure_score >= m))
            .filter(|a| match &needle {
                None => true,
                Some(needle) => {
                    let haystack = format!(
                        "{} {} {} {}",
                        a.name,
                        a.fingerprint,
                        a.endpoint.clone().unwrap_or_default(),
                        a.kind.as_str()
                    )
                    .to_lowercase();
                    haystack.contains(needle)
                }
            })
            .collect();
        Ok(super::pagination_page(items, req))
    }

    /// 更新资产生命周期。
    ///
    /// # Errors
    /// 资产不存在或锁中毒。
    pub fn asset_set_lifecycle(&self, tenant: TenantId, id: Id, state: LifecycleState) -> DomainResult<()> {
        let mut mem = self.lock()?;
        let Some(asset) = mem.assets.get_mut(&(tenant, id)) else {
            return Err(DomainError::NotFound { entity: "asset", id: id.to_string() });
        };
        asset.lifecycle = state;
        asset.updated_at = Timestamp::now();
        drop(mem);
        self.journal(PgWrite::AssetLifecycle { tenant, id, state });
        Ok(())
    }

    /// 资产变更台账。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn asset_changes(&self, tenant: TenantId, asset_id: Id, limit: i64) -> DomainResult<Vec<AssetChange>> {
        let mem = self.lock()?;
        Ok(mem
            .changes
            .iter()
            .filter(|c| c.tenant_id == tenant && c.asset_id == asset_id)
            .rev()
            .take(usize::try_from(limit.max(0)).unwrap_or(0))
            .cloned()
            .collect())
    }

    /// 记录资产变更。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn asset_record_change(&self, change: &AssetChange) -> DomainResult<()> {
        self.lock()?.changes.push(change.clone());
        self.journal(PgWrite::AssetChange { change: Box::new(change.clone()) });
        Ok(())
    }

    /// 保留该资产当日首次观测快照；重复采集不覆盖基线。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn asset_snapshot(&self, tenant: TenantId, date: &str, asset: &Asset) -> DomainResult<()> {
        let hash = agf_asset::asset_content_hash(
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
        let mut mem = self.lock()?;
        if mem.snapshots.contains_key(&(tenant, date.to_string(), asset.id)) {
            return Ok(());
        }
        mem.snapshots.insert((tenant, date.to_string(), asset.id), hash);
        drop(mem);
        self.journal(PgWrite::AssetSnapshot { tenant, date: date.to_string(), asset: Box::new(asset.clone()) });
        Ok(())
    }

    /// 指定日期的 `asset_id → content_hash`。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn asset_snapshot_hashes(&self, tenant: TenantId, date: &str) -> DomainResult<BTreeMap<Id, String>> {
        let mem = self.lock()?;
        Ok(mem
            .snapshots
            .iter()
            .filter(|((t, d, _), _)| *t == tenant && d == date)
            .map(|((_, _, id), h)| (*id, h.clone()))
            .collect())
    }

    /// 盘点统计。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn asset_stats(&self, tenant: TenantId) -> DomainResult<InventoryStats> {
        let assets = self.asset_list_all(tenant)?;
        Ok(InventoryStats::from_assets(&assets))
    }
}
