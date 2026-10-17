//! Read action targets from SQL so another API instance's asset changes are visible.
use super::*;

impl ApiStore {
    pub async fn asset_get_durable(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Asset>> {
        let Some(db) = &self.database else {
            return self.asset_get(tenant, id);
        };
        let asset = db
            .with_tenant(tenant, move |tx| Box::pin(async move { agf_storage::AssetRepo::get(tx, id).await }))
            .await?;
        if let Some(asset) = &asset {
            self.remember_asset(asset)?;
        } else {
            self.lock()?.assets.remove(&(tenant, id));
        }
        Ok(asset)
    }
}
