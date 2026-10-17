//! Resolve names for one visible page without N+1 queries or crossing the tenant boundary.
use super::*;

impl ApiStore {
    pub(crate) async fn asset_names(&self, tenant: TenantId, ids: &[Id]) -> DomainResult<BTreeMap<Id, String>> {
        if ids.len() > 200 {
            return Err(DomainError::Validation("Asset names are limited to one 200-row page".into()));
        }
        if ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let Some(db) = &self.database else {
            let memory = self.lock()?;
            return Ok(ids
                .iter()
                .filter_map(|id| {
                    memory
                        .assets
                        .get(&(tenant, *id))
                        .filter(|asset| asset.deleted_at.is_none())
                        .map(|asset| (*id, asset.name.clone()))
                })
                .collect());
        };
        let ids = ids.iter().map(Id::as_uuid).collect::<Vec<_>>();
        db.with_tenant(tenant, move |tx| {
            Box::pin(async move {
                let rows: Vec<(uuid::Uuid, String)> =
                    sqlx::query_as("SELECT id,name FROM assets WHERE id=ANY($1) AND deleted_at IS NULL")
                        .bind(ids)
                        .fetch_all(&mut **tx)
                        .await
                        .map_err(|error| agf_storage::map_sqlx_err("asset_names", &error))?;
                Ok(rows.into_iter().map(|(id, name)| (Id::from_uuid(id), name)).collect())
            })
        })
        .await
    }
}
