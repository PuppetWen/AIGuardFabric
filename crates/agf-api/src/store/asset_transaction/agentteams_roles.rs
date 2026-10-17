//! The caller already owns the tenant governance lock; roles are read from the existing catalog.
use super::AssetTransaction;
use crate::agentteams_role_mapping::RoleEntry;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};

impl AssetTransaction<'_> {
    pub(crate) async fn agentteams_platform_role(&self, id: Id) -> DomainResult<Option<RoleEntry>> {
        let mut tx = self.transaction(self.tenant).await?;
        let value: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT jsonb_build_object('id',id,
            'tenant_id',tenant_id,'name',name,'display_name',display_name,'permissions',permissions,'builtin',builtin)
            FROM roles WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL FOR SHARE",
        )
        .bind(self.tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| agf_storage::map_sqlx_err("agentteams_platform_role", &error))?;
        value.map(serde_json::from_value).transpose().map_err(Into::into)
    }
    pub(crate) async fn agentteams_role_capacity(&self, kind: &str, limit: usize) -> DomainResult<()> {
        let mut tx = self.transaction(self.tenant).await?;
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM console_configurations WHERE tenant_id=$1 AND kind=$2")
                .bind(self.tenant.as_uuid())
                .bind(kind)
                .fetch_one(&mut **tx)
                .await
                .map_err(|error| agf_storage::map_sqlx_err("agentteams_role_capacity", &error))?;
        // Tombstones and immutable receipts also consume capacity; no silent history purge.
        if usize::try_from(count).ok().is_none_or(|count| count >= limit) {
            return Err(DomainError::PreconditionFailed("角色约束永久台账已达上限，不能删除事实来恢复权限".into()));
        }
        Ok(())
    }
}
