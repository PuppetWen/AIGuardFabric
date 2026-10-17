//! Narrow tenant-local admission key reads retain tombstones; no public raw executor.
use super::*;

impl AssetTransaction<'_> {
    pub(crate) async fn admission_key_record(&self, kind: &str, id: Id) -> DomainResult<Option<serde_json::Value>> {
        if !matches!(kind, "gateway-admission-key-v1" | "gateway-admission-key-capacity-v1") {
            return Err(DomainError::Validation("Unsupported admission key record kind".into()));
        }
        self.configuration_lock(kind, id).await?;
        let mut tx = self.transaction(self.tenant).await?;
        let row: Option<(serde_json::Value, bool)> = sqlx::query_as(
            "SELECT payload,deleted_at IS NOT NULL FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND id=$3 FOR UPDATE",
        ).bind(self.tenant.as_uuid()).bind(kind).bind(id.as_uuid()).fetch_optional(&mut **tx).await
            .map_err(|error| agf_storage::map_sqlx_err("gateway_admission_key_read", &error))?;
        match row {
            Some((_, true)) => Err(DomainError::Crypto("Permanent admission key record was retired".into())),
            Some((value, false)) => Ok(Some(value)),
            None => Ok(None),
        }
    }

    /// Count at most the permanent capacity plus one, including deleted key records.
    pub(crate) async fn admission_key_count(&self) -> DomainResult<u32> {
        let mut tx = self.transaction(self.tenant).await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM (SELECT id FROM console_configurations WHERE tenant_id=$1 AND kind='gateway-admission-key-v1' LIMIT 16385) AS bounded",
        ).bind(self.tenant.as_uuid()).fetch_one(&mut **tx).await
            .map_err(|error| agf_storage::map_sqlx_err("gateway_admission_key_count", &error))?;
        u32::try_from(count).map_err(|_| DomainError::Crypto("Admission key count is invalid".into()))
    }
}
