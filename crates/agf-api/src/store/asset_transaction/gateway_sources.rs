//! Same-transaction complete source reads: bounded payloads, never a prefix witness.
use super::*;
use agf_storage::configuration::BoundedConfigurationList;

impl AssetTransaction<'_> {
    pub(crate) async fn configurations_bounded(
        &self,
        kind: &str,
        max_records: usize,
        max_bytes: usize,
    ) -> DomainResult<BoundedConfigurationList<(Id, serde_json::Value)>> {
        if kind.is_empty() || kind.len() > 64 || max_records > 512 || max_bytes > 8 * 1024 * 1024 {
            return Err(DomainError::Validation("Invalid locked gateway source bound".into()));
        }
        let mut tx = self.transaction(self.tenant).await?;
        let (count, bytes, payload): (i64, i64, Option<serde_json::Value>) = sqlx::query_as(
            "WITH limited AS MATERIALIZED (
                SELECT id,payload,octet_length(payload::text)::bigint AS bytes
                FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND deleted_at IS NULL
                ORDER BY id LIMIT $3 FOR UPDATE
             ), stats AS (
                SELECT count(*)::bigint AS count,coalesce(sum(bytes),0)::bigint AS bytes FROM limited
             ) SELECT count,bytes,CASE WHEN count <= $4 AND bytes <= $5 THEN
                coalesce((SELECT jsonb_agg(jsonb_build_array(id,payload) ORDER BY id) FROM limited),'[]'::jsonb)
             ELSE NULL END FROM stats",
        )
        .bind(self.tenant.as_uuid())
        .bind(kind)
        .bind(i64::try_from(max_records + 1).map_err(|_| bound())?)
        .bind(i64::try_from(max_records).map_err(|_| bound())?)
        .bind(i64::try_from(max_bytes).map_err(|_| bound())?)
        .fetch_one(&mut **tx)
        .await
        .map_err(|error| agf_storage::map_sqlx_err("gateway_locked_source_bound", &error))?;
        if count > i64::try_from(max_records).map_err(|_| bound())? {
            return Ok(BoundedConfigurationList::TooMany);
        }
        if bytes > i64::try_from(max_bytes).map_err(|_| bound())? {
            return Ok(BoundedConfigurationList::TooLarge);
        }
        let rows: Vec<(Id, serde_json::Value)> = serde_json::from_value(payload.ok_or_else(bound)?)?;
        let mut measured = 0usize;
        for (_, value) in &rows {
            measured = measured.checked_add(serde_json::to_vec(value)?.len()).ok_or_else(bound)?;
            if measured > max_bytes {
                return Ok(BoundedConfigurationList::TooLarge);
            }
        }
        Ok(BoundedConfigurationList::Complete(rows))
    }
}
fn bound() -> DomainError {
    DomainError::Internal("Locked gateway source bound is invalid".into())
}
