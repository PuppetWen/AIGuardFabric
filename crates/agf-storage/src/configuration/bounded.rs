//! Complete bounded configuration witnesses. A rejected collection never returns a prefix.
use super::*;
use std::io::{self, Write};

/// Complete collection or a fixed boundary verdict, without provider/configuration diagnostics.
pub enum BoundedConfigurationList<T> {
    /// Every active row for the tenant/kind in this one statement or memory mutex snapshot.
    Complete(Vec<T>),
    /// At least max_records+1 rows exist; no partial rows are returned.
    TooMany,
    /// The complete encoded payload exceeds the supplied byte budget; no rows are returned.
    TooLarge,
}
impl<T> std::fmt::Debug for BoundedConfigurationList<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Complete(rows) => f.debug_struct("Complete").field("records", &rows.len()).finish_non_exhaustive(),
            Self::TooMany => f.write_str("TooMany"),
            Self::TooLarge => f.write_str("TooLarge"),
        }
    }
}

impl ConfigStore {
    /// Read a complete kind with max+1 row detection, at most 512 rows and 8MiB payload bytes.
    ///
    /// SQL first selects a bounded set and its aggregate JSONB byte size in one statement.
    /// Only a complete set within both bounds is returned. Memory uses one mutex and counts
    /// JSON encoding with an allocation-free limited writer before cloning each payload.
    /// Zero bounds may prove absence; they never admit a nonempty collection. Returned typed
    /// JSON is also measured, so PostgreSQL and serde encoding differences cannot evade limits.
    /// This is one-kind evidence, not a strong multi-kind snapshot or a membership write lock.
    ///
    /// # Errors
    /// Invalid bounds/kind/tenant, database or mutex errors, or malformed stored typed payloads.
    pub async fn list_bounded<T: DeserializeOwned>(
        &self,
        tenant: TenantId,
        kind: &str,
        max_records: usize,
        max_encoded_bytes: usize,
    ) -> DomainResult<BoundedConfigurationList<T>> {
        if tenant.as_uuid().is_nil()
            || kind.is_empty()
            || kind.len() > 64
            || !kind.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
            || max_records > 512
            || max_encoded_bytes > 8 * 1024 * 1024
        {
            return Err(DomainError::Validation("Invalid bounded configuration witness".into()));
        }
        let values = if let Some(database) = &self.database {
            let mut tx = database.db().begin_tenant(tenant).await?;
            let (count, bytes, payload): (i64, i64, Option<Value>) = sqlx::query_as(
                "WITH limited AS MATERIALIZED (
                    SELECT id,payload,octet_length(payload::text)::bigint AS bytes
                    FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND deleted_at IS NULL
                    ORDER BY id LIMIT $3
                 ), stats AS (
                    SELECT count(*)::bigint AS count,coalesce(sum(bytes),0)::bigint AS bytes FROM limited
                 ) SELECT count,bytes,CASE WHEN count <= $4 AND bytes <= $5 THEN
                    coalesce((SELECT jsonb_agg(payload ORDER BY id) FROM limited),'[]'::jsonb)
                 ELSE NULL END FROM stats",
            )
            .bind(tenant.as_uuid())
            .bind(kind)
            .bind(i64::try_from(max_records + 1).map_err(|_| bounds())?)
            .bind(i64::try_from(max_records).map_err(|_| bounds())?)
            .bind(i64::try_from(max_encoded_bytes).map_err(|_| bounds())?)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage_error)?;
            tx.commit().await?;
            if count > i64::try_from(max_records).map_err(|_| bounds())? {
                return Ok(BoundedConfigurationList::TooMany);
            }
            if bytes > i64::try_from(max_encoded_bytes).map_err(|_| bounds())? {
                return Ok(BoundedConfigurationList::TooLarge);
            }
            serde_json::from_value::<Vec<Value>>(payload.ok_or_else(bounds)?)?
        } else {
            let records = self.memory.lock().map_err(lock_error)?;
            let minimum = Id::from_uuid(uuid::Uuid::nil());
            let maximum = Id::from_uuid(uuid::Uuid::from_bytes([u8::MAX; 16]));
            let start = (tenant, kind.to_owned(), minimum);
            let end = (tenant, kind.to_owned(), maximum);
            let mut values = Vec::new();
            let mut bytes = 0usize;
            for (_, payload) in records.range(start..=end).take(max_records + 1) {
                if values.len() == max_records {
                    return Ok(BoundedConfigurationList::TooMany);
                }
                let Some(encoded) = encoded_size(payload, max_encoded_bytes - bytes)? else {
                    return Ok(BoundedConfigurationList::TooLarge);
                };
                bytes += encoded;
                values.push(payload.clone());
            }
            values
        };
        let mut bytes = 0usize;
        for payload in &values {
            let Some(encoded) = encoded_size(payload, max_encoded_bytes - bytes)? else {
                return Ok(BoundedConfigurationList::TooLarge);
            };
            bytes += encoded;
        }
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<T>, _>>()
            .map(BoundedConfigurationList::Complete)
            .map_err(Into::into)
    }
}

struct Counter {
    bytes: usize,
    limit: usize,
    exceeded: bool,
}
impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.bytes.checked_add(bytes.len()).filter(|next| *next <= self.limit) else {
            self.exceeded = true;
            return Err(io::Error::other("Configuration witness byte limit"));
        };
        self.bytes = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encoded_size(value: &Value, limit: usize) -> DomainResult<Option<usize>> {
    let mut counter = Counter { bytes: 0, limit, exceeded: false };
    match serde_json::to_writer(&mut counter, value) {
        Ok(()) => Ok(Some(counter.bytes)),
        Err(_) if counter.exceeded => Ok(None),
        Err(error) => Err(error.into()),
    }
}
fn bounds() -> DomainError {
    DomainError::Internal("Bounded configuration witness shape is invalid".into())
}

#[cfg(test)]
mod tests;
