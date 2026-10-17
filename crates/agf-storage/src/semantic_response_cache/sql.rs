use super::{
    Admission, DomainIssuer, Lookup, MAX_CANDIDATES, MAX_ROWS, MAX_TENANT_BYTES, SearchVector, SemanticReadAuthority,
    SemanticRepository, TrustedSemanticDomain,
    codec::{self, SealedEntry},
};
use crate::{Database, FieldCipher, TenantTransaction};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use async_trait::async_trait;
use sqlx::Row;

/// RLS PostgreSQL cache. Every entry is AEAD sealed, and legacy semantic_cache is never read.
#[derive(Debug, Clone)]
pub struct SqlRepository {
    database: Database,
    issuer: DomainIssuer,
    cipher: FieldCipher,
}

impl SqlRepository {
    /// Construct from existing service-owned database, domain issuer and field cipher.
    pub const fn new(database: Database, issuer: DomainIssuer, cipher: FieldCipher) -> Self {
        Self { database, issuer, cipher }
    }
    /// Insert under the caller's tenant transaction so final authorization/settlement/audit can be atomic.
    /// It never commits; the caller must recheck original authority after any subsequent audit wait.
    pub async fn admit_in_transaction(
        &self,
        tx: &mut TenantTransaction<'_>,
        domain: &TrustedSemanticDomain,
        entry: Admission,
    ) -> DomainResult<Id> {
        self.issuer.validate(domain)?;
        if tx.tenant() != domain.tenant {
            return Err(stale());
        }
        let stored = codec::seal(&self.cipher, domain, entry)?;
        let payload = serde_json::to_vec(&stored)?;
        current_sources(tx, domain).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("{}:semantic-response-v2:capacity", domain.tenant))
            .execute(&mut **tx)
            .await
            .map_err(sql_error)?;
        self.issuer.validate(domain)?;
        sqlx::query("DELETE FROM semantic_response_cache_v2 WHERE tenant_id=$1 AND expires_ms<=$2")
            .bind(domain.tenant.as_uuid())
            .bind(chrono::Utc::now().timestamp_millis())
            .execute(&mut **tx)
            .await
            .map_err(sql_error)?;
        let rows=sqlx::query("SELECT id,sealed_bytes FROM semantic_response_cache_v2 WHERE tenant_id=$1 ORDER BY created_ms,id FOR UPDATE")
            .bind(domain.tenant.as_uuid()).fetch_all(&mut **tx).await.map_err(sql_error)?;
        if rows.len() > MAX_ROWS {
            return Err(stale());
        }
        let mut total = 0usize;
        let mut old = Vec::with_capacity(rows.len());
        for row in &rows {
            let bytes =
                usize::try_from(row.try_get::<i32, _>("sealed_bytes").map_err(sql_error)?).map_err(|_| stale())?;
            total = total.checked_add(bytes).ok_or_else(stale)?;
            old.push((row.try_get::<uuid::Uuid, _>("id").map_err(sql_error)?, bytes));
        }
        if total > MAX_TENANT_BYTES {
            return Err(stale());
        }
        let mut count = rows.len();
        for (id, bytes) in old {
            if count < MAX_ROWS && total.checked_add(payload.len()).is_some_and(|sum| sum <= MAX_TENANT_BYTES) {
                break;
            }
            sqlx::query("DELETE FROM semantic_response_cache_v2 WHERE tenant_id=$1 AND id=$2")
                .bind(domain.tenant.as_uuid())
                .bind(id)
                .execute(&mut **tx)
                .await
                .map_err(sql_error)?;
            count -= 1;
            total -= bytes;
        }
        sqlx::query("INSERT INTO semantic_response_cache_v2(tenant_id,id,domain_hash,dimensions,created_ms,expires_ms,sealed_bytes,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(domain.tenant.as_uuid()).bind(stored.id.as_uuid()).bind(&stored.domain).bind(i32::from(stored.dimensions))
            .bind(stored.created_ms).bind(stored.expires_ms).bind(i32::try_from(payload.len()).map_err(|_|stale())?).bind(payload)
            .execute(&mut **tx).await.map_err(sql_error)?;
        self.issuer.validate(domain)?;
        Ok(stored.id)
    }
}

#[async_trait]
impl SemanticRepository for SqlRepository {
    async fn lookup(
        &self,
        domain: &TrustedSemanticDomain,
        query: &SearchVector,
        authority: &dyn SemanticReadAuthority,
    ) -> DomainResult<Lookup> {
        authority.revalidate(domain).await?;
        self.issuer.validate(domain)?;
        let mut tx = self.database.begin_tenant(domain.tenant).await?;
        current_sources(&mut tx, domain).await?;
        let rows=sqlx::query("SELECT id,domain_hash,dimensions,created_ms,expires_ms,sealed_bytes,payload FROM semantic_response_cache_v2 WHERE tenant_id=$1 AND domain_hash=$2 AND expires_ms>$3 ORDER BY created_ms,id LIMIT $4")
            .bind(domain.tenant.as_uuid()).bind(&domain.hash).bind(chrono::Utc::now().timestamp_millis())
            .bind(i64::try_from(MAX_CANDIDATES+1).map_err(|_|stale())?).fetch_all(&mut *tx).await.map_err(sql_error)?;
        if rows.len() > MAX_CANDIDATES {
            tx.commit().await?;
            authority.revalidate(domain).await?;
            self.issuer.validate(domain)?;
            return Ok(Lookup::CandidateLimit);
        }
        let mut entries = Vec::with_capacity(rows.len());
        for row in rows {
            let bytes: Vec<u8> = row.try_get("payload").map_err(sql_error)?;
            if bytes.len() > super::MAX_ENTRY_BYTES
                || i32::try_from(bytes.len()).ok() != Some(row.try_get::<i32, _>("sealed_bytes").map_err(sql_error)?)
            {
                return Err(codec::corrupt());
            }
            let entry: SealedEntry = serde_json::from_slice(&bytes).map_err(|_| codec::corrupt())?;
            if entry.tenant != domain.tenant
                || entry.id.as_uuid() != row.try_get::<uuid::Uuid, _>("id").map_err(sql_error)?
                || entry.domain != row.try_get::<String, _>("domain_hash").map_err(sql_error)?
                || i32::from(entry.dimensions) != row.try_get::<i32, _>("dimensions").map_err(sql_error)?
                || entry.created_ms != row.try_get::<i64, _>("created_ms").map_err(sql_error)?
                || entry.expires_ms != row.try_get::<i64, _>("expires_ms").map_err(sql_error)?
            {
                return Err(codec::corrupt());
            }
            entries.push(entry);
        }
        let result = codec::choose(&self.cipher, domain, query, entries)?;
        self.issuer.validate(domain)?;
        tx.commit().await?;
        authority.revalidate(domain).await?;
        self.issuer.validate(domain)?;
        Ok(result)
    }
}

async fn current_sources(tx: &mut TenantTransaction<'_>, domain: &TrustedSemanticDomain) -> DomainResult<()> {
    let active: bool =
        sqlx::query_scalar("SELECT agf_agentteams_lock_tenant()").fetch_one(&mut **tx).await.map_err(sql_error)?;
    if !active {
        return Err(stale());
    }
    // Same ordinary ConfigStore writer locks, canonical order, held through this transaction.
    for fence in &domain.fences {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("{}:{}:{}", domain.tenant, fence.kind, fence.id))
            .execute(&mut **tx)
            .await
            .map_err(sql_error)?;
        let payload:Option<serde_json::Value>=sqlx::query_scalar("SELECT payload FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NULL FOR SHARE")
            .bind(domain.tenant.as_uuid()).bind(&fence.kind).bind(fence.id.as_uuid()).fetch_optional(&mut **tx).await.map_err(sql_error)?;
        if !payload
            .as_ref()
            .is_some_and(|value| super::domain::content_hash(value).is_ok_and(|hash| hash == fence.content_hash))
        {
            return Err(stale());
        }
    }
    Ok(())
}

fn stale() -> DomainError {
    DomainError::PreconditionFailed("Semantic cache source, tenant, or bounded capacity is stale".into())
}
fn sql_error(_error: sqlx::Error) -> DomainError {
    DomainError::DependencyUnavailable {
        dependency: "semantic-cache".into(),
        cause: "Bounded cache storage unavailable".into(),
    }
}
