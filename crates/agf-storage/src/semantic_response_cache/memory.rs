use super::{
    Admission, ConfigurationFence, DomainIssuer, Lookup, MAX_CANDIDATES, MAX_ROWS, MAX_TENANT_BYTES, SearchVector,
    SemanticReadAuthority, SemanticRepository, TrustedSemanticDomain,
    codec::{self, SealedEntry},
};
use crate::FieldCipher;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use async_trait::async_trait;
use std::{collections::BTreeMap, sync::Mutex};

/// Explicit process-only encrypted backend; no cross-process or restart guarantee.
pub struct MemoryRepository {
    issuer: DomainIssuer,
    cipher: FieldCipher,
    pub(super) rows: Mutex<BTreeMap<(TenantId, Id), SealedEntry>>,
}

impl std::fmt::Debug for MemoryRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryRepository(<encrypted>)")
    }
}

impl MemoryRepository {
    /// Service-owned issuer/cipher must match those used to issue the current domain.
    pub fn new(issuer: DomainIssuer, cipher: FieldCipher) -> Self {
        Self { issuer, cipher, rows: Mutex::new(BTreeMap::new()) }
    }
    /// Check current sources synchronously under the cache lock, then publish one bounded entry.
    /// The trusted callback must not reenter this repository. It does not replace actor authorization.
    pub fn admit<F>(&self, domain: &TrustedSemanticDomain, entry: Admission, check_sources: F) -> DomainResult<Id>
    where
        F: FnOnce(&[ConfigurationFence]) -> DomainResult<()>,
    {
        self.issuer.validate(domain)?;
        let stored = codec::seal(&self.cipher, domain, entry)?;
        let bytes = codec::encoded_size(&stored)?;
        let mut rows = self.rows.lock().map_err(|_| unavailable())?;
        check_sources(&domain.fences)?;
        self.issuer.validate(domain)?;
        let now = chrono::Utc::now().timestamp_millis();
        rows.retain(|(tenant, _), value| *tenant != domain.tenant || value.expires_ms > now);
        let mut current = rows
            .iter()
            .filter(|((tenant, _), _)| *tenant == domain.tenant)
            .map(|(key, value)| Ok((*key, value.created_ms, codec::encoded_size(value)?)))
            .collect::<DomainResult<Vec<_>>>()?;
        current.sort_by_key(|(key, created, _)| (*created, key.1));
        let mut total = current
            .iter()
            .try_fold(0usize, |total, (_, _, bytes)| total.checked_add(*bytes).ok_or_else(unavailable))?;
        let mut count = current.len();
        for (key, _, old_bytes) in current {
            if count < MAX_ROWS && total.checked_add(bytes).is_some_and(|sum| sum <= MAX_TENANT_BYTES) {
                break;
            }
            rows.remove(&key);
            count -= 1;
            total -= old_bytes;
        }
        rows.insert((domain.tenant, stored.id), stored.clone());
        Ok(stored.id)
    }
    /// Retrieve a current-domain snapshot after checking the service's current source view.
    /// All lookups remain read-only; expired rows are not removed as a GET side effect.
    pub fn lookup_checked<F>(
        &self,
        domain: &TrustedSemanticDomain,
        query: &SearchVector,
        check_sources: F,
    ) -> DomainResult<Lookup>
    where
        F: FnOnce(&[ConfigurationFence]) -> DomainResult<()>,
    {
        self.issuer.validate(domain)?;
        let rows = self.rows.lock().map_err(|_| unavailable())?;
        check_sources(&domain.fences)?;
        self.issuer.validate(domain)?;
        let now = chrono::Utc::now().timestamp_millis();
        let candidates = rows
            .values()
            .filter(|entry| entry.tenant == domain.tenant && entry.domain == domain.digest() && entry.expires_ms > now)
            .take(MAX_CANDIDATES + 1)
            .cloned()
            .collect();
        let result = codec::choose(&self.cipher, domain, query, candidates)?;
        self.issuer.validate(domain)?;
        Ok(result)
    }
}

#[async_trait]
impl SemanticRepository for MemoryRepository {
    async fn lookup(
        &self,
        domain: &TrustedSemanticDomain,
        query: &SearchVector,
        authority: &dyn SemanticReadAuthority,
    ) -> DomainResult<Lookup> {
        authority.revalidate(domain).await?;
        let result = self.lookup_checked(domain, query, |_| Ok(()))?;
        authority.revalidate(domain).await?;
        self.issuer.validate(domain)?;
        Ok(result)
    }
}

fn unavailable() -> DomainError {
    DomainError::DependencyUnavailable {
        dependency: "semantic-cache".into(),
        cause: "Bounded cache state unavailable".into(),
    }
}
