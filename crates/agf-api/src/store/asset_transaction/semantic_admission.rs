//! Typed cache contribution to this exact governance transaction, with no executor exposure.
use super::AssetTransaction;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use agf_storage::semantic_response_cache::{Admission, SqlRepository, TrustedSemanticDomain};

impl AssetTransaction<'_> {
    pub(crate) async fn admit_semantic_cache(
        &self,
        repository: &SqlRepository,
        domain: &TrustedSemanticDomain,
        entry: Admission,
    ) -> DomainResult<Id> {
        if domain.tenant() != self.tenant {
            return Err(DomainError::TenantViolation {
                tenant: self.tenant.to_string(),
                resource: "semantic-response-cache".into(),
            });
        }
        let mut transaction = self.transaction(self.tenant).await?;
        repository.admit_in_transaction(&mut transaction, domain, entry).await
    }
}
