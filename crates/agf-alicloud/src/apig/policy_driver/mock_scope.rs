use super::{Binding, json, observe::evidence};
use crate::AdapterMode;
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId, deterministic_id},
};
use serde_json::json as value;

/// Authenticated Mock target identity, supplied by the server rather than a public request body.
/// Cloud configuration revision is checked separately and does not reset existing provider state.
#[derive(Debug, Clone)]
pub struct MockScope {
    pub(super) tenant: TenantId,
    pub(super) source_id: Id,
    pub(super) region: String,
    pub(super) source_identity: String,
    pub(super) binding: Binding,
    pub(super) fingerprint: String,
    pub(super) id: Id,
}

impl MockScope {
    /// Create one explicit Mock scope from trusted tenant/source/account/region and target evidence.
    /// The account identity must be an irreversible server-derived SHA256, never a raw credential.
    ///
    /// # Errors
    /// Mode is not Mock, resource identifiers are invalid, or the source evidence is absent.
    pub fn new(
        tenant: TenantId,
        source_id: Id,
        region: &str,
        source_identity: &str,
        binding: Binding,
        mode: AdapterMode,
    ) -> DomainResult<Self> {
        binding.validate()?;
        if mode != AdapterMode::Mocked || tenant.as_id().is_nil() || source_id.is_nil() {
            return Err(evidence("The persistent APIG Mock needs a trusted Mock source"));
        }
        if region.is_empty() || region.len() > 64 || !region.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(evidence("The persistent APIG Mock needs an explicit region"));
        }
        check_hash(source_identity)?;
        let fingerprint = json::fingerprint(&value!({
            "tenant": tenant, "sourceId": source_id, "sourceIdentity": source_identity,
            "region": region, "mode": "mock", "binding": binding,
        }));
        let id = deterministic_id("aiguardfabric.apig.policy.mock", &fingerprint);
        Ok(Self {
            tenant,
            source_id,
            region: region.into(),
            source_identity: source_identity.into(),
            binding,
            fingerprint,
            id,
        })
    }

    /// Tenant-scoped encrypted provider record identity, separate from workflow receipt identities.
    pub fn record_id(&self) -> Id {
        self.id
    }

    /// Stable source/target comparison key; not a provider revision or authorization assertion.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

pub(super) fn check_hash(hash: &str) -> DomainResult<()> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f')) {
        return Err(evidence("Expected a canonical server-derived SHA256"));
    }
    Ok(())
}
