//! A randomized AEAD token hides the private config digest from readers.
use super::util;
use crate::integration_store::Stored;
use agf_core::{
    credential::SecretMaterial,
    error::DomainResult,
    ids::{Id, TenantId, deterministic_id},
    source::SourceRecord,
};
use agf_storage::crypto::FieldCipher;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::json;

const DOMAIN: &str = "agf.agentteams.task-handling.source.v1";
const MAX_TOKEN: usize = 8192;

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub(super) struct SourceFingerprint(String);
impl std::fmt::Debug for SourceFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceFingerprint").finish_non_exhaustive()
    }
}
impl SourceFingerprint {
    pub(super) fn validate(&self) -> DomainResult<()> {
        if self.0.is_empty() || self.0.len() > MAX_TOKEN {
            return Err(util::invalid());
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    domain: String,
    tenant: TenantId,
    source_id: Id,
    cloud_id: Id,
    cloud_version: u64,
    config_digest: String,
}

pub(super) struct AuthenticatedSourceProof {
    proof: Proof,
    token_hash: String,
}
pub(super) struct VerifiedSource {
    proof: Proof,
    token_hash: String,
}

/// Trusted locked-source result. Missing configuration is not a made-up source version.
pub(super) struct ArchiveSource {
    tenant: TenantId,
    source_id: Id,
    current: Option<VerifiedSource>,
}
impl ArchiveSource {
    pub(super) fn current(source: VerifiedSource) -> Self {
        Self { tenant: source.tenant(), source_id: source.source_id(), current: Some(source) }
    }
    /// Caller supplies the original authenticated evidence and the exact tenant-scoped locked row.
    pub(super) fn gone(evidence: &super::FailureEvidence, row: Option<&SourceRecord>) -> DomainResult<Self> {
        evidence.validate()?;
        if row.is_some_and(|row| row.source.is_some()) {
            return Err(util::stale());
        }
        Ok(Self { tenant: evidence.tenant, source_id: evidence.source_id, current: None })
    }
    pub(super) fn is_current(&self) -> bool {
        self.current.is_some()
    }
    pub(super) fn verify(
        &self,
        tenant: TenantId,
        expected: &super::input::SourceExpectation,
        cloud_version: Option<u64>,
    ) -> DomainResult<()> {
        if self.tenant != tenant || self.source_id != expected.source_id {
            return Err(util::corrupt());
        }
        match &self.current {
            Some(source) => {
                let token = expected.fingerprint.as_ref().ok_or_else(util::stale)?;
                if Some(source.cloud_version()) != cloud_version || !source.matches(token)? {
                    return Err(util::stale());
                }
            }
            None if expected.fingerprint.is_some() => return Err(util::stale()),
            None => {}
        }
        Ok(())
    }
}
impl VerifiedSource {
    pub(super) fn source_id(&self) -> Id {
        self.proof.source_id
    }
    pub(super) fn tenant(&self) -> TenantId {
        self.proof.tenant
    }
    pub(super) fn cloud_version(&self) -> u64 {
        self.proof.cloud_version
    }
    pub(super) fn matches(&self, token: &SourceFingerprint) -> DomainResult<bool> {
        Ok(self.token_hash == util::hash(&token.0)?)
    }
}

fn aad(tenant: TenantId, source: Id) -> String {
    FieldCipher::make_aad(&tenant, &deterministic_id(DOMAIN, &source.to_string()))
}
fn capture(tenant: TenantId, cloud: &Stored, row: &SourceRecord) -> DomainResult<Proof> {
    let source = row.source.as_ref().ok_or_else(util::stale)?;
    if tenant.as_uuid().is_nil()
        || source.tenant_id != tenant
        || source.id.is_nil()
        || cloud.id != crate::integration_store::id(tenant, "alicloud-agentteams")
        || cloud.name != "alicloud-agentteams"
        || cloud.version == 0
    {
        return Err(util::stale());
    }
    // Health, counters, poll leases and receive watermarks must not invalidate a review.
    let mut connection = source.connection.clone();
    connection.cursor_value = None;
    let config = json!({
        "tenant":tenant, "cloud":cloud,
        "source":{"id":source.id,"name":source.name,"vendor":source.vendor,"product":source.product,
            "enabled":source.enabled,"protocol":source.protocol,"mode":source.mode,
            "connection":connection,"parser_id":source.parser_id,"tags":source.tags,
            "poll_interval_secs":source.poll_interval_secs,"require_mtls":source.require_mtls,
            "allowed_cidrs":source.allowed_cidrs,"max_message_bytes":source.max_message_bytes,
            "max_eps":source.max_eps,"created_at":source.created_at,"updated_at":source.updated_at},
        "sealed_headers":row.headers,"native_receiver":row.native_receiver
    });
    util::bounded(&config, 256 * 1024)?;
    Ok(Proof {
        domain: DOMAIN.into(),
        tenant,
        source_id: source.id,
        cloud_id: cloud.id,
        cloud_version: cloud.version,
        config_digest: util::hash(&config)?,
    })
}

pub(super) fn issue(
    cipher: &FieldCipher,
    tenant: TenantId,
    cloud: &Stored,
    source: &SourceRecord,
) -> DomainResult<SourceFingerprint> {
    let proof = capture(tenant, cloud, source)?;
    let plain = SecretString::from(serde_json::to_string(&proof)?);
    let material = cipher.encrypt(&plain, &aad(tenant, proof.source_id))?;
    let token = SourceFingerprint(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&material)?));
    token.validate()?;
    Ok(token)
}

pub(super) fn authenticate(
    cipher: &FieldCipher,
    tenant: TenantId,
    source: Id,
    token: &SourceFingerprint,
) -> DomainResult<AuthenticatedSourceProof> {
    token.validate()?;
    let raw = URL_SAFE_NO_PAD.decode(&token.0).map_err(|_| util::invalid())?;
    let material: SecretMaterial = serde_json::from_slice(&raw).map_err(|_| util::invalid())?;
    if material.aad.as_deref() != Some(&aad(tenant, source)) || material.plaintext_len > 2048 {
        return Err(util::corrupt());
    }
    let plain = cipher.decrypt(&material).map_err(|_| util::corrupt())?;
    if plain.expose_secret().len() > 2048 {
        return Err(util::corrupt());
    }
    let proof: Proof = serde_json::from_str(plain.expose_secret()).map_err(|_| util::corrupt())?;
    if proof.domain != DOMAIN
        || proof.tenant != tenant
        || proof.source_id != source
        || proof.cloud_version == 0
        || !util::digest(&proof.config_digest)
    {
        return Err(util::corrupt());
    }
    Ok(AuthenticatedSourceProof { proof, token_hash: util::hash(&token.0)? })
}

pub(super) fn check_current(
    expected: &AuthenticatedSourceProof,
    cloud: &Stored,
    source: &SourceRecord,
) -> DomainResult<VerifiedSource> {
    let current = capture(expected.proof.tenant, cloud, source)?;
    if current != expected.proof {
        return Err(util::stale());
    }
    Ok(VerifiedSource { proof: current, token_hash: expected.token_hash.clone() })
}
