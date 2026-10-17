use super::{Admission, Lookup, MAX_CANDIDATES, MAX_ENTRY_BYTES, PlainResponse, SearchVector, TrustedSemanticDomain};
use crate::FieldCipher;
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct SealedEntry {
    pub(super) tenant: TenantId,
    pub(super) id: Id,
    pub(super) domain: String,
    pub(super) dimensions: u16,
    pub(super) created_ms: i64,
    pub(super) expires_ms: i64,
    pub(super) secret: SecretMaterial,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    schema: u8,
    tenant: TenantId,
    id: Id,
    domain: String,
    vector: Vec<f32>,
    response: Value,
}

pub(super) fn seal(
    cipher: &FieldCipher,
    domain: &TrustedSemanticDomain,
    entry: Admission,
) -> DomainResult<SealedEntry> {
    if entry.vector.len() != usize::from(domain.dimensions) {
        return Err(corrupt());
    }
    let response = PlainResponse::from_canonical(entry.response.0, &domain.model)?;
    let created_ms = chrono::Utc::now().timestamp_millis();
    let expires_ms = created_ms.checked_add(i64::from(entry.ttl_seconds) * 1000).ok_or_else(corrupt)?;
    let payload = Payload {
        schema: 1,
        tenant: domain.tenant,
        id: entry.id,
        domain: domain.hash.clone(),
        vector: entry.vector,
        response: response.0,
    };
    let bytes = serde_json::to_string(&payload)?;
    if bytes.len() > MAX_ENTRY_BYTES {
        return Err(corrupt());
    }
    let associated = format!(
        "agf-semantic-response-v2|tenant:{}|id:{}|domain:{}|dim:{}|created:{}|expires:{}",
        domain.tenant, entry.id, domain.hash, domain.dimensions, created_ms, expires_ms
    );
    let stored = SealedEntry {
        tenant: domain.tenant,
        id: entry.id,
        domain: domain.hash.clone(),
        dimensions: domain.dimensions,
        created_ms,
        expires_ms,
        secret: cipher.encrypt(&SecretString::from(bytes), &associated)?,
    };
    if encoded_size(&stored)? > MAX_ENTRY_BYTES {
        return Err(corrupt());
    }
    Ok(stored)
}

pub(super) fn encoded_size(entry: &SealedEntry) -> DomainResult<usize> {
    Ok(serde_json::to_vec(entry)?.len())
}

fn aad(entry: &SealedEntry) -> String {
    format!(
        "agf-semantic-response-v2|tenant:{}|id:{}|domain:{}|dim:{}|created:{}|expires:{}",
        entry.tenant, entry.id, entry.domain, entry.dimensions, entry.created_ms, entry.expires_ms
    )
}

fn open(
    cipher: &FieldCipher,
    domain: &TrustedSemanticDomain,
    stored: &SealedEntry,
) -> DomainResult<(Vec<f32>, PlainResponse)> {
    // Identity/domain eligibility is checked before decrypting any payload.
    if stored.tenant != domain.tenant
        || stored.domain != domain.digest()
        || stored.dimensions != domain.dimensions
        || stored.created_ms > chrono::Utc::now().timestamp_millis()
        || stored.expires_ms <= chrono::Utc::now().timestamp_millis()
        || stored
            .expires_ms
            .checked_sub(stored.created_ms)
            .is_none_or(|ttl| ttl > i64::from(super::MAX_TTL_SECONDS) * 1000)
        || stored.expires_ms <= stored.created_ms
        || encoded_size(stored)? > MAX_ENTRY_BYTES
        || stored.secret.aad.as_deref() != Some(aad(stored).as_str())
    {
        return Err(corrupt());
    }
    let clear = cipher.decrypt(&stored.secret).map_err(|_| corrupt())?;
    if clear.expose_secret().len() > MAX_ENTRY_BYTES {
        return Err(corrupt());
    }
    let payload: Payload = serde_json::from_str(clear.expose_secret()).map_err(|_| corrupt())?;
    if payload.schema != 1
        || payload.tenant != stored.tenant
        || payload.id != stored.id
        || payload.domain != stored.domain
        || payload.vector.len() != usize::from(domain.dimensions)
    {
        return Err(corrupt());
    }
    super::vector::validate(&payload.vector)?;
    Ok((payload.vector, PlainResponse::from_canonical(payload.response, &domain.model)?))
}

pub(super) fn choose(
    cipher: &FieldCipher,
    domain: &TrustedSemanticDomain,
    query: &SearchVector,
    entries: Vec<SealedEntry>,
) -> DomainResult<Lookup> {
    if query.dimensions() != usize::from(domain.dimensions) {
        return Err(corrupt());
    }
    if entries.len() > MAX_CANDIDATES {
        return Ok(Lookup::CandidateLimit);
    }
    let mut scored = Vec::with_capacity(entries.len());
    for entry in entries {
        let (vector, response) = open(cipher, domain, &entry)?;
        scored.push((query.score(&vector)?, entry.id, response));
    }
    scored.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let Some(first) = scored.first() else {
        return Ok(Lookup::Miss);
    };
    if !query.accepted(first.0) {
        return Ok(Lookup::Miss);
    }
    if scored.get(1).is_some_and(|next| query.ambiguous(first.0, next.0)) {
        return Ok(Lookup::Ambiguous);
    }
    let Some((score, id, response)) = scored.into_iter().next() else {
        return Ok(Lookup::Miss);
    };
    Ok(Lookup::Hit { id, similarity: score, response })
}

pub(super) fn corrupt() -> DomainError {
    DomainError::Crypto("Semantic cache entry failed identity, bounds or authentication validation".into())
}
