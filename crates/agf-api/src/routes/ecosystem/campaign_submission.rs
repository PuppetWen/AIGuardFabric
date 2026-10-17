//! A caller can retry a lost acknowledgement without creating another campaign.
use super::*;
use agf_core::ids::{Id, deterministic_id};
use sha2::{Digest, Sha256};

pub(super) fn identity(
    principal: &Principal,
    headers: &axum::http::HeaderMap,
    body: &CampaignBody,
) -> ApiResult<Option<(Id, String)>> {
    let Some(key) = headers.get("idempotency-key") else { return Ok(None) };
    let key = key
        .to_str()
        .ok()
        .filter(|key| !key.is_empty() && key.len() <= 200 && key.bytes().all(|b| b.is_ascii_graphic()))
        .ok_or_else(|| DomainError::Validation("Idempotency-Key must contain 1–200 printable ASCII bytes".into()))?;
    let id = deterministic_id("redteam-submission-v1", &format!("{}:{}:{key}", principal.tenant, principal.display()));
    let fingerprint = format!("{:x}", Sha256::digest(serde_json::to_vec(body).map_err(DomainError::from)?));
    Ok(Some((id, fingerprint)))
}

pub(super) fn matches(record: &crate::store::CampaignRecord, fingerprint: &str) -> ApiResult<()> {
    if record.request_fingerprint.as_deref() != Some(fingerprint) {
        return Err(DomainError::Conflict("Idempotency-Key already belongs to a different request".into()).into());
    }
    Ok(())
}
