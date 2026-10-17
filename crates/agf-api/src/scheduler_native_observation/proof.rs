//! Adoption evidence is self-contained and authenticated independently of archived observation bodies.
use super::{claim, input::Assignment, records::BindingRecord, scope::SourceTarget, util};
use crate::{model_gateway::cipher, state::AppState};
use agf_core::{
    credential::SecretMaterial,
    error::DomainResult,
    ids::{Id, TenantId, deterministic_id},
    time::Timestamp,
};
use agf_storage::crypto::FieldCipher;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const DOMAIN: &str = "agf.scheduler.native.adoption.v1";
const QUALIFICATION_DOMAIN: &str = "agf.scheduler.native.qualification.v1";
const MAX_PROOF_BYTES: usize = 16 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdoptedProof {
    pub id: Id,
    pub hash: String,
    pub secret: SecretMaterial,
}
impl std::fmt::Debug for AdoptedProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdoptedProof").field("id", &self.id).finish_non_exhaustive()
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Provenance {
    pub domain: String,
    pub tenant: TenantId,
    pub binding_id: Id,
    pub adoption_version: u64,
    pub proof_id: Id,
    pub assignment: Assignment,
    pub source: SourceTarget,
    pub observation_id: Id,
    pub observed_at: Timestamp,
    pub app_id: String,
    pub observation_fingerprint: String,
    pub http_job: bool,
    pub enabled: bool,
}

fn expected(row: &BindingRecord, tenant: TenantId, assignment: &Assignment) -> DomainResult<Provenance> {
    let source = row.target.clone().ok_or_else(util::corrupt)?;
    claim::validate_target(&source, tenant)?;
    if row.tenant != Some(tenant)
        || row.adoption_version == 0
        || row.adoption_version > row.version
        || !super::KINDS.contains(&assignment.kind.as_str())
        || !util::positive_id(&assignment.job_id)
    {
        return Err(util::corrupt());
    }
    let binding_id = util::binding_key(tenant).1;
    let proof_id = deterministic_id(
        DOMAIN,
        &format!("{tenant}:{binding_id}:{}:{}:{}", row.adoption_version, assignment.kind, assignment.job_id),
    );
    Ok(Provenance {
        domain: DOMAIN.into(),
        tenant,
        binding_id,
        adoption_version: row.adoption_version,
        proof_id,
        assignment: assignment.clone(),
        source,
        observation_id: row.observation_id.filter(|id| !id.is_nil()).ok_or_else(util::corrupt)?,
        observed_at: row.verified_at.ok_or_else(util::corrupt)?,
        app_id: row.app_id.clone().filter(|id| util::positive_id(id)).ok_or_else(util::corrupt)?,
        observation_fingerprint: row.fingerprint.clone().filter(|hash| util::digest(hash)).ok_or_else(util::corrupt)?,
        http_job: true,
        enabled: true,
    })
}

pub(super) fn validate_record(row: &BindingRecord, tenant: TenantId) -> DomainResult<()> {
    if row.adoption_version == 0 {
        if !row.adopted_proofs.is_empty() || !row.eligibility.is_empty() || row.qualification_seal.is_some() {
            return Err(util::corrupt());
        }
        // An old record is readable but has no authenticated execution qualification.
        return Ok(());
    }
    if row.adopted_proofs.len() != row.items.len() || row.items.len() > 6 || row.adoption_version > row.version {
        return Err(util::corrupt());
    }
    if row.tenant != Some(tenant)
        || row.target.is_none()
        || row.observation_id.is_none_or(|id| id.is_nil())
        || row.app_id.as_deref().is_none_or(|id| !util::positive_id(id))
        || row.fingerprint.as_deref().is_none_or(|hash| !util::digest(hash))
        || row.verified_at.is_none()
        || row.items.iter().map(|item| &item.kind).collect::<BTreeSet<_>>().len() != row.items.len()
        || row.items.iter().map(|item| &item.job_id).collect::<BTreeSet<_>>().len() != row.items.len()
        || row.adopted_proofs.iter().map(|proof| proof.id).collect::<BTreeSet<_>>().len() != row.items.len()
    {
        return Err(util::corrupt());
    }
    claim::validate_target(row.target.as_ref().ok_or_else(util::corrupt)?, tenant)?;
    for (assignment, proof) in row.items.iter().zip(&row.adopted_proofs) {
        let identity = expected(row, tenant, assignment)?;
        if proof.id != identity.proof_id || !util::digest(&proof.hash) {
            return Err(util::corrupt());
        }
        util::bound(proof, MAX_PROOF_BYTES)?;
    }
    let seal = row.qualification_seal.as_ref().ok_or_else(util::corrupt)?;
    if seal.id != qualification_id(row, tenant) || !util::digest(&seal.hash) {
        return Err(util::corrupt());
    }
    util::bound(seal, MAX_PROOF_BYTES)?;
    super::eligibility::validate_record(row, tenant)
}

pub(super) fn seal(state: &AppState, row: &BindingRecord, tenant: TenantId) -> DomainResult<Vec<AdoptedProof>> {
    seal_with_cipher(&cipher(state)?, row, tenant)
}
pub(super) fn seal_with_cipher(
    cipher: &FieldCipher,
    row: &BindingRecord,
    tenant: TenantId,
) -> DomainResult<Vec<AdoptedProof>> {
    if row.items.len() > 6 {
        return Err(util::corrupt());
    }
    row.items
        .iter()
        .map(|assignment| {
            let evidence = expected(row, tenant, assignment)?;
            let clear = serde_json::to_string(&evidence)?;
            if clear.len() > MAX_PROOF_BYTES / 2 {
                return Err(util::capacity());
            }
            let hash = util::hash(clear.as_bytes());
            let secret =
                cipher.encrypt(&SecretString::from(clear), &FieldCipher::make_aad(&tenant, &evidence.proof_id))?;
            let proof = AdoptedProof { id: evidence.proof_id, hash, secret };
            util::bound(&proof, MAX_PROOF_BYTES)?;
            Ok(proof)
        })
        .collect()
}

pub(super) fn restore(state: &AppState, row: &BindingRecord, tenant: TenantId) -> DomainResult<Vec<Provenance>> {
    if row.adoption_version == 0 {
        validate_record(row, tenant)?;
        return Ok(Vec::new());
    }
    restore_with_cipher(&cipher(state)?, row, tenant)
}
pub(super) fn restore_with_cipher(
    cipher: &FieldCipher,
    row: &BindingRecord,
    tenant: TenantId,
) -> DomainResult<Vec<Provenance>> {
    validate_record(row, tenant)?;
    if row.adoption_version > 0 {
        let seal = row.qualification_seal.as_ref().ok_or_else(util::corrupt)?;
        let value = util::decode_secret(cipher, tenant, seal.id, &seal.secret, &seal.hash)?;
        if value != qualification_value(row, tenant)? {
            return Err(util::corrupt());
        }
        util::bound(&value, MAX_PROOF_BYTES / 2)?;
    }
    row.items
        .iter()
        .zip(&row.adopted_proofs)
        .map(|(assignment, proof)| {
            let value = util::decode_secret(cipher, tenant, proof.id, &proof.secret, &proof.hash)?;
            util::bound(&value, MAX_PROOF_BYTES / 2)?;
            let actual: Provenance = serde_json::from_value(value).map_err(|_| util::corrupt())?;
            if actual != expected(row, tenant, assignment)? {
                return Err(util::corrupt());
            }
            Ok(actual)
        })
        .collect()
}

fn qualification_id(row: &BindingRecord, tenant: TenantId) -> Id {
    deterministic_id(QUALIFICATION_DOMAIN, &format!("{tenant}:{}:{}", util::binding_key(tenant).1, row.version))
}
fn qualification_value(row: &BindingRecord, tenant: TenantId) -> DomainResult<serde_json::Value> {
    let value = serde_json::json!({
        "domain":QUALIFICATION_DOMAIN,"tenant":tenant,"bindingId":util::binding_key(tenant).1,
        "version":row.version,"adoptionVersion":row.adoption_version,"locallyEnabled":row.enabled,
        "source":row.target,"eligibility":row.eligibility,
        "proofIds":row.adopted_proofs.iter().map(|proof|proof.id).collect::<Vec<_>>()
    });
    util::bound(&value, MAX_PROOF_BYTES / 2)?;
    Ok(value)
}
pub(super) fn seal_qualification(state: &AppState, row: &mut BindingRecord, tenant: TenantId) -> DomainResult<()> {
    seal_qualification_with_cipher(&cipher(state)?, row, tenant)
}
pub(super) fn seal_qualification_with_cipher(
    cipher: &FieldCipher,
    row: &mut BindingRecord,
    tenant: TenantId,
) -> DomainResult<()> {
    if row.adoption_version == 0 {
        row.qualification_seal = None;
        return Ok(());
    }
    let value = qualification_value(row, tenant)?;
    let clear = serde_json::to_string(&value)?;
    let hash = util::hash(clear.as_bytes());
    let id = qualification_id(row, tenant);
    let secret = cipher.encrypt(&SecretString::from(clear), &FieldCipher::make_aad(&tenant, &id))?;
    let seal = AdoptedProof { id, hash, secret };
    util::bound(&seal, MAX_PROOF_BYTES)?;
    row.qualification_seal = Some(seal);
    Ok(())
}
