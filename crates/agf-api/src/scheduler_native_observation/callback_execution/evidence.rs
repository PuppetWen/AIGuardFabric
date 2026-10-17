//! A latest progress pointer cannot turn untrusted cleartext partition flags into success evidence.
use super::super::util;
use super::{
    identity,
    model::{Batch, Fact, Progress, ProgressSeal},
};
use crate::{model_gateway::cipher, state::AppState};
use agf_core::{error::DomainResult, ids::TenantId};
use agf_storage::crypto::FieldCipher;
use secrecy::SecretString;
use serde_json::{Value, json};
const DOMAIN: &str = "agf.scheduler.callback.progress.v1";
const MAX_SEAL: usize = 128 * 1024;
const MAX_RECORD: usize = 256 * 1024;
const MAX_CLEAR: usize = 90 * 1024;
fn value(tenant: TenantId, kind: &str, batch: &Batch) -> DomainResult<Value> {
    batch.validate(tenant)?;
    if batch.context.kind != kind {
        return Err(util::corrupt());
    }
    let value = json!({"domain":DOMAIN,"tenant":tenant,"kind":kind,"batch":batch});
    util::bound(&value, MAX_CLEAR)?;
    Ok(value)
}
pub(super) fn seal(state: &AppState, tenant: TenantId, kind: &str, batch: Batch) -> DomainResult<Progress> {
    seal_with_cipher(&cipher(state)?, tenant, kind, batch)
}
pub(super) fn seal_with_cipher(
    cipher: &FieldCipher,
    tenant: TenantId,
    kind: &str,
    batch: Batch,
) -> DomainResult<Progress> {
    let key = identity::progress_key(tenant, kind);
    let clear = serde_json::to_string(&value(tenant, kind, &batch)?)?;
    let hash = util::hash(clear.as_bytes());
    let secret = cipher.encrypt(&SecretString::from(clear), &FieldCipher::make_aad(&tenant, &key.1))?;
    let seal = ProgressSeal { hash, secret };
    util::bound(&seal, MAX_SEAL)?;
    let row = Progress { tenant, kind: kind.into(), batch, seal };
    util::bound(&row, MAX_RECORD)?;
    Ok(row)
}
pub(super) fn verify(state: &AppState, row: &Progress) -> DomainResult<()> {
    verify_with_cipher(&cipher(state)?, row)
}
pub(super) fn verify_with_cipher(cipher: &FieldCipher, row: &Progress) -> DomainResult<()> {
    util::bound(row, MAX_RECORD)?;
    util::bound(&row.seal, MAX_SEAL)?;
    let key = identity::progress_key(row.tenant, &row.kind);
    let decoded = util::decode_secret(cipher, row.tenant, key.1, &row.seal.secret, &row.seal.hash)?;
    if decoded != value(row.tenant, &row.kind, &row.batch)? {
        return Err(util::corrupt());
    }
    Ok(())
}
fn fact_value(row: &Fact) -> DomainResult<Value> {
    let mut plain = row.clone();
    plain.seal = None;
    let value = json!({"domain":"agf.scheduler.callback.fact.v1","fact":plain});
    util::bound(&value, 32 * 1024)?;
    Ok(value)
}
pub(super) fn seal_fact(state: &AppState, row: &mut Fact) -> DomainResult<()> {
    seal_fact_with_cipher(&cipher(state)?, row)
}
pub(super) fn seal_fact_with_cipher(cipher: &FieldCipher, row: &mut Fact) -> DomainResult<()> {
    row.validate(row.context.tenant, row.id)?;
    let clear = serde_json::to_string(&fact_value(row)?)?;
    let hash = util::hash(clear.as_bytes());
    let secret = cipher.encrypt(&SecretString::from(clear), &FieldCipher::make_aad(&row.context.tenant, &row.id))?;
    row.seal = Some(ProgressSeal { hash, secret });
    util::bound(row, 64 * 1024)?;
    Ok(())
}
pub(super) fn verify_fact(state: &AppState, row: &Fact) -> DomainResult<()> {
    verify_fact_with_cipher(&cipher(state)?, row)
}
pub(super) fn verify_fact_with_cipher(cipher: &FieldCipher, row: &Fact) -> DomainResult<()> {
    row.validate(row.context.tenant, row.id)?;
    let seal = row.seal.as_ref().ok_or_else(util::corrupt)?;
    let decoded = util::decode_secret(cipher, row.context.tenant, row.id, &seal.secret, &seal.hash)?;
    if decoded != fact_value(row)? {
        return Err(util::corrupt());
    }
    Ok(())
}
