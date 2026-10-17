use super::super::{claim, store, util};
use super::model::{Envelope, Index, Journal, Known, MAX_DETAIL, Operation, Preview, PreviewRecord, Purpose, State};
use crate::state::AppState;
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

pub(super) fn key(tenant: TenantId, id: Id, kind: &str) -> (String, Id) {
    (kind.into(), util::key_id(tenant, id, kind))
}
pub(super) fn state_key(tenant: TenantId) -> (String, Id) {
    key(tenant, util::main_id(tenant), super::model::STATE)
}
pub(in super::super) fn request_key(tenant: TenantId, id: Id) -> (String, Id) {
    key(tenant, id, super::model::REQUEST)
}
pub(super) fn hash<T: Serialize>(purpose: Purpose, input: &T) -> DomainResult<String> {
    util::canonical_hash(&json!({"domain":"agf.scheduler.managed.request.v1","purpose":purpose,"input":input}))
}
pub(super) fn seal<T: Serialize>(
    state: &AppState,
    tenant: TenantId,
    key: &(String, Id),
    row: &T,
) -> DomainResult<Value> {
    seal_at(state, tenant, key, row, Timestamp::now())
}
pub(super) fn seal_at<T: Serialize>(
    state: &AppState,
    tenant: TenantId,
    key: &(String, Id),
    row: &T,
    encrypted_at: Timestamp,
) -> DomainResult<Value> {
    let value = serde_json::to_value(row)?;
    util::bound(&value, MAX_DETAIL / 2)?;
    let (mut secret, hash) = util::encrypt_json(state, tenant, key.1, &value)?;
    secret.encrypted_at = encrypted_at;
    let sealed = Envelope { tenant, id: key.1, hash, secret };
    util::bound(&sealed, MAX_DETAIL)?;
    Ok(serde_json::to_value(sealed)?)
}
pub(super) fn decode<T: DeserializeOwned>(
    state: &AppState,
    tenant: TenantId,
    key: &(String, Id),
    value: &Value,
) -> DomainResult<T> {
    let envelope: Envelope = serde_json::from_value(value.clone()).map_err(|_| util::corrupt())?;
    if envelope.tenant != tenant || envelope.id != key.1 || !util::digest(&envelope.hash) {
        return Err(util::corrupt());
    }
    util::bound(&envelope, MAX_DETAIL)?;
    serde_json::from_value(util::decrypt_json(state, tenant, key.1, &envelope.secret, &envelope.hash)?)
        .map_err(|_| util::corrupt())
}
pub(super) async fn load<T: DeserializeOwned>(
    state: &AppState,
    tenant: TenantId,
    key: &(String, Id),
) -> DomainResult<Option<T>> {
    let value = store::get::<Value>(state, tenant, key).await?;
    value.as_ref().map(|value| decode(state, tenant, key, value)).transpose()
}
pub(super) async fn journal(state: &AppState, tenant: TenantId) -> DomainResult<Journal> {
    let row = load(state, tenant, &state_key(tenant)).await?.unwrap_or_default();
    super::model::validate_journal(&row, tenant)?;
    Ok(row)
}
pub(super) fn snapshot<T: DeserializeOwned>(
    state: &AppState,
    tenant: TenantId,
    values: &super::super::records::Values,
    key: &(String, Id),
) -> DomainResult<Option<T>> {
    values.get(key).and_then(Option::as_ref).map(|value| decode(state, tenant, key, value)).transpose()
}
pub(super) fn index(
    row: &Index,
    tenant: TenantId,
    id: Id,
    purpose: Purpose,
    actor: Id,
    hash: &str,
) -> DomainResult<()> {
    if row.tenant != tenant || row.request_id != id || !util::digest(&row.hash) || row.actor.is_nil() {
        return Err(util::corrupt());
    }
    if row.purpose != purpose || row.actor != actor || row.hash != hash {
        return Err(super::conflict());
    }
    Ok(())
}
pub(super) fn preview(row: &Preview, tenant: TenantId, id: Id) -> DomainResult<()> {
    row.input.validate().map_err(|_| util::corrupt())?;
    claim::validate_target(&row.target, tenant)?;
    if row.tenant != tenant
        || row.id != id
        || row.input.request_id != id
        || row.actor.is_nil()
        || row.input_hash != hash(Purpose::Preview, &row.input)?
        || row.expires_at != row.created_at.offset_secs(120)
        || !util::positive_id(&row.app_id)
        || !util::digest(&row.baseline_fingerprint)
        || row.operation_id.is_some_and(|id| id.is_nil())
        || row.input.configuration_version != row.target.configuration_version
        || !util::digest(&row.fingerprint)
    {
        return Err(util::corrupt());
    }
    let fingerprint = util::canonical_hash(&json!({"domain":"agf.scheduler.managed.preview.v1","tenant":row.tenant,
        "id":row.id,"actor":row.actor,"inputHash":row.input_hash,"target":row.target,"before":row.before,
        "desired":row.desired,"baselineFingerprint":row.baseline_fingerprint,"expiresAt":row.expires_at}))?;
    if fingerprint != row.fingerprint {
        return Err(util::corrupt());
    }
    util::bound(row, MAX_DETAIL / 2)?;
    Ok(())
}
pub(super) fn preview_record(row: &PreviewRecord, tenant: TenantId, id: Id) -> DomainResult<()> {
    match row {
        PreviewRecord::Content(row) => preview(row, tenant, id),
        PreviewRecord::Archived(row) => {
            claim::validate_target(&row.target, tenant)?;
            if (row.tenant, row.id) != (tenant, id)
                || row.actor.is_nil()
                || !util::digest(&row.input_hash)
                || !util::digest(&row.fingerprint)
                || row.archived_at < row.created_at
                || row.operation_id.is_some_and(|id| id.is_nil())
            {
                return Err(util::corrupt());
            }
            util::bound(row, MAX_DETAIL / 2).map(|_| ())
        }
    }
}
pub(super) fn operation(row: &Operation, tenant: TenantId, id: Id) -> DomainResult<()> {
    row.input.validate().map_err(|_| util::corrupt())?;
    claim::validate_target(&row.target, tenant)?;
    if row.tenant != tenant
        || row.request_id != id
        || row.actor.is_nil()
        || row.claim_id.is_nil()
        || row.input_hash != hash(Purpose::Apply, &row.input)?
        || row.submitted_at > row.started_at
        || row.expires_at != row.started_at.offset_secs(120)
        || row.job_id.as_deref().is_some_and(|id| !util::positive_id(id))
        || (row.state == State::Complete) != row.finished_at.is_some()
        || (row.state == State::Started && row.write.is_some())
        || row.detail_bytes > MAX_DETAIL
        || (row.state == State::Complete && row.write.is_none())
        || !["create_disabled", "update_schedule", "disable", "enable"].contains(&row.action.as_str())
    {
        return Err(util::corrupt());
    }
    if row.readback_fingerprint.as_deref().is_some_and(|hash| !util::digest(hash))
        || row.readback_at.is_some() != row.readback_fingerprint.is_some()
    {
        return Err(util::corrupt());
    }
    if row
        .write
        .as_ref()
        .is_some_and(|write| write.provider_request_id.as_deref().is_some_and(|id| !util::text(id, 256)))
    {
        return Err(util::corrupt());
    }
    if let Some(preview) = &row.preview {
        self::preview(preview, tenant, row.input.preview_id)?;
        if preview.target != row.target
            || preview.actor != row.actor
            || preview.fingerprint != row.input.preview_fingerprint
        {
            return Err(util::corrupt());
        }
    } else if row.archived_at.is_none() {
        return Err(util::corrupt());
    }
    if row.archived_at.is_some() && (row.state != State::Complete || row.preview.is_some()) {
        return Err(util::corrupt());
    }
    util::bound(row, MAX_DETAIL / 2)?;
    Ok(())
}
pub(super) fn known(row: &Known, original: &Operation) -> DomainResult<()> {
    if row.domain != "agf.scheduler.managed.known.v1"
        || (row.tenant, row.request_id, row.claim_id, row.input_hash.as_str())
            != (original.tenant, original.request_id, original.claim_id, original.input_hash.as_str())
        || row.staged_at < original.started_at
        || row.staged_at > Timestamp::now().offset_secs(30)
        || row.job_id != original.job_id
        || row.write.provider_request_id.as_deref().is_some_and(|id| !util::text(id, 256))
    {
        return Err(util::corrupt());
    }
    util::bound(row, MAX_DETAIL / 2)?;
    Ok(())
}
