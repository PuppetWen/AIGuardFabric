//! Authenticated cursors bind all query inputs and reject a changed bounded snapshot.
use super::{binding::Context, trace::TraceQuery};
use crate::{model_gateway, state::AppState};
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_ingest::pipeline::{AgentTeamsAuditCursor, AgentTeamsAuditRecord, AgentTeamsTraceSnapshot};
use agf_storage::crypto::FieldCipher;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cursor {
    pub tenant: TenantId,
    pub scope: Id,
    pub trace_id: String,
    pub from: Timestamp,
    pub until: Timestamp,
    pub received_until: Timestamp,
    pub issued_at: Timestamp,
    pub before: AgentTeamsAuditCursor,
    pub emitted: usize,
    pub snapshot_digest: String,
}

pub(super) fn encode(state: &AppState, value: &Cursor) -> DomainResult<String> {
    let encrypted = model_gateway::encrypt(state, value.tenant, value.scope, serde_json::to_string(value)?)?;
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&encrypted)?))
}

pub(super) fn decode(
    state: &AppState,
    raw: &str,
    tenant: TenantId,
    context: &Context,
    trace_id: &str,
    query: &TraceQuery,
    now: Timestamp,
) -> DomainResult<Cursor> {
    if raw.len() > 4096 {
        return Err(invalid());
    }
    let encrypted: SecretMaterial =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(raw).map_err(|_| invalid())?).map_err(|_| invalid())?;
    let text = model_gateway::cipher(state)?.decrypt(&encrypted).map_err(|_| invalid())?;
    let cursor: Cursor = serde_json::from_str(text.expose_secret()).map_err(|_| invalid())?;
    let expected_aad = FieldCipher::make_aad(&tenant, &cursor.scope);
    if cursor.tenant != tenant || encrypted.aad.as_deref() != Some(expected_aad.as_str()) {
        return Err(invalid());
    }
    if cursor.scope != context.scope_id {
        return Err(super::stale());
    }
    let before = cursor.before.event_time.as_datetime().timestamp_micros();
    if cursor.trace_id != trace_id
        || query.from.is_some_and(|from| from != cursor.from)
        || query.until.is_some_and(|until| until != cursor.until)
        || cursor.issued_at > now
        || now.since_secs(&cursor.issued_at) > 1800
        || cursor.emitted == 0
        || cursor.emitted >= 2000
        || before < cursor.from.as_datetime().timestamp_micros()
        || before >= cursor.until.as_datetime().timestamp_micros()
    {
        return Err(invalid());
    }
    Ok(cursor)
}

pub(super) fn digest(snapshot: &AgentTeamsTraceSnapshot) -> DomainResult<String> {
    let mut hash = Sha256::new();
    hash.update(snapshot.total.to_be_bytes());
    for record in &snapshot.records {
        let bytes = serde_json::to_vec(record)?;
        hash.update(
            u64::try_from(bytes.len()).map_err(|error| DomainError::Internal(error.to_string()))?.to_be_bytes(),
        );
        hash.update(bytes);
    }
    Ok(hex::encode(hash.finalize()))
}

pub(super) fn offset(cursor: Option<&Cursor>, records: &[AgentTeamsAuditRecord], digest: &str) -> DomainResult<usize> {
    let Some(cursor) = cursor else { return Ok(0) };
    if cursor.snapshot_digest != digest {
        return Err(DomainError::Conflict("Trace 审计记录已改变，请刷新查询；没有拼接不同快照的页面".into()));
    }
    let Some(previous) = records.get(cursor.emitted - 1) else { return Err(invalid()) };
    if previous.id != cursor.before.id || previous.event_time != cursor.before.event_time {
        return Err(invalid());
    }
    Ok(cursor.emitted)
}

fn invalid() -> DomainError {
    DomainError::Validation("Trace 游标无效、条件已改变或已过期，请刷新查询".into())
}
