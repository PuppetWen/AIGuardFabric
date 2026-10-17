//! Opaque, authenticated event-snapshot cursors. Annotation projections may change separately.
use super::{
    authority::{self, Submission},
    util,
};
use crate::state::AppState;
use agf_core::{
    credential::SecretMaterial,
    error::DomainResult,
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_ingest::pipeline::{AgentTeamsFailureQuery, AgentTeamsFailureSnapshot};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Query {
    pub(super) source_id: Option<Id>,
    pub(super) scope_id: Option<Id>,
    pub(super) from: Option<Timestamp>,
    pub(super) until: Option<Timestamp>,
    pub(super) limit: Option<usize>,
    pub(super) cursor: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    tenant: TenantId,
    source: Option<Id>,
    scope: Option<Id>,
    from: Timestamp,
    until: Timestamp,
    received_until: Timestamp,
    limit: usize,
    offset: usize,
    total: u64,
    digest: String,
    issued_at: Timestamp,
}
pub(super) struct Page {
    pub(super) snapshot: AgentTeamsFailureSnapshot,
    pub(super) query: AgentTeamsFailureQuery,
    pub(super) offset: usize,
    pub(super) limit: usize,
    pub(super) next: Option<String>,
}
pub(super) async fn load(state: &AppState, submission: &Submission, input: &Query) -> DomainResult<Page> {
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let now = Timestamp::now();
    let cursor = input.cursor.as_deref().map(|raw| decode(state, tenant, raw, now)).transpose()?;
    if let Some(row) = &cursor {
        if input.source_id != row.source
            || input.scope_id != row.scope
            || input.from.is_some_and(|at| at != row.from)
            || input.until.is_some_and(|at| at != row.until)
            || input.limit.is_some_and(|limit| limit != row.limit)
        {
            return Err(util::invalid());
        }
    }
    let until = cursor.as_ref().map_or_else(|| input.until.unwrap_or(now), |row| row.until);
    let query = AgentTeamsFailureQuery {
        tenant_id: tenant,
        source_id: input.source_id,
        scope_id: input.scope_id,
        from: cursor.as_ref().map_or_else(|| input.from.unwrap_or(until.offset_secs(-86_400)), |row| row.from),
        until,
        received_until: cursor.as_ref().map_or(now, |row| row.received_until),
    };
    let limit = cursor.as_ref().map_or(input.limit.unwrap_or(50), |row| row.limit);
    if !(1..=100).contains(&limit) {
        return Err(util::invalid());
    }
    let snapshot =
        authority::bounded(submission.deadline, state.ingest_sink.agentteams_failure_snapshot(&query)).await?;
    let digest = snapshot_hash(&snapshot)?;
    let offset = cursor.as_ref().map_or(0, |row| row.offset);
    if cursor.as_ref().is_some_and(|row| row.total != snapshot.total || row.digest != digest) {
        return Err(util::stale());
    }
    if offset > snapshot.records.len() {
        return Err(util::invalid());
    }
    let end = offset.saturating_add(limit).min(snapshot.records.len());
    let next = if end < snapshot.records.len() {
        Some(encode(
            state,
            &Cursor {
                tenant,
                source: query.source_id,
                scope: query.scope_id,
                from: query.from,
                until,
                received_until: query.received_until,
                limit,
                offset: end,
                total: snapshot.total,
                digest,
                issued_at: cursor.as_ref().map_or(now, |row| row.issued_at),
            },
        )?)
    } else {
        None
    };
    submission.authorize(state).await?;
    Ok(Page { snapshot, query, offset, limit, next })
}
fn snapshot_hash(snapshot: &AgentTeamsFailureSnapshot) -> DomainResult<String> {
    if snapshot.records.len() > 2000
        || snapshot.total < u64::try_from(snapshot.records.len()).map_err(|_| util::corrupt())?
        || snapshot.truncated != (snapshot.total > 2000)
    {
        return Err(util::corrupt());
    }
    util::hash(&(snapshot.total, &snapshot.records))
}
fn aad(tenant: TenantId) -> String {
    format!("agf.agentteams.task-handling.cursor.v1:{tenant}")
}
fn encode(state: &AppState, row: &Cursor) -> DomainResult<String> {
    let cipher = crate::model_gateway::cipher(state)?;
    encode_with_cipher(&cipher, row)
}
fn encode_with_cipher(cipher: &agf_storage::crypto::FieldCipher, row: &Cursor) -> DomainResult<String> {
    let material = cipher.encrypt(&SecretString::from(serde_json::to_string(row)?), &aad(row.tenant))?;
    let value = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&material)?);
    if value.len() > 4096 {
        return Err(util::invalid());
    }
    Ok(value)
}
fn decode(state: &AppState, tenant: TenantId, raw: &str, now: Timestamp) -> DomainResult<Cursor> {
    decode_with_cipher(&crate::model_gateway::cipher(state)?, tenant, raw, now)
}
fn decode_with_cipher(
    cipher: &agf_storage::crypto::FieldCipher,
    tenant: TenantId,
    raw: &str,
    now: Timestamp,
) -> DomainResult<Cursor> {
    if raw.is_empty() || raw.len() > 4096 {
        return Err(util::invalid());
    }
    let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| util::invalid())?;
    let material: SecretMaterial = serde_json::from_slice(&bytes).map_err(|_| util::invalid())?;
    if material.aad.as_deref() != Some(aad(tenant).as_str()) || material.plaintext_len > 2048 {
        return Err(util::invalid());
    }
    let text = cipher.decrypt(&material).map_err(|_| util::invalid())?;
    let row: Cursor = serde_json::from_str(text.expose_secret()).map_err(|_| util::invalid())?;
    let age =
        now.as_datetime().signed_duration_since(row.issued_at.as_datetime()).to_std().map_err(|_| util::invalid())?;
    if row.tenant != tenant
        || age > std::time::Duration::from_mins(30)
        || !util::digest(&row.digest)
        || row.offset == 0
        || row.offset >= 2000
        || !(1..=100).contains(&row.limit)
    {
        return Err(util::invalid());
    }
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cursor_authenticates_tenant_and_every_filter_without_creating_records() -> DomainResult<()> {
        let fixture = super::super::tests_support::Fixture::new()?;
        let tenant = TenantId::new();
        let now = Timestamp::now();
        let row = Cursor {
            tenant,
            source: Some(Id::new()),
            scope: Some(Id::new()),
            from: now.offset_secs(-100),
            until: now,
            received_until: now,
            limit: 1,
            offset: 1,
            total: 2,
            digest: "a".repeat(64),
            issued_at: now,
        };
        let encoded = encode_with_cipher(&fixture.cipher, &row)?;
        let decoded = decode_with_cipher(&fixture.cipher, tenant, &encoded, now)?;
        assert_eq!((decoded.source, decoded.scope, decoded.total), (row.source, row.scope, 2));
        assert!(decode_with_cipher(&fixture.cipher, TenantId::new(), &encoded, now).is_err());
        assert!(decode_with_cipher(&fixture.cipher, tenant, &encoded, now.offset_secs(1801)).is_err());
        let mut bytes = encoded.into_bytes();
        bytes[10] = if bytes[10] == b'A' { b'B' } else { b'A' };
        assert!(
            decode_with_cipher(&fixture.cipher, tenant, std::str::from_utf8(&bytes).map_err(|_| util::invalid())?, now)
                .is_err()
        );
        Ok(())
    }
}
