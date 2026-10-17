//! Self-contained, authenticated SSE recovery cursors; no database write per event.
use super::invalid;
use crate::{Principal, model_gateway::cipher, state::AppState};
use agf_core::{credential::SecretMaterial, error::DomainResult, ids::Id, time::Timestamp};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "agf1.";
const MAX_UPSTREAM_ID: usize = 512;
const MAX_CURSOR: usize = 4096;

#[derive(Serialize, Deserialize)]
struct Token {
    ciphertext: String,
    nonce: String,
    tag: String,
}

fn aad(principal: &Principal, endpoint: Id, version: u64, session: Id) -> String {
    format!(
        "mcp-event:v1|tenant:{}|endpoint:{endpoint}|version:{version}|session:{session}|owner:{}",
        principal.tenant,
        principal.display()
    )
}

fn valid_upstream_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_UPSTREAM_ID && value.bytes().all(|byte| (32..=126).contains(&byte))
}

pub(super) fn seal(
    state: &AppState,
    principal: &Principal,
    endpoint: Id,
    version: u64,
    session: Id,
    upstream: &str,
) -> DomainResult<String> {
    if !valid_upstream_id(upstream) {
        return Err(invalid("Upstream returned an invalid MCP event ID"));
    }
    let material = cipher(state)?
        .encrypt(&SecretString::from(upstream.to_owned()), &aad(principal, endpoint, version, session))?;
    let token = Token {
        ciphertext: material.ciphertext_b64,
        nonce: material.nonce_b64,
        tag: material.tag_b64.ok_or_else(|| invalid("MCP event encryption did not produce an authentication tag"))?,
    };
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(&token)?)))
}

pub(super) fn open(
    state: &AppState,
    principal: &Principal,
    endpoint: Id,
    version: u64,
    session: Id,
    cursor: &str,
) -> DomainResult<String> {
    let encoded = cursor.strip_prefix(PREFIX).ok_or_else(|| invalid("Invalid MCP event cursor"))?;
    if encoded.is_empty() || encoded.len() > MAX_CURSOR {
        return Err(invalid("Invalid MCP event cursor"));
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| invalid("Invalid MCP event cursor"))?;
    let token: Token = serde_json::from_slice(&bytes).map_err(|_| invalid("Invalid MCP event cursor"))?;
    let key = cipher(state)?;
    let material = SecretMaterial {
        backend: key.backend(),
        key_id: key.key_id().to_owned(),
        ciphertext_b64: token.ciphertext,
        nonce_b64: token.nonce,
        tag_b64: Some(token.tag),
        plaintext_len: 0,
        encrypted_at: Timestamp::now(),
        aad: Some(aad(principal, endpoint, version, session)),
    };
    let upstream = key.decrypt(&material).map_err(|_| invalid("Invalid MCP event cursor"))?;
    if !valid_upstream_id(upstream.expose_secret()) {
        return Err(invalid("Invalid MCP event cursor"));
    }
    Ok(upstream.expose_secret().to_owned())
}
