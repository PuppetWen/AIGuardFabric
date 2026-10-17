//! Persist invalid deliveries before ACK. Tenant claims inside broker bytes are never trusted.
use super::{AppState, database};
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    event::Event,
    ids::{Id, TenantId, deterministic_id},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

mod actions;
mod queries;
pub use actions::{act, recover_expired};
pub use queries::{detail, history, list};

#[derive(Serialize, Deserialize)]
struct Envelope {
    prefix: String,
    subject: String,
    payload_b64: String,
}

/// Stream sequence identifies a delivery; the content digest distinguishes a recreated stream.
pub fn message_id(stream: &str, sequence: u64, subject: &str, payload: &[u8]) -> Id {
    let digest = hex::encode(Sha256::digest(payload));
    deterministic_id("agf.broker-quarantine", &format!("{stream}:{sequence}:{subject}:{digest}"))
}

/// Successful return permits ACK: analysis, SQL retry ownership, or durable quarantine.
pub async fn handle_delivery(
    state: &AppState,
    stream: &str,
    sequence: u64,
    prefix: &str,
    subject: &str,
    payload: &[u8],
) -> DomainResult<()> {
    let reason = match serde_json::from_slice::<Event>(payload) {
        Err(_) => Some("invalid_payload"),
        Ok(event) if subject != format!("{prefix}.{}.{}", event.tenant_id, event.severity.as_str()) => {
            Some("subject_mismatch")
        }
        Ok(_) => match super::process_or_defer_delivery(state, prefix, subject, payload).await {
            Ok(_) => return Ok(()),
            Err(DomainError::NotFound { entity: "committed-event", .. }) => Some("missing_event"),
            Err(DomainError::NotFound { entity: "tenant", .. }) => Some("unknown_tenant"),
            Err(error) => return Err(error), // SQL/network failures retain broker ownership.
        },
    };
    let reason = reason.unwrap_or("invalid_payload");
    let tenant = TenantId::default_tenant();
    let id = message_id(stream, sequence, subject, payload);
    let sequence = i64::try_from(sequence).map_err(|_| DomainError::Validation("Broker sequence overflow".into()))?;
    let length = i64::try_from(payload.len()).map_err(|_| DomainError::Validation("Broker payload overflow".into()))?;
    let envelope = Envelope { prefix: prefix.into(), subject: subject.into(), payload_b64: STANDARD.encode(payload) };
    let sealed = crate::model_gateway::encrypt(state, tenant, id, serde_json::to_string(&envelope)?)?;
    let sealed = serde_json::to_value(sealed)?;
    let hash = hex::encode(Sha256::digest(payload));
    let stream = stream.to_owned();
    database(state)?
        .with_tenant(tenant, move |tx| {
            Box::pin(async move {
                sqlx::query(
                    "INSERT INTO broker_quarantine
            (tenant_id,id,stream,stream_sequence,payload_hash,payload_bytes,sealed_envelope,reason_code)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (tenant_id,id) DO NOTHING",
                )
                .bind(tenant.as_uuid())
                .bind(id.as_uuid())
                .bind(stream)
                .bind(sequence)
                .bind(hash)
                .bind(length)
                .bind(sealed)
                .bind(reason)
                .execute(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("broker_quarantine_save", &e))?;
                Ok(())
            })
        })
        .await?;
    tracing::warn!(message_id=%id, reason, "Invalid broker delivery preserved in platform quarantine");
    Ok(())
}

fn decrypt(state: &AppState, id: Id, sealed: Value) -> DomainResult<Envelope> {
    let sealed: SecretMaterial = serde_json::from_value(sealed)?;
    let expected = agf_storage::crypto::FieldCipher::make_aad(&TenantId::default_tenant(), &id);
    if sealed.aad.as_deref() != Some(&expected) {
        return Err(DomainError::Crypto("Broker evidence binding mismatch".into()));
    }
    let plaintext = crate::model_gateway::cipher(state)?.decrypt(&sealed)?;
    serde_json::from_str(plaintext.expose_secret()).map_err(|_| DomainError::Crypto("Invalid broker evidence".into()))
}

fn not_found(id: Id) -> DomainError {
    DomainError::NotFound { entity: "broker-quarantine", id: id.to_string() }
}
