use super::{Binding, Observation, observe};
use crate::http::RpcResponse;
use agf_core::error::DomainResult;
use serde_json::{Value, json};

const MAX_EVIDENCE_BYTES: usize = 512 * 1024;

/// Restore authenticated evidence by validating the original three complete response bodies.
///
/// The caller must authenticate tenant/source ownership and AEAD before calling this function.
/// Stored evidence is never accepted merely because it deserializes or carries a stored hash.
///
/// # Errors
/// Schema, encoded byte budget, exact resource identities or provider/configuration evidence is invalid.
pub fn restore_evidence(binding: &Binding, evidence: &Value) -> DomainResult<Observation> {
    bounded(evidence)?;
    let fields = evidence.as_object().ok_or_else(|| observe::evidence("APIG evidence is not an object"))?;
    if fields.len() != 4 || fields.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(observe::evidence("APIG evidence schema is unsupported"));
    }
    observe::parse_current(
        binding,
        &response(evidence, "httpApi")?,
        &response(evidence, "policy")?,
        &response(evidence, "attachment")?,
    )
}

pub(super) fn capture(api: &RpcResponse, policy: &RpcResponse, attachment: &RpcResponse) -> DomainResult<Value> {
    let value = json!({
        "version": 1,
        "httpApi": {"status": api.status, "body": api.body},
        "policy": {"status": policy.status, "body": policy.body},
        "attachment": {"status": attachment.status, "body": attachment.body},
    });
    bounded(&value)?;
    Ok(value)
}

fn bounded(evidence: &Value) -> DomainResult<()> {
    if serde_json::to_vec(evidence)?.len() > MAX_EVIDENCE_BYTES {
        return Err(observe::evidence("Complete APIG evidence exceeds 512 KiB"));
    }
    Ok(())
}

fn response(evidence: &Value, name: &str) -> DomainResult<RpcResponse> {
    let fields = evidence[name].as_object().ok_or_else(|| observe::evidence("APIG response evidence is missing"))?;
    let status = fields
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|status| u16::try_from(status).ok())
        .ok_or_else(|| observe::evidence("APIG evidence status is invalid"))?;
    if fields.len() != 2 {
        return Err(observe::evidence("APIG response evidence has unexpected fields"));
    }
    let body = fields.get("body").cloned().ok_or_else(|| observe::evidence("APIG evidence body is missing"))?;
    Ok(RpcResponse { status, body, raw: String::new() })
}
