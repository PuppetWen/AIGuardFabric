//! Stable identities, content authentication and bounded serialization precede every write.
use super::{
    MAX_CONTENT_BYTES, NAME,
    records::{Fact, Main, Purpose, STATE, Values},
};
use crate::{
    model_gateway::{cipher, encrypt},
    state::AppState,
};
use agf_core::{
    audit::AuditLog,
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
};
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

pub(super) fn main_id(tenant: TenantId) -> Id {
    crate::integration_store::id(tenant, NAME)
}
pub(super) fn fact_id(tenant: TenantId, request: Id) -> Id {
    deterministic_id("agf.mse.config-publication.fact", &format!("{tenant}:{request}"))
}
pub(super) fn content_id(tenant: TenantId, request: Id, purpose: &str) -> Id {
    deterministic_id("agf.mse.config-publication.content", &format!("{tenant}:{request}:{purpose}"))
}
pub(super) fn risk_id(tenant: TenantId, scope: Id) -> Id {
    deterministic_id("agf.mse.config-publication.risk", &format!("{tenant}:{scope}"))
}
pub(super) fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub(super) fn request_hash<T: Serialize>(input: &T) -> DomainResult<String> {
    Ok(hash(&serde_json::to_vec(input)?))
}
pub(super) fn encrypt_content(state: &AppState, tenant: TenantId, id: Id, text: &str) -> DomainResult<SecretMaterial> {
    if text.len() > MAX_CONTENT_BYTES {
        return Err(capacity());
    }
    encrypt(state, tenant, id, text.to_owned())
}
pub(super) fn decrypt_content(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    encrypted: &SecretMaterial,
    expected_hash: &str,
) -> DomainResult<String> {
    if encrypted.aad.as_deref() != Some(FieldCipher::make_aad(&tenant, &id).as_str()) {
        return Err(corrupt());
    }
    let text = cipher(state)?.decrypt(encrypted)?;
    let text = text.expose_secret();
    if text.len() > MAX_CONTENT_BYTES || hash(text.as_bytes()) != expected_hash {
        return Err(corrupt());
    }
    Ok(text.to_owned())
}
pub(super) fn read<T: DeserializeOwned>(values: &Values, kind: &str, id: Id) -> DomainResult<Option<T>> {
    values
        .get(&(kind.to_owned(), id))
        .and_then(Option::as_ref)
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(Into::into)
}
pub(super) fn put<T: Serialize>(values: &mut Values, kind: &str, id: Id, record: &T) -> DomainResult<()> {
    let payload = serde_json::to_value(record)?;
    bound(&payload, 1024 * 1024)?;
    values.insert((kind.to_owned(), id), Some(payload));
    Ok(())
}
pub(super) fn bound<T: Serialize>(value: &T, max: usize) -> DomainResult<usize> {
    let bytes = serde_json::to_vec(value)?.len();
    if bytes > max {
        return Err(capacity());
    }
    Ok(bytes)
}

#[derive(Serialize)]
struct SerializedWrite<'a> {
    tenant: TenantId,
    kind: &'a str,
    id: Id,
    delete: bool,
    payload: Option<&'a serde_json::Value>,
}

/// Match the offline batch budget without serializing tuple keys as JSON object keys.
/// Explicit deletion markers, record identities and the maximum sealed audit are included.
pub(super) fn batch_bound(
    tenant: TenantId,
    main: &Main,
    related: &Values,
    audit: &AuditLog,
    max: usize,
) -> DomainResult<usize> {
    let bytes = serialized_batch(tenant, main, related, audit)?.len();
    if bytes > max {
        return Err(capacity());
    }
    Ok(bytes)
}

fn serialized_batch(tenant: TenantId, main: &Main, related: &Values, audit: &AuditLog) -> DomainResult<Vec<u8>> {
    let payload = serde_json::to_value(main)?;
    let mut writes =
        vec![SerializedWrite { tenant, kind: STATE, id: main_id(tenant), delete: false, payload: Some(&payload) }];
    for ((kind, id), value) in related {
        writes.push(SerializedWrite { tenant, kind, id: *id, delete: value.is_none(), payload: value.as_ref() });
    }
    let mut sealed_budget = audit.clone();
    sealed_budget.sequence = i64::MAX;
    sealed_budget.prev_hash = "0".repeat(64);
    sealed_budget.entry_hash = "0".repeat(64);
    Ok(serde_json::to_vec(&(writes, sealed_budget))?)
}
pub(super) fn initialize(main: &mut Main, tenant: TenantId) -> DomainResult<()> {
    if main.tenant.is_some_and(|owner| owner != tenant) {
        return Err(corrupt());
    }
    main.tenant = Some(tenant);
    if main.operations.len() > 128 || main.previews.len() > 32 || main.observations.len() > 8 {
        return Err(corrupt());
    }
    Ok(())
}
pub(super) fn bump(main: &mut Main) -> DomainResult<()> {
    main.version = main.version.checked_add(1).ok_or_else(capacity)?;
    main.generation = main.generation.checked_add(1).ok_or_else(capacity)?;
    Ok(())
}
pub(super) fn match_fact(fact: &Fact, tenant: TenantId, request: Id, purpose: Purpose, hash: &str) -> DomainResult<()> {
    if (fact.tenant, fact.request_id, fact.purpose) != (tenant, request, purpose) || fact.request_hash != hash {
        return Err(DomainError::Conflict("请求编号已领取或归档，不能用于不同内容、动作或目标；旧编号永不重派".into()));
    }
    Ok(())
}
pub(super) fn corrupt() -> DomainError {
    DomainError::Crypto("MSE发布持久记录的身份、密文或内容绑定不一致".into())
}
pub(super) fn stale() -> DomainError {
    DomainError::Conflict("配置、依赖或预览已改变；请重新读取并明确创建新预览".into())
}
pub(super) fn capacity() -> DomainError {
    DomainError::PreconditionFailed("MSE发布候选超出容量上限；请缩小政策选择或明确归档已结束的正文记录".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agf_core::audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget};
    use serde_json::{Value, json};

    fn entry(tenant: TenantId) -> AuditLog {
        AppState::audit_entry(
            tenant,
            AuditAction::Read,
            AuditOutcome::Success,
            AuditActor::system("owned-sql-batch-budget-test"),
            AuditTarget::new(STATE, None, None),
            "owned serialization test",
        )
    }

    #[test]
    fn scalar_record_keys_keep_null_and_delete_distinct_and_reserve_sealed_audit() -> DomainResult<()> {
        let tenant = TenantId::new();
        let main = Main { tenant: Some(tenant), ..Main::default() };
        let audit = entry(tenant);
        let null_id = Id::new();
        let deleted_id = Id::new();
        let related = Values::from([
            (("explicit-null".into(), null_id), Some(Value::Null)),
            (("explicit-delete".into(), deleted_id), None),
        ]);
        let encoded = serialized_batch(tenant, &main, &related, &audit)?;
        let decoded: Value = serde_json::from_slice(&encoded)?;
        assert_eq!(decoded[0][0]["tenant"], json!(tenant));
        assert_eq!(decoded[0][0]["id"], json!(main_id(tenant)));
        assert_eq!(decoded[0][1]["id"], json!(deleted_id));
        assert_eq!(decoded[0][1]["delete"], true);
        assert_eq!(decoded[0][2]["id"], json!(null_id));
        assert_eq!(decoded[0][2]["delete"], false);
        assert!(decoded[0][1]["payload"].is_null());
        assert!(decoded[0][2]["payload"].is_null());
        assert_eq!(decoded[1]["sequence"], i64::MAX);
        assert_eq!(decoded[1]["entry_hash"], "0".repeat(64));
        assert_eq!(audit.sequence, 0);
        assert_eq!(batch_bound(tenant, &main, &related, &audit, encoded.len())?, encoded.len());
        assert!(matches!(
            batch_bound(tenant, &main, &related, &audit, encoded.len() - 1),
            Err(DomainError::PreconditionFailed(_))
        ));
        Ok(())
    }

    #[test]
    fn the_full_batch_limit_counts_all_record_payloads_and_key_overhead() {
        let tenant = TenantId::new();
        let main = Main { tenant: Some(tenant), ..Main::default() };
        let audit = entry(tenant);
        let related = (0..9)
            .map(|index| ((format!("related-{index}"), Id::new()), Some(json!({"body":"x".repeat(1024 * 1024 - 32)}))))
            .collect();
        assert!(matches!(
            batch_bound(tenant, &main, &related, &audit, 8 * 1024 * 1024),
            Err(DomainError::PreconditionFailed(_))
        ));
    }
}
