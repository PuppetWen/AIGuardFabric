//! 加密的 TOTP 绑定；验证码与恢复码在数据库锁内消费，防止并发重放。
use crate::config_store::ConfigStore;
use agf_auth::mfa::TotpService;
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
    user::User,
};
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub const KIND: &str = "mfa-enrollment";

mod transition;
pub use transition::{confirm_sql, disable_sql};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Enrollment {
    pub secret: Option<SecretMaterial>,
    pub confirmed: bool,
    pub created_at: i64,
    #[serde(default)]
    pub confirmed_at: i64,
    pub recovery_hashes: Vec<String>,
    pub used_codes: Vec<(String, i64)>,
}
impl std::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrollment").field("confirmed", &self.confirmed).finish_non_exhaustive()
    }
}

pub fn decrypt(cipher: &FieldCipher, tenant: TenantId, id: Id, value: &Enrollment) -> DomainResult<String> {
    let secret = value.secret.as_ref().ok_or_else(|| DomainError::PreconditionFailed("请先发起 MFA 绑定".into()))?;
    if secret.aad.as_deref() != Some(&FieldCipher::make_aad(&tenant, &id)) {
        return Err(DomainError::Crypto("MFA 凭据绑定不匹配".into()));
    }
    Ok(cipher.decrypt(secret)?.expose_secret().to_string())
}

pub async fn verify(
    store: &Arc<ConfigStore>,
    cipher: &FieldCipher,
    tenant: TenantId,
    user: &User,
    code: Option<&str>,
) -> DomainResult<bool> {
    if tenant != user.tenant_id {
        return Ok(false);
    }
    if !user.mfa_enabled {
        return Ok(true);
    }
    let Some(code) = code.filter(|code| !code.trim().is_empty()) else { return Ok(false) };
    let mut accepted = false;
    store
        .mutate::<Enrollment, _>(tenant, KIND, user.id, |record| {
            accepted = verify_record(record, cipher, tenant, user, code)?;
            Ok(())
        })
        .await?;
    Ok(accepted)
}

fn verify_record(
    record: &mut Enrollment,
    cipher: &FieldCipher,
    tenant: TenantId,
    user: &User,
    code: &str,
) -> DomainResult<bool> {
    if !record.confirmed {
        return Ok(false);
    }
    let secret = decrypt(cipher, tenant, user.id, record)?;
    let service = TotpService::default();
    let now = Timestamp::now().unix_secs();
    record.used_codes.retain(|(_, expires)| *expires > now);
    let normalized = code.trim().replace(' ', "");
    let digest = agf_core::secret::fingerprint(&normalized, &user.id.to_string());
    if service.verify(&user.username, &secret, &normalized)? {
        if record.used_codes.iter().any(|(previous, _)| *previous == digest) {
            return Ok(false);
        }
        record.used_codes.push((digest, now + 120));
        return Ok(true);
    }
    if let Some(index) = service.verify_recovery_code(code, &record.recovery_hashes, &user.id.to_string())? {
        record.recovery_hashes.remove(index);
        return Ok(true);
    }
    Ok(false)
}
