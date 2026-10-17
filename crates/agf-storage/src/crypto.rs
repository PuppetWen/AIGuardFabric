//! 字段级加解密（§4.4 密钥管理、§5.3 凭据不落明文）。
//!
//! 设计：
//! - 算法 **AES-256-GCM**，12 字节随机 nonce，16 字节认证标签；
//! - 主密钥来自 `AGF_MASTER_KEY_BASE64`（32 字节）或 KMS（`KeyBackend`）；
//! - **AAD 绑定租户与凭据 id**，使得密文被"搬家"到别的租户/记录时解密失败；
//! - 明文在内存中包在 [`SecretString`]（`zeroize`）里，Drop 时清零；
//! - 本模块不含任何 I/O，可完整单元测试。

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use agf_core::credential::{KeyBackend, SecretMaterial};
use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::Id;
use agf_core::time::Timestamp;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};

/// AES-GCM nonce 长度（字节）。
pub const NONCE_LEN: usize = 12;
/// AES-256 密钥长度（字节）。
pub const KEY_LEN: usize = 32;

/// 数据加密器：持有主密钥，提供加解密与轮换能力。
///
/// `Debug` 实现不打印密钥内容。
#[derive(Clone)]
pub struct FieldCipher {
    key: [u8; KEY_LEN],
    key_id: String,
    backend: KeyBackend,
}

impl std::fmt::Debug for FieldCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldCipher")
            .field("key", &"<redacted 32 bytes>")
            .field("key_id", &self.key_id)
            .field("backend", &self.backend)
            .finish()
    }
}

impl FieldCipher {
    /// 由 32 字节主密钥构造。
    ///
    /// # Errors
    /// 密钥长度不为 32 字节时返回 [`DomainError::Crypto`]。
    pub fn new(key: &[u8], key_id: impl Into<String>, backend: KeyBackend) -> DomainResult<Self> {
        if key.len() != KEY_LEN {
            return Err(DomainError::Crypto(format!(
                "主密钥长度必须为 {KEY_LEN} 字节（AES-256），实际 {} 字节",
                key.len()
            )));
        }
        let mut buf = [0_u8; KEY_LEN];
        buf.copy_from_slice(key);
        Ok(Self { key: buf, key_id: key_id.into(), backend })
    }

    /// 由 base64 主密钥构造。
    ///
    /// # Errors
    /// base64 非法或长度不为 32 字节。
    pub fn from_base64(value: &str, key_id: impl Into<String>, backend: KeyBackend) -> DomainResult<Self> {
        let raw = B64.decode(value.trim()).map_err(|e| DomainError::Crypto(format!("主密钥不是合法 base64: {e}")))?;
        Self::new(&raw, key_id, backend)
    }

    /// 生成新的随机主密钥（base64），供 `agfctl genkey` 使用。
    #[must_use]
    pub fn generate_master_key_b64() -> String {
        let mut buf = [0_u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut buf);
        B64.encode(buf)
    }

    /// 密钥标识。
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// 后端类型。
    #[must_use]
    pub const fn backend(&self) -> KeyBackend {
        self.backend
    }

    /// 构造 AAD：`tenant:<租户>|id:<记录 id>`。
    ///
    /// 作用：密文与租户/记录绑定，防止把 A 租户的密文搬到 B 租户记录上复用。
    #[must_use]
    pub fn make_aad(tenant: &agf_core::ids::TenantId, record: &Id) -> String {
        format!("tenant:{tenant}|id:{record}")
    }

    /// 加密明文。
    ///
    /// # Errors
    /// 加密失败（理论上仅当明文长度超出 GCM 限制）。
    pub fn encrypt(&self, plaintext: &SecretString, aad: &str) -> DomainResult<SecretMaterial> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| DomainError::Crypto(format!("初始化 AES-256-GCM 失败: {e}")))?;
        let mut nonce_bytes = [0_u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, Payload { msg: plaintext.expose_secret().as_bytes(), aad: aad.as_bytes() })
            .map_err(|e| DomainError::Crypto(format!("加密失败: {e}")))?;
        // GCM 输出 = 密文 ‖ 16 字节 tag；拆开存储便于与其它后端统一
        if ct.len() < 16 {
            return Err(DomainError::Crypto("密文长度异常（缺少认证标签）".to_string()));
        }
        let (body, tag) = ct.split_at(ct.len() - 16);
        Ok(SecretMaterial {
            backend: self.backend,
            key_id: self.key_id.clone(),
            ciphertext_b64: B64.encode(body),
            nonce_b64: B64.encode(nonce_bytes),
            tag_b64: Some(B64.encode(tag)),
            plaintext_len: plaintext.expose_secret().chars().count(),
            encrypted_at: Timestamp::now(),
            aad: Some(aad.to_string()),
        })
    }

    /// 解密。
    ///
    /// # Errors
    /// - 密钥不匹配 → `key_id` 与本实例不一致（应先轮换密钥）；
    /// - AAD 不匹配 / 密文被篡改 → GCM 认证失败（`DomainError::Crypto`）。
    pub fn decrypt(&self, material: &SecretMaterial) -> DomainResult<SecretString> {
        if material.key_id != self.key_id {
            return Err(DomainError::Crypto(format!(
                "密文由密钥 {} 加密，当前密钥为 {}，请先执行密钥轮换解密",
                material.key_id, self.key_id
            )));
        }
        let body = B64
            .decode(material.ciphertext_b64.trim())
            .map_err(|e| DomainError::Crypto(format!("密文不是合法 base64: {e}")))?;
        let tag = match &material.tag_b64 {
            Some(t) => B64.decode(t.trim()).map_err(|e| DomainError::Crypto(format!("认证标签非法: {e}")))?,
            None => {
                // 兼容：密文与 tag 拼接存储的形态
                if body.len() < 16 {
                    return Err(DomainError::Crypto("密文长度不足以包含认证标签".to_string()));
                }
                body[body.len() - 16..].to_vec()
            }
        };
        let nonce_bytes =
            B64.decode(material.nonce_b64.trim()).map_err(|e| DomainError::Crypto(format!("nonce 非法: {e}")))?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(DomainError::Crypto(format!("nonce 长度必须为 {NONCE_LEN} 字节")));
        }
        let mut combined = body;
        if material.tag_b64.is_some() {
            combined.extend_from_slice(&tag);
        }
        let aad = material.aad.clone().unwrap_or_default();
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| DomainError::Crypto(format!("初始化 AES-256-GCM 失败: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let pt = cipher
            .decrypt(nonce, Payload { msg: &combined, aad: aad.as_bytes() })
            .map_err(|_| DomainError::Crypto("解密失败：认证标签校验不通过（密文被篡改或 AAD 不匹配）".to_string()))?;
        let s = String::from_utf8(pt).map_err(|e| DomainError::Crypto(format!("明文不是合法 UTF-8: {e}")))?;
        Ok(SecretString::from(s))
    }

    /// 用同密钥重新加密（AAD 变更时使用，例如凭据迁移到另一个 id）。
    ///
    /// # Errors
    /// 解密或加密失败。
    pub fn rewrap(&self, material: &SecretMaterial, new_aad: &str) -> DomainResult<SecretMaterial> {
        let plain = self.decrypt(material)?;
        self.encrypt(&plain, new_aad)
    }

    /// 校验密文是否可解密（自检页使用，不返回明文）。
    ///
    /// # Errors
    /// 解密失败时返回错误。
    pub fn verify(&self, material: &SecretMaterial) -> DomainResult<()> {
        self.decrypt(material).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agf_core::ids::TenantId;

    fn cipher() -> FieldCipher {
        let key = [7_u8; KEY_LEN];
        FieldCipher::new(&key, "v1", KeyBackend::LocalFile).unwrap_or_else(|_| unreachable!())
    }

    fn aad() -> String {
        FieldCipher::make_aad(&TenantId::default_tenant(), &Id::new())
    }

    #[test]
    fn roundtrip_returns_original_plaintext() {
        let c = cipher();
        let plaintext = "sk-proj-VerySecretValue1234567890";
        let secret = SecretString::from(plaintext.to_string());
        let material = c.encrypt(&secret, &aad());
        assert!(material.is_ok());
        let Ok(material) = material else { return };
        assert_eq!(material.key_id, "v1");
        assert_eq!(material.backend, KeyBackend::LocalFile);
        assert!(material.tag_b64.is_some());
        assert_eq!(material.plaintext_len, plaintext.chars().count());
        let back = c.decrypt(&material);
        assert_eq!(back.map(|s| s.expose_secret().to_string()).ok(), Some(plaintext.to_string()));
    }

    #[test]
    fn ciphertext_never_contains_plaintext() {
        let c = cipher();
        let secret = SecretString::from("MostSecretToken".to_string());
        let aad = aad();
        let Ok(material) = c.encrypt(&secret, &aad) else { return };
        assert!(!material.ciphertext_b64.contains("MostSecretToken"));
        assert!(!material.nonce_b64.contains("MostSecretToken"));
    }

    #[test]
    fn nonce_is_unique_per_encryption() {
        let c = cipher();
        let secret = SecretString::from("same-plaintext".to_string());
        let aad = aad();
        let Ok(a) = c.encrypt(&secret, &aad) else { return };
        let Ok(b) = c.encrypt(&secret, &aad) else { return };
        assert_ne!(a.nonce_b64, b.nonce_b64, "nonce 必须每次随机");
        assert_ne!(a.ciphertext_b64, b.ciphertext_b64, "同明文不同 nonce 应产出不同密文");
    }

    #[test]
    fn aad_mismatch_fails_authentication() {
        let c = cipher();
        let secret = SecretString::from("secret".to_string());
        let Ok(mut material) = c.encrypt(&secret, "tenant:A|id:1") else { return };
        material.aad = Some("tenant:B|id:1".to_string());
        let res = c.decrypt(&material);
        assert!(res.is_err(), "AAD 被替换后必须解密失败（防止密文搬家）");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let c = cipher();
        let secret = SecretString::from("secret".to_string());
        let aad = aad();
        let Ok(mut material) = c.encrypt(&secret, &aad) else { return };
        // 翻转密文最后一个字符
        let mut chars: Vec<char> = material.ciphertext_b64.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == 'A' { 'B' } else { 'A' };
        }
        material.ciphertext_b64 = chars.into_iter().collect();
        assert!(c.decrypt(&material).is_err(), "篡改密文必须被 GCM 拒绝");
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let c1 = FieldCipher::new(&[1_u8; KEY_LEN], "v1", KeyBackend::LocalFile);
        let c2 = FieldCipher::new(&[2_u8; KEY_LEN], "v1", KeyBackend::LocalFile);
        assert!(c1.is_ok() && c2.is_ok());
        let (Ok(c1), Ok(c2)) = (c1, c2) else { return };
        let secret = SecretString::from("secret".to_string());
        let aad = aad();
        let Ok(material) = c1.encrypt(&secret, &aad) else { return };
        assert!(c2.decrypt(&material).is_err(), "换密钥后必须解密失败");
    }

    #[test]
    fn key_id_mismatch_reports_rotation_required() {
        let c1 = FieldCipher::new(&[1_u8; KEY_LEN], "v1", KeyBackend::LocalFile);
        let c2 = FieldCipher::new(&[1_u8; KEY_LEN], "v2", KeyBackend::LocalFile);
        let (Ok(c1), Ok(c2)) = (c1, c2) else { return };
        let secret = SecretString::from("x".to_string());
        let aad = aad();
        let Ok(material) = c1.encrypt(&secret, &aad) else { return };
        let err = c2.decrypt(&material).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err.contains("轮换"), "错误信息应提示轮换: {err}");
    }

    #[test]
    fn rewrap_changes_aad_and_keeps_plaintext() {
        let c = cipher();
        let secret = SecretString::from("keep-me".to_string());
        let Ok(material) = c.encrypt(&secret, "tenant:A|id:1") else { return };
        let Ok(re) = c.rewrap(&material, "tenant:A|id:2") else { return };
        assert_eq!(re.aad.as_deref(), Some("tenant:A|id:2"));
        assert_ne!(re.ciphertext_b64, material.ciphertext_b64);
        let back = c.decrypt(&re);
        assert_eq!(back.map(|s| s.expose_secret().to_string()).ok(), Some("keep-me".to_string()));
    }

    #[test]
    fn verify_does_not_leak_plaintext() {
        let c = cipher();
        let secret = SecretString::from("abc".to_string());
        let aad = aad();
        let Ok(material) = c.encrypt(&secret, &aad) else { return };
        assert!(c.verify(&material).is_ok());
    }

    #[test]
    fn wrong_key_length_rejected() {
        assert!(FieldCipher::new(&[0_u8; 16], "v1", KeyBackend::LocalFile).is_err());
        let e = FieldCipher::new(&[0_u8; 16], "v1", KeyBackend::LocalFile).err().map(|e| e.to_string());
        assert!(e.unwrap_or_default().contains("32"));
    }

    #[test]
    fn from_base64_roundtrip() {
        let b64 = FieldCipher::generate_master_key_b64();
        let c = FieldCipher::from_base64(&b64, "v1", KeyBackend::LocalFile);
        assert!(c.is_ok());
        let secret = SecretString::from("value".to_string());
        let Ok(c) = c else { return };
        let Ok(m) = c.encrypt(&secret, "aad") else { return };
        assert!(c.decrypt(&m).is_ok());
        assert!(FieldCipher::from_base64("not-base64!!", "v1", KeyBackend::LocalFile).is_err());
        assert!(FieldCipher::from_base64(&B64.encode([0_u8; 8]), "v1", KeyBackend::LocalFile).is_err());
    }

    #[test]
    fn generated_keys_are_unique_and_correct_size() {
        let a = FieldCipher::generate_master_key_b64();
        let b = FieldCipher::generate_master_key_b64();
        assert_ne!(a, b);
        let Ok(raw) = B64.decode(&a) else { return };
        assert_eq!(raw.len(), KEY_LEN);
    }

    #[test]
    fn debug_output_hides_key() {
        let c = cipher();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("7, 7, 7"), "Debug 不应打印密钥字节: {dbg}");
    }

    #[test]
    fn legacy_tag_appended_format_is_supported() {
        // 模拟"密文包含 tag"的形态：tag_b64 为 None
        let c = cipher();
        let secret = SecretString::from("legacy".to_string());
        let aad = aad();
        let Ok(material) = c.encrypt(&secret, &aad) else { return };
        let body = B64.decode(&material.ciphertext_b64).unwrap_or_default();
        let tag = B64.decode(material.tag_b64.clone().unwrap_or_default()).unwrap_or_default();
        let mut combined = body;
        combined.extend_from_slice(&tag);
        let legacy = SecretMaterial { tag_b64: None, ciphertext_b64: B64.encode(&combined), ..material };
        let back = c.decrypt(&legacy);
        assert_eq!(back.map(|s| s.expose_secret().to_string()).ok(), Some("legacy".to_string()));
    }
}
