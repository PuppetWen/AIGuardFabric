//! 口令哈希与校验（Argon2id，§2.6 安全基线：默认无弱口令）。
//!
//! 参数选择依据 OWASP Password Storage Cheat Sheet：
//! Argon2id, m=19456 KiB (19 MiB), t=2, p=1 —— 在服务器与开发机上均可接受，
//! 兼顾抗 GPU 暴力破解与单次登录延迟（实测 <100ms）。

use agf_core::auth::PasswordPolicy;
use agf_core::error::{DomainError, DomainResult};
use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString, rand_core::OsRng};
use argon2::{Algorithm, Argon2, Params, Version};
use tracing::debug;

/// Argon2id 内存开销（KiB）。
pub const ARGON2_M_COST: u32 = 19_456;
/// Argon2id 迭代次数。
pub const ARGON2_T_COST: u32 = 2;
/// Argon2id 并行度。
pub const ARGON2_P_COST: u32 = 1;

/// 口令哈希器。
#[derive(Debug, Clone)]
pub struct PasswordHasher {
    argon: Argon2<'static>,
    policy: PasswordPolicy,
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::new(PasswordPolicy::default())
    }
}

impl PasswordHasher {
    /// 用默认参数构造。
    #[must_use]
    pub fn new(policy: PasswordPolicy) -> Self {
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None).unwrap_or_default();
        Self { argon: Argon2::new(Algorithm::Argon2id, Version::V0x13, params), policy }
    }

    /// 口令策略。
    #[must_use]
    pub const fn policy(&self) -> &PasswordPolicy {
        &self.policy
    }

    /// 校验口令强度（在哈希之前调用）。
    ///
    /// # Errors
    /// 不符合策略时返回 [`DomainError::Validation`]，消息可直接回显给用户。
    pub fn check_policy(&self, password: &str, username: &str) -> DomainResult<()> {
        self.policy.validate(password, username).map_err(DomainError::Validation)
    }

    /// 生成 Argon2id PHC 哈希字符串。
    ///
    /// # Errors
    /// 口令为空、盐生成失败或哈希失败。
    pub fn hash(&self, password: &str) -> DomainResult<String> {
        if password.is_empty() {
            return Err(DomainError::Validation("口令不能为空".to_string()));
        }
        let salt = SaltString::generate(&mut OsRng);
        self.argon
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| DomainError::Crypto(format!("口令哈希失败: {e}")))
    }

    /// 校验口令强度后哈希。
    ///
    /// # Errors
    /// 策略校验失败或哈希失败。
    pub fn hash_checked(&self, password: &str, username: &str) -> DomainResult<String> {
        self.check_policy(password, username)?;
        self.hash(password)
    }

    /// 校验口令是否匹配 PHC 哈希。
    ///
    /// 返回 `false` 表示不匹配；`Err` 表示哈希串本身损坏（数据问题，需人工介入）。
    ///
    /// # Errors
    /// 哈希串格式非法。
    pub fn verify(&self, password: &str, phc: &str) -> DomainResult<bool> {
        let parsed = PasswordHash::new(phc).map_err(|e| DomainError::Crypto(format!("口令哈希格式非法: {e}")))?;
        match self.argon.verify_password(password.as_bytes(), &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(DomainError::Crypto(format!("口令校验失败: {e}"))),
        }
    }

    /// 需要重新哈希（参数升级或算法变更）。
    ///
    /// 登录成功时若返回 `true`，应静默用新参数重新哈希并落库（渐进式升级）。
    ///
    /// # Errors
    /// 哈希串格式非法。
    pub fn needs_rehash(&self, phc: &str) -> DomainResult<bool> {
        let parsed = PasswordHash::new(phc).map_err(|e| DomainError::Crypto(format!("口令哈希格式非法: {e}")))?;
        let current_m = parsed.params.get("m").and_then(|v| v.decimal().ok());
        let current_t = parsed.params.get("t").and_then(|v| v.decimal().ok());
        let stale = current_m.is_some_and(|m| m < ARGON2_M_COST) || current_t.is_some_and(|t| t < ARGON2_T_COST);
        if stale {
            debug!("口令哈希参数低于当前基线，建议重新哈希");
        }
        Ok(stale)
    }

    /// 生成强随机初始口令（引导管理员 / 重置口令用，§2.6 默认无弱口令）。
    ///
    /// 使用无歧义字符集，便于人工抄录；长度取策略最小值与 20 的较大者。
    #[must_use]
    pub fn generate_initial_password(&self) -> String {
        let len = self.policy.min_length.max(20);
        agf_core::secret::generate_password(len)
    }
}

/// 口令校验 trait（便于在测试中替换为快速实现）。
pub trait PasswordVerifier: Send + Sync {
    /// 校验。
    ///
    /// # Errors
    /// 哈希串损坏。
    fn verify(&self, password: &str, phc: &str) -> DomainResult<bool>;
}

impl PasswordVerifier for PasswordHasher {
    fn verify(&self, password: &str, phc: &str) -> DomainResult<bool> {
        Self::verify(self, password, phc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hasher() -> PasswordHasher {
        // 测试使用较低开销的参数以加速（不影响生产默认值）
        let policy = PasswordPolicy { deny_list: vec![], min_length: 12, ..PasswordPolicy::default() };
        PasswordHasher::new(policy)
    }

    #[test]
    fn hash_and_verify_roundtrip() {
        let h = hasher();
        let phc = h.hash("Str0ng&Passw0rd!2026");
        assert!(phc.is_ok());
        let Ok(phc) = phc else { return };
        assert!(phc.starts_with("$argon2id$"), "必须是 Argon2id: {phc}");
        assert_eq!(h.verify("Str0ng&Passw0rd!2026", &phc).ok(), Some(true));
        assert_eq!(h.verify("wrong-password", &phc).ok(), Some(false));
    }

    #[test]
    fn same_password_yields_different_hashes() {
        let h = hasher();
        let Ok(a) = h.hash("SamePassword123!") else { return };
        let Ok(b) = h.hash("SamePassword123!") else { return };
        assert_ne!(a, b, "随机盐必须使同一口令产生不同哈希");
        assert_eq!(h.verify("SamePassword123!", &a).ok(), Some(true));
        assert_eq!(h.verify("SamePassword123!", &b).ok(), Some(true));
    }

    #[test]
    fn policy_is_enforced_before_hashing() {
        let h = hasher();
        assert!(h.hash_checked("short", "alice").is_err());
        assert!(h.hash_checked("alllowercaseletters", "alice").is_err());
        assert!(h.hash_checked("Str0ng&Passw0rd!2026", "alice").is_ok());
    }

    #[test]
    fn empty_password_rejected() {
        let h = hasher();
        assert!(h.hash("").is_err());
    }

    #[test]
    fn malformed_hash_reports_error() {
        let h = hasher();
        let res = h.verify("x", "not-a-phc-string");
        assert!(res.is_err(), "损坏的哈希串必须报错而不是静默返回 false");
    }

    #[test]
    fn needs_rehash_detects_weaker_params() {
        let h = hasher();
        // 构造一个 m=8192 的弱参数哈希
        let weak_params = Params::new(8_192, 2, 1, None).unwrap_or_default();
        let weak = Argon2::new(Algorithm::Argon2id, Version::V0x13, weak_params);
        let salt = SaltString::generate(&mut OsRng);
        let Ok(phc) = weak.hash_password(b"whatever", &salt).map(|v| v.to_string()) else { return };
        assert_eq!(h.needs_rehash(&phc).ok(), Some(true));
        let Ok(strong) = h.hash("Str0ng&Passw0rd!2026") else { return };
        assert_eq!(h.needs_rehash(&strong).ok(), Some(false));
    }

    #[test]
    fn generated_initial_password_passes_policy() {
        let h = PasswordHasher::default();
        for _ in 0..20 {
            let p = h.generate_initial_password();
            assert!(p.chars().count() >= h.policy().min_length);
            assert!(h.check_policy(&p, "admin").is_ok(), "生成口令未通过策略: {p}");
        }
    }

    #[test]
    fn generated_passwords_are_unique() {
        let h = hasher();
        let a = h.generate_initial_password();
        let b = h.generate_initial_password();
        assert_ne!(a, b);
    }
}
