//! MFA（TOTP）实现（§4.7 身份对接：MFA）。
//!
//! - 使用 RFC 6238 TOTP，步长 30s，允许 ±1 步时钟偏移；
//! - 密钥以 base32 编码，**落库前必须经 `agf-storage::FieldCipher` 加密**（本模块只负责生成与校验）；
//! - 恢复码一次性使用：校验成功后由调用方删除对应哈希。

use agf_core::error::{DomainError, DomainResult};
use agf_core::time::Timestamp;
use totp_rs::{Algorithm, Secret, TOTP};

/// TOTP 服务。
#[derive(Debug, Clone)]
pub struct TotpService {
    digits: usize,
    step: u64,
    skew: u8,
    issuer: String,
}

impl Default for TotpService {
    fn default() -> Self {
        Self::new(6, crate::defaults::TOTP_STEP_SECS, crate::defaults::TOTP_SKEW, "AIGuardFabric")
    }
}

impl TotpService {
    /// 构造。
    #[must_use]
    pub fn new(digits: usize, step: u64, skew: u8, issuer: impl Into<String>) -> Self {
        Self { digits: digits.clamp(6, 8), step: step.max(10), skew, issuer: issuer.into() }
    }

    /// 生成新的 TOTP 密钥（base32）。
    #[must_use]
    pub fn generate_secret(&self) -> String {
        Secret::generate_secret().to_encoded().to_string()
    }

    /// 构造绑定 URL（`otpauth://totp/...`），供前端渲染二维码。
    ///
    /// # Errors
    /// 密钥非法时返回错误。
    pub fn provisioning_uri(&self, account: &str, secret_b32: &str) -> DomainResult<String> {
        let totp = self.build(account, secret_b32)?;
        Ok(totp.get_url())
    }

    /// 校验一次性验证码。
    ///
    /// 返回 `Ok(true)` 表示通过；`Ok(false)` 表示码错误；`Err` 表示密钥非法。
    ///
    /// # Errors
    /// 密钥非法（base32 解码失败）。
    pub fn verify(&self, account: &str, secret_b32: &str, code: &str) -> DomainResult<bool> {
        let code = code.trim().replace(' ', "");
        if code.len() != self.digits || !code.chars().all(|c| c.is_ascii_digit()) {
            return Ok(false);
        }
        let totp = self.build(account, secret_b32)?;
        // 检查当前时刻 ±skew 步
        let now = Timestamp::now().unix_secs();
        let step = i64::try_from(self.step).unwrap_or(30);
        for offset in -(i64::from(self.skew))..=i64::from(self.skew) {
            let t = u64::try_from(now + offset * step).unwrap_or(0);
            if totp.generate(t) == code {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// 生成当前验证码（自动化测试与演示用；生产不对外暴露）。
    ///
    /// # Errors
    /// 密钥非法。
    pub fn current_code(&self, account: &str, secret_b32: &str) -> DomainResult<String> {
        let totp = self.build(account, secret_b32)?;
        Ok(totp.generate(Timestamp::now().unix_secs().unsigned_abs()))
    }

    /// 生成一次性恢复码（返回明文与哈希列表，明文只回显一次）。
    ///
    /// 返回 `(明文列表, 哈希列表)`。恢复码为 10 位大写十六进制，展示为 `XXXXX-XXXXX`，
    /// 短小便于抄写；冲突时重试，保证**互不相同**（否则一次校验会命中多条记录）。
    #[must_use]
    pub fn generate_recovery_codes(&self, count: usize, salt: &str) -> (Vec<String>, Vec<String>) {
        let mut plain: Vec<String> = Vec::with_capacity(count);
        let mut hashed: Vec<String> = Vec::with_capacity(count);
        let mut guard = 0;
        while plain.len() < count && guard < count * 64 {
            guard += 1;
            let hex = agf_core::secret::generate_api_key("");
            if hex.len() < 10 {
                continue;
            }
            let code = format!("{}-{}", &hex[0..5], &hex[5..10]).to_uppercase();
            if plain.contains(&code) {
                continue;
            }
            hashed.push(agf_core::secret::fingerprint(&code, salt));
            plain.push(code);
        }
        (plain, hashed)
    }

    /// 校验恢复码（返回命中的哈希索引，供调用方删除已用码）。
    ///
    /// # Errors
    /// 输入为空。
    pub fn verify_recovery_code(&self, code: &str, hashes: &[String], salt: &str) -> DomainResult<Option<usize>> {
        // 归一化：去空格、去分隔符、统一大写，容忍用户输入 `xxxxx-xxxxx` 或 `XXXXXXXXXX`
        let compact: String = code.trim().chars().filter(char::is_ascii_alphanumeric).collect();
        if compact.is_empty() {
            return Err(DomainError::Validation("恢复码不能为空".to_string()));
        }
        let normalized = if compact.len() == 10 {
            format!("{}-{}", &compact[0..5], &compact[5..10]).to_uppercase()
        } else {
            compact.to_uppercase()
        };
        let target = agf_core::secret::fingerprint(&normalized, salt);
        Ok(hashes.iter().position(|h| constant_time_eq(h.as_bytes(), target.as_bytes())))
    }

    fn build(&self, account: &str, secret_b32: &str) -> DomainResult<TOTP> {
        let secret = Secret::Encoded(secret_b32.trim().to_uppercase())
            .to_bytes()
            .map_err(|e| DomainError::Crypto(format!("TOTP 密钥不是合法 base32: {e}")))?;
        TOTP::new(
            Algorithm::SHA1,
            self.digits,
            self.skew,
            self.step,
            secret,
            Some(self.issuer.clone()),
            account.to_string(),
        )
        .map_err(|e| DomainError::Crypto(format!("TOTP 初始化失败: {e}")))
    }
}

/// 常量时间字节比较（防时序侧信道）。
#[must_use]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc() -> TotpService {
        TotpService::default()
    }

    #[test]
    fn secret_generation_is_base32_and_unique() {
        let s = svc();
        let a = s.generate_secret();
        let b = s.generate_secret();
        assert_ne!(a, b);
        assert!(a.len() >= 16);
        assert!(a.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn provisioning_uri_shape() {
        let s = svc();
        let secret = s.generate_secret();
        let uri = s.provisioning_uri("alice@example.com", &secret);
        assert!(uri.is_ok());
        let Ok(uri) = uri else { return };
        assert!(uri.starts_with("otpauth://totp/"), "{uri}");
        assert!(uri.contains("AIGuardFabric"));
        assert!(uri.contains("secret="));
    }

    #[test]
    fn current_code_verifies() {
        let s = svc();
        let secret = s.generate_secret();
        let Ok(code) = s.current_code("alice", &secret) else { return };
        assert_eq!(code.len(), 6);
        assert_eq!(s.verify("alice", &secret, &code).ok(), Some(true));
    }

    #[test]
    fn wrong_code_rejected() {
        let s = svc();
        let secret = s.generate_secret();
        assert_eq!(s.verify("alice", &secret, "000000").ok(), Some(false));
        assert_eq!(s.verify("alice", &secret, "abcdef").ok(), Some(false));
        assert_eq!(s.verify("alice", &secret, "12345").ok(), Some(false));
        assert_eq!(s.verify("alice", &secret, "").ok(), Some(false));
    }

    #[test]
    fn code_with_spaces_is_normalized() {
        let s = svc();
        let secret = s.generate_secret();
        let Ok(code) = s.current_code("alice", &secret) else { return };
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert_eq!(s.verify("alice", &secret, &spaced).ok(), Some(true));
    }

    #[test]
    fn invalid_secret_reports_error() {
        let s = svc();
        let res = s.verify("alice", "not-base32!!!", "123456");
        assert!(res.is_err(), "非法密钥应报错而不是静默失败");
    }

    #[test]
    fn recovery_codes_are_unique_and_verifiable() {
        let s = svc();
        let (plain, hashed) = s.generate_recovery_codes(8, "salt");
        assert_eq!(plain.len(), 8);
        assert_eq!(hashed.len(), 8);
        let mut sorted = plain.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 8, "恢复码必须互不相同");
        for p in &plain {
            let idx = s.verify_recovery_code(p, &hashed, "salt");
            assert!(idx.ok().flatten().is_some(), "恢复码 {p} 应校验通过");
        }
    }

    #[test]
    fn recovery_code_wrong_salt_fails() {
        let s = svc();
        let (plain, hashed) = s.generate_recovery_codes(4, "salt-a");
        let res = s.verify_recovery_code(&plain[0], &hashed, "salt-b");
        assert_eq!(res.ok().flatten(), None);
    }

    #[test]
    fn empty_recovery_code_rejected() {
        let s = svc();
        let (_, hashed) = s.generate_recovery_codes(2, "s");
        assert!(s.verify_recovery_code("   ", &hashed, "s").is_err());
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
