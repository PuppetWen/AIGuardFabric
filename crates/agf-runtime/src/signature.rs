//! 策略签名与校验（§4.3 防绕过：策略签名校验）。
//!
//! ## 为什么签名
//!
//! 运行时代理与被管 Agent 处于同一台机器/同一个信任域。若策略以明文缓存落盘，
//! 被控 Agent 只要改写本地缓存就能"合法地"关闭管控。因此平台要求：
//!
//! - 策略入库前由**平台主密钥**签名：`signature = HMAC-SHA256(master_key, policy.compute_hash())`，hex 编码；
//! - 运行时装载策略前校验签名，签名缺失/非法即为**篡改或未授权下发**；
//! - 主密钥支持轮换：旧密钥保留在 [`PolicySigner::previous_keys`] 中，
//!   形成"当前密钥签名 + 上一把密钥仍可验证"的过渡窗口，避免轮换瞬间全部策略失效。
//!
//! ## 密钥材料来源
//!
//! 引擎只接受**原始字节密钥**（由 `agf-api` / 配置文件从 KMS 或
//! `AGF_MASTER_KEY_BASE64` 解出后传入），本模块不做任何 I/O，便于完整单测。

use agf_core::error::{DomainError, DomainResult};
use agf_core::policy::Policy;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// 策略签名格式前缀（便于将来平滑升级到 Ed25519：`hmac256:` → `ed25519:`）。
pub const SIGNATURE_PREFIX: &str = "hmac256:";

/// 一次签名状态快照（控制台「运行时防护」页展示用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySignatureState {
    /// 签名存在且校验通过。
    Valid {
        /// 签名密钥标识（轮换排查用，非机密）。
        key_id: String,
    },
    /// 策略未签名（`signature` 为空）。
    Missing,
    /// 签名存在但校验失败（密钥不匹配或策略内容被改动）。
    Invalid {
        /// 失败原因。
        reason: String,
    },
}

impl PolicySignatureState {
    /// 是否校验通过。
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }

    /// 中文简述（审计与自检文案）。
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Valid { key_id } => format!("签名有效（密钥 {key_id}）"),
            Self::Missing => "签名缺失".to_string(),
            Self::Invalid { reason } => format!("签名非法：{reason}"),
        }
    }
}

/// 策略签名器：持有当前主密钥与若干历史密钥（轮换过渡期）。
#[derive(Clone)]
pub struct PolicySigner {
    /// 当前签名密钥。
    current: Vec<u8>,
    /// 当前密钥标识。
    key_id: String,
    /// 历史密钥（只用于验证，不再用于签名）。
    previous_keys: Vec<(String, Vec<u8>)>,
}

impl std::fmt::Debug for PolicySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 密钥内容绝不进日志/Debug 输出。
        f.debug_struct("PolicySigner")
            .field("key_id", &self.key_id)
            .field("current", &format!("<redacted {} bytes>", self.current.len()))
            .field("previous_keys", &self.previous_keys.iter().map(|(id, _)| id).collect::<Vec<_>>())
            .finish()
    }
}

impl PolicySigner {
    /// 由原始密钥字节构造。
    ///
    /// # Errors
    /// 密钥长度小于 16 字节时拒绝（HMAC 允许任意长度，但过短的密钥不构成安全强度）。
    pub fn new(key: impl Into<Vec<u8>>, key_id: impl Into<String>) -> DomainResult<Self> {
        let key = key.into();
        if key.len() < 16 {
            return Err(DomainError::Crypto(format!("策略签名密钥过短：{} 字节（至少 16 字节）", key.len())));
        }
        Ok(Self { current: key, key_id: key_id.into(), previous_keys: Vec::new() })
    }

    /// 开发/离线演示用固定密钥（**禁止用于生产**；自检会对该密钥标识告警）。
    #[must_use]
    pub fn dev_default() -> Self {
        Self {
            current: b"agf-dev-only-policy-signing-key!!".to_vec(),
            key_id: "dev-default".to_string(),
            previous_keys: Vec::new(),
        }
    }

    /// 当前密钥标识。
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// 是否为开发默认密钥（自检据此提示"生产必须轮换"）。
    #[must_use]
    pub fn is_dev_key(&self) -> bool {
        self.key_id == "dev-default"
    }

    /// 轮换主密钥：原当前密钥降级为历史密钥（仍可验证），新密钥生效。
    pub fn rotate(&mut self, new_key: impl Into<Vec<u8>>, new_key_id: impl Into<String>) {
        let old_key = std::mem::replace(&mut self.current, new_key.into());
        let old_id = std::mem::replace(&mut self.key_id, new_key_id.into());
        self.previous_keys.push((old_id, old_key));
    }

    /// 丢弃全部历史密钥（轮换过渡期结束）。
    pub fn prune_previous_keys(&mut self) {
        self.previous_keys.clear();
    }

    /// 历史密钥标识列表。
    #[must_use]
    pub fn previous_key_ids(&self) -> Vec<&str> {
        self.previous_keys.iter().map(|(id, _)| id.as_str()).collect()
    }

    /// 对策略内容哈希签名，返回带前缀的 hex 字符串。
    #[must_use]
    pub fn sign_hash(&self, content_hash: &str) -> String {
        format!("{SIGNATURE_PREFIX}{}", self.mac_hex(&self.current, content_hash))
    }

    /// 对策略签名（覆盖 [`Policy::compute_hash`] 的全部字段，含 `version`）。
    #[must_use]
    pub fn sign(&self, policy: &Policy) -> String {
        self.sign_hash(&policy.compute_hash())
    }

    /// 校验策略签名。
    ///
    /// 顺序：当前密钥 → 历史密钥（轮换过渡期）。
    ///
    /// # Errors
    /// 签名缺失或任何密钥都无法验证时返回 [`DomainError::PreconditionFailed`]。
    pub fn verify(&self, policy: &Policy) -> DomainResult<()> {
        match self.state(policy) {
            PolicySignatureState::Valid { .. } => Ok(()),
            PolicySignatureState::Missing => Err(DomainError::PreconditionFailed(format!(
                "策略「{}」未签名，拒绝装载（防止本地策略缓存被篡改绕过管控）",
                policy.name
            ))),
            PolicySignatureState::Invalid { reason } => {
                Err(DomainError::PreconditionFailed(format!("策略「{}」签名校验失败：{reason}", policy.name)))
            }
        }
    }

    /// 计算签名状态（不返回 `Err`，供自检与 UI 展示）。
    #[must_use]
    pub fn state(&self, policy: &Policy) -> PolicySignatureState {
        if policy.signature.trim().is_empty() {
            return PolicySignatureState::Missing;
        }
        let expected_hash = policy.compute_hash();
        let Some(hex_part) = policy.signature.strip_prefix(SIGNATURE_PREFIX) else {
            return PolicySignatureState::Invalid {
                reason: format!("签名缺少 `{SIGNATURE_PREFIX}` 前缀（当前仅支持 HMAC-SHA256）"),
            };
        };
        if hex_part.len() != 64 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return PolicySignatureState::Invalid { reason: "签名不是 64 位 hex 字符串".to_string() };
        }
        // 当前密钥
        if constant_time_eq(hex_part, &self.mac_hex(&self.current, &expected_hash)) {
            return PolicySignatureState::Valid { key_id: self.key_id.clone() };
        }
        // 历史密钥（轮换过渡期）
        for (id, key) in &self.previous_keys {
            if constant_time_eq(hex_part, &self.mac_hex(key, &expected_hash)) {
                return PolicySignatureState::Valid { key_id: id.clone() };
            }
        }
        PolicySignatureState::Invalid {
            reason: "与主密钥不匹配（策略内容被改动或使用了未授权密钥）".to_string()
        }
    }

    /// 对任意字符串做 HMAC（审计锚点等复用）。
    #[must_use]
    pub fn mac_hex(&self, key: &[u8], message: &str) -> String {
        mac_hex(key, message)
    }
}

/// 定长 hex 字符串比较（长度已知，逐字节异或累加，避免提前返回泄露信息）。
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in ab.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 用指定密钥为策略签名（一次性便捷函数）。
#[must_use]
pub fn sign_policy(policy: &Policy, key: &[u8]) -> String {
    format!("{SIGNATURE_PREFIX}{}", mac_hex(key, &policy.compute_hash()))
}

/// 计算 `HMAC-SHA256(key, message)` 的 hex。
///
/// HMAC 接受任意长度密钥，`new_from_slice` 对本算法**不会失败**；
/// 为满足"无 `unwrap`"约束，失败分支退化为空串（调用方按"签名非法"处理）。
#[must_use]
pub fn mac_hex(key: &[u8], message: &str) -> String {
    match HmacSha256::new_from_slice(key) {
        Ok(mut mac) => {
            mac.update(message.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        }
        Err(_) => String::new(),
    }
}

/// 用指定密钥验证策略签名。
///
/// 与 [`sign_policy`] 配对使用（`agf-api` 侧只持有密钥字节、不构造 [`PolicySigner`] 的场景）。
///
/// # Errors
/// 签名缺失、格式非法或不匹配。
pub fn verify_policy(policy: &Policy, key: &[u8]) -> DomainResult<()> {
    if policy.signature.trim().is_empty() {
        return Err(DomainError::PreconditionFailed(format!("策略「{}」未签名", policy.name)));
    }
    let expected = sign_policy(policy, key);
    if constant_time_eq(&policy.signature, &expected) {
        Ok(())
    } else {
        Err(DomainError::PreconditionFailed(format!("策略「{}」签名校验失败：与给定密钥不匹配", policy.name)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::assert_err_is;
    use crate::testkit::assert_ok_is;
    use crate::testkit::sample_policy;
    use agf_core::enums::{InterceptPoint, PolicyAction};

    fn prod_signer() -> PolicySigner {
        PolicySigner::new(b"0123456789abcdef0123456789abcdef".to_vec(), "k1")
            .unwrap_or_else(|_| PolicySigner::dev_default())
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = prod_signer();
        let mut p = sample_policy("block-rm");
        p.signature = signer.sign(&p);
        assert_ok_is!(signer.verify(&p), ());
        assert!(signer.state(&p).is_valid());
        assert!(p.signature.starts_with(SIGNATURE_PREFIX));
    }

    #[test]
    fn tampering_content_breaks_signature() {
        let signer = PolicySigner::dev_default();
        let mut p = sample_policy("block-rm");
        p.signature = signer.sign(&p);
        p.priority = 1;
        let state = signer.state(&p);
        assert!(!state.is_valid());
        assert!(signer.verify(&p).is_err());
    }

    #[test]
    fn missing_signature_is_reported() {
        let signer = PolicySigner::dev_default();
        let p = sample_policy("unsigned");
        assert_eq!(signer.state(&p), PolicySignatureState::Missing);
        // 断言**具体错误身份**（而不是仅 `is_err`）：文案是控制台与审计的契约
        assert_err_is!(
            signer.verify(&p),
            DomainError::PreconditionFailed(
                "策略「unsigned」未签名，拒绝装载（防止本地策略缓存被篡改绕过管控）".to_string()
            )
        );
    }

    #[test]
    fn malformed_signature_shapes_are_invalid() {
        let signer = PolicySigner::dev_default();
        let mut p = sample_policy("x");
        p.signature = "deadbeef".to_string();
        assert!(!signer.state(&p).is_valid());
        p.signature = format!("{SIGNATURE_PREFIX}zzzz");
        assert!(!signer.state(&p).is_valid());
        p.signature = format!("{SIGNATURE_PREFIX}{}", "a".repeat(64));
        assert!(matches!(signer.state(&p), PolicySignatureState::Invalid { .. }));
    }

    #[test]
    fn key_rotation_keeps_old_signature_valid() {
        let mut signer = PolicySigner::new(b"old-key-old-key-old-key-old-key!".to_vec(), "old")
            .unwrap_or_else(|_| PolicySigner::dev_default());
        let mut p = sample_policy("rotate");
        p.signature = signer.sign(&p);
        signer.rotate(b"new-key-new-key-new-key-new-key!".to_vec(), "new");
        assert_eq!(signer.key_id(), "new");
        assert_eq!(signer.previous_key_ids(), vec!["old"]);
        // 过渡期：旧签名仍可验证
        assert!(signer.state(&p).is_valid());
        // 新签名也有效
        let mut q = sample_policy("rotate2");
        q.signature = signer.sign(&q);
        assert!(signer.state(&q).is_valid());
        // 过渡期结束后旧签名失效
        signer.prune_previous_keys();
        assert!(!signer.state(&p).is_valid());
        assert!(signer.state(&q).is_valid());
    }

    #[test]
    fn short_key_is_rejected() {
        assert!(PolicySigner::new(b"short".to_vec(), "k").is_err());
    }

    #[test]
    fn dev_key_is_flagged() {
        assert!(PolicySigner::dev_default().is_dev_key());
        assert!(!prod_signer().is_dev_key());
    }

    #[test]
    fn one_shot_functions_match_signer() {
        let key = b"shared-secret-shared-secret-1234";
        let mut p = sample_policy("oneshot");
        p.signature = sign_policy(&p, key);
        assert_ok_is!(verify_policy(&p, key), ());
        assert!(verify_policy(&p, b"another-key-another-key-1234567").is_err());
        assert!(verify_policy(&sample_policy("nope"), key).is_err());
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let signer = PolicySigner::new(b"super-secret-key-material-here!!".to_vec(), "k")
            .unwrap_or_else(|_| PolicySigner::dev_default());
        let text = format!("{signer:?}");
        assert!(!text.contains("super-secret"), "Debug 输出不得含密钥原文: {text}");
        assert!(text.contains("redacted"));
    }

    #[test]
    fn signature_is_stable_for_same_content() {
        let signer = PolicySigner::dev_default();
        let p = sample_policy("stable");
        assert_eq!(signer.sign(&p), signer.sign(&p));
    }

    #[test]
    fn state_describe_is_human_readable() {
        let signer = prod_signer();
        let mut p = sample_policy("d");
        assert_eq!(signer.state(&p).describe(), "签名缺失");
        p.signature = signer.sign(&p);
        assert!(signer.state(&p).describe().contains("签名有效"));
        p.priority = 999;
        assert!(signer.state(&p).describe().contains("签名非法"));
    }

    #[test]
    fn signed_content_covers_intercept_points_and_action() {
        // compute_hash 覆盖 intercept_points 与 action ⇒ 改动它们必然让签名失效
        let signer = prod_signer();
        let mut p = sample_policy("signed-fields");
        p.signature = signer.sign(&p);
        assert!(signer.state(&p).is_valid());
        p.intercept_points = vec![InterceptPoint::AiGateway];
        assert!(!signer.state(&p).is_valid(), "改动拦截点必须破坏签名");
        let mut q = sample_policy("signed-action");
        q.signature = signer.sign(&q);
        q.action = PolicyAction::Audit;
        assert!(!signer.state(&q).is_valid(), "改动动作必须破坏签名");
    }
}
