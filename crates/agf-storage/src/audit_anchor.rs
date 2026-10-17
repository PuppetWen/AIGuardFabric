//! 签名审计检查点；密钥仅来自已配置的平台主密钥。
use agf_core::{
    audit::{AuditChainKind, SignedAuditAnchor},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

mod agent;
mod management;
mod sql;
mod witness;
pub use agent::{append_agent, lock_agent_chain};
pub use management::{checkpoint_management, verify_management};
pub use sql::latest_anchor;
pub use witness::AuditWitness;

/// 使用主密钥签名，隔离消息用途，并在 Debug 输出中隐藏密钥。
pub struct AuditAnchorSigner {
    key: Zeroizing<[u8; 32]>,
}
impl std::fmt::Debug for AuditAnchorSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("AuditAnchorSigner").field("key", &"<redacted>").finish()
    }
}
impl AuditAnchorSigner {
    /// 解码既有平台主密钥，禁止开发环境备用密钥。
    ///
    /// # Errors
    /// 配置的密钥不是恰含 32 字节的有效 base64。
    pub fn from_base64(value: &str) -> DomainResult<Self> {
        let bytes = Zeroizing::new(STANDARD.decode(value.trim()).map_err(|_| invalid())?);
        let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| invalid())?;
        Ok(Self { key: Zeroizing::new(key) })
    }

    /// 使用 HMAC-SHA256 认证完整身份封装。
    ///
    /// # Errors
    /// 身份格式无效，或无法初始化 HMAC。
    pub fn sign(&self, envelope: &mut SignedAuditAnchor) -> DomainResult<()> {
        envelope.validate_identity(envelope.anchor.tenant_id, envelope.kind, envelope.agent_id)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.as_ref()).map_err(|_| invalid())?;
        mac.update(envelope.signing_payload().as_bytes());
        envelope.anchor.signature = hex::encode(mac.finalize().into_bytes());
        Ok(())
    }

    /// 校验可信身份，并以恒定时间的 HMAC 校验验证签名。
    ///
    /// # Errors
    /// 身份、编码或签名与配置的主密钥不匹配。
    pub fn verify(
        &self,
        envelope: &SignedAuditAnchor,
        tenant: TenantId,
        kind: AuditChainKind,
        agent: Option<Id>,
    ) -> DomainResult<()> {
        envelope.validate_identity(tenant, kind, agent)?;
        if !agf_core::audit::valid_hash(&envelope.anchor.signature) {
            return Err(invalid());
        }
        let signature = hex::decode(&envelope.anchor.signature).map_err(|_| invalid())?;
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.as_ref()).map_err(|_| invalid())?;
        mac.update(envelope.signing_payload().as_bytes());
        mac.verify_slice(&signature).map_err(|_| invalid())
    }
}

/// 对于尚无检查点的旧链，完整性与是否已锚定分别判定。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnchoredChainVerification {
    /// 既有完整哈希链的结构校验结果。
    pub chain: agf_core::audit::ChainVerification,
    /// 签名、检查点连接、见证或已锚定记录无效时为假。
    pub anchors_valid: bool,
    /// 通过密码学校验的检查点数量。
    pub anchors_checked: usize,
    /// 报告历史无签名行，绝不将其视作已验证的检查点。
    pub unsigned_legacy_checkpoints: usize,
    /// 最近的已验证检查点；None 明确表示从未锚定。
    pub latest: Option<SignedAuditAnchor>,
    /// 仅当当前全部记录均被最近的有效检查点及持久见证覆盖时为真。
    pub fully_anchored: bool,
    /// 可读的失败原因；未锚定的旧链另行明确报告。
    pub violations: Vec<String>,
}

fn invalid() -> DomainError {
    DomainError::Crypto("Audit anchor key or signature is invalid".into())
}

#[cfg(test)]
mod tests;
