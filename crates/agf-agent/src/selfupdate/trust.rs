//! 发布签名验证与操作员的本机安装授权分别校验。
use super::{ReleaseManifest, UpdatePlan, plan_update};
use crate::platform::HostPlatform;
use agf_core::error::{DomainError, DomainResult};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 由操作员独立配置的信任锚，不能从发布清单读取。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedReleaseKey {
    /// 固定公钥的稳定标识符。
    pub key_id: String,
    /// 以十六进制编码的 32 字节 Ed25519 公钥。
    pub public_key_hex: String,
}
/// 明确配置的下载权限；下载发布资产不携带平台凭据。
#[derive(Debug, Clone)]
pub struct DownloadPolicy {
    /// 允许的 HTTPS 来源；非默认端口必须显式包含。
    pub allowed_origins: Vec<String>,
    /// 可选的企业根证书 PEM 文件。
    pub enterprise_ca: Option<PathBuf>,
    /// 发布资产的硬大小上限，范围为 1 字节至 1 GiB。
    pub max_bytes: u64,
}
/// 已验签且满足灰度条件的发布；私有字段且不实现 Deserialize，防止伪造可信计划。
///
/// ```compile_fail
/// let forged: agf_agent::selfupdate::VerifiedUpdate = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone)]
pub struct VerifiedUpdate {
    pub(crate) plan: UpdatePlan,
    pub(crate) policy: DownloadPolicy,
    pub(crate) key_id: String,
    pub(crate) manifest_sha256: String,
}
impl std::fmt::Debug for VerifiedUpdate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedUpdate")
            .field("version", &self.plan.target)
            .field("sha256", &self.plan.sha256)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}
impl VerifiedUpdate {
    /// 已认证的只读计划预览，不执行安装。
    #[must_use]
    pub fn plan(&self) -> &UpdatePlan {
        &self.plan
    }
}
fn invalid() -> DomainError {
    DomainError::Validation("Release signature, trust anchor or bounded manifest is invalid".into())
}
/// 发布工具签名的精确字节，包含域分隔前缀并排除签名字段本身。
///
/// # Errors
/// 序列化失败时返回错误；签名端与验证端必须使用相同结构。
pub fn release_signing_payload(manifest: &ReleaseManifest) -> DomainResult<Vec<u8>> {
    let mut unsigned = manifest.clone();
    unsigned.signature = None;
    let mut bytes = b"AIGuardFabric/release-manifest/v1\n".to_vec();
    bytes.extend(serde_json::to_vec(&unsigned)?);
    Ok(bytes)
}
/// 稳定的灰度分组，不随进程重启或输入顺序变化。
#[must_use]
pub fn rollout_selected(agent_id: &str, percent: u8) -> bool {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(format!("AIGuardFabric/release-rollout/v1\n{agent_id}"));
    !agent_id.is_empty() && percent <= 100 && u16::from_be_bytes([hash[0], hash[1]]) % 100 < u16::from(percent)
}
/// 先校验固定 Ed25519 公钥签名，再信任平台、下载地址、大小与灰度字段。
///
/// # Errors
/// 拒绝缺失或伪造签名、歧义资产、非法地址及超预算数据。
pub fn verify_release(
    manifest: &ReleaseManifest,
    trusted: &TrustedReleaseKey,
    policy: DownloadPolicy,
    agent_id: &str,
    current: &str,
    platform: HostPlatform,
    arch: &str,
) -> DomainResult<Option<VerifiedUpdate>> {
    if trusted.key_id.is_empty()
        || trusted.key_id.len() > 64
        || trusted.public_key_hex.len() != 64
        || manifest.version.len() > 64
        || manifest.signature.as_ref().is_none_or(|s| s.len() > 256)
        || !trusted.key_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || manifest.assets.len() > 16
        // 仅做分配前预算预检；字段要通过下方验签后才获得信任。
        || manifest.assets.iter().any(|asset| {
            asset.platform.len() > 7 || asset.arch.len() > 7 || asset.url.len() > 4096 || asset.sha256.len() > 64
        })
        || manifest.rollout_percent > 100
        || manifest.notes.as_ref().is_some_and(|notes| notes.len() > 4096)
        || agent_id.is_empty()
        || agent_id.len() > 256
        || policy.max_bytes == 0
        || policy.max_bytes > 1024 * 1024 * 1024
        || policy.allowed_origins.is_empty()
        || policy.allowed_origins.len() > 16
        || policy.allowed_origins.iter().any(|origin| origin.len() > 4096)
    {
        return Err(invalid());
    }
    let key_bytes: [u8; 32] =
        hex::decode(&trusted.public_key_hex).map_err(|_| invalid())?.try_into().map_err(|_| invalid())?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| invalid())?;
    let parts = manifest.signature.as_deref().ok_or_else(invalid)?.split(':').collect::<Vec<_>>();
    if parts.len() != 3 || parts[0] != "ed25519-v1" || parts[1] != trusted.key_id {
        return Err(invalid());
    }
    let raw = STANDARD.decode(parts[2]).map_err(|_| invalid())?;
    let signature = Signature::from_slice(&raw).map_err(|_| invalid())?;
    let payload = release_signing_payload(manifest)?;
    key.verify_strict(&payload, &signature).map_err(|_| invalid())?;
    let mut selectors = std::collections::BTreeSet::new();
    for asset in &manifest.assets {
        if !selectors.insert((&asset.platform, &asset.arch))
            || asset.url.len() > 4096
            || !["windows", "linux", "macos"].contains(&asset.platform.as_str())
            || !["x86_64", "aarch64"].contains(&asset.arch.as_str())
            || asset.size == 0
            || asset.size > policy.max_bytes
            || asset.sha256.len() != 64
            || !asset.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(invalid());
        }
        let url = reqwest::Url::parse(&asset.url).map_err(|_| invalid())?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || !policy.allowed_origins.contains(&url.origin().ascii_serialization())
        {
            return Err(invalid());
        }
    }
    let Some(mut plan) = plan_update(current, manifest, platform, arch)? else {
        return Ok(None);
    };
    if !rollout_selected(agent_id, manifest.rollout_percent) {
        return Ok(None);
    }
    plan.requires_manual_approval = false;
    Ok(Some(VerifiedUpdate {
        plan,
        policy,
        key_id: trusted.key_id.clone(),
        manifest_sha256: super::sha256_hex(&payload),
    }))
}
