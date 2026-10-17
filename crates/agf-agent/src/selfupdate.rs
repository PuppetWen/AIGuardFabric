//! 显式外部 helper 自更新：可信发布验签、受限 HTTPS、原子替换与启动心跳回滚。
//!
//! `plan_update` 只是未验签预览；只有 `verify_release` 能构造不可反序列化的
//! `VerifiedUpdate`，供 `download_and_apply` 使用。默认采集不会触发更新。
//! 安装前必须由服务管理器停止旧目标；更新 helper 不能覆盖自己的运行映像。
//! 成功平台回执在原始 60 秒期限内形成事务/nonce/目标 SHA 绑定的持久心跳。
//! 更新失败只恢复本事务校验过的备份，不终止无归属进程、不重新下载。
//!
//! 本地测试仅使用临时根和受控子进程；真实 Windows/Linux/macOS 服务、签名密钥
//! 运维和设备灰度/重启行为仍须按 pending verification 完成阶段二验证。

mod download;
mod health;
mod install;
mod journal;
mod paths;
mod supervisor;
mod trust;
mod version;
pub use health::{acknowledge_platform_heartbeat, arm_update_watchdog};
pub use install::{StagedUpdate, UpdateReceipt, recover_update};
pub use paths::InstallRoot;
pub use supervisor::download_and_apply;
pub use trust::{
    DownloadPolicy, TrustedReleaseKey, VerifiedUpdate, release_signing_payload, rollout_selected, verify_release,
};
pub use version::{Version, is_newer, parse_version};
#[cfg(test)]
#[path = "selfupdate/regression.rs"]
mod regression;
#[cfg(test)]
#[path = "selfupdate/tls_tests.rs"]
mod tls_tests;
use agf_core::error::DomainResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::platform::HostPlatform;

/// 自更新验证登记锚点（真实设备验证仍需单独登记）。
pub const TODO_ANCHOR: &str = "agent-self-update";

/// 单个发布资产。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseAsset {
    /// 平台标识（`windows` / `linux` / `macos`）。
    pub platform: String,
    /// 架构（`x86_64` / `aarch64`）。
    pub arch: String,
    /// 下载地址（必须 HTTPS）。
    pub url: String,
    /// 期望 SHA-256（小写 hex）。
    pub sha256: String,
    /// 字节数。
    #[serde(default)]
    pub size: u64,
}

/// 发布清单。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    /// 版本号（`x.y.z` 或 `vx.y.z`，可带 `-pre`）。
    pub version: String,
    /// 发布说明。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// 灰度百分比（0-100）。
    #[serde(default = "default_rollout")]
    pub rollout_percent: u8,
    /// 平台资产列表。
    #[serde(default)]
    pub assets: Vec<ReleaseAsset>,
    /// 分离签名，格式为 ed25519-v1:<操作员密钥标识>:<base64签名>。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

const fn default_rollout() -> u8 {
    100
}

/// 校验 SHA-256（大小写不敏感；长度不符直接判否）。
#[must_use]
pub fn verify_checksum(bytes: &[u8], expected_hex: &str) -> bool {
    let expected = expected_hex.trim().to_ascii_lowercase();
    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let digest = Sha256::digest(bytes);
    let actual = hex::encode(digest);
    // 常量时间比较（避免把校验和当侧信道）
    let mut diff = 0_u8;
    for (a, b) in actual.bytes().zip(expected.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// 计算 SHA-256（小写 hex），供 manifest 生成与测试对照。
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// 选择匹配平台与架构的资产。
#[must_use]
pub fn select_asset<'a>(manifest: &'a ReleaseManifest, platform: HostPlatform, arch: &str) -> Option<&'a ReleaseAsset> {
    manifest
        .assets
        .iter()
        .find(|a| a.platform.eq_ignore_ascii_case(platform.as_str()) && a.arch.eq_ignore_ascii_case(arch))
}

/// 升级计划（**只描述、不执行**）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePlan {
    /// 当前版本。
    pub current: String,
    /// 目标版本。
    pub target: String,
    /// 下载地址。
    pub url: String,
    /// 期望校验和。
    pub sha256: String,
    /// 期望字节数。
    pub size: u64,
    /// 未验签预览恒 true；只有 verify_release 成功后返回的认证计划才是 false。
    pub requires_manual_approval: bool,
}

/// 依据 manifest 生成升级计划。
///
/// # Errors
/// 版本号非法时返回 `DomainError::Validation`。
pub fn plan_update(
    current: &str,
    manifest: &ReleaseManifest,
    platform: HostPlatform,
    arch: &str,
) -> DomainResult<Option<UpdatePlan>> {
    if !is_newer(current, &manifest.version)? {
        return Ok(None);
    }
    let Some(asset) = select_asset(manifest, platform, arch) else {
        return Ok(None);
    };
    Ok(Some(UpdatePlan {
        current: current.to_string(),
        target: manifest.version.clone(),
        url: asset.url.clone(),
        sha256: asset.sha256.clone(),
        size: asset.size,
        requires_manual_approval: true,
    }))
}

/// 阶段二验证条件清单（供"待验证项"页与测试断言使用）。
#[must_use]
pub fn verification_conditions() -> Vec<&'static str> {
    vec![
        "manifest 签名链（平台私钥签名 + Agent 内置公钥验签）",
        "下载走 HTTPS 并校验证书链（支持企业自定义 CA）",
        "原子替换二进制（Windows 需处理运行中文件占用 + 单例锁 + 重启）",
        "新版本启动 60 秒内未上报心跳则自动回滚",
        "manifest 携带 rollout_percent，按 agent_id 哈希灰度",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(version: &str, signature: Option<&str>) -> ReleaseManifest {
        ReleaseManifest {
            version: version.to_string(),
            notes: Some("测试".to_string()),
            rollout_percent: 100,
            assets: vec![ReleaseAsset {
                platform: "windows".into(),
                arch: "x86_64".into(),
                url: "https://dl.example.invalid/agf-agent-0.2.0.exe".into(),
                sha256: sha256_hex(b"payload"),
                size: 7,
            }],
            signature: signature.map(ToString::to_string),
        }
    }

    #[test]
    fn version_parsing_accepts_v_prefix_and_prerelease() {
        let v = parse_version("v1.2.3").expect("解析应成功");
        assert_eq!((v.major, v.minor, v.patch), (1, 2, 3));
        assert!(v.pre.is_none());
        let pre = parse_version("1.2.3-rc.1").expect("解析应成功");
        assert_eq!(pre.pre.as_deref(), Some("rc.1"));
        assert_eq!(pre.to_string(), "1.2.3-rc.1");
        let build = parse_version("1.2.3+build.9").expect("解析应成功");
        assert_eq!(build.to_string(), "1.2.3");
    }

    #[test]
    fn version_parsing_rejects_malformed() {
        for bad in ["1.2", "1.2.3.4", "a.b.c", "", "v1.2.x"] {
            assert!(parse_version(bad).is_err(), "{bad} 应被判非法");
        }
    }

    #[test]
    fn version_ordering_follows_semver() {
        assert!(is_newer("1.2.3", "1.2.4").unwrap_or(false));
        assert!(is_newer("1.2.3", "1.10.0").unwrap_or(false), "数字比较而非字典序");
        assert!(is_newer("1.2.3", "2.0.0").unwrap_or(false));
        assert!(!is_newer("1.2.3", "1.2.3").unwrap_or(true));
        assert!(!is_newer("2.0.0", "1.9.9").unwrap_or(true));
        assert!(is_newer("1.2.3", "1.2.4-rc.1").unwrap_or(false), "预发布版仍高于旧正式版");
        assert!(!is_newer("1.2.4", "1.2.4-rc.1").unwrap_or(true), "预发布小于同号正式版");
        assert!(is_newer("not-a-version", "1.0.0").is_err(), "非法版本必须报错而不是猜");
    }

    #[test]
    fn checksum_verification_matrix() {
        let bytes = b"agf-agent-binary";
        let hex = sha256_hex(bytes);
        assert!(verify_checksum(bytes, &hex));
        assert!(verify_checksum(bytes, &hex.to_ascii_uppercase()), "大小写不敏感");
        assert!(!verify_checksum(bytes, &sha256_hex(b"tampered")));
        assert!(!verify_checksum(bytes, "short"));
        assert!(!verify_checksum(bytes, &"z".repeat(64)), "非 hex 必须判否");
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn asset_selection_matches_platform_and_arch() {
        let manifest = manifest("0.2.0", Some("sig"));
        assert!(select_asset(&manifest, HostPlatform::Windows, "x86_64").is_some());
        assert!(select_asset(&manifest, HostPlatform::Windows, "aarch64").is_none());
        assert!(select_asset(&manifest, HostPlatform::Linux, "x86_64").is_none());
    }

    #[test]
    fn plan_update_returns_none_for_same_or_missing_asset() {
        let current = manifest("0.1.0", Some("sig"));
        assert!(plan_update("0.1.0", &current, HostPlatform::Windows, "x86_64").unwrap_or(None).is_none());
        let newer = manifest("9.9.9", Some("sig"));
        assert!(plan_update("0.1.0", &newer, HostPlatform::Linux, "x86_64").unwrap_or(None).is_none());
        let plan = plan_update("0.1.0", &newer, HostPlatform::Windows, "x86_64").unwrap_or(None).expect("应有计划");
        assert_eq!(plan.target, "9.9.9");
        assert!(plan.requires_manual_approval, "预览只看字段，尚未验签，不能直接安装");
        assert_eq!(plan.sha256.len(), 64);
    }

    #[test]
    fn unsigned_manifest_requires_manual_approval() {
        let manifest = manifest("0.2.0", None);
        let plan = plan_update("0.1.0", &manifest, HostPlatform::Windows, "x86_64").unwrap_or(None).expect("计划");
        assert!(plan.requires_manual_approval, "无签名必须要求人工确认");
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let manifest = manifest("1.0.0", Some("sig"));
        let json = serde_json::to_string(&manifest).expect("序列化");
        let back: ReleaseManifest = serde_json::from_str(&json).expect("反序列化");
        assert_eq!(back, manifest);
        // 缺省 rollout_percent 应是 100（全量）
        let minimal: ReleaseManifest = serde_json::from_str(r#"{"version":"1.0.0"}"#).expect("最小 manifest");
        assert_eq!(minimal.rollout_percent, 100);
        assert!(minimal.assets.is_empty());
    }
}
