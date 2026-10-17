//! 资产发现（§4.1 发现来源）。
//!
//! | 发现源 | 入口 | 离线可用 |
//! |---|---|---|
//! | 终端 Agent 上报 | [`DiscoveryBatch::from_agent_report`] | ✅ 完全离线（纯转换） |
//! | Git / 本地目录扫描 | [`GitScanner`] | ✅ 本地目录可用（远端仓库需凭据，PV-008） |
//! | 网段扫描 | [`NetworkScanner`] | ✅ TCP 连通性探测（Mock 模式下走 fixtures） |
//! | 云 API 拉取 | `agf-alicloud` / `agf-adapters` | ❌ 无凭据时降级为不产出 |
//! | 手工登记 | `agf-api` 的 `POST /assets` | ✅ |
//!
//! 本模块的产出统一为 [`DiscoveredAsset`]：**只描述事实**（发现了什么、从哪发现、指纹是什么），
//! 风险判定交给 `agf-scan`，保证规则可热更新而无需重跑发现。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::path::Path;
pub(crate) use std::path::PathBuf;

pub(crate) use agf_core::agent::AgentReport;
pub(crate) use agf_core::agent::DetectedMcp;

pub(crate) use agf_core::asset::ExposureInput;
pub(crate) use agf_core::asset::score_exposure;

pub(crate) use agf_core::enums::AssetKind;
pub(crate) use agf_core::enums::DiscoverySource;
pub(crate) use agf_core::enums::Protocol;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::mcp::McpTransport;

pub(crate) use agf_core::secret::CredentialMatch;
pub(crate) use agf_core::secret::scan_credentials;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use tracing::debug;
pub(crate) use tracing::info;
pub(crate) use tracing::warn;

pub(crate) use crate::fingerprint::agent_fingerprint;
pub(crate) use crate::fingerprint::asset_fingerprint;
pub(crate) use crate::fingerprint::asset_id_from_fingerprint;
pub(crate) use crate::fingerprint::mcp_fingerprint;
pub(crate) use crate::fingerprint::model_endpoint_fingerprint;

#[cfg(test)]
pub(crate) use agf_core::agent::AgentFlavor;
#[cfg(test)]
pub(crate) use agf_core::agent::DetectedAgent;
#[cfg(test)]
pub(crate) use agf_core::agent::DetectedCredential;

#[allow(unused_imports)]
pub use impl_discovered_asset::*;
#[allow(unused_imports)]
pub use parse_mcp_config::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 一个被发现的资产（发现层的统一产出）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAsset {
    /// 确定性资产 id（由指纹推导，保证多次发现归并）。
    pub id: Id,
    /// 资产类型。
    pub kind: AssetKind,
    /// 名称。
    pub name: String,
    /// 指纹。
    pub fingerprint: String,
    /// 厂商。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// 版本。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// 协议。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    /// 端点。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// 宿主机。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// 归属用户。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// 归属部门。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// 发现来源。
    pub discovery_source: DiscoverySource,
    /// 证据引用（配置文件路径 / 上报 id / 扫描任务 id）。
    pub evidence_ref: String,
    /// 暴露面评分。
    pub exposure_score: u8,
    /// 暴露面扣分项。
    #[serde(default)]
    pub exposure_items: Vec<(String, u8)>,
    /// 是否检测到明文凭据。
    pub has_plaintext_secret: bool,
    /// 是否要求认证。
    pub requires_auth: bool,
    /// 附加属性（保真）。
    #[serde(default)]
    pub attributes: serde_json::Value,
    /// 发现时间。
    pub discovered_at: Timestamp,
}

/// 一次发现的产出集合。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveryBatch {
    /// 租户。
    pub tenant_id: Option<TenantId>,
    /// 发现来源。
    pub source: Option<DiscoverySource>,
    /// 发现的资产。
    pub assets: Vec<DiscoveredAsset>,
    /// 发现的凭据（只有掩码与位置，**没有明文**）。
    pub credentials: Vec<CredentialMatch>,
    /// 警告（用于排障，例如配置文件无法解析）。
    pub warnings: Vec<String>,
    /// 扫描范围（路径/网段，审计用）。
    pub scope: Vec<String>,
    /// 耗时（毫秒）。
    pub elapsed_ms: u64,
}

// ===========================================================================
// Git / 本地目录扫描
// ===========================================================================

/// 扫描到的配置文件类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigFileKind {
    /// `.mcp.json` / `mcp.json`（MCP 服务器配置）。
    McpJson,
    /// `claude_desktop_config.json`。
    ClaudeDesktop,
    /// `.cursor/mcp.json`。
    CursorMcp,
    /// 通用 JSON/YAML 配置（含 `mcpServers` 字段）。
    GenericJson,
    /// `.env` 文件。
    DotEnv,
    /// 源码文件（扫描硬编码凭据）。
    SourceCode,
}

/// 本地仓库/目录扫描器（§4.1 Git 仓库扫描：MCP 配置 + 硬编码密钥）。
#[derive(Debug, Clone)]
pub struct GitScanner {
    max_file_bytes: u64,
    skip_dirs: Vec<String>,
    source_extensions: Vec<String>,
}

// ===========================================================================
// 网段扫描
// ===========================================================================

/// 网段扫描目标。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkScanTarget {
    /// 目标地址。
    pub host: String,
    /// 端口列表。
    pub ports: Vec<u16>,
}

/// 网段扫描器（§4.1 网段扫描 + MCP 握手探测）。
///
/// **Mock 模式**（`AGF_MOCK_MODE=1`）下不发起真实连接，
/// 直接返回 fixtures 中的模拟探测结果，保证离线可演示。
#[derive(Debug, Clone)]
pub struct NetworkScanner {
    timeout_ms: u64,
    mock: bool,
    common_ports: Vec<u16>,
}

mod impl_discovered_asset;
mod parse_mcp_config;
#[cfg(test)]
mod tests;
