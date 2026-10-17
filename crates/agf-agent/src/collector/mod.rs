//! 采集器集合：统一上下文、统一产出、统一状态登记。
//!
//! ## 设计约定
//!
//! - **终端只做事实采集，不做判定**（判定在服务端，规则可热更新）；
//! - 每个采集器返回 [`CollectorOutcome`]，失败只记 `error`，**绝不中断其它采集器**；
//! - 采集范围（扫过的路径）进入 `AgentReport::scan_scope`，用于审计与排障；
//! - 目录不存在 = 空结果（不是错误），与"平台不支持"（`NotImplemented`）严格区分。
//!
//! ## 降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 单个采集器失败 | 记 `CollectorStatus.error`；其余采集器照常产出 |
//! | Linux/macOS | 六类共用采集；Linux 从 `/proc/net`、macOS 从系统 `lsof` 采监听端口；后者待真机验收 |
//! | 无 `home` 目录（容器/服务账号） | 路径类采集器产出空结果 + scope 记录 |
//! | 进程/端口采集关闭 | 由 [`CollectContext`] 开关控制（默认开启） |

pub(crate) use std::path::PathBuf;

pub(crate) use crate::payload::CollectorStatus;

pub(crate) use crate::payload::SnapshotPayload;

pub(crate) use crate::platform::SupportLevel;

#[allow(unused_imports)]
pub use impl_collect_context::*;

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

pub mod env_secrets;

pub mod ide_plugins;

#[cfg(any(target_os = "macos", test))]
mod macos_ports;

mod mcp_auth;
pub mod mcp_config;
mod mcp_config_redaction;

pub mod model_endpoints;

pub mod ports;
mod project_paths;

pub mod processes;

mod skill_hash;
mod skill_package;
pub mod skills;
mod url_safety;

/// 采集上下文（可注入 `home`，测试用临时目录替代真实用户目录）。
#[derive(Debug, Clone)]
pub struct CollectContext {
    /// 用户主目录（`%USERPROFILE%` / `$HOME`）。
    pub home: PathBuf,
    /// 显式授权采集的项目根目录（只读取固定配置文件，不递归扫描仓库）。
    pub project_roots: Vec<PathBuf>,
    /// Agent 数据目录（队列/状态文件）。
    pub data_dir: PathBuf,
    /// 单文件最大读取字节（超过跳过，避免读入大二进制）。
    pub max_file_bytes: u64,
    /// 是否采集进程。
    pub include_processes: bool,
    /// 是否采集监听端口。
    pub include_ports: bool,
    /// 目录遍历最大深度。
    pub max_depth: usize,
}

/// 单采集器产出。
#[derive(Debug, Clone)]
pub struct CollectorOutcome<T> {
    /// 采集器名。
    pub name: &'static str,
    /// 条目。
    pub items: Vec<T>,
    /// 附带发现的明文凭据命中（掩码形态；仅 MCP / 模型端点采集器会填）。
    pub credential_hits: Vec<agf_core::agent::DetectedCredential>,
    /// 采集范围（扫过的路径/来源）。
    pub scope: Vec<String>,
    /// 警告（不阻断）。
    pub warnings: Vec<String>,
    /// 支持级别。
    pub level: SupportLevel,
    /// 耗时（毫秒）。
    pub elapsed_ms: u64,
    /// 错误（`NotImplemented` 也记在这里，供状态如实上报）。
    pub error: Option<String>,
}

/// 一次完整采集的产出。
#[derive(Debug, Clone)]
pub struct CollectionSnapshot {
    /// 可直接上行的快照载荷。
    pub payload: SnapshotPayload,
    /// 各采集器状态（心跳与排障用）。
    pub statuses: Vec<CollectorStatus>,
}

mod impl_collect_context;

#[cfg(test)]
mod tests;
