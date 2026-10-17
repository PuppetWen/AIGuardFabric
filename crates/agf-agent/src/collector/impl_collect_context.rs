//! 由 `mod.rs` 拆分：`impl_CollectContext`/`impl_CollectContext` 等 11 项（纯搬移，逻辑不变）。
use super::*;

use crate::identity::AgentIdentity;
use crate::payload::{CollectionExtras, CollectorStatus, SnapshotPayload};
use crate::platform::{SupportLevel, current};
use agf_core::agent::AgentReport;
use agf_core::time::Timestamp;
use std::path::{Path, PathBuf};

impl Default for CollectContext {
    fn default() -> Self {
        Self {
            home: dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")),
            project_roots: std::env::var_os("AGF_AGENT_PROJECT_ROOTS")
                .map(|raw| std::env::split_paths(&raw).filter(|path| path.is_absolute()).take(8).collect())
                .unwrap_or_default(),
            data_dir: dirs::data_dir().map_or_else(|| PathBuf::from("./data"), |d| d.join("aiguardfabric")),
            max_file_bytes: 2 * 1024 * 1024,
            include_processes: true,
            include_ports: true,
            max_depth: 4,
        }
    }
}

impl CollectContext {
    /// 当前用户上下文。
    #[must_use]
    pub fn for_current_user() -> Self {
        Self::default()
    }

    /// 指定主目录（链式；测试必用）。
    #[must_use]
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = home.into();
        self
    }

    /// 显式指定项目根目录（最多 8 个绝对路径，仅扫描固定的 MCP 配置文件）。
    #[must_use]
    pub fn with_project_roots(mut self, roots: impl IntoIterator<Item = PathBuf>) -> Self {
        self.project_roots = roots.into_iter().filter(|path| path.is_absolute()).take(8).collect();
        self
    }

    /// 指定数据目录（链式）。
    #[must_use]
    pub fn with_data_dir(mut self, data_dir: impl Into<PathBuf>) -> Self {
        self.data_dir = data_dir.into();
        self
    }

    /// 关闭进程/端口采集（链式；最小权限/低开销模式）。
    #[must_use]
    pub fn without_system_probes(mut self) -> Self {
        self.include_processes = false;
        self.include_ports = false;
        self
    }

    /// 主目录是否可用。
    #[must_use]
    pub fn home_available(&self) -> bool {
        self.home.is_dir()
    }
}

impl<T> CollectorOutcome<T> {
    /// 构造空产出（用于"跳过"）。
    #[must_use]
    pub fn skipped(name: &'static str, reason: &str) -> Self {
        Self {
            name,
            items: Vec::new(),
            credential_hits: Vec::new(),
            scope: Vec::new(),
            warnings: vec![reason.to_string()],
            level: SupportLevel::Implemented,
            elapsed_ms: 0,
            error: None,
        }
    }

    /// 构造"平台不支持"产出。
    #[must_use]
    pub fn unsupported(name: &'static str, error: String) -> Self {
        Self {
            name,
            items: Vec::new(),
            credential_hits: Vec::new(),
            scope: Vec::new(),
            warnings: vec![error.clone()],
            level: SupportLevel::InterfaceOnly,
            elapsed_ms: 0,
            error: Some(error),
        }
    }

    /// 追加采集范围。
    pub fn extend_scope(&mut self, extra: impl IntoIterator<Item = String>) {
        self.scope.extend(extra);
    }

    /// 转状态记录。
    #[must_use]
    pub fn status(&self) -> CollectorStatus {
        CollectorStatus {
            name: self.name.to_string(),
            level: self.level.as_str().to_string(),
            items: self.items.len(),
            elapsed_ms: self.elapsed_ms,
            error: self.error.clone(),
        }
    }

    /// 是否成功。
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

impl CollectionSnapshot {
    /// 采集到的资产/事实总条数。
    #[must_use]
    pub fn total_items(&self) -> usize {
        let report = &self.payload.report;
        report.agents.len()
            + report.mcp_configs.len()
            + report.credential_hits.len()
            + self.payload.extras.model_endpoints.len()
            + self.payload.extras.skills.len()
            + self.payload.extras.processes.len()
            + self.payload.extras.listening_ports.len()
    }

    /// 失败的采集器名。
    #[must_use]
    pub fn failed_collectors(&self) -> Vec<String> {
        self.statuses.iter().filter(|s| s.error.is_some()).map(|s| s.name.clone()).collect()
    }
}

/// 执行全部采集器（单个失败不影响其它）。
#[must_use]
pub fn collect_all(identity: &AgentIdentity, ctx: &CollectContext) -> CollectionSnapshot {
    let mut statuses: Vec<CollectorStatus> = Vec::new();
    let mut scan_scope: Vec<String> = Vec::new();

    // ① 环境变量硬编码密钥
    let env_outcome = env_secrets::collect(ctx);
    statuses.push(env_outcome.status());
    scan_scope.extend(env_outcome.scope.iter().cloned());
    let mut credential_hits = env_outcome.items;

    // ② MCP 配置（同时产出 Agent 资产与凭据命中）
    let mcp_outcome = mcp_config::collect(ctx);
    statuses.push(mcp_outcome.status());
    scan_scope.extend(mcp_outcome.scope.iter().cloned());
    let mcp_assets = mcp_outcome.items;
    credential_hits.extend(mcp_outcome.credential_hits);

    // ③ IDE / Agent 插件目录
    let ide_outcome = ide_plugins::collect(ctx);
    statuses.push(ide_outcome.status());
    scan_scope.extend(ide_outcome.scope.iter().cloned());

    // ④ 工具与 Skill
    let skill_outcome = skills::collect(ctx);
    statuses.push(skill_outcome.status());
    scan_scope.extend(skill_outcome.scope.iter().cloned());

    // ⑤ 模型端点
    let endpoint_outcome = model_endpoints::collect(ctx);
    statuses.push(endpoint_outcome.status());
    scan_scope.extend(endpoint_outcome.scope.iter().cloned());
    credential_hits.extend(endpoint_outcome.credential_hits);

    // ⑥ 进程（可在上下文里关闭）
    let process_outcome = if ctx.include_processes {
        let outcome = processes::collect(ctx);
        statuses.push(outcome.status());
        outcome.items
    } else {
        let skipped = processes::skipped_outcome();
        statuses.push(skipped.status());
        Vec::new()
    };

    // ⑦ 监听端口（同上）
    let port_outcome = if ctx.include_ports {
        let outcome = ports::collect(ctx);
        statuses.push(outcome.status());
        outcome.items
    } else {
        let skipped = ports::skipped_outcome();
        statuses.push(skipped.status());
        Vec::new()
    };

    credential_hits.sort_by(|a, b| (a.source_file.as_str(), a.line).cmp(&(b.source_file.as_str(), b.line)));
    credential_hits.dedup_by(|a, b| a.source_file == b.source_file && a.line == b.line && a.kind == b.kind);
    scan_scope.sort();
    scan_scope.dedup();

    let mut agents = ide_outcome.items;
    agents.extend(mcp_config::agents_from_mcp(&mcp_assets, &identity.hostname));

    let report = AgentReport {
        collector_id: identity.agent_id.clone(),
        collected_at: Timestamp::now(),
        hostname: identity.hostname.clone(),
        os: identity.os.clone(),
        os_user: identity.os_user.clone(),
        agents,
        mcp_configs: mcp_assets,
        credential_hits,
        scan_scope,
        agent_version: identity.agent_version.clone(),
    };
    let extras = CollectionExtras {
        model_endpoints: endpoint_outcome.items,
        skills: skill_outcome.items,
        processes: process_outcome,
        listening_ports: port_outcome,
    };
    CollectionSnapshot { payload: SnapshotPayload { report, extras }, statuses }
}

/// 当前平台是否七类采集均已接线（Windows/Linux）。
#[must_use]
pub fn platform_supports_collection() -> bool {
    matches!(current(), crate::platform::HostPlatform::Windows | crate::platform::HostPlatform::Linux)
}

/// 读取文本文件（受 `max_file_bytes` 与 UTF-8 限制；失败返回原因字符串）。
///
/// # Errors
/// 文件过大、非 UTF-8 或不可读时返回错误描述（调用方记 warning 即可）。
pub fn read_text(path: &Path, max_file_bytes: u64) -> Result<String, String> {
    let metadata = std::fs::metadata(path).map_err(|e| format!("stat 失败: {e}"))?;
    if !metadata.is_file() {
        return Err("不是普通文件".to_string());
    }
    if metadata.len() > max_file_bytes {
        return Err(format!("文件过大（{} 字节）", metadata.len()));
    }
    std::fs::read_to_string(path).map_err(|e| format!("读取失败（非 UTF-8 或权限不足）: {e}"))
}

/// 在文本中扫描硬编码凭据（**只产出掩码与位置，绝不产出明文**）。
///
/// 两条互补路径：
/// 1. `agf_core::secret::scan_credentials` 的内置模式表（与平台侧口径一致）；
/// 2. **逐行 `KEY=VALUE` / `"KEY": "VALUE"` 启发式**：模式表覆盖不到的键名
///    （如 `.env` 里的 `SERVICE_TOKEN=…`）也能被发现，命中类型记为 `generic_kv_secret`。
///
/// 命中位置一律换算为从 1 开始的行号。
#[must_use]
pub fn scan_text_secrets(source: &str, text: &str) -> Vec<agf_core::agent::DetectedCredential> {
    let mut out: Vec<agf_core::agent::DetectedCredential> = agf_core::secret::scan_credentials(text, &[])
        .into_iter()
        .map(|hit| {
            let line = u32::try_from(text[..hit.start.min(text.len())].matches('\n').count() + 1).unwrap_or(1);
            agf_core::agent::DetectedCredential {
                source_file: source.to_string(),
                line,
                kind: hit.pattern,
                masked: hit.masked,
                context: None,
                confidence: hit.confidence,
            }
        })
        .collect();
    for (index, line) in text.lines().enumerate() {
        let line_number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        for (key, value) in extract_kv_pairs(line) {
            if !looks_like_plaintext_secret(&key, &value) {
                continue;
            }
            out.push(agf_core::agent::DetectedCredential {
                source_file: source.to_string(),
                line: line_number,
                kind: "generic_kv_secret".to_string(),
                masked: agf_core::secret::mask_default(&value),
                context: None,
                confidence: 0.55,
            });
        }
    }
    out.sort_by(|a, b| {
        (a.source_file.as_str(), a.line, a.kind.as_str()).cmp(&(b.source_file.as_str(), b.line, b.kind.as_str()))
    });
    out.dedup_by(|a, b| a.source_file == b.source_file && a.line == b.line && a.kind == b.kind);
    out
}

/// 从一行文本中提取 `键值对`（支持 `KEY=VALUE`、`"KEY": "VALUE"`、YAML 的 `KEY: VALUE`）。
///
/// 跳过注释行与空行；引号与行尾逗号会被剥离。
#[must_use]
pub fn extract_kv_pairs(line: &str) -> Vec<(String, String)> {
    let trimmed = line.trim().trim_start_matches(['-', '\t', ' ']);
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
        return Vec::new();
    }
    let separator = if trimmed.contains('=') { '=' } else { ':' };
    let Some((raw_key, raw_value)) = trimmed.split_once(separator) else {
        return Vec::new();
    };
    let key = raw_key.trim().trim_matches(['"', '\'', '{', ',']).to_string();
    let value = raw_value.trim().trim_matches(['"', '\'', ',', '}', ';']).to_string();
    if key.is_empty() || value.is_empty() || key.chars().any(char::is_whitespace) {
        return Vec::new();
    }
    vec![(key, value)]
}

/// 判断配置键名是否属于"敏感键"（决定是否需要提示明文风险）。
#[must_use]
pub fn is_sensitive_key(key: &str) -> bool {
    agf_core::mcp_config_safety::is_sensitive_key(key)
}

/// 判断一个"敏感键 + 值"是否构成明文凭据（排除占位符与短值噪声）。
#[must_use]
pub fn looks_like_plaintext_secret(key: &str, value: &str) -> bool {
    agf_core::mcp_config_safety::looks_like_plaintext_secret(key, value)
}
