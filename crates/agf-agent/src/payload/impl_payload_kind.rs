//! 由 `payload.rs` 拆分：`impl_PayloadKind`/`impl_unknown` 等 9 项（纯搬移，逻辑不变）。
use super::*;

impl PayloadKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Heartbeat => "heartbeat",
            Self::Diff => "diff",
            Self::Register => "register",
        }
    }

    /// 上行路径（服务端契约）。
    #[must_use]
    pub const fn default_path(&self) -> &'static str {
        match self {
            Self::Snapshot | Self::Diff => "/api/v1/agent/report",
            Self::Heartbeat => "/api/v1/agent/heartbeat",
            Self::Register => "/api/v1/agent/register",
        }
    }
}

impl<T: Serialize> Envelope<T> {
    /// 构造信封（幂等键由 `(agent_id, kind, payload)` 派生）。
    ///
    /// # Errors
    /// 载荷序列化失败时返回 `DomainError::Parse`。
    pub fn new(identity: &AgentIdentity, kind: PayloadKind, payload: T) -> DomainResult<Self> {
        let idempotency_key = identity.idempotency_key(kind, &payload)?;
        Ok(Self {
            schema: SCHEMA.to_string(),
            kind,
            agent_id: identity.agent_id.clone(),
            tenant_id: identity.tenant_id,
            agent_version: identity.agent_version.clone(),
            hostname: identity.hostname.clone(),
            sent_at: Timestamp::now(),
            idempotency_key,
            payload,
        })
    }

    /// 序列化为上行 JSON。
    ///
    /// # Errors
    /// 序列化失败时返回 `DomainError::Parse`。
    pub fn to_json(&self) -> DomainResult<String> {
        serde_json::to_string(self).map_err(DomainError::from)
    }
}

impl DiffPayload {
    /// 是否有任何变更。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added_agents.is_empty()
            && self.removed_agent_keys.is_empty()
            && self.changed_agents.is_empty()
            && self.added_mcp.is_empty()
            && self.removed_mcp_keys.is_empty()
            && self.credential_hits.is_empty()
    }

    /// 变更总条数（截断前）。
    #[must_use]
    pub fn change_count(&self) -> usize {
        self.added_agents.len()
            + self.removed_agent_keys.len()
            + self.changed_agents.len()
            + self.added_mcp.len()
            + self.removed_mcp_keys.len()
            + self.credential_hits.len()
    }
}

/// 幂等键派生（SHA-256 前 16 字节 hex）。
#[must_use]
pub fn payload_key(agent_id: &str, kind: PayloadKind, canonical_payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(agent_id.as_bytes());
    hasher.update(b"|");
    hasher.update(kind.as_str().as_bytes());
    hasher.update(b"|");
    hasher.update(canonical_payload.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

/// Agent 资产键（服务端与终端共用的去重语义：类型 + 路径/配置目录）。
#[must_use]
pub fn agent_key(detected: &DetectedAgent) -> String {
    let anchor =
        detected.config_dir.clone().or_else(|| detected.binary_path.clone()).unwrap_or_else(|| "-".to_string());
    format!("agent:{}:{anchor}", detected.flavor.as_str())
}

/// MCP 资产键（来源文件 + 服务器名）。
#[must_use]
pub fn mcp_key(mcp: &DetectedMcp) -> String {
    format!("mcp:{}:{}", mcp.source_file, mcp.server_name)
}

/// 资产键集合指纹（用于 diff 基线标识）。
#[must_use]
pub fn fingerprint(report: &AgentReport) -> String {
    let mut keys: Vec<String> = report.agents.iter().map(agent_key).collect();
    keys.extend(report.mcp_configs.iter().map(mcp_key));
    keys.sort_unstable();
    keys.dedup();
    payload_key("agf-fingerprint", PayloadKind::Snapshot, &keys.join("|"))
}

/// 计算增量变更（纯函数，可离线完整单测）。
///
/// `previous = None` 表示首次上报：当前全部资产计为 `added`。
#[must_use]
pub fn compute_diff(previous: Option<&AgentReport>, current: &AgentReport) -> DiffPayload {
    let current_agents: BTreeMap<String, &DetectedAgent> = current.agents.iter().map(|a| (agent_key(a), a)).collect();
    let current_mcp: BTreeMap<String, &DetectedMcp> = current.mcp_configs.iter().map(|m| (mcp_key(m), m)).collect();
    let previous_agents: BTreeMap<String, &DetectedAgent> =
        previous.map(|p| p.agents.iter().map(|a| (agent_key(a), a)).collect()).unwrap_or_default();
    let previous_mcp: BTreeMap<String, &DetectedMcp> =
        previous.map(|p| p.mcp_configs.iter().map(|m| (mcp_key(m), m)).collect()).unwrap_or_default();

    let mut added_agents = Vec::new();
    let mut changed_agents = Vec::new();
    for (key, agent) in &current_agents {
        match previous_agents.get(key) {
            None => added_agents.push((*agent).clone()),
            Some(old) if old.version != agent.version || old.config_hash != agent.config_hash => {
                changed_agents.push((*agent).clone());
            }
            Some(_) => {}
        }
    }
    let removed_agent_keys: Vec<String> =
        previous_agents.keys().filter(|k| !current_agents.contains_key(*k)).cloned().collect();
    let added_mcp: Vec<DetectedMcp> =
        current_mcp.iter().filter(|(k, _)| !previous_mcp.contains_key(*k)).map(|(_, m)| (*m).clone()).collect();
    let removed_mcp_keys: Vec<String> =
        previous_mcp.keys().filter(|k| !current_mcp.contains_key(*k)).cloned().collect();

    // 凭据命中：只在"新增文件"或"位置变化"时上报，避免每次全量重复
    let previous_credential_keys: BTreeSet<String> = previous
        .map(|p| p.credential_hits.iter().map(|c| format!("{}:{}:{}", c.source_file, c.line, c.kind)).collect())
        .unwrap_or_default();
    let mut credential_hits: Vec<DetectedCredential> = current
        .credential_hits
        .iter()
        .filter(|c| !previous_credential_keys.contains(&format!("{}:{}:{}", c.source_file, c.line, c.kind)))
        .cloned()
        .collect();

    let mut diff = DiffPayload {
        base_fingerprint: previous.map_or_else(|| "none".to_string(), fingerprint),
        added_agents,
        removed_agent_keys,
        changed_agents,
        added_mcp,
        removed_mcp_keys,
        credential_hits: Vec::new(),
        truncated: false,
    };
    if diff.change_count() + credential_hits.len() > MAX_DIFF_ITEMS {
        diff.truncated = true;
        diff.added_agents.truncate(MAX_DIFF_ITEMS);
        diff.changed_agents.truncate(MAX_DIFF_ITEMS.saturating_sub(diff.added_agents.len()));
        diff.added_mcp.truncate(MAX_DIFF_ITEMS.saturating_sub(diff.added_agents.len() + diff.changed_agents.len()));
        credential_hits.truncate(MAX_DIFF_ITEMS.saturating_sub(diff.change_count()));
    }
    diff.credential_hits = credential_hits;
    diff
}

/// 由 Agent 类型推断是否需要重点关注的 Skill 目录名（用于 Skill 采集的 flavor 提示）。
#[must_use]
pub fn flavor_of_dir(name: &str) -> Option<AgentFlavor> {
    match name.to_ascii_lowercase().as_str() {
        "claude" | ".claude" => Some(AgentFlavor::ClaudeCode),
        "cursor" | ".cursor" => Some(AgentFlavor::Cursor),
        "windsurf" | ".windsurf" | "codeium" => Some(AgentFlavor::Windsurf),
        "cline" | "roo" => Some(AgentFlavor::Cline),
        _ => None,
    }
}
