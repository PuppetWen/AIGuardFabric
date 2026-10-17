//! AI Agent 资产模型（§4.1）。

use serde::{Deserialize, Serialize};

use crate::enums::{DataClass, DiscoverySource, LifecycleState};
use crate::ids::{Id, TenantId, TenantScoped};
use crate::time::Timestamp;

/// Agent 类型（内置识别规则 + 自研）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentFlavor {
    /// Claude Code。
    ClaudeCode,
    /// Cursor。
    Cursor,
    /// GitHub Copilot / Copilot Workspace。
    Copilot,
    /// Windsurf。
    Windsurf,
    /// Cline / Roo Code。
    Cline,
    /// LangGraph。
    LangGraph,
    /// Dify。
    Dify,
    /// Coze（扣子）。
    Coze,
    /// n8n。
    N8n,
    /// AutoGen。
    AutoGen,
    /// CrewAI。
    CrewAi,
    /// OpenAI Assistants / Agents SDK。
    OpenAiAgents,
    /// 自研 Agent。
    Custom,
    /// 未知/待识别。
    Unknown,
}

impl AgentFlavor {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Cursor => "cursor",
            Self::Copilot => "copilot",
            Self::Windsurf => "windsurf",
            Self::Cline => "cline",
            Self::LangGraph => "langgraph",
            Self::Dify => "dify",
            Self::Coze => "coze",
            Self::N8n => "n8n",
            Self::AutoGen => "autogen",
            Self::CrewAi => "crewai",
            Self::OpenAiAgents => "openai-agents",
            Self::Custom => "custom",
            Self::Unknown => "unknown",
        }
    }

    /// 全部类型。
    #[must_use]
    pub const fn all() -> [Self; 14] {
        [
            Self::ClaudeCode,
            Self::Cursor,
            Self::Copilot,
            Self::Windsurf,
            Self::Cline,
            Self::LangGraph,
            Self::Dify,
            Self::Coze,
            Self::N8n,
            Self::AutoGen,
            Self::CrewAi,
            Self::OpenAiAgents,
            Self::Custom,
            Self::Unknown,
        ]
    }

    /// 是否为商业闭源 IDE Agent（决定免改造纳管方式）。
    #[must_use]
    pub const fn is_ide_agent(&self) -> bool {
        matches!(self, Self::ClaudeCode | Self::Cursor | Self::Copilot | Self::Windsurf | Self::Cline)
    }

    /// 解析文本。
    ///
    /// # Errors
    /// 未知类型返回错误。
    pub fn parse(value: &str) -> Result<Self, String> {
        let v = value.to_ascii_lowercase().replace('_', "-");
        Self::all().into_iter().find(|f| f.as_str() == v).ok_or_else(|| format!("未知 Agent 类型: {value}"))
    }
}

/// 免改造纳管模式（§5.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OnboardingMode {
    /// 侧车代理（MCP stdio/HTTP 代理接管）。
    Sidecar,
    /// SDK 注入（自研 Agent 引入 AGF SDK）。
    SdkInjection,
    /// 网关注册（把模型/MCP 出口指向 AGF 网关）。
    GatewayRegistration,
    /// 仅采集不改流（旁路观测）。
    ObserveOnly,
}

impl OnboardingMode {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Sidecar => "sidecar",
            Self::SdkInjection => "sdk-injection",
            Self::GatewayRegistration => "gateway-registration",
            Self::ObserveOnly => "observe-only",
        }
    }
}

/// Agent 实例。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInstance {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 关联资产 id。
    pub asset_id: Id,
    /// Agent 类型。
    pub flavor: AgentFlavor,
    /// 版本。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// 宿主（终端/容器/函数）。
    pub host: String,
    /// 操作系统。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// 当前用户（终端 Agent 的登录用户）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_user: Option<String>,
    /// 归属人。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// 部门。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// 纳管模式。
    pub onboarding_mode: OnboardingMode,
    /// 生命周期。
    pub lifecycle: LifecycleState,
    /// 数据分级。
    pub data_class: DataClass,
    /// 关联的 MCP Server 资产 id。
    #[serde(default)]
    pub mcp_servers: Vec<Id>,
    /// 关联的模型端点资产 id。
    #[serde(default)]
    pub model_endpoints: Vec<Id>,
    /// 配置指纹（`.mcp.json` / settings 内容哈希）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    /// 采集器上报 id（终端 Agent 安装时生成）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collector_id: Option<String>,
    /// 心跳最后上报时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_heartbeat_at: Option<Timestamp>,
    /// 心跳间隔（秒）。
    pub heartbeat_interval_secs: i64,
    /// 发现来源。
    pub discovery_source: DiscoverySource,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
}

impl TenantScoped for AgentInstance {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl AgentInstance {
    /// 心跳是否新鲜（默认 3 倍间隔内视为在线）。
    #[must_use]
    pub fn is_online(&self, now: Timestamp) -> bool {
        match self.last_heartbeat_at {
            Some(at) => now.since_secs(&at) <= self.heartbeat_interval_secs.saturating_mul(3),
            None => false,
        }
    }
}

/// 终端采集器上报的载荷（`agf-agent` → `agf-ingest`）。
///
/// 终端侧只做"事实采集"，不做判定；判定全部在服务端完成，保证规则可热更新。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentReport {
    /// 采集器 id。
    pub collector_id: String,
    /// 采集时间。
    pub collected_at: Timestamp,
    /// 主机名。
    pub hostname: String,
    /// 操作系统。
    pub os: String,
    /// OS 用户。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_user: Option<String>,
    /// 检测到的 Agent 实例。
    #[serde(default)]
    pub agents: Vec<DetectedAgent>,
    /// 检测到的 MCP 配置项。
    #[serde(default)]
    pub mcp_configs: Vec<DetectedMcp>,
    /// 检测到的硬编码凭据（仅类型与位置，**不传明文**，可传掩码片段用于人工确认）。
    #[serde(default)]
    pub credential_hits: Vec<DetectedCredential>,
    /// 采集范围（扫过的路径/注册表键，用于审计与排障）。
    #[serde(default)]
    pub scan_scope: Vec<String>,
    /// 采集器版本。
    pub agent_version: String,
}

/// 单次上报中的 Agent 检测项。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedAgent {
    /// 类型。
    pub flavor: AgentFlavor,
    /// 版本。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// 可执行文件路径。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
    /// 配置目录。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_dir: Option<String>,
    /// 配置内容哈希。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
}

/// MCP 配置检测项。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedMcp {
    /// 配置来源文件。
    pub source_file: String,
    /// 服务器名（配置里的 key）。
    pub server_name: String,
    /// 传输方式（`stdio` / `sse` / `http`）。
    pub transport: String,
    /// 命令（stdio）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// 参数。
    #[serde(default)]
    pub args: Vec<String>,
    /// URL（sse/http）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// 环境变量键名（值一律脱敏，只报键名与是否疑似密钥）。
    #[serde(default)]
    pub env_keys: Vec<String>,
    /// 配置中是否发现疑似明文凭据（env、HTTP 头、URL 或命令参数）。
    pub has_plaintext_secret: bool,
    /// 客户端配置是否显式提供 HTTP 认证信息；旧版 Agent 未上报时默认为 false。
    #[serde(default)]
    pub auth_configured: bool,
}

/// 硬编码凭据检测项（终端侧只报位置与掩码，服务端二次确认）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedCredential {
    /// 来源文件。
    pub source_file: String,
    /// 行号。
    pub line: u32,
    /// 凭据类型（`openai_key` / `aws_ak` / `jwt` / `private_key` / `generic`）。
    pub kind: String,
    /// 掩码片段（如 `sk-abc...xyz`，仅前 6 后 4）。
    pub masked: String,
    /// 上下文摘要（前后各 20 字符，已脱敏）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// 置信度（0.0-1.0）。
    pub confidence: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_flavor_roundtrip() {
        for f in AgentFlavor::all() {
            assert_eq!(AgentFlavor::parse(f.as_str()), Ok(f));
        }
        assert!(AgentFlavor::parse("nope").is_err());
    }

    #[test]
    fn ide_agents_flagged() {
        assert!(AgentFlavor::ClaudeCode.is_ide_agent());
        assert!(AgentFlavor::Cursor.is_ide_agent());
        assert!(!AgentFlavor::LangGraph.is_ide_agent());
    }

    #[test]
    fn heartbeat_online_logic() {
        let now = Timestamp::now();
        let mut a = AgentInstance {
            id: Id::new(),
            tenant_id: TenantId::default_tenant(),
            asset_id: Id::new(),
            flavor: AgentFlavor::ClaudeCode,
            version: None,
            host: "host1".into(),
            os: None,
            os_user: None,
            owner: None,
            department: None,
            onboarding_mode: OnboardingMode::Sidecar,
            lifecycle: LifecycleState::Production,
            data_class: DataClass::Internal,
            mcp_servers: vec![],
            model_endpoints: vec![],
            config_hash: None,
            collector_id: None,
            last_heartbeat_at: Some(now),
            heartbeat_interval_secs: 60,
            discovery_source: DiscoverySource::AgentReport,
            created_at: now,
            updated_at: now,
        };
        assert!(a.is_online(now));
        a.last_heartbeat_at = None;
        assert!(!a.is_online(now));
        a.last_heartbeat_at = Some(now.offset_secs(-600));
        assert!(!a.is_online(now));
    }

    #[test]
    fn onboarding_mode_str() {
        assert_eq!(OnboardingMode::SdkInjection.as_str(), "sdk-injection");
        assert_eq!(OnboardingMode::ObserveOnly.as_str(), "observe-only");
    }

    #[test]
    fn agent_report_serde_roundtrip() {
        let report = AgentReport {
            collector_id: "c1".into(),
            collected_at: Timestamp::now(),
            hostname: "host1".into(),
            os: "windows".into(),
            os_user: Some("alice".into()),
            agents: vec![DetectedAgent {
                flavor: AgentFlavor::ClaudeCode,
                version: Some("1.2.3".into()),
                binary_path: None,
                config_dir: None,
                config_hash: None,
            }],
            mcp_configs: vec![],
            credential_hits: vec![],
            scan_scope: vec!["%USERPROFILE%\\.claude.json".into()],
            agent_version: "0.1.0".into(),
        };
        let json = serde_json::to_string(&report);
        assert!(json.is_ok());
        let back: Result<AgentReport, _> = serde_json::from_str(json.as_deref().unwrap_or("{}"));
        assert!(back.is_ok());
    }
}
