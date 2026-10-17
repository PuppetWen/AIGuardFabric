//! 由 `enums.rs` 拆分：`AssetKind`/`DataClass`/`DiscoverySource`/`LifecycleState`/`PolicyAction`/`Protocol`/`RiskDomain`/`Severity` 的实现（纯搬移，逻辑不变）。
use super::*;

impl Severity {
    /// 文本形式（落库用）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// 解析文本。
    ///
    /// # Errors
    /// 未知等级返回错误描述。
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(format!("未知严重等级: {other}")),
        }
    }

    /// 数值权重（用于风险评分与排序）。
    #[must_use]
    pub const fn weight(&self) -> u8 {
        match self {
            Self::Info => 1,
            Self::Low => 2,
            Self::Medium => 4,
            Self::High => 8,
            Self::Critical => 16,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl RiskDomain {
    /// 文本形式（与 `rules/<domain>/` 目录名一致）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PromptAttack => "prompt-attack",
            Self::CredentialLeak => "credential-leak",
            Self::RagPoison => "rag-poison",
            Self::ToolAbuse => "tool-abuse",
            Self::ModelData => "model-data",
        }
    }

    /// 全部五个域。
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [Self::PromptAttack, Self::CredentialLeak, Self::RagPoison, Self::ToolAbuse, Self::ModelData]
    }

    /// 解析文本。
    ///
    /// # Errors
    /// 未知域返回错误描述。
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().replace('_', "-").as_str() {
            "prompt-attack" | "promptattack" => Ok(Self::PromptAttack),
            "credential-leak" | "credentialleak" | "credential" => Ok(Self::CredentialLeak),
            "rag-poison" | "ragpoison" | "rag" => Ok(Self::RagPoison),
            "tool-abuse" | "toolabuse" | "tool" => Ok(Self::ToolAbuse),
            "model-data" | "modeldata" | "model" => Ok(Self::ModelData),
            other => Err(format!("未知安全域: {other}")),
        }
    }

    /// 中文显示名（控制台/报表直接使用；i18n 覆盖在 `apps/web`）。
    #[must_use]
    pub const fn display_zh(&self) -> &'static str {
        match self {
            Self::PromptAttack => "提示词攻击",
            Self::CredentialLeak => "凭证泄露",
            Self::RagPoison => "RAG 投毒",
            Self::ToolAbuse => "工具与权限滥用",
            Self::ModelData => "模型与数据安全",
        }
    }
}

impl std::fmt::Display for RiskDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AssetKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::McpServer => "mcp-server",
            Self::McpClient => "mcp-client",
            Self::Skill => "skill",
            Self::PromptTemplate => "prompt-template",
            Self::RagKb => "rag-kb",
            Self::VectorStore => "vector-store",
            Self::ModelEndpoint => "model-endpoint",
            Self::Credential => "credential",
            Self::ComputeNode => "compute-node",
            Self::IdePlugin => "ide-plugin",
            Self::Collector => "collector",
            Self::DataSource => "data-source",
            Self::Other => "other",
        }
    }

    /// 全部类型。
    #[must_use]
    pub const fn all() -> [Self; 14] {
        [
            Self::Agent,
            Self::McpServer,
            Self::McpClient,
            Self::Skill,
            Self::PromptTemplate,
            Self::RagKb,
            Self::VectorStore,
            Self::ModelEndpoint,
            Self::Credential,
            Self::ComputeNode,
            Self::IdePlugin,
            Self::Collector,
            Self::DataSource,
            Self::Other,
        ]
    }

    /// 解析文本。
    ///
    /// # Errors
    /// 未知类型返回错误描述。
    pub fn parse(value: &str) -> Result<Self, String> {
        let v = value.to_ascii_lowercase().replace('_', "-");
        Self::all().into_iter().find(|k| k.as_str() == v).ok_or_else(|| format!("未知资产类型: {value}"))
    }
}

impl std::fmt::Display for AssetKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl DiscoverySource {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AgentReport => "agent-report",
            Self::NetworkScan => "network-scan",
            Self::CloudApi => "cloud-api",
            Self::PassiveTraffic => "passive-traffic",
            Self::Manual => "manual",
            Self::GitScan => "git-scan",
            Self::Collector => "collector",
            Self::Sidecar => "sidecar",
            Self::Import => "import",
        }
    }
}

impl Protocol {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::McpStdio => "mcp-stdio",
            Self::McpSse => "mcp-sse",
            Self::McpHttp => "mcp-http",
            Self::OpenAiCompat => "openai-compat",
            Self::Anthropic => "anthropic",
            Self::Gemini => "gemini",
            Self::A2a => "a2a",
            Self::Http => "http",
            Self::Grpc => "grpc",
            Self::WebSocket => "websocket",
            Self::Syslog => "syslog",
            Self::Kafka => "kafka",
            Self::Nats => "nats",
            Self::Mqtt => "mqtt",
            Self::Other => "other",
        }
    }
}

impl LifecycleState {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::UnderReview => "under-review",
            Self::Trial => "trial",
            Self::Production => "production",
            Self::Changing => "changing",
            Self::Archived => "archived",
            Self::Rejected => "rejected",
        }
    }

    /// 合法状态流转（用于 API 层校验）。
    #[must_use]
    pub const fn allowed_next(&self) -> &'static [Self] {
        match self {
            Self::Requested => &[Self::UnderReview, Self::Rejected],
            Self::UnderReview => &[Self::Trial, Self::Rejected],
            Self::Trial => &[Self::Production, Self::Rejected, Self::Archived],
            Self::Production => &[Self::Changing, Self::Archived],
            Self::Changing => &[Self::Production, Self::Archived],
            Self::Archived | Self::Rejected => &[],
        }
    }

    /// 是否允许流转到目标状态。
    #[must_use]
    pub fn can_transition_to(&self, next: Self) -> bool {
        self.allowed_next().contains(&next)
    }
}

impl DataClass {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Confidential => "confidential",
            Self::Restricted => "restricted",
        }
    }

    /// 是否要求数据不出域（禁止送外部大模型）。
    #[must_use]
    pub const fn requires_local_inference(&self) -> bool {
        matches!(self, Self::Restricted)
    }
}

impl PolicyAction {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Audit => "audit",
            Self::Quota => "quota",
            Self::Redact => "redact",
            Self::Throttle => "throttle",
            Self::Degrade => "degrade",
            Self::CircuitBreak => "circuit-break",
            Self::Isolate => "isolate",
            Self::Approval => "approval",
        }
    }

    /// 解析文本。
    ///
    /// # Errors
    /// 未知动作返回错误描述。
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().replace('_', "-").as_str() {
            "allow" => Ok(Self::Allow),
            "deny" | "block" => Ok(Self::Deny),
            "audit" => Ok(Self::Audit),
            "quota" => Ok(Self::Quota),
            "redact" | "mask" => Ok(Self::Redact),
            "throttle" | "rate-limit" => Ok(Self::Throttle),
            "degrade" | "fallback" => Ok(Self::Degrade),
            "circuit-break" | "breaker" => Ok(Self::CircuitBreak),
            "isolate" | "quarantine" => Ok(Self::Isolate),
            "approval" | "manual-approval" => Ok(Self::Approval),
            other => Err(format!("未知策略动作: {other}")),
        }
    }

    /// 是否改变了原请求内容（用于审计判定）。
    #[must_use]
    pub const fn mutates_payload(&self) -> bool {
        matches!(self, Self::Redact)
    }
}
