//! 由 `enums.rs` 拆分：`AlertState`/`AliCloudService`/`CaseState`/`EvidenceLevel`/`HealthState`/`IngestProtocol`/`LlmProvider`/`QuotaDimension`/`QuotaScope`/`RuleKind`/`Verdict` 的实现（纯搬移，逻辑不变）。
use super::*;

impl QuotaDimension {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tokens => "tokens",
            Self::Requests => "requests",
            Self::Concurrency => "concurrency",
            Self::Cost => "cost",
        }
    }

    /// 全部维度。
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [Self::Tokens, Self::Requests, Self::Concurrency, Self::Cost]
    }
}

impl QuotaScope {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Agent => "agent",
            Self::Session => "session",
        }
    }
}

impl AlertState {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Suppressed => "suppressed",
            Self::Escalated => "escalated",
            Self::Closed => "closed",
        }
    }
}

impl CaseState {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Investigating => "investigating",
            Self::Containing => "containing",
            Self::Resolved => "resolved",
            Self::Closed => "closed",
        }
    }
}

impl Verdict {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Malicious => "malicious",
            Self::Suspicious => "suspicious",
            Self::Benign => "benign",
            Self::Unknown => "unknown",
        }
    }
}

impl EvidenceLevel {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Partial => "partial",
            Self::Confirmed => "confirmed",
            Self::Impact => "impact",
        }
    }
}

impl HealthState {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
            Self::Unconfigured => "unconfigured",
            Self::CircuitOpen => "circuit-open",
        }
    }

    /// 是否能承载真实流量。
    #[must_use]
    pub const fn is_serving(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }
}

impl LlmProvider {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::Gemini => "gemini",
            Self::AzureOpenAi => "azure-openai",
            Self::Bedrock => "bedrock",
            Self::DashScope => "dashscope",
            Self::Ark => "ark",
            Self::Hunyuan => "hunyuan",
            Self::Qianfan => "qianfan",
            Self::Moonshot => "moonshot",
            Self::DeepSeek => "deepseek",
            Self::Zhipu => "zhipu",
            Self::MiniMax => "minimax",
            Self::Ollama => "ollama",
            Self::Vllm => "vllm",
            Self::CustomOpenAiCompat => "custom-openai-compat",
        }
    }

    /// 是否支持 OpenAI 兼容协议（可用同一适配器实现）。
    #[must_use]
    pub const fn is_openai_compatible(&self) -> bool {
        matches!(
            self,
            Self::OpenAi
                | Self::AzureOpenAi
                | Self::DashScope
                | Self::Ark
                | Self::Hunyuan
                | Self::Qianfan
                | Self::Moonshot
                | Self::DeepSeek
                | Self::Zhipu
                | Self::MiniMax
                | Self::Ollama
                | Self::Vllm
                | Self::CustomOpenAiCompat
        )
    }

    /// 全部厂商。
    #[must_use]
    pub const fn all() -> [Self; 17] {
        [
            Self::Mock,
            Self::OpenAi,
            Self::Anthropic,
            Self::Gemini,
            Self::AzureOpenAi,
            Self::Bedrock,
            Self::DashScope,
            Self::Ark,
            Self::Hunyuan,
            Self::Qianfan,
            Self::Moonshot,
            Self::DeepSeek,
            Self::Zhipu,
            Self::MiniMax,
            Self::Ollama,
            Self::Vllm,
            Self::CustomOpenAiCompat,
        ]
    }

    /// 解析文本。
    ///
    /// # Errors
    /// 未知厂商返回错误描述。
    pub fn parse(value: &str) -> Result<Self, String> {
        let v = value.to_ascii_lowercase().replace('_', "-");
        Self::all().into_iter().find(|p| p.as_str() == v).ok_or_else(|| format!("未知大模型厂商: {value}"))
    }
}

impl AliCloudService {
    /// 文本形式（也是适配器注册名）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Cms => "alicloud-cms",
            Self::Apig => "alicloud-apig",
            Self::Mse => "alicloud-mse",
            Self::Privatelink => "alicloud-privatelink",
            Self::SchedulerX3 => "alicloud-schedulerx3",
            Self::AgentTeams => "alicloud-agentteams",
        }
    }

    /// 全部服务。
    #[must_use]
    pub const fn all() -> [Self; 6] {
        [Self::Cms, Self::Apig, Self::Mse, Self::Privatelink, Self::SchedulerX3, Self::AgentTeams]
    }
}

impl IngestProtocol {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Mcp => "mcp",
            Self::Syslog => "syslog",
            Self::Webhook => "webhook",
            Self::Kafka => "kafka",
            Self::Pulsar => "pulsar",
            Self::Nats => "nats",
            Self::Mqtt => "mqtt",
            Self::HttpPull => "http-pull",
            Self::HttpPush => "http-push",
            Self::SnmpTrap => "snmp-trap",
            Self::ObjectStorage => "object-storage",
            Self::Jdbc => "jdbc",
            Self::Beats => "beats",
            Self::Otlp => "otlp",
            Self::SqlPoll => "sql-poll",
            Self::File => "file",
        }
    }

    /// 全部协议。
    #[must_use]
    pub const fn all() -> [Self; 16] {
        [
            Self::Mcp,
            Self::Syslog,
            Self::Webhook,
            Self::Kafka,
            Self::Pulsar,
            Self::Nats,
            Self::Mqtt,
            Self::HttpPull,
            Self::HttpPush,
            Self::SnmpTrap,
            Self::ObjectStorage,
            Self::Jdbc,
            Self::Beats,
            Self::Otlp,
            Self::SqlPoll,
            Self::File,
        ]
    }
}

impl RuleKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Regex => "regex",
            Self::Keyword => "keyword",
            Self::Semantic => "semantic",
            Self::Ast => "ast",
            Self::Yara => "yara",
            Self::Entropy => "entropy",
            Self::Composite => "composite",
        }
    }
}
