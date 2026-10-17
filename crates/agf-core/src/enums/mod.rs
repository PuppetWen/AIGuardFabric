//! 跨域枚举定义。
//!
//! 这些枚举是平台"共同语言"：API、数据库（以文本存储）、前端 i18n key、规则引擎谓词
//! 全部引用同一份定义。**变更时需同步 `deploy/sql/migrations/` 的 CHECK 约束与前端词表。**

use serde::{Deserialize, Serialize};

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 严重等级（对齐 CVSS 语义与阿里云智能体安全中心风险分级）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// 信息。
    Info,
    /// 低。
    Low,
    /// 中。
    Medium,
    /// 高。
    High,
    /// 严重。
    Critical,
}

/// 五大安全域（§4.2，与阿里云智能体安全中心对齐）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskDomain {
    /// 提示词攻击：注入/越狱/角色劫持/系统提示词泄露/多轮诱导/编码绕过。
    PromptAttack,
    /// 凭证泄露：API Key / AK-SK / Token / 私钥 / JWT / 硬编码密钥。
    CredentialLeak,
    /// RAG 投毒：知识库注入/检索越权/上下文污染/向量库投毒。
    RagPoison,
    /// 工具与权限滥用：越权调用/SSRF/命令注入/路径穿越/过度 Scope。
    ToolAbuse,
    /// 模型与数据安全：数据外传/敏感回显/模型越权/供应链后门/横向移动。
    ModelData,
}

/// 资产类型（§4.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssetKind {
    /// AI Agent 实例。
    Agent,
    /// MCP Server。
    McpServer,
    /// MCP Client（内嵌于 Agent/IDE）。
    McpClient,
    /// Skill / Tool / Function Call。
    Skill,
    /// Prompt 模板。
    PromptTemplate,
    /// RAG 知识库。
    RagKb,
    /// 向量库。
    VectorStore,
    /// 模型端点。
    ModelEndpoint,
    /// API Key / 凭据条目。
    Credential,
    /// 算力节点。
    ComputeNode,
    /// IDE 插件。
    IdePlugin,
    /// 南向采集器实例。
    Collector,
    /// 数据源（数据库/对象存储/MCP 背后的服务）。
    DataSource,
    /// 其他未分类资产。
    Other,
}

/// 资产发现来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoverySource {
    /// 终端 Agent 上报。
    AgentReport,
    /// 网段扫描（含 MCP 握手探测）。
    NetworkScan,
    /// K8s / 云 API 拉取。
    CloudApi,
    /// 流量被动识别（LLM 协议指纹）。
    PassiveTraffic,
    /// 手工登记。
    Manual,
    /// Git 仓库扫描（MCP 配置 + 硬编码密钥）。
    GitScan,
    /// 南向采集器上报。
    Collector,
    /// 免改造纳管（侧车/SDK 注入/网关注册）。
    Sidecar,
    /// 导入文件（CSV/JSON）。
    Import,
}

/// 通信协议（资产画像 + 网关接入）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    /// MCP over stdio。
    McpStdio,
    /// MCP over SSE。
    McpSse,
    /// MCP over Streamable HTTP。
    McpHttp,
    /// OpenAI 兼容 HTTP。
    #[serde(rename = "openai-compat", alias = "open-ai-compat")]
    OpenAiCompat,
    /// Anthropic Messages API。
    Anthropic,
    /// Google Gemini。
    Gemini,
    /// A2A（Agent to Agent）。
    A2a,
    /// 通用 HTTP/REST。
    Http,
    /// gRPC。
    Grpc,
    /// WebSocket。
    #[serde(rename = "websocket", alias = "web-socket")]
    WebSocket,
    /// Syslog。
    Syslog,
    /// Kafka。
    Kafka,
    /// NATS。
    Nats,
    /// MQTT。
    Mqtt,
    /// 其他。
    Other,
}

/// 生命周期状态（§4.1 上线申请 → 评审 → 试运行 → 生产 → 变更 → 下线归档）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleState {
    /// 申请中。
    Requested,
    /// 评审中。
    UnderReview,
    /// 试运行。
    Trial,
    /// 生产。
    Production,
    /// 变更中。
    Changing,
    /// 已下线归档。
    Archived,
    /// 已拒绝。
    Rejected,
}

/// 数据分级（数据不出域 / 脱敏策略依据）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataClass {
    /// 公开。
    Public,
    /// 内部。
    Internal,
    /// 秘密。
    Confidential,
    /// 绝密。
    Restricted,
}

/// 策略动作（§4.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    /// 放行。
    Allow,
    /// 阻断。
    Deny,
    /// 放行但记录。
    Audit,
    /// 计入配额并可能限流。
    Quota,
    /// 双向脱敏后放行。
    Redact,
    /// 限速。
    Throttle,
    /// 降级到本地模型/缓存。
    Degrade,
    /// 熔断。
    CircuitBreak,
    /// 隔离（挂起 Agent）。
    Isolate,
    /// 人工审批。
    Approval,
}

/// 配额维度（§4.3 三级配额）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuotaDimension {
    /// Token 用量。
    Tokens,
    /// 调用次数。
    Requests,
    /// 并发数。
    Concurrency,
    /// 金额（分）。
    Cost,
}

/// 配额作用域（三级）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuotaScope {
    /// 租户级。
    Tenant,
    /// Agent 级。
    Agent,
    /// 会话级。
    Session,
}

/// 告警状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AlertState {
    /// 新建。
    Open,
    /// 已确认。
    Acknowledged,
    /// 已抑制（聚合去重）。
    Suppressed,
    /// 已升级。
    Escalated,
    /// 已关闭。
    Closed,
}

/// 案件状态（§4.6 告警→案件→证据→处置→复盘）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseState {
    /// 待受理。
    New,
    /// 调查中。
    Investigating,
    /// 处置中。
    Containing,
    /// 已解决。
    Resolved,
    /// 已复盘归档。
    Closed,
}

/// 判定结论（规则引擎 + LLM 二次研判共用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// 恶意/命中。
    Malicious,
    /// 疑似。
    Suspicious,
    /// 良性（负样本命中）。
    Benign,
    /// 不确定。
    Unknown,
}

/// 证据等级（四档，与 finding 字段语义一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceLevel {
    /// 未知。
    Unknown,
    /// 部分证据（工具输出/间接推断）。
    Partial,
    /// 可复现（对照三件套齐 / 多源交叉一致）。
    Confirmed,
    /// 影响已证（数据实际获取 / 业务动作达成）。
    Impact,
}

/// 适配器健康状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthState {
    /// 健康。
    Healthy,
    /// 降级（部分能力不可用）。
    Degraded,
    /// 不可用。
    Unhealthy,
    /// 未配置（Mock 模式下的常态）。
    Unconfigured,
    /// 熔断中。
    CircuitOpen,
}

/// 大模型厂商（§4.4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LlmProvider {
    /// 离线 Mock（无 Key 时的默认值）。
    Mock,
    /// OpenAI。
    OpenAi,
    /// Anthropic。
    Anthropic,
    /// Google Gemini。
    Gemini,
    /// Azure OpenAI。
    AzureOpenAi,
    /// AWS Bedrock。
    Bedrock,
    /// 阿里云百炼/通义。
    DashScope,
    /// 火山方舟/豆包。
    Ark,
    /// 腾讯混元。
    Hunyuan,
    /// 百度文心。
    Qianfan,
    /// Kimi / Moonshot。
    Moonshot,
    /// DeepSeek。
    DeepSeek,
    /// 智谱 GLM。
    Zhipu,
    /// MiniMax。
    MiniMax,
    /// Ollama 本地推理。
    Ollama,
    /// vLLM 本地推理。
    Vllm,
    /// 任意 OpenAI 兼容自定义端点。
    CustomOpenAiCompat,
}

/// 阿里云底座服务（§5.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AliCloudService {
    /// 云监控。
    Cms,
    /// AI 网关。
    Apig,
    /// 微服务引擎。
    Mse,
    /// 私网链接。
    Privatelink,
    /// 分布式任务调度。
    SchedulerX3,
    /// AgentTeams 多智能体治理平台。
    AgentTeams,
}

/// 日志/告警接入协议（§4.5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IngestProtocol {
    /// MCP。
    Mcp,
    /// Syslog（RFC3164/5424）。
    Syslog,
    /// Webhook。
    Webhook,
    /// Kafka。
    Kafka,
    /// Pulsar。
    Pulsar,
    /// NATS。
    Nats,
    /// MQTT。
    Mqtt,
    /// HTTP 拉取。
    HttpPull,
    /// HTTP 推送。
    HttpPush,
    /// SNMP Trap。
    SnmpTrap,
    /// 对象存储拉取。
    ObjectStorage,
    /// JDBC。
    Jdbc,
    /// Filebeat / Fluent Bit / Vector。
    Beats,
    /// OTLP。
    Otlp,
    /// SQL 轮询。
    SqlPoll,
    /// 文件系统采集。
    File,
}

/// 规则引擎类型（规则可组合多种检测手段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    /// 正则匹配。
    Regex,
    /// 关键字/字面量匹配。
    Keyword,
    /// 语义相似度（向量/模型判定）。
    Semantic,
    /// 抽象语法树结构匹配（如 shell 命令字面量节点）。
    Ast,
    /// YARA 规则。
    Yara,
    /// 熵/统计特征。
    Entropy,
    /// 组合规则（多条件布尔组合）。
    Composite,
}

/// 运行时拦截点（§4.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InterceptPoint {
    /// MCP 代理（南北向，stdio/SSE/HTTP）。
    McpProxy,
    /// AI 网关南北向。
    AiGateway,
    /// eBPF/进程 Hook 东西向。
    ProcessHook,
    /// 南向采集网关。
    Collector,
}

mod impl_intercept_point;
mod impl_quota_dimension;
mod impl_severity;
#[cfg(test)]
mod tests;
