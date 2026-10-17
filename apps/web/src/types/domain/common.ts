/* ------------------------------------------------------------------ */
/* Core enums & union types                                            */
/* ------------------------------------------------------------------ */

/** Finding / rule severity, ordered most severe first. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** AIGuardFabric is organised around five security domains (五大安全域). */
export type RiskDomain =
  | 'asset' //          资产域：AI 资产发现、纳管与暴露面
  | 'data' //           数据域：敏感数据、外传路径与出域管控
  | 'identity' //       身份域：凭据、令牌、越权与身份滥用
  | 'runtime' //        运行时域：提示注入、工具滥用与实时拦截
  | 'compliance'; //    合规域：策略符合性、审计与留痕

/** Asset taxonomy across agents, MCP servers, skills, models and data. */
export type AssetKind =
  | 'agent'
  | 'mcp'
  | 'skill'
  | 'model'
  | 'tool'
  | 'datasource'
  | 'credential'
  | 'endpoint';

/** Data classification (数据分级) used by governance and policy engines. */
export type DataClassification = 'public' | 'internal' | 'confidential' | 'restricted';

/** Asset lifecycle state (生命周期). */
export type LifecycleState = 'planned' | 'onboarding' | 'active' | 'deprecated' | 'retired';

/** Exposure surface (暴露面). */
export type ExposureSurface = 'public-internet' | 'partner' | 'intranet' | 'isolated' | 'unknown';

/** Where an asset was discovered — drives the "发现来源" column and dedup. */
export type DiscoverySource =
  | 'agent-scan' //        主动扫描
  | 'ingest-log' //        日志接入
  | 'gateway-mirror' //    AI 网关镜像
  | 'manual' //            人工登记
  | 'cloud-api'; //        云厂商 API 同步

/** Agent runtime flavour。 */
export type AgentFlavor =
  | 'langchain'
  | 'langgraph'
  | 'autogen'
  | 'crewai'
  | 'dify'
  | 'coze'
  | 'qwen-agent'
  | 'custom';

/** How an agent got under management (纳管模式). */
export type ManagementMode = 'sidecar' | 'sdk-inject' | 'gateway-register' | 'unmanaged';

/** MCP transport. */
export type McpTransport = 'stdio' | 'sse' | 'streamable-http' | 'websocket';

/** Capability profile of an MCP tool, used for risk scoring. */
export type ToolCapability =
  | 'read'
  | 'write'
  | 'execute'
  | 'network'
  | 'filesystem'
  | 'credential'
  | 'payment';

/** Skill authorization transitions. */
export type SkillStatus = 'pending' | 'approved' | 'rejected' | 'revoked';

/** Model endpoint vendor. */
export type ModelVendor =
  | 'openai'
  | 'anthropic'
  | 'azure-openai'
  | 'qwen'
  | 'deepseek'
  | 'zhipu'
  | 'moonshot'
  | 'baichuan'
  | 'ollama'
  | 'vllm'
  | 'custom';

/** Policy verbs understood by the enforcement plane. */
export type PolicyAction = 'allow' | 'deny' | 'alert' | 'mask' | 'redirect' | 'throttle' | 'quota'
  | 'quarantine' | 'approval' | 'circuit-break' | 'unknown';

/** Policy authoring / rollout state. */
export type PolicyLifecycle = 'draft' | 'dry-run' | 'enforced' | 'disabled';

/** Enforcement points (拦截点). */
export type InterceptPoint = 'mcp-proxy' | 'ai-gateway' | 'process-hook' | 'egress-proxy';

/** Quota scope (三级配额). */
export type QuotaScope = 'tenant' | 'agent' | 'session';

/** Adapter health (适配器健康度). */
export type AdapterHealth = 'healthy' | 'degraded' | 'unhealthy' | 'unknown';

/** Adapter categories in the integration hub. */
export type AdapterCategory =
  | 'llm-provider'
  | 'edr'
  | 'siem'
  | 'soar'
  | 'iam'
  | 'cloud'
  | 'dlp'
  | 'notify'
  | 'storage';

/** Ingest protocol (日志源协议, 16 supported). */
export type IngestProtocol =
  | 'syslog-udp'
  | 'syslog-tcp'
  | 'syslog-tls'
  | 'kafka'
  | 'http-webhook'
  | 'http-pull'
  | 'file-tail'
  | 'fluentd'
  | 'otlp-grpc'
  | 'otlp-http'
  | 'splunk-hec'
  | 'elastic-beats'
  | 'mqtt'
  | 'nats'
  | 'amqp'
  | 'syslog-cef'
  | 'cloudtrail-s3';

/** Parser engine behind an ingest parser. */
export type ParserEngine = 'regex-grok' | 'json-path' | 'kv' | 'cef' | 'lua' | 'llm-assisted'
  | 'grok' | 'regex' | 'jq' | 'syslog' | 'leef' | 'gelf' | 'csv' | 'cel' | 'plugin' | 'ai-inferred';

/** Finding workflow status. */
export type FindingStatus = 'pending' | 'code-reviewed' | 'verified' | 'false-positive' | 'fixed';

/** Alert lifecycle. */
export type AlertStatus = 'escalated' | 'open' | 'acknowledged' | 'in-progress' | 'resolved' | 'suppressed';

/** Case lifecycle, rendered as kanban columns. */
export type CaseState = 'new' | 'triaged' | 'containing' | 'recovered' | 'closed';

/** Remediation verbs offered by the case console. */
export type ContainmentAction = 'isolate' | 'revoke' | 'block' | 'quarantine' | 'notify';

/** Red-team campaign lifecycle. */
export type CampaignStatus = 'planned' | 'running' | 'succeeded' | 'failed' | 'aborted';

/** Red-team attack-case categories. */
export type AttackCategory =
  | 'direct-injection' | 'indirect-injection' | 'rag-poisoning' | 'multi-turn-social'
  | 'credential-theft' | 'privilege-escalation' | 'lateral-movement' | 'resource-exhaustion'
  | 'prompt-injection'
  | 'jailbreak'
  | 'tool-abuse'
  | 'data-exfiltration'
  | 'credential-leak'
  | 'mcp-shadow'
  | 'model-dos'
  | 'supply-chain';

/** Report artifact formats. */
export type ReportFormat = 'pdf' | 'docx' | 'xlsx' | 'markdown' | 'html' | 'csv' | 'json';

/** Report schedules. */
export type ReportSchedule = 'manual' | 'daily' | 'weekly' | 'monthly';

/** Notification channels. */
export type NotificationChannel = 'email' | 'webhook' | 'dingtalk' | 'feishu' | 'wecom' | 'slack' | 'sms';

/** Audit hash-chain verification verdict. */
export type ChainVerdict = 'valid' | 'broken' | 'partial';

/* ------------------------------------------------------------------ */
/* Shared shapes                                                       */
/* ------------------------------------------------------------------ */

/** ISO-8601 timestamp string, always UTC with `Z`. */
export type IsoTimestamp = string;

/** Every list endpoint returns this envelope. */
export interface Paged<T> {
  /** Supplied by the server for lists with editable rows. Missing means read-only. */
  canWrite?: boolean;
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

/** Common list query used by the tables. */
export interface ListQuery {
  page?: number;
  pageSize?: number;
  keyword?: string;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

/** Named reference to another entity (用于画像/依赖展示). */
export interface EntityRef {
  id: string;
  name: string;
  kind: AssetKind;
}

/** Time series point for trend / metering charts. */
export interface SeriesPoint {
  ts: IsoTimestamp;
  value: number;
}

/** A labelled metric used by KPI tiles and gauges. */
export interface Metric {
  key: string;
  value: number;
  unit?: string;
  delta?: number;
}

/** Hash-chain audit proof attached to mutable governance actions. */
export interface AuditProof {
  hash: string;
  prevHash: string;
  signer: string;
  verified: boolean;
}
