import type {
  AdapterHealth,
  AgentFlavor,
  AssetKind,
  DataClassification,
  DiscoverySource,
  EntityRef,
  ExposureSurface,
  IsoTimestamp,
  LifecycleState,
  ManagementMode,
  McpTransport,
  ModelVendor,
  Severity,
  SkillStatus,
  ToolCapability,
} from './common';

/* ------------------------------------------------------------------ */
/* Assets                                                              */
/* ------------------------------------------------------------------ */

export interface Asset {
  id: string;
  tenantId: string;
  name: string;
  kind: AssetKind;
  owner: string;
  department: string;
  classification: DataClassification;
  lifecycle: LifecycleState;
  exposure: ExposureSurface;
  riskScore: number | null;
  openFindings: number | null;
  sources: DiscoverySource[];
  tags: string[];
  firstSeenAt: IsoTimestamp;
  lastSeenAt: IsoTimestamp;
  description: string;
  edrHostId?: string;
  scimUserId?: string;
}

export interface SkillPackageObservation {
  algorithm: string;
  status: string;
  sha256?: string;
  files?: number;
  bytes?: number;
}
export interface AssetProfile {
  packageObservation?: {
    current?: SkillPackageObservation;
    receivedAt?: string;
    lastVerified?: SkillPackageObservation;
    lastVerifiedAt?: string;
  };
  asset: Asset;
  contentObservation?: { sha256?: string; status?: string; receivedAt?: string };
  governance?: {
    canWrite: boolean;
    lifecycle: string;
    allowedNext: string[];
    updatedAt: string;
    owner?: string;
    department?: string;
    dataClass: DataClassification;
  };
  changes?: {
    id: string; changeKind: string; field?: string;
    oldValue?: unknown; newValue?: unknown; riskNote?: string; detectedAt: string;
  }[];
  /** 画像：运行时统计。 */
  runtime: {
    invocations24h: number;
    errorRate: number;
    avgLatencyMs: number;
    distinctCallers: number;
  } | null;
  /** 依赖：上下游资产。 */
  dependencies: {
    upstream: EntityRef[];
    downstream: EntityRef[];
    models: EntityRef[];
    datasources: EntityRef[];
  };
  /** 暴露面扣分项。 */
  exposurePenalties: ExposurePenalty[];
  sources: DiscoverySourceRecord[];
}

export interface ExposurePenalty {
  code: string;
  label: string;
  points: number;
  remediation: string;
}

export interface DiscoverySourceRecord {
  source: DiscoverySource;
  at: IsoTimestamp;
  detail: string;
}

export interface AssetFilter {
  kinds?: AssetKind[];
  departments?: string[];
  classifications?: DataClassification[];
  lifecycles?: LifecycleState[];
  exposures?: ExposureSurface[];
  keyword?: string;
}

/* ------------------------------------------------------------------ */
/* Agents / MCP / Skills / Models                                      */
/* ------------------------------------------------------------------ */

export interface Agent {
  id: string;
  name: string;
  flavor: AgentFlavor;
  version: string;
  host: string;
  ip: string;
  management: ManagementMode;
  online: boolean | null;
  lastHeartbeatAt: IsoTimestamp | null;
  heartbeatIntervalSec: number | null;
  department: string;
  owner: string;
  activeSessions: number | null;
  toolCount: number | null;
  riskScore: number | null;
}

/** 免改造纳管向导的三种模式。 */
export type OnboardingMode = 'sidecar' | 'sdk-inject' | 'gateway-register';

export interface OnboardingPlan {
  agentId: string;
  mode: OnboardingMode;
  endpoint: string;
  artifactUrl: string | null;
  artifactSha256: string | null;
  platform: string;
  envSnippet: string;
  steps: OnboardingStep[];
  estimatedDowntimeSec: number | null;
  rollout: 'manual';
}

export interface OnboardingStep {
  order: number;
  title: string;
  command: string;
  rollback: string;
}

export interface McpServer {
  id: string;
  name: string;
  transport: McpTransport | 'unknown';
  endpoint: string;
  toolCount: number | null;
  shadow: boolean;
  plaintextCredential: boolean;
  owner: string;
  department: string;
  online: boolean | null;
  registeredAt: IsoTimestamp;
  lastSeenAt: IsoTimestamp | null;
  riskScore: number | null;
}

export interface McpTool {
  id: string;
  serverId: string;
  name: string;
  description: string;
  capabilities: ToolCapability[];
  riskLevel: Severity;
  invocations24h: number | null;
  sensitiveParams: string[];
  datasources: string[];
}

export interface Skill {
  review?: {
    lifecycle: string; allowedNext: string[]; updatedAt: string;
    owner: string; department: string; dataClass: DataClassification;
  };
  id: string;
  name: string;
  version: string;
  publisher: string;
  status: SkillStatus;
  requestedBy: string;
  requestedAt: IsoTimestamp;
  decidedAt: IsoTimestamp | null;
  decidedBy: string | null;
  riskScore: number | null;
  capabilities: ToolCapability[];
  whitelist: SkillWhitelist;
  attachedAgents: number | null;
}

export interface SkillWhitelist {
  domains: string[];
  paths: string[];
}

export interface ModelEndpoint {
  id: string;
  vendor: ModelVendor;
  model: string;
  endpoint: string;
  local: boolean | null;
  mockMode: boolean | null;
  inputPricePerKTok: number | null;
  outputPricePerKTok: number | null;
  priority: number | null;
  fallback: boolean | null;
  latencyP95Ms: number | null;
  health: AdapterHealth;
}

export interface ModelRoutePolicy {
  id: string;
  version: number;
  name: string;
  primaryEndpointId: string;
  fallbackEndpointIds: string[];
  strategy: 'priority' | 'weighted' | 'cost-first' | 'latency-first';
  weights: Record<string, number>;
  budgetCnyPerDay: number;
  enabled: boolean;
}

export interface TokenUsageRecord {
  cacheHit: boolean;
  id: string;
  ts: IsoTimestamp;
  tenantId: string;
  agentId: string;
  agentName: string;
  endpointId: string;
  model: string;
  inputTokens: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
  cacheWrite1hTokens?: number;
  outputTokens: number;
  costCny: number;
  currency: 'CNY';
  mocked: boolean;
}

/** Token metering aggregated per model endpoint (成本计量图与明细表). */
export interface ModelUsageAggregate {
  endpointId: string;
  model: string;
  vendor: ModelVendor;
  inputTokens: number;
  outputTokens: number;
  costCny: number;
  currency: 'CNY';
  mocked: boolean;
  calls: number;
}

/* ------------------------------------------------------------------ */
/* Topology                                                            */
/* ------------------------------------------------------------------ */

export type TopologyNodeType = 'agent' | 'mcp' | 'tool' | 'datasource' | 'model';

export interface TopologyNode {
  id: string;
  label: string;
  type: TopologyNodeType;
  riskScore: number | null;
  shadow: boolean;
  classification?: DataClassification;
  detail: string;
}

export type TopologyEdgeKind = 'invokes' | 'exposes' | 'reads' | 'writes' | 'routes-to';

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  kind: TopologyEdgeKind;
  /** True when the edge carries data leaving the governance boundary. */
  egress: boolean;
  calls24h: number;
}

export interface TopologyGraph {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  /** Pre-computed 数据外传路径 for the "highlight egress" toggle. */
  egressPaths: string[][];
}
