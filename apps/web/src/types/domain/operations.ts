import type { Asset } from './assets';
import type {
  AdapterCategory,
  AdapterHealth,
  AlertStatus,
  AssetKind,
  CaseState,
  ChainVerdict,
  IngestProtocol,
  IsoTimestamp,
  NotificationChannel,
  ParserEngine,
  ReportFormat,
  ReportSchedule,
  RiskDomain,
  SeriesPoint,
  Severity,
} from './common';
import type { UserRole } from './identity';

/* ------------------------------------------------------------------ */
/* Ingest                                                              */
/* ------------------------------------------------------------------ */

export interface LogSource {
  totalEvents?: number;
  matched?: number;
  lastError?: string;
  pollIntervalSecs?: number;
  headersConfigured?: boolean;
  id: string;
  name: string;
  protocol: IngestProtocol;
  nativeReceiver?: string;
  allowedCidrs?: string[];
  requireMtls?: boolean;
  mode: 'push' | 'pull' | 'poll' | 'subscribe' | 'tail';
  endpoint: string;
  parserId: string;
  health: AdapterHealth;
  eventsPerSec: number;
  lastEventAt: IsoTimestamp;
  droppedEvents24h: number;
  enabled: boolean;
  tls: boolean;
}

export interface Parser {
  id: string;
  name: string;
  engine: ParserEngine;
  successRate: number;
  sampleCount: number;
  sourceId: string;
  version: string;
  updatedAt: IsoTimestamp;
  sampleRaw: string;
  sampleParsed: Record<string, string | number>;
}

/* ------------------------------------------------------------------ */
/* Alerts & cases                                                      */
/* ------------------------------------------------------------------ */

export interface Alert {
  id: string;
  title: string;
  severity: Severity;
  domain: RiskDomain;
  status: AlertStatus;
  source: string;
  assetId: string;
  assetName: string;
  findingId: string | null;
  /** 聚合计数：同一根因折叠的告警条数。 */
  aggregateCount: number;
  firstSeenAt: IsoTimestamp;
  lastSeenAt: IsoTimestamp;
  slaDueAt: IsoTimestamp;
  slaBreached: boolean;
  assignee: string | null;
  escalationTier: 0 | 1 | 2 | 3;
  description: string;
}

export interface EscalationRoute {
  id: string;
  name: string;
  minSeverity: Severity;
  afterMinutes: number;
  tiers: EscalationTier[];
  enabled: boolean;
}

export interface EscalationTier {
  tier: 1 | 2 | 3;
  channels: NotificationChannel[];
  targets: string[];
  afterMinutes: number;
}

export interface Case {
  assetIds?: string[];
  findingIds?: string[];
  id: string;
  title: string;
  state: CaseState;
  severity: Severity;
  alertIds: string[];
  assetNames: string[];
  owner: string;
  createdAt: IsoTimestamp;
  updatedAt: IsoTimestamp;
  dueAt: IsoTimestamp;
  summary: string;
}

export interface CaseTimelineEntry {
  id: string;
  caseId: string;
  at: IsoTimestamp;
  actor: string;
  kind: 'state-change' | 'action' | 'note' | 'soar' | 'evidence';
  title: string;
  detail: string;
}

export interface SoarRun {
  dryRun?: boolean;
  id: string;
  caseId: string;
  playbook: string;
  status: 'queued' | 'running' | 'succeeded' | 'failed';
  startedAt: IsoTimestamp;
  finishedAt: IsoTimestamp | null;
  steps: SoarStep[];
}

export interface SoarStep {
  name: string;
  status: 'pending' | 'running' | 'done' | 'failed' | 'skipped';
  output: string;
  durationMs: number;
}

/* ------------------------------------------------------------------ */
/* Integrations                                                        */
/* ------------------------------------------------------------------ */

export interface Adapter {
  healthNote?: string;
  id: string;
  name: string;
  category: AdapterCategory;
  vendor: string;
  health: AdapterHealth;
  mock: boolean;
  configured: boolean;
  capabilities: string[];
  version: string;
  lastSyncAt: IsoTimestamp | null;
  latencyMs: number | null;
  config: Record<string, string>;
  degradedBehavior: string;
}

/* ------------------------------------------------------------------ */
/* Alibaba Cloud AgentTeams                                            */
/* ------------------------------------------------------------------ */

export type AliCloudService = 'cms' | 'apig' | 'mse' | 'privatelink' | 'schedulerx3';

export interface AgentTeamMember {
  id: string;
  name: string;
  /** Legacy field; cloud values are strings, not platform permission enums. */
  role: string | null;
  cloudRole?: string | null;
  model: string;
  status: 'active' | 'idle' | 'offline';
  invocations24h: number;
  metricsAvailable?: boolean;
  assetId?: string;
  cloudStatus?: string;
}

export interface AgentTeam {
  id: string;
  name: string;
  workspaceId: string;
  region: string;
  memberCount: number | null;
  /** Absent in older responses; the UI treats absence as unverified. */
  relationshipAvailable?: boolean;
  relationshipEvidence?: 'team-worker-names' | 'worker-groups' | 'unverified';
  members: AgentTeamMember[];
  dag: TeamDagNode[];
  dagAvailable?: boolean;
  dagEvidence?: 'not-provided';
  crossTeamCalls24h: number;
  riskScore: number;
  createdAt: IsoTimestamp | null;
  mocked?: boolean;
  syncedAt?: IsoTimestamp;
  metricsAvailable?: boolean;
  riskAvailable?: boolean;
  tasks?: { taskId: string | null; taskTitle: string | null; assignedTo: string | null; status: string | null; createdAt: string | null }[];
  humanMembers?: { name: string }[];
  humanMembersAvailable?: boolean;
  humanMemberCount?: number | null;
  adminName?: string | null;
  leaderName?: string | null;
}

export interface TeamDagNode {
  id: string;
  label: string;
  role: AgentTeamMember['role'];
  dependsOn: string[];
}

export interface CrossTeamCall {
  mocked?: boolean;
  id: string;
  callerTeam: string;
  calleeTeam: string;
  calleeAgent: string;
  count24h: number;
  authorized: boolean | null;
  sensitiveData: boolean | null;
}

export interface ServiceBinding {
  service: AliCloudService;
  displayName: string;
  bound: boolean;
  resourceId: string | null;
  region: string;
  health: AdapterHealth;
  note: string;
}

export interface SelfCheckItem {
  id: string;
  category: 'connectivity' | 'least-privilege' | 'quota';
  name: string;
  result: 'pass' | 'warn' | 'fail';
  detail: string;
  value: string;
  requirement: string;
  checkedAt: IsoTimestamp | null;
}

/* ------------------------------------------------------------------ */
/* Audit, reports, dashboard                                           */
/* ------------------------------------------------------------------ */

export interface AuditEntry {
  id: string;
  ts: IsoTimestamp;
  actor: string;
  actorRole: UserRole;
  action: string;
  sensitive: boolean;
  resourceKind: AssetKind | 'policy' | 'user' | 'tenant' | 'report';
  resourceId: string;
  resourceName: string;
  result: 'success' | 'failure' | 'denied';
  ip: string;
  userAgent: string;
  detail: string;
  hash: string;
  prevHash: string;
}

export interface ChainCheckIssue {
  entryId: string;
  ts: IsoTimestamp;
  expectedHash: string;
  actualHash: string;
  reason: string;
}

export interface ChainCheckResult {
  verdict: ChainVerdict;
  checkedEntries: number;
  from: IsoTimestamp;
  to: IsoTimestamp;
  firstSequence?: number | null;
  lastSequence?: number | null;
  issues: ChainCheckIssue[];
  checkedAt: IsoTimestamp;
}

export interface ReportJob {
  scheduleId?: string;
  id: string;
  name: string;
  type: 'executive' | 'compliance' | 'asset-inventory' | 'redteam' | 'incident';
  format: ReportFormat;
  schedule: ReportSchedule;
  windowDays: number;
  status: 'ready' | 'generating' | 'scheduled' | 'failed';
  sizeKb: number;
  createdAt: IsoTimestamp;
  createdBy: string;
  recipients: string[];
  preview: string;
}

export interface DashboardKpi {
  key: 'assets' | 'openAlerts' | 'criticalFindings' | 'redteamSuccessRate' | 'tokenSpend';
  label: string;
  value: number | null;
  unit: string;
  delta: number | null;
  sparkline: number[];
}

export interface DomainDistribution {
  domain: RiskDomain;
  assets: number;
  findings: number | null;
  critical: number | null;
}

export interface RecentAlert {
  id: string;
  title: string;
  severity: Severity;
  domain: RiskDomain;
  assetName: string;
  occurredAt: IsoTimestamp;
  status: AlertStatus;
}

export interface AdapterHealthBar {
  id: string;
  name: string;
  category: AdapterCategory;
  health: AdapterHealth;
  uptimePercent: number | null;
  mock: boolean;
}

export interface DashboardOverview {
  kpis: DashboardKpi[];
  riskTrend: SeriesPoint[];
  domainDistribution: DomainDistribution[];
  topRiskAssets: Asset[];
  recentAlerts: RecentAlert[];
  adapterHealth: AdapterHealthBar[];
  access?: Record<string, boolean>;
  generatedAt?: IsoTimestamp;
}

export interface TopologyQuery {
  tenantId?: string;
  includeShadow?: boolean;
  maxNodes?: number;
}
