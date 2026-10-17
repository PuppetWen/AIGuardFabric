import type {
  AdapterHealth,
  AttackCategory,
  CampaignStatus,
  FindingStatus,
  InterceptPoint,
  IsoTimestamp,
  PolicyAction,
  PolicyLifecycle,
  QuotaScope,
  RiskDomain,
  Severity,
} from './common';

/* ------------------------------------------------------------------ */
/* Findings & rules                                                    */
/* ------------------------------------------------------------------ */

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  domain: RiskDomain;
  status: FindingStatus;
  target: string;
  assetId: string;
  assetName: string;
  canReadAsset?: boolean;
  detectedAt: IsoTimestamp;
  updatedAt: IsoTimestamp;
  ruleId: string;
  ruleName: string;
  summary: string;
  description: string;
  /** 证据链。 */
  evidence: EvidenceItem[];
  /** 三件套：基线 / 差分 / marker 回显。 */
  triple: FindingTriple;
  /** 调用链 entry → sink。 */
  callChain: string[];
  correlationAnalysis?: { rule: string; details: string };
  remediation: string;
  cvss: string;
  /** LLM 研判。 */
  llmVerdict: LlmVerdict | null;
  assignee: string | null;
  cwe?: string;
}

export interface EvidenceItem {
  id: string;
  kind: 'request' | 'response' | 'log' | 'screenshot' | 'artifact' | 'hash' | 'event' | 'rule' | 'payload';
  contentHash?: string;
  artifactRef?: string;
  label: string;
  content: string;
  capturedAt: IsoTimestamp;
}

export interface FindingTriple {
  baseline: string;
  diff: string;
  markerEcho: string;
}

export interface LlmVerdict {
  model: string;
  confidence: number;
  verdict: 'true-positive' | 'false-positive' | 'inconclusive';
  reasoning: string;
  reviewedAt: IsoTimestamp;
}

export interface Rule {
  /** File-backed rules are exposed read-only by the current server. */
  readOnly?: boolean;
  id: string;
  name: string;
  domain: RiskDomain;
  severity: Severity;
  enabled: boolean;
  /** 灰度比例 0-100. */
  rolloutPercent: number;
  version: string;
  lifecycle: 'draft' | 'gray' | 'ga' | 'deprecated';
  hitCount24h: number;
  falsePositiveRate: number;
  author: string;
  updatedAt: IsoTimestamp;
  description: string;
}

export interface RuleSample {
  id: string;
  ruleId: string;
  label: 'positive' | 'negative';
  payload: string;
  matched: boolean;
  latencyMs: number;
  note: string;
}

export interface RuleTestResult {
  ruleId: string;
  ranAt: IsoTimestamp;
  truePositive: number;
  falseNegative: number;
  trueNegative: number;
  falsePositive: number;
  samples: RuleSample[];
}

/* ------------------------------------------------------------------ */
/* Red team                                                            */
/* ------------------------------------------------------------------ */

export interface Campaign {
  id: string;
  name: string;
  status: CampaignStatus;
  categories: AttackCategory[];
  targets: string[];
  totalCases: number;
  succeeded: number;
  blocked: number | null;
  bypassed: number | null;
  successRate: number | null;
  startedAt: IsoTimestamp;
  finishedAt: IsoTimestamp | null;
  operator: string;
  ciGateEnabled: boolean;
  severityThreshold: Severity;
  state?: string;
  executionMode?: string | null;
  executedCases?: number;
  evaluatedCases?: number | null;
  inconclusiveCases?: number | null;
  failedCases?: number | null;
  targetName?: string;
  targetProfileId?: string | null;
  targetProfileVersion?: number | null;
  guardStrength?: number | null;
  scheduled?: boolean;
  ciPassed?: boolean | null;
  error?: string | null;
  retestOf?: string | null;
  comparison?: { baseline: string; comparable: boolean; simulated?: boolean; resolved: string[]; persistent: string[]; regressed: string[]; unassessed?: string[] } | null;
}

export interface CampaignResult {
  id: string;
  campaignId: string;
  caseId: string;
  category: AttackCategory;
  target: string;
  severity: Severity;
  outcome: 'succeeded' | 'blocked' | 'bypassed' | 'inconclusive' | 'execution-error';
  evaluation?: string;
  evaluationNote?: string | null;
  bypassPath: string[];
  payload: string;
  modelResponse: string;
  evidenceRef: string;
  findingId?: string | null;
  mocked?: boolean;
  transcript?: unknown[];
  matchedSignals?: string[];
  ranAt: IsoTimestamp;
}

export interface CampaignReport {
  campaignId: string;
  title: string;
  summary: string;
  markdown: string | null;
  generatedAt: IsoTimestamp;
  findings: number;
}

/* ------------------------------------------------------------------ */
/* Policies & runtime                                                  */
/* ------------------------------------------------------------------ */

export interface Policy {
  /** Actual server revision; absent in legacy/offline data, never inferred. */
  version?: number;
  /** Original server action for inspection when this client cannot interpret it. */
  rawAction?: string;
  /** Original server policy fields retained when editing structured policies. */
  language?: 'rego' | 'cel' | 'structured' | 'structured';
  source?: string;
  structured?: Record<string, string | boolean | number | string[]>;
  scopeAgentIds?: string[];
  scopeDepartments?: string[];
  quotaId?: string;
  degradeEndpointId?: string;
  id: string;
  name: string;
  description: string;
  action: PolicyAction;
  priority: number;
  lifecycle: PolicyLifecycle;
  interceptPoints: InterceptPoint[];
  expression: string;
  /** CEL / Rego source kept in sync with the form model. */
  code: string;
  codeLanguage: 'rego' | 'cel' | 'structured';
  enabled: boolean;
  dryRun: boolean;
  hitCount24h: number;
  blockedCount24h: number;
  signature: PolicySignature;
  updatedAt: IsoTimestamp;
  author: string;
}

export interface PolicySignature {
  status: 'signed' | 'unsigned' | 'invalid';
  signer: string;
  keyId: string;
  digest: string;
  signedAt: IsoTimestamp | null;
}

export interface InterceptPointStatus {
  point: InterceptPoint;
  enabled: boolean;
  mode: 'enforce' | 'monitor' | 'bypass';
  health: AdapterHealth;
  throughputPerMin: number;
  blocked24h: number;
  p95LatencyMs: number;
  version: string;
  lastError: string | null;
}

export interface InterceptEvent {
  id: string;
  ts: IsoTimestamp;
  point: InterceptPoint;
  agentName: string;
  mcpName: string | null;
  toolName: string | null;
  action: PolicyAction;
  policyName: string;
  reason: string;
  payloadDigest: string;
  latencyMs: number;
  severity: Severity;
}

export interface QuotaUsage {
  scope: QuotaScope;
  scopeId: string;
  scopeName: string;
  unit: 'tokens' | 'calls' | 'sessions';
  used: number;
  limit: number;
  windowStart: IsoTimestamp;
  windowEnd: IsoTimestamp;
  throttled: boolean;
}

export interface BlacklistEntry {
  id: string;
  version: number;
  kind: 'command' | 'domain';
  pattern: string;
  action: PolicyAction;
  scope: QuotaScope;
  enabled: boolean;
  hits24h: number;
  note: string;
  updatedAt: IsoTimestamp;
}
