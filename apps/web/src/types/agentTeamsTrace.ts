import type { AgentTeamsAuditEvent } from './agentTeamsAudit';

export interface TraceQuery {
  traceId: string;
  from: string;
  until: string;
  limit: number;
}
export interface TraceSelection { traceId: string; recordId: string; revision: number }
export interface TraceDraft { traceId: string; from: string; until: string; limit: number }
export interface TraceNode {
  id: string;
  eventId: string;
  spanId: string | null;
  parentSpanId: string | null;
  sourceId: string;
  bindingId: string;
  kind: AgentTeamsAuditEvent['kind'];
  status: string;
  eventTime: string;
  fromTeam: string | null;
  fromWorker: string | null;
  fromAssetId: string | null;
  toTeam: string | null;
  toWorker: string | null;
  toAssetId: string | null;
  taskId: string | null;
  durationMs: number | null;
  mocked: boolean;
  resolution: 'observed' | 'unknown' | 'conflict';
  authorized: null;
  authorizationStatus: 'unknown';
}
export interface TraceEdge {
  fromNodeId: string;
  toNodeId: string;
  parentSpanId: string;
  evidence: 'parent_span_id';
}
export interface TraceIssue {
  nodeId: string;
  spanId: string | null;
  parentSpanId: string | null;
  kind: 'missing_span' | 'duplicate_span' | 'missing_parent' | 'ambiguous_parent' | 'cycle' | 'conflicted_parent';
  status: 'unknown' | 'conflict';
}
export interface TraceGraph {
  status: 'unavailable' | 'unobserved' | 'observed' | 'unknown' | 'conflict';
  nodes: TraceNode[];
  edges: TraceEdge[];
  issues: TraceIssue[];
}
export interface AgentTeamsTrace {
  traceId: string;
  scopeId: string | null;
  cloudVersion: number;
  mocked: boolean | null;
  inventoryAvailable: boolean;
  windowFrom: string;
  windowTo: string;
  asOfReceivedAt: string;
  totalEvents: number | null;
  items: AgentTeamsAuditEvent[];
  nextCursor: string | null;
  truncated: boolean;
  nodeLimit: 2000;
  complete: false;
  coverage: 'observed_only';
  consistency: 'statement';
  timePrecision: 'microsecond';
  graph: TraceGraph;
}
