export interface AgentTeamsAuditBinding {
  sourceId: string;
  sourceName: string;
  version: number;
  bindingId: string;
  cloudVersion: number;
  scopeId: string;
  mocked: boolean;
  state: 'waiting' | 'active' | 'stale' | 'disabled';
  acceptsEvents: boolean;
  boundAt: string;
  lastEventAt?: string | null;
  coverageStart?: string | null;
  completeWindow: boolean;
}

export interface AgentTeamsAuditSources {
  items: AgentTeamsAuditBinding[];
  sources: { id: string; name: string; enabled: boolean }[];
  cloudVersion: number;
  inventoryAvailable: boolean;
  canWrite: boolean;
}

export interface AgentTeamsAuditBindResult {
  sourceId: string;
  version: number;
  bindingId: string;
  scopeId: string;
  cloudVersion: number;
  enabled: boolean;
  mocked: boolean;
  boundAt: string;
}

export interface AgentTeamsAuditEvent {
  id: string;
  eventId: string;
  eventTime: string;
  receivedAt: string;
  kind: 'call' | 'message' | 'task' | 'heartbeat';
  sourceId: string;
  sourceName?: string | null;
  fromTeam?: string | null;
  fromWorker?: string | null;
  fromAssetId?: string | null;
  toTeam?: string | null;
  toWorker?: string | null;
  toAssetId?: string | null;
  taskId?: string | null;
  traceId?: string | null;
  spanId?: string | null;
  parentSpanId?: string | null;
  status?: string | null;
  durationMs?: number | null;
  messagePreview?: string | null;
  mocked: boolean;
  authorizationStatus: 'unknown';
  authorized: null;
}

export interface AgentTeamsAuditEvents {
  items: AgentTeamsAuditEvent[];
  nextCursor?: string | null;
  windowFrom: string;
  windowTo: string;
}
