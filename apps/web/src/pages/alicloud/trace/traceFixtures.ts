import type { AgentTeamsTrace, TraceNode, TraceQuery } from '@/types/agentTeamsTrace';
import type { AgentTeamsAuditEvent } from '@/types/agentTeamsAudit';

// Synthetic HTTP/DOM fixtures only; production never falls back to these records.
export const traceMeta = { source: 'live' as const, elapsedMs: 1, at: 1 };
export const traceWindow: TraceQuery = { traceId: 'sdk:observed-root', from: '2026-09-19T10:00:00.000Z',
  until: '2026-09-20T10:00:00.000Z', limit: 50 };
export const traceUuid = (index: number) => `10000000-0000-4000-8000-${index.toString().padStart(12, '0')}`;
export function traceNode(index = 1): TraceNode {
  return { id: traceUuid(index), eventId: `external-event-${index}`, spanId: `span-${index}`, parentSpanId: null,
    sourceId: traceUuid(8001), bindingId: traceUuid(8002), kind: 'call', status: 'success',
    eventTime: '2026-09-19T11:00:00.000Z', fromTeam: 'observed-team', fromWorker: 'actual-worker',
    fromAssetId: traceUuid(8003), toTeam: null, toWorker: null, toAssetId: null, taskId: 'actual-task',
    durationMs: 12, mocked: false, resolution: 'observed', authorized: null, authorizationStatus: 'unknown' };
}
export function traceEvent(index = 1): AgentTeamsAuditEvent {
  const node = traceNode(index);
  return { ...node, traceId: traceWindow.traceId, receivedAt: '2026-09-19T11:00:01.000Z',
    messagePreview: `redacted-event-${index}` };
}
export function traceFixture(count = 2): AgentTeamsTrace {
  const nodes = Array.from({ length: count }, (_, index) => traceNode(index + 1));
  if (nodes[1]) nodes[1].parentSpanId = nodes[0].spanId;
  return { traceId: traceWindow.traceId, scopeId: traceUuid(8004), cloudVersion: 4, mocked: false,
    inventoryAvailable: true, windowFrom: traceWindow.from, windowTo: traceWindow.until,
    asOfReceivedAt: '2026-09-20T10:00:00.000Z', totalEvents: count,
    items: count ? [traceEvent(1)] : [], nextCursor: count > 1 ? 'opaque-first-cursor' : null,
    truncated: false, nodeLimit: 2000, complete: false, coverage: 'observed_only',
    consistency: 'statement', timePrecision: 'microsecond', graph: {
      status: count ? 'observed' : 'unobserved', nodes,
      edges: count > 1 ? [{ fromNodeId: nodes[0].id, toNodeId: nodes[1].id,
        parentSpanId: nodes[0].spanId!, evidence: 'parent_span_id' }] : [], issues: [],
    } };
}
export function unavailableTrace(): AgentTeamsTrace {
  return { ...traceFixture(0), scopeId: null, mocked: null, inventoryAvailable: false, totalEvents: null,
    graph: { status: 'unavailable', nodes: [], edges: [], issues: [] } };
}
export function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((success, failure) => { resolve = success; reject = failure; });
  return { promise, resolve, reject };
}
