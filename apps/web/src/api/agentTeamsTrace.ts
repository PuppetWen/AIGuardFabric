import { ApiRequestError, callApi } from './transport';
import type { AgentTeamsTrace, TraceQuery } from '@/types/agentTeamsTrace';

const unavailable = (): never => { throw new Error('Trace requires the backend / Trace 查询需要连接后端'); };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function valid(value: AgentTeamsTrace, query: TraceQuery): boolean {
  if (!value || value.traceId !== query.traceId || value.complete !== false || value.coverage !== 'observed_only'
    || value.consistency !== 'statement' || value.timePrecision !== 'microsecond' || value.nodeLimit !== 2000
    || typeof value.inventoryAvailable !== 'boolean' || typeof value.truncated !== 'boolean'
    || !Number.isSafeInteger(value.cloudVersion) || !Array.isArray(value.items) || value.items.length > query.limit
    || !value.graph || !Array.isArray(value.graph.nodes) || !Array.isArray(value.graph.edges)
    || !Array.isArray(value.graph.issues) || value.graph.nodes.length > 2000
    || !['unavailable', 'unobserved', 'observed', 'unknown', 'conflict'].includes(value.graph.status)
    || [value.windowFrom, value.windowTo, value.asOfReceivedAt].some(at => typeof at !== 'string' || !Number.isFinite(Date.parse(at)))
    || (value.nextCursor !== null && (typeof value.nextCursor !== 'string' || value.nextCursor.length > 4096))) return false;
  if (value.inventoryAvailable) {
    if (typeof value.scopeId !== 'string' || !uuid.test(value.scopeId) || typeof value.mocked !== 'boolean'
      || !Number.isSafeInteger(value.totalEvents) || (value.totalEvents ?? -1) < 0
      || value.graph.nodes.length > Math.min(value.totalEvents ?? 0, 2000)) return false;
  } else if (value.totalEvents !== null || value.scopeId !== null || value.mocked !== null || value.items.length !== 0
    || value.graph.nodes.length !== 0 || value.graph.edges.length !== 0 || value.graph.status !== 'unavailable') return false;
  const ids = new Set(value.graph.nodes.map(node => node?.id));
  const nullableStrings = (item: object, names: string[]) => names.every(name => {
    const field = (item as Record<string, unknown>)[name];
    return field === null || field === undefined || typeof field === 'string';
  });
  return ids.size === value.graph.nodes.length
    && value.graph.nodes.every(node => node && typeof node.id === 'string' && uuid.test(node.id)
      && node.authorized === null && node.authorizationStatus === 'unknown' && typeof node.mocked === 'boolean'
      && typeof node.eventId === 'string' && typeof node.status === 'string' && typeof node.eventTime === 'string'
      && Number.isFinite(Date.parse(node.eventTime)) && ['call', 'message', 'task', 'heartbeat'].includes(node.kind)
      && nullableStrings(node, ['spanId', 'parentSpanId', 'fromTeam', 'fromWorker', 'fromAssetId', 'toTeam', 'toWorker', 'toAssetId', 'taskId'])
      && ['observed', 'unknown', 'conflict'].includes(node.resolution))
    && value.items.every(item => item && typeof item.id === 'string' && uuid.test(item.id)
      && item.authorized === null && item.authorizationStatus === 'unknown' && typeof item.mocked === 'boolean'
      && ['call', 'message', 'task', 'heartbeat'].includes(item.kind)
      && nullableStrings(item, ['sourceName', 'status', 'messagePreview', 'traceId', 'spanId', 'parentSpanId', 'fromTeam', 'fromWorker', 'fromAssetId', 'toTeam', 'toWorker', 'toAssetId', 'taskId']))
    && value.graph.edges.every(edge => edge && ids.has(edge.fromNodeId) && ids.has(edge.toNodeId)
      && typeof edge.parentSpanId === 'string' && edge.evidence === 'parent_span_id')
    && value.graph.issues.every(issue => issue && ids.has(issue.nodeId) && ['unknown', 'conflict'].includes(issue.status)
      && ['missing_span', 'duplicate_span', 'missing_parent', 'ambiguous_parent', 'cycle', 'conflicted_parent'].includes(issue.kind));
}

export const agentTeamsTraceApi = {
  get: async (query: TraceQuery, cursor?: string, signal?: AbortSignal) => {
    const response = await callApi<AgentTeamsTrace>(`/api/v1/alicloud/agentteams/traces/${encodeURIComponent(query.traceId)}`,
      unavailable, { method: 'GET', query: { from: query.from, until: query.until, limit: query.limit, cursor },
        signal, noFallback: true });
    if (!valid(response.data, query)) throw new ApiRequestError('Invalid Trace evidence response / Trace 证据返回格式不正确', 502, 'trace_contract', false);
    return response;
  },
};
