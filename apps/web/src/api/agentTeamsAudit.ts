import { callApi } from './transport';
import type { AgentTeamsAuditBindResult, AgentTeamsAuditEvents, AgentTeamsAuditSources } from '@/types/agentTeamsAudit';

const base = '/api/v1/alicloud/agentteams';
const unavailable = (): never => { throw new Error('AgentTeams audit requires the backend / 审计接入需要连接后端'); };

export const agentTeamsAuditApi = {
  sources: () => callApi<AgentTeamsAuditSources>(`${base}/audit-sources`, unavailable, { noFallback: true }),
  bind: (sourceId: string, expectedVersion: number, enabled: boolean) =>
    callApi<AgentTeamsAuditBindResult>(`${base}/audit-sources/${encodeURIComponent(sourceId)}`, unavailable,
      { method: 'PUT', body: { expected_version: expectedVersion, enabled }, noFallback: true }),
  events: (cursor?: string) => callApi<AgentTeamsAuditEvents>(`${base}/audit-events`, unavailable,
    { query: { limit: 50, cursor }, noFallback: true }),
};
