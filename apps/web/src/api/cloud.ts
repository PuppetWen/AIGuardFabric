import { callApi } from './transport';
import type { IntegrationRun } from './integrations';
const unavailable = (): never => { throw new Error('云配置需要连接后端 / Cloud configuration requires the server'); };
const options = { noFallback: true, opaqueKeys: ['settings', 'operations', 'receipt'] };
export interface CloudContract {
  action: string; version: string; method: string; path: string; read_only: boolean;
  parameters: { name: string; location: string; schema: { type?: string; required?: boolean; enum?: (string | number)[]; properties?: Record<string, unknown> } }[];
}
export interface CloudProbe { version: number; checkedAt: string; mocked: boolean; status: string; action: string; note: string; runId: string }
export interface CloudConfig {
  name: string; displayName: string; enabled: boolean; mock: boolean; environmentMock: boolean; version: number;
  endpoint: string; settings: Record<string, unknown>; secretKeys: string[]; probe?: CloudProbe;
  operations: CloudContract[];
}
export interface CloudSummary { name: string; displayName: string; enabled: boolean; mock: boolean; configured: boolean; version: number }
const path = (name: string) => '/api/v1/alicloud/connections/' + encodeURIComponent(name);
export const cloudApi = {
  list: () => callApi<{ items: CloudSummary[] }>('/api/v1/alicloud/connections', unavailable, options),
  configuration: (name: string, signal?: AbortSignal) => callApi<CloudConfig>(path(name), unavailable, { ...options, signal }),
  save: (name: string, body: unknown) => callApi<CloudConfig>(path(name), unavailable, { ...options, method: 'PUT', body }),
  history: (name: string) => callApi<{ items: IntegrationRun[] }>(path(name) + '/operations', unavailable, options),
  receipt: (name: string, id: string) => callApi<IntegrationRun>(path(name) + '/operations/' + encodeURIComponent(id), unavailable, options),
  recover: (name: string, id: string) => callApi<IntegrationRun>(path(name) + '/operations/' + encodeURIComponent(id) + '/recover', unavailable, { ...options, method: 'POST', body: {} }),
  execute: (name: string, body: unknown) => callApi<IntegrationRun>(path(name) + '/operations', unavailable, { ...options, method: 'POST', body, timeoutMs: 130000 }),
  probe: (name: string, body: unknown) => callApi<CloudProbe>(path(name) + '/probe', unavailable, { ...options, method: 'POST', body, timeoutMs: 130000 }),
  syncTeams: (body: unknown) => callApi<{ mocked: boolean; teams: number; workers: number; assets: number; tasks: number; note: string }>('/api/v1/alicloud/agentteams/sync', unavailable, { ...options, method: 'POST', body, timeoutMs: 130000 }),
};
