import { callApi } from './transport';
const unavailable = (): never => { throw new Error('集成配置需要连接后端'); };
const options = { noFallback: true, opaqueKeys: ['receipt'] };
export interface Probe { mocked: boolean; tcpReachable: boolean | null; host?: string; port?: number; note: string; checkedAt: string }
export interface IntegrationConfig {
  name: string; enabled: boolean; mock: boolean; environmentMock: boolean; version: number;
  settingsJson: string; secretKeys: string[]; probe: Probe | null;
  metadata: { requiredSecrets: string[]; optionalSecrets: string[]; endpointKey: string | null; degradation: string;
    semantics: Record<string, 'implemented' | { unsupported: { reason: string } }> };
}
export interface IntegrationRun {
  id: string; requestId: string; operation: string; configurationVersion: number; actor: string;
  startedAt: string; finishedAt?: string | null; status: 'started' | 'succeeded' | 'failed' | 'uncertain'; mocked: boolean;
  adapter?: string; completionState?: 'running' | 'pending_audit' | 'complete';
  providerStatus?: 'succeeded' | 'failed' | 'uncertain';
  receipt?: Record<string, unknown>;
}
export function receiptSucceeded(run: IntegrationRun) {
  return run.status === 'succeeded' && run.completionState === 'complete';
}
export function matchesReceipt(run: IntegrationRun, name: string, id: string) {
  return run.id === id && (run.adapter === undefined || run.adapter === name);
}
const path = (name: string) => '/api/v1/integrations/adapters/' + encodeURIComponent(name);
export const integrationsApi = {
  configuration: (name: string) => callApi<IntegrationConfig>(path(name) + '/configuration', unavailable, options),
  save: (name: string, body: unknown) => callApi<IntegrationConfig>(path(name) + '/configuration', unavailable, { ...options, method: 'PUT', body }),
  probe: (name: string) => callApi<Probe>(path(name) + '/probe', unavailable, { ...options, method: 'POST', body: {}, timeoutMs: 15000 }),
  history: (name: string) => callApi<{ items: IntegrationRun[] }>(path(name) + '/operations', unavailable, options),
  receipt: (name: string, id: string) => callApi<IntegrationRun>(path(name) + '/operations/' + encodeURIComponent(id), unavailable, options),
  recover: (name: string, id: string) => callApi<IntegrationRun>(path(name) + '/operations/' + encodeURIComponent(id) + '/recover', unavailable, { ...options, method: 'POST', body: {} }),
  execute: (name: string, body: unknown) => callApi<IntegrationRun>(path(name) + '/operations', unavailable, { ...options, opaqueKeys: ['receipt'], method: 'POST', body, timeoutMs: 130000 }),
};
