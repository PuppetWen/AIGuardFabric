import { callApi } from './transport';
import type { Case } from '@/types/domain';
const unavailable = (): never => { throw new Error('案件处置需要连接后端'); };
const options = { noFallback: true };
export interface PlaybookResult {
  outcome: string; dryRun: boolean; hasFailure: boolean; reason?: string; runId: string;
  steps: { name: string; outcome: string; note: string; error?: string }[];
}
export interface CaseControl {
  id: string; action: string; target: string; active: boolean; reason: string;
  createdAt: string; releasedAt?: string; tools: string[];
}
export const casesApi = {
  get: (id: string) => callApi<{case: Case; canWrite: boolean}>('/api/v1/cases/' + encodeURIComponent(id), unavailable, options),
  execute: (id: string, body: unknown) => callApi<PlaybookResult>('/api/v1/cases/' + encodeURIComponent(id) + '/playbook', unavailable,
    { ...options, method: 'POST', body, timeoutMs: 130_000 }),
  controls: (id: string) => callApi<{items: CaseControl[]; canWrite: boolean; canRelease: boolean}>('/api/v1/cases/' + encodeURIComponent(id) + '/containments', unavailable, options),
  release: (id: string, control: string) => callApi('/api/v1/cases/' + encodeURIComponent(id) + '/containments/' + encodeURIComponent(control) + '/release', unavailable,
    { ...options, method: 'POST', body: {} }),
  create: (body: unknown) => callApi<{case: Case}>('/api/v1/cases', unavailable, { ...options, method: 'POST', body }),
  state: (id: string, state: string, resolution: string) => callApi('/api/v1/cases/' + encodeURIComponent(id) + '/state', unavailable,
    { ...options, method: 'POST', body: { state, resolution } }),
};
