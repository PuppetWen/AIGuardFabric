import { callApi } from './transport';
import { policyBody } from './payloads';
import { policy as adaptPolicy } from './adapters/governance';
import { object } from './adapters/shared';
import type { Policy } from '@/types/domain';

const unavailable = (): never => { throw new Error('需要连接服务端 / Backend connection required'); };
export function validPolicyVersion(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value > 0 && value <= 4_294_967_295;
}
function revision(value: unknown): number {
  if (!validPolicyVersion(value)) throw new Error('请先读取并核对真实策略版本 / Read and review the actual policy revision first');
  return value;
}
const path = (id: string) => `/api/v1/policies/${encodeURIComponent(id)}`;

export const policiesApi = {
  get: (id: string) => callApi<Policy>(path(id), unavailable, { noFallback: true }),
  save: (draft: Partial<Policy>, expectedVersion?: number) => {
    const version = draft.id ? revision(expectedVersion) : undefined;
    return callApi<Policy>(draft.id ? path(draft.id) : '/api/v1/policies', unavailable, {
      method: draft.id ? 'PUT' : 'POST', noFallback: true,
      body: policyBody({ ...draft, version }),
    });
  },
  delete: (id: string, expectedVersion: number) => callApi<{ deleted: string }>(path(id), unavailable, {
    method: 'DELETE', query: { expected_version: revision(expectedVersion) }, noFallback: true,
  }),
  history: async (id: string) => {
    const result = await callApi<{ versions: unknown[] }>(`${path(id)}/versions`, unavailable, { noFallback: true });
    return { ...result, data: { versions: result.data.versions.map(row => adaptPolicy(object(row)) as unknown as Policy) } };
  },
  restore: async (id: string, version: number, expectedVersion: number) => {
    const result = await callApi<{ policy: unknown }>(`${path(id)}/versions/${revision(version)}/restore`, unavailable, {
      method: 'POST', noFallback: true, body: { version, expected_version: revision(expectedVersion) },
    });
    return { ...result, data: adaptPolicy(object(result.data.policy)) as unknown as Policy };
  },
  simulate: (id: string, sample: unknown) => callApi<unknown>(`${path(id)}/dry-run`, unavailable, {
    method: 'POST', noFallback: true, body: sample,
  }),
};
