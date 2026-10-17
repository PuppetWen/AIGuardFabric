import { callApi } from './transport';
import type { ApigOperation, ApigObservation, ApigPreview, ApigPublicationState, ApplyInput, ObserveInput, PreviewInput, SourceQuery } from '@/types/apigPolicyPublication';

const base = '/api/v1/alicloud/apig/policy-publication';
const unavailable = (): never => { throw new Error('APIG publication requires the server / APIG 发布需要连接后端'); };
const path = (id: string) => `${base}/operations/${encodeURIComponent(id)}`;
export const apigPublicationApi = {
  state: (query: SourceQuery = {}, signal?: AbortSignal) => callApi<ApigPublicationState>(base, unavailable, { noFallback: true, signal, query: { ...query } }),
  observe: (body: ObserveInput) => callApi<ApigObservation>(`${base}/observe`, unavailable, { noFallback: true, method: 'POST', body, timeoutMs: 130_000 }),
  preview: (body: PreviewInput) => callApi<ApigPreview>(`${base}/previews`, unavailable, { noFallback: true, method: 'POST', body, timeoutMs: 130_000 }),
  apply: (body: ApplyInput) => callApi<ApigOperation>(`${base}/operations`, unavailable, { noFallback: true, method: 'POST', body, timeoutMs: 130_000 }),
  receipt: (id: string, signal?: AbortSignal) => callApi<ApigOperation>(path(id), unavailable, { noFallback: true, signal }),
  observeOriginal: (id: string, body: ObserveInput) => callApi<ApigObservation>(`${path(id)}/observe`, unavailable, { noFallback: true, method: 'POST', body, timeoutMs: 130_000 }),
  recover: (id: string) => callApi<ApigOperation>(`${path(id)}/recover`, unavailable, { noFallback: true, method: 'POST', body: {} }),
  archive: (body: { expected_generation: number; request_ids: string[] }) => callApi<{ generation: number; archivedCount: number; archivedRequestIds: string[]; unchanged: boolean }>(
    `${base}/operations/archive`, unavailable, { noFallback: true, method: 'POST', body }),
};
