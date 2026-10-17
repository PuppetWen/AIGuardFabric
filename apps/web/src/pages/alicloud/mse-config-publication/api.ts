import { callApi } from '@/api/transport';
import type { Paged, Policy } from '@/types/domain';
import type { ApplyInput, ArchiveInput, ArchiveResult, Observation, ObserveInput, Operation, Preview, PreviewInput, PublicationState } from './types';

const base = '/api/v1/alicloud/mse/config-publication';
const unavailable = (): never => { throw new Error('MSE 配置发布需要后端 / MSE configuration publication requires the server'); };
const read = { noFallback: true };
const post = { ...read, method: 'POST' as const, timeoutMs: 130_000 };
const operation = (id: string) => `${base}/operations/${encodeURIComponent(id)}`;
export const publicationApi = {
  state: (signal?: AbortSignal) => callApi<PublicationState>(base, unavailable, { ...read, signal }),
  policies: (page: number, signal?: AbortSignal) => callApi<Paged<Policy>>('/api/v1/policies', unavailable,
    { ...read, signal, query: { page, pageSize: 50 } }),
  observe: (body: ObserveInput) => callApi<Observation>(`${base}/observe`, unavailable, { ...post, body }),
  preview: (body: PreviewInput) => callApi<Preview>(`${base}/previews`, unavailable, { ...post, body }),
  apply: (body: ApplyInput) => callApi<Operation>(`${base}/operations`, unavailable, { ...post, body }),
  receipt: (id: string, signal?: AbortSignal) => callApi<Operation>(operation(id), unavailable, { ...read, signal }),
  observeOriginal: (id: string, body: ObserveInput) => callApi<Observation>(`${operation(id)}/observe`, unavailable, { ...post, body }),
  recover: (id: string) => callApi<Operation>(`${operation(id)}/recover`, unavailable, { ...post, body: {} }),
  archive: (body: ArchiveInput) => callApi<ArchiveResult>(`${base}/operations/archive`, unavailable, { ...post, body }),
};
