import { callApi } from './transport';
import type { ApplyInput, ArchiveResult, ManagedState, Operation, Preview, PreviewInput } from '@/pages/alicloud/scheduler-managed/types';
const base = '/api/v1/alicloud/schedulerx3/native/jobs';
const unavailable = (): never => { throw new Error('Scheduler managed jobs require the server / 受管任务需要服务端'); };
export const schedulerManagedJobsApi = {
  state: (signal?: AbortSignal) => callApi<ManagedState>(base, unavailable, { noFallback: true, signal }),
  preview: (body: PreviewInput) => callApi<Preview>(`${base}/previews`, unavailable, { noFallback: true, method: 'POST', body }),
  readPreview: (id: string, signal?: AbortSignal) => callApi<Preview>(`${base}/previews/${encodeURIComponent(id)}`, unavailable,
    { noFallback: true, signal }),
  apply: (id: string, body: ApplyInput) => callApi<Operation>(`${base}/operations/${encodeURIComponent(id)}`, unavailable,
    { noFallback: true, method: 'PUT', body, timeoutMs: 130_000 }),
  receipt: (id: string, signal?: AbortSignal) => callApi<Operation>(`${base}/operations/${encodeURIComponent(id)}`, unavailable,
    { noFallback: true, signal }),
  observeOriginal: (id: string) => callApi<Operation>(`${base}/operations/${encodeURIComponent(id)}/observe`, unavailable,
    { noFallback: true, method: 'POST', body: {}, timeoutMs: 130_000 }),
  recover: (id: string) => callApi<Operation>(`${base}/operations/${encodeURIComponent(id)}/recover`, unavailable,
    { noFallback: true, method: 'POST', body: {} }),
  archive: (ids: string[], generation: number) => callApi<ArchiveResult>(`${base}/operations/archive`, unavailable,
    { noFallback: true, method: 'POST', body: { expected_generation: generation, request_ids: ids, confirm_loss_of_preview: true } }),
};
