import { callApi } from './transport';
import type { ArchiveInput, EnqueueInput, Item, QueueState, Receipt, SendInput } from '@/pages/alicloud/cms-queue/types';
const base = '/api/v1/alicloud/cms/queue';
const unavailable = (): never => { throw new Error('CMS queue requires the server / CMS 队列需要服务端'); };
export const cmsQueueApi = {
  state: (page = 1, signal?: AbortSignal) => callApi<QueueState>(base, unavailable,
    { noFallback: true, query: { page, page_size: 20 }, signal }),
  receipt: (id: string, signal?: AbortSignal) => callApi<Receipt>(`${base}/requests/${encodeURIComponent(id)}`, unavailable,
    { noFallback: true, signal }),
  enqueue: (body: EnqueueInput) => callApi<Receipt>(`${base}/enqueue`, unavailable,
    { noFallback: true, method: 'POST', body, timeoutMs: 130_000 }),
  send: (body: SendInput) => callApi<Receipt>(`${base}/send`, unavailable,
    { noFallback: true, method: 'POST', body, timeoutMs: 130_000 }),
  archive: (body: ArchiveInput) => callApi<Receipt>(`${base}/archive`, unavailable,
    { noFallback: true, method: 'POST', body, timeoutMs: 130_000 }),
  recover: (id: string) => callApi<Item>(`${base}/items/${encodeURIComponent(id)}/recover-local`, unavailable,
    { noFallback: true, method: 'POST', body: {}, timeoutMs: 130_000 }),
};
