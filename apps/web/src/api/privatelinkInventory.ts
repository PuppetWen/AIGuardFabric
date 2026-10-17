import { callApi } from './transport';
import type { PrivateLinkArchiveInput, PrivateLinkArchiveResult, PrivateLinkInventory, PrivateLinkOperation, PrivateLinkSyncInput } from '@/types/privatelinkInventory';

const unavailable = (): never => { throw new Error('PrivateLink inventory requires the server / PrivateLink 盘点需要连接后端'); };
const base = '/api/v1/alicloud/privatelink/inventory', options = { noFallback: true };
const operationPath = (id: string) => `${base}/operations/${encodeURIComponent(id)}`;
export const privatelinkInventoryApi = {
  list: (signal?: AbortSignal) => callApi<PrivateLinkInventory>(base, unavailable, { ...options, signal }),
  sync: (body: PrivateLinkSyncInput, signal?: AbortSignal) => callApi<PrivateLinkOperation>(`${base}/sync`, unavailable,
    { ...options, method: 'POST', body, signal, timeoutMs: 130_000 }),
  receipt: (id: string, signal?: AbortSignal) => callApi<PrivateLinkOperation>(operationPath(id), unavailable, { ...options, signal }),
  cancel: (id: string) => callApi<PrivateLinkOperation>(`${operationPath(id)}/cancel`, unavailable, { ...options, method: 'POST', body: {} }),
  archive: (body: PrivateLinkArchiveInput) => callApi<PrivateLinkArchiveResult>('/api/v1/alicloud/privatelink/operations/archive', unavailable,
    { ...options, method: 'POST', body }),
};
