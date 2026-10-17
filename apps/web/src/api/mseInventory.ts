import { callApi } from './transport';
import type { MseArchiveInput, MseArchiveResult, MseInventory, MseOperation, MseSyncInput } from '@/types/mseInventory';

const unavailable = (): never => { throw new Error('MSE inventory requires the server / MSE 盘点需要连接后端'); };
const base = '/api/v1/alicloud/mse/inventory';
const options = { noFallback: true };
const operationPath = (id: string) => `${base}/operations/${encodeURIComponent(id)}`;
export const mseInventoryApi = {
  list: (signal?: AbortSignal) => callApi<MseInventory>(base, unavailable, { ...options, signal }),
  sync: (body: MseSyncInput, signal?: AbortSignal) => callApi<MseOperation>(`${base}/sync`, unavailable,
    { ...options, method: 'POST', body, signal, timeoutMs: 130_000 }),
  receipt: (id: string, signal?: AbortSignal) => callApi<MseOperation>(operationPath(id), unavailable, { ...options, signal }),
  cancel: (id: string) => callApi<MseOperation>(`${operationPath(id)}/cancel`, unavailable, { ...options, method: 'POST', body: {} }),
  archive: (body: MseArchiveInput) => callApi<MseArchiveResult>('/api/v1/alicloud/mse/operations/archive', unavailable,
    { ...options, method: 'POST', body }),
};
