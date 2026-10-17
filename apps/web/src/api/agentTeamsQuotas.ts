import { callApi } from './transport';
import type {
  WorkerQuotaBinding, WorkerQuotaBindRequest, WorkerQuotaObserveRequest,
  WorkerQuotaObserveResult, WorkerQuotaSyncRequest, WorkerQuotaSyncResult, WorkerQuotas,
} from '@/types/agentTeamsQuotas';

const base = '/api/v1/alicloud/agentteams/worker-quotas';
const unavailable = (): never => { throw new Error('Worker quota synchronization requires the backend / Worker 配额同步需要连接后端'); };
const workerPath = (assetId: string) => `${base}/${encodeURIComponent(assetId)}`;

export const agentTeamsQuotasApi = {
  list: () => callApi<WorkerQuotas>(base, unavailable, { noFallback: true }),
  bind: (assetId: string, body: WorkerQuotaBindRequest) =>
    callApi<WorkerQuotaBinding>(workerPath(assetId), unavailable, { method: 'PUT', body, noFallback: true }),
  observe: (assetId: string, body: WorkerQuotaObserveRequest) =>
    callApi<WorkerQuotaObserveResult>(`${workerPath(assetId)}/observe`, unavailable,
      { method: 'POST', body, noFallback: true, timeoutMs: 130_000 }),
  sync: (assetId: string, body: WorkerQuotaSyncRequest) =>
    callApi<WorkerQuotaSyncResult>(`${workerPath(assetId)}/sync`, unavailable,
      { method: 'POST', body, noFallback: true, timeoutMs: 130_000 }),
};
