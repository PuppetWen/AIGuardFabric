import { callApi } from './transport';
import type { Input, Preview, Receipt, RecordView, State } from '@/pages/alicloud/agentteams-orchestration/types';
const base = '/api/v1/alicloud/agentteams/orchestration-definitions';
const unavailable = (): never => { throw new Error('The server is required / 编排声明需要服务端'); };
const opaqueKeys = ['local', 'receiver', 'template', 'definition'];
export const agentteamsOrchestrationApi = {
  state: (signal?: AbortSignal) => callApi<State>(base, unavailable, { noFallback: true, signal, opaqueKeys }),
  current: (team: string, signal?: AbortSignal) => callApi<RecordView>(`${base}/teams/${encodeURIComponent(team)}`, unavailable, { noFallback: true, signal, opaqueKeys }),
  preview: (team: string, body: Input, signal?: AbortSignal) => callApi<Preview>(`${base}/teams/${encodeURIComponent(team)}/preview`, unavailable, { method: 'POST', body, noFallback: true, signal, opaqueKeys }),
  apply: (team: string, body: Readonly<Input>, signal?: AbortSignal) => callApi<Receipt>(`${base}/teams/${encodeURIComponent(team)}`, unavailable, { method: 'PUT', body, noFallback: true, signal, opaqueKeys }),
  receipt: (request: string, signal?: AbortSignal) => callApi<Receipt>(`${base}/requests/${encodeURIComponent(request)}`, unavailable, { noFallback: true, signal, opaqueKeys }),
};
