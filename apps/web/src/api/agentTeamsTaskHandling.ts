import { callApi } from './transport';
import type { ArchiveInput, HandlingEvent, HandlingPage, HandlingReceipt, HandlingWindow, ResolutionInput } from '@/types/agentTeamsTaskHandling';

const base = '/api/v1/alicloud/agentteams/task-handling';
const unavailable = (): never => { throw new Error('Task handling requires the backend / 人工处理需要连接后端'); };
export const taskHandlingApi = {
  list: (cursor?: string, window?: HandlingWindow) => callApi<HandlingPage>(base, unavailable, {
    query: { limit: 50, cursor, ...window }, noFallback: true }),
  event: (id: string) => callApi<HandlingEvent>(`${base}/events/${encodeURIComponent(id)}`, unavailable, { noFallback: true }),
  resolve: (id: string, body: ResolutionInput) => callApi<HandlingReceipt>(`${base}/events/${encodeURIComponent(id)}/resolution`,
    unavailable, { method: 'PUT', body, noFallback: true }),
  archive: (body: ArchiveInput) => callApi<HandlingReceipt>(`${base}/archive`, unavailable, { method: 'POST', body, noFallback: true }),
  request: (id: string) => callApi<HandlingReceipt>(`${base}/requests/${encodeURIComponent(id)}`, unavailable, { noFallback: true }),
};
