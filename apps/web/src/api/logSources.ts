import { callApi } from './transport';
import type { LogSource } from '@/types/domain';

export interface SourceInput {
  nativeReceiver?: string;
  name: string; protocol: string; endpoint?: string; parserId?: string;
  enabled?: boolean; pollIntervalSecs?: number; headers?: Record<string, string>;
  allowedCidrs?: string[]; requireMtls?: boolean;
}
export interface IngestResult {
  received: number; accepted: number; matched: number; deduped: number; failed: number; errors: string[];
}
const unavailable = (): never => { throw new Error('日志源配置需要连接后端'); };
export const logSourcesApi = {
  save: (value: SourceInput, id?: string) => callApi<LogSource>(
    id ? '/api/v1/ingest/sources/' + encodeURIComponent(id) : '/api/v1/ingest/sources', unavailable,
    { method: id ? 'PUT' : 'POST', body: value, noFallback: true }),
  toggle: (id: string, enabled: boolean) => callApi<LogSource>(
    '/api/v1/ingest/sources/' + encodeURIComponent(id), unavailable, { method: 'PATCH', body: { enabled }, noFallback: true }),
  remove: (id: string) => callApi('/api/v1/ingest/sources/' + encodeURIComponent(id), unavailable,
    { method: 'DELETE', noFallback: true }),
  poll: (id: string) => callApi<IngestResult>(
    '/api/v1/ingest/sources/' + encodeURIComponent(id) + '/poll', unavailable,
    { method: 'POST', noFallback: true, timeoutMs: 30000 }),
};

