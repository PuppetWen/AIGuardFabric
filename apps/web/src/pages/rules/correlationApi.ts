import { callApi } from '@/api/transport';

export interface Definition {
  rule: { kind: string; key: string; name: string; severity: string; window_secs?: number; [key: string]: unknown };
  domain: string; enabled: boolean; group_by: string; window_secs: number; slot_by_time: boolean;
  event_filter: Record<string, unknown>; positive: unknown[]; negative: unknown[];
}
export interface Revision { definition: Definition; version: number; actor: string; changedAt: string; deleted: boolean }
export interface RuleRow { current: Revision; history: Revision[] }
export async function correlationApi<T>(path: string, body?: unknown) {
  return (await correlationRequest<T>(path, body)).data;
}
export function correlationRequest<T>(path: string, body?: unknown) {
  return callApi<T>(`/api/v1/correlation/${path}`, () => { throw new Error('Correlation API unavailable'); }, {
    noFallback: true, opaqueKeys: ['definition'], ...(body === undefined ? {} : { method: 'POST' as const, body }),
  });
}
