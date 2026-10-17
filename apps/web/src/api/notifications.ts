import { callApi } from './transport';
import type { Severity } from '@/types/domain';
export interface InboxMessage {
  id: string; title: string; body: string; severity: Severity; at: string;
  subjectKind: string; subjectId: string; read: boolean; canMark: boolean;
}
export interface ChannelRow {
  channel: string; version: number; target: string; enabled: boolean; configured: boolean; mocked: boolean;
  settingsJson: string; secretKeys: string[]; minSeverity: string; editingSecrets?: Record<string, string>;
}
export interface DeliveryResult {
  mocked: boolean; anyDelivered: boolean; note: string;
  deliveries: { outcome: string; error?: string; receipt?: string; kind: string }[];
}
export interface DeliveryRow {
  id?: string; channelId: string; kind: string; outcome: string; status?: string;
  attempts: number; at: string; nextAttemptAt?: string; mocked: boolean;
  error?: string; receipt?: string | { detail?: string; externalId?: string };
}
const unavailable = (): never => { throw new Error('通知配置需要连接后端'); };
export const notificationApi = {
  inbox: () => callApi<InboxMessage[]>('/api/v1/notifications/inbox', unavailable, { noFallback: true }),
  markRead: (ids: string[]) => callApi<{ marked: number }>('/api/v1/notifications/inbox/read', unavailable,
    { method: 'POST', body: { ids }, noFallback: true }),
  history: () => callApi<DeliveryRow[]>('/api/v1/notifications/history', unavailable, { noFallback: true }),
  retry: (id: string) => callApi<DeliveryRow>(`/api/v1/notifications/${id}/retry`, unavailable,
    { method: 'POST', noFallback: true }),
  list: () => callApi<ChannelRow[]>('/api/v1/settings/notifications', unavailable, { noFallback: true }),
  save: (row: ChannelRow) => callApi<ChannelRow>(`/api/v1/settings/notifications/${row.channel}`, unavailable,
    { method: 'PUT', noFallback: true, body: { expectedVersion: row.version, enabled: row.enabled, target: row.target,
      settings: JSON.parse(row.settingsJson), secrets: row.editingSecrets ?? {}, minSeverity: row.minSeverity } }),
  test: (kind: string) => callApi<DeliveryResult>(`/api/v1/settings/notifications/${kind}/test`, unavailable,
    { method: 'POST', noFallback: true, timeoutMs: 60000 }),
};
