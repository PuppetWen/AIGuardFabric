import { callApi } from './transport';
import type { Severity } from '@/types/domain';
import type { DeliveryRow } from './notifications';

export interface EscalationTier { level: number; overdueMinutes: number; target: string; channels: string[] }
export interface EscalationPolicyRoute { severity: Severity; responseMinutes: number; enabled: boolean; tiers: EscalationTier[] }
export interface EscalationPolicy { route: EscalationPolicyRoute; since: string | null }
export interface EscalationRevision { version: number; at: string; actor: string; reason: string; policies: EscalationPolicy[] }
export interface EscalationConfig {
  version: number; policies: EscalationPolicy[]; history: EscalationRevision[]; canWrite: boolean;
  automaticAvailable: boolean; mockMode: boolean;
  channels: { channel: string; enabled: boolean; minSeverity: Severity }[];
  health: { at: string; enqueued: number | null; error: string | null } | null;
}
export interface EscalationReceipt {
  alertId: string; title: string | null; policyVersion: number; tier: number; enqueuedAt: string;
  actor: string; notifications: DeliveryRow[];
}
export interface EscalationChange { expectedVersion: number; routes: EscalationPolicyRoute[]; reason: string; includeExisting: boolean }
const unavailable = (): never => { throw new Error('Escalation requires a server connection'); };
export const escalationApi = {
  get: () => callApi<EscalationConfig>('/api/v1/alerts/escalation-config', unavailable, { noFallback: true }),
  save: (body: EscalationChange) => callApi<Pick<EscalationConfig, 'version' | 'policies' | 'history'>>(
    '/api/v1/alerts/escalation-config', unavailable, { noFallback: true, method: 'PUT', body }),
  history: (page: number) => callApi<{ items: EscalationReceipt[]; total: number; page: number; pageSize: number }>(
    '/api/v1/alerts/escalation-history', unavailable, { noFallback: true, query: { page, pageSize: 10 } }),
};
