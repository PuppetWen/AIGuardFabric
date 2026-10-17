import { callApi } from './transport';

export type SettlementEvidence = 'not-sent' | 'local-reply' | 'sent-usage-known' | 'sent-usage-partial' | 'sent-usage-unknown';
export interface SettlementReceipt {
  attemptId: string; usageId: string;
  state: 'reserved' | 'pending-audit' | 'conservatively-settled' | 'settled';
  originalSubmittedAt: string; originalExecuteBefore: string;
  chargeState: 'reserved' | 'conservative' | 'actual' | null;
  auditId: string | null; outcomeEvidence: SettlementEvidence | null; outcomeHash: string | null;
  components?: { usageId: string; evidence: SettlementEvidence; costMicro: number | null }[] | null;
  mayExecute: false; recoveryAvailable: boolean;
}
const path = (id: string) => `/api/v1/gateway/attempts/${encodeURIComponent(id)}`;
export const gatewaySettlementApi = {
  read: (id: string, signal?: AbortSignal) => callApi<SettlementReceipt>(path(id), () => null as never,
    { noFallback: true, signal }),
  recover: (id: string, signal?: AbortSignal) => callApi<SettlementReceipt>(`${path(id)}/recover`, () => null as never,
    { method: 'POST', body: {}, noFallback: true, signal }),
};
