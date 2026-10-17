import type { ApiResult } from '@/api/dataSource';
import type { SettlementReceipt } from '@/api/gatewaySettlement';

export const attempt = '957a5c39-28a3-4a45-a830-6855f4763730';
export const usage = '2f34ef30-a1d4-47f1-8f2c-8c2d2dbe689c';
export const audit = 'ca3148b9-e330-4b3a-a901-51cb09089c56';
export const result = <T,>(data: T): ApiResult<T> => ({ data, meta: { source: 'live', elapsedMs: 1, at: Date.now() } });
export function receipt(patch: Partial<SettlementReceipt> = {}): SettlementReceipt {
  return { attemptId: attempt, usageId: usage, state: 'pending-audit', originalSubmittedAt: '2026-10-02T07:00:00Z',
    originalExecuteBefore: '2026-10-02T07:01:50Z', chargeState: 'reserved', auditId: null,
    outcomeEvidence: 'sent-usage-known', outcomeHash: 'a'.repeat(64), mayExecute: false, recoveryAvailable: true,
    components: [{ usageId: usage, evidence: 'sent-usage-known', costMicro: 100 }], ...patch };
}
export function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(yes => { resolve = yes; });
  return { promise, resolve };
}
