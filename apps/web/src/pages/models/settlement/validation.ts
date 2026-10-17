import type { SettlementReceipt } from '@/api/gatewaySettlement';

export const validAttempt = (id: string) => /^[\da-f]{8}-(?:[\da-f]{4}-){3}[\da-f]{12}$/i.test(id)
  && id !== '00000000-0000-0000-0000-000000000000';
const states = ['reserved', 'pending-audit', 'conservatively-settled', 'settled'];
const evidence = ['not-sent', 'local-reply', 'sent-usage-known', 'sent-usage-partial', 'sent-usage-unknown'];
export function validReceipt(value: SettlementReceipt, id: string): boolean {
  if (!value || value.attemptId !== id || !validAttempt(value.usageId) || !states.includes(value.state)
    || value.mayExecute !== false || typeof value.recoveryAvailable !== 'boolean'
    || !Number.isFinite(Date.parse(value.originalSubmittedAt)) || !Number.isFinite(Date.parse(value.originalExecuteBefore))
    || (value.auditId !== null && !validAttempt(value.auditId))
    || (value.outcomeHash !== null && !/^[a-f0-9]{64}$/.test(value.outcomeHash))
    || (value.outcomeEvidence !== null && !evidence.includes(value.outcomeEvidence))
    || (value.chargeState !== null && !['reserved', 'conservative', 'actual'].includes(value.chargeState))) return false;
  if (value.state === 'settled' && (value.auditId === null || value.recoveryAvailable)) return false;
  if (value.recoveryAvailable && value.state !== 'pending-audit') return false;
  return value.components === null || value.components === undefined || (Array.isArray(value.components) && value.components.length <= 8
    && value.components.every(component => validAttempt(component.usageId) && evidence.includes(component.evidence)
      && (component.costMicro === null || (Number.isSafeInteger(component.costMicro) && component.costMicro >= 0))));
}
