import { useTranslation } from 'react-i18next';
import type { ObservationReceipt, SchedulerState } from './types';

export function useSchedulerText() {
  const { i18n } = useTranslation();
  return (cn: string, en: string) => i18n.language.startsWith('zh') ? cn : en;
}
export const uuid = (value: string) => /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
export const failure = (cause: unknown) => cause instanceof Error ? cause.message : String(cause);
export function adoptable(state: SchedulerState, receipt: ObservationReceipt | null) {
  const completed = Date.parse(receipt?.finishedAt ?? '');
  return !!receipt?.observation && receipt.status === 'observed' && receipt.available && receipt.current
    && receipt.listingComplete && receipt.requestId === state.latestObservation?.requestId
    && state.latestObservation.status === 'observed' && state.latestObservation.available && state.latestObservation.current
    && receipt.originalTarget?.fingerprint === state.sourceTarget?.fingerprint
    && completed <= Date.now() && completed + state.limits.observationFreshSeconds * 1000 >= Date.now();
}
