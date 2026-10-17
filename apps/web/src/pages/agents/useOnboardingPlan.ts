import { useEffect, useRef, useState } from 'react';
import { onboardingApi } from '@/api/onboarding';
import { useAuthStore } from '@/stores/authStore';
import type { ConnectionPlan, PlanRequest } from '@/types/onboarding';

export function useOnboardingPlan() {
  const pending = useRef<AbortController | null>(null), sequence = useRef(0);
  const [plan, setPlan] = useState<ConnectionPlan | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState('');
  useEffect(() => () => pending.current?.abort(), []);
  const invalidate = () => { sequence.current += 1; pending.current?.abort(); setPlan(null); setError(''); setBusy(false); };
  const run = async (input: PlanRequest, choices = false) => {
    pending.current?.abort(); const controller = new AbortController(); pending.current = controller;
    const rank = ++sequence.current, before = useAuthStore.getState();
    const current = () => {
      const now = useAuthStore.getState(); return !controller.signal.aborted && sequence.current === rank
        && now.tenant?.id === before.tenant?.id && now.tenant?.slug === before.tenant?.slug && now.sessionGeneration === before.sessionGeneration;
    };
    setBusy(true); setError(''); setPlan(null);
    try {
      const result = await (choices ? onboardingApi.choices(input, controller.signal) : onboardingApi.plan(input, controller.signal));
      if (!current()) return undefined;
      if (!choices) setPlan(result.data); return result.data;
    } catch (failure) {
      if (current()) setError(failure instanceof Error ? failure.message : 'Plan request failed');
      return undefined;
    } finally { if (current()) setBusy(false); }
  };
  return { plan, busy, error, invalidate, run };
}
