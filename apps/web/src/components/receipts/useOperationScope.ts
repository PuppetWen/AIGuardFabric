import { useCallback, useEffect, useMemo, useRef } from 'react';
import { useAuthStore } from '@/stores/authStore';

/** Keep an older read or operation from publishing into a newer operation or sign-in. */
export function useOperationScope() {
  const initial = useAuthStore.getState();
  const identity = useRef({ tenantId: initial.tenant?.id, tenantSlug: initial.tenant?.slug,
    sessionGeneration: initial.sessionGeneration });
  const lane = useRef({ active: true, generation: 0, busy: false });
  useEffect(() => {
    lane.current.active = true;
    return () => { lane.current.active = false; lane.current.generation++; lane.current.busy = false; };
  }, []);
  const current = useCallback((generation?: number) => {
    const auth = useAuthStore.getState();
    return lane.current.active && (generation === undefined || generation === lane.current.generation)
      && auth.tenant?.id === identity.current.tenantId && auth.tenant?.slug === identity.current.tenantSlug
      && auth.sessionGeneration === identity.current.sessionGeneration;
  }, []);
  const checkpoint = useCallback(() => lane.current.generation, []);
  const begin = useCallback(() => {
    if (!current() || lane.current.busy) return undefined;
    lane.current.busy = true;
    return ++lane.current.generation;
  }, [current]);
  const finish = useCallback((generation: number) => {
    if (generation !== lane.current.generation) return false;
    lane.current.busy = false;
    return current(generation);
  }, [current]);
  const reset = useCallback(() => {
    if (lane.current.busy || !current()) return false;
    lane.current.generation++;
    return true;
  }, [current]);
  return useMemo(() => ({ current, checkpoint, begin, finish, reset }), [current, checkpoint, begin, finish, reset]);
}
