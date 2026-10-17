import { useEffect, useRef, useState } from 'react';
import { ApiRequestError } from '@/api/client';
import { useAuthStore } from '@/stores/authStore';

/** A scoped operation cannot update a drawer opened in a newer tenant/session. */
export function usePolicyOperation() {
  const initial = useRef(useAuthStore.getState());
  const alive = useRef(true), running = useRef(false);
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [conflict, setConflict] = useState(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const isCurrent = () => {
    const current = useAuthStore.getState(), source = initial.current;
    return alive.current && current.tenant?.id === source.tenant?.id && current.tenant?.slug === source.tenant?.slug
      && current.sessionGeneration === source.sessionGeneration;
  };
  const clearError = () => { setError(''); setConflict(false); };
  const run = async (operation: (current: () => boolean) => Promise<void>) => {
    if (running.current || !isCurrent()) return;
    running.current = true; setBusy(true); clearError();
    try { await operation(isCurrent); }
    catch (reason) {
      if (isCurrent()) {
        setError(reason instanceof Error ? reason.message : String(reason));
        setConflict(reason instanceof ApiRequestError && reason.status === 409);
      }
    } finally { running.current = false; if (isCurrent()) setBusy(false); }
  };
  return { busy, error, conflict, run, isCurrent, clearError };
}
