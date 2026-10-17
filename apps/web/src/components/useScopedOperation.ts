import { useEffect, useRef, useState } from 'react';
import { useAuthStore } from '@/stores/authStore';

function identity() {
  const state = useAuthStore.getState();
  return `${state.tenant?.id}:${state.sessionGeneration}`;
}

/** Prevent duplicate submissions and ignore completions after a tenant/session change. */
export function useScopedOperation() {
  const active = useRef(false);
  const mounted = useRef(true);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);
  const run = async (operation: (current: () => boolean) => Promise<void>) => {
    if (active.current || !mounted.current) return;
    active.current = true;
    setBusy(true);
    const startedFor = identity();
    const current = () => mounted.current && identity() === startedFor;
    try { await operation(current); }
    finally {
      active.current = false;
      if (current()) setBusy(false);
    }
  };
  return { busy, run };
}
