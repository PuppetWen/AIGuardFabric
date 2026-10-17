import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { provisioningApi } from '@/api/privatelinkProvisioning';
import { useAuthStore } from '@/stores/authStore';
import { receiptValid, stateValid, uuid } from './validation';
import type { ArchiveInput, PreviewInput, State, Receipt, ApplyInput, ObserveInput } from './types';
type Pending = {kind:'preview';body:PreviewInput}|{kind:'apply';body:ApplyInput}|{kind:'observe';body:ObserveInput}|{kind:'archive';body:ArchiveInput};
export function useProvisioning(canRead: boolean) {
  const [params, setParams] = useSearchParams();
  const [queue, setQueue] = useState<State>();
  const [receipt, setReceipt] = useState<Receipt>();
  const [pending, setPending] = useState<Pending>();
  const [recoverId, setRecoverId] = useState(params.get('privatelink_request_id') ?? '');
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const alive = useRef(true); const running = useRef(false); const submitted = useRef<Pending | undefined>(undefined);
  const run = async (work: (current: () => boolean) => Promise<void>) => {
    if (running.current) return;
    const auth = useAuthStore.getState();
    const current = () => alive.current && useAuthStore.getState().tenant?.id === auth.tenant?.id
      && useAuthStore.getState().sessionGeneration === auth.sessionGeneration;
    running.current = true; setBusy(true); setError(false);
    try { await work(current); } catch { if (current()) setError(true); }
    finally { running.current = false; if (current()) setBusy(false); }
  };
  const load = async (current: () => boolean, page = 1, signal?: AbortSignal) => {
    const value = (await provisioningApi.state(page, signal)).data;
    if (!stateValid(value)) throw new Error('invalid state');
    if (current()) setQueue(value);
  };
  const initial = useRef((signal: AbortSignal) => run(current => load(current, 1, signal)));
  useEffect(() => {
    alive.current = true;
    const controller = new AbortController();
    if (canRead) void initial.current(controller.signal);
    return () => { alive.current = false; controller.abort(); };
    // The parent remounts on tenant/session changes; this performs only an initial GET.
  }, [canRead]);
  const refresh = (page = 1) => run(current => load(current, page));
  const write = (intent: Pending) => run(async current => {
    if (submitted.current) return;
    submitted.current = intent; setPending(intent); setConfirmed(false); setReceipt(undefined);
    setRecoverId(intent.body.request_id);
    setParams(previous => { const next = new URLSearchParams(previous); next.set('privatelink_request_id', intent.body.request_id); return next; });
    const response = intent.kind==='preview'?await provisioningApi.preview(intent.body):intent.kind==='apply'?await provisioningApi.apply(intent.body):intent.kind==='observe'?await provisioningApi.observe(intent.body):await provisioningApi.archive(intent.body);
      if (!receiptValid(response.data, intent.body.request_id, intent.kind)) throw new Error('invalid receipt');
      if (current()) { setReceipt(response.data); setConfirmed(true); await load(current); }
    // HTTP error status cannot prove absence of an admitted claim or provider effect.
  });
  const readOriginal = () => run(async current => {
    const original = submitted.current?.body.request_id ?? recoverId;
    if (!uuid(original)) throw new Error('invalid UUID');
    const value = (await provisioningApi.receipt(original)).data;
    if (!receiptValid(value, original, submitted.current?.kind)) throw new Error('invalid receipt');
    if (current()) { setReceipt(value); setConfirmed(true); await load(current); }
    // 404, timeout and untrusted 2xx do not unlock an unknown write.
  });
  const newIntent = () => { if (confirmed && !running.current) { submitted.current = undefined; setPending(undefined); setConfirmed(false); } };
  const recover = (id: string) => run(async current => {
    if (submitted.current) return;
    const value=(await provisioningApi.recover(id)).data;if(!receiptValid(value,id))throw new Error('invalid receipt');if(current()){setReceipt(value);await load(current);}
  });
  return { queue, receipt, pending, recoverId, setRecoverId, confirmed, busy, error, refresh, write, readOriginal, newIntent, recover };
}
