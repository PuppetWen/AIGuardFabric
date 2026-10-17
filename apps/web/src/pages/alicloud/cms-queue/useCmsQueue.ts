import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { cmsQueueApi } from '@/api/cmsQueue';
import { useAuthStore } from '@/stores/authStore';
import { receiptValid, stateValid, uuid } from './validation';
import type { ArchiveInput, EnqueueInput, QueueState, Receipt, SendInput } from './types';
type Pending = { kind: 'enqueue'; body: EnqueueInput } | { kind: 'send'; body: SendInput } | { kind: 'archive'; body: ArchiveInput };
export function useCmsQueue(canRead: boolean) {
  const [params, setParams] = useSearchParams();
  const [queue, setQueue] = useState<QueueState>();
  const [receipt, setReceipt] = useState<Receipt>();
  const [pending, setPending] = useState<Pending>();
  const [recoverId, setRecoverId] = useState(params.get('cms_queue_request_id') ?? '');
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
    const value = (await cmsQueueApi.state(page, signal)).data;
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
    setParams(previous => { const next = new URLSearchParams(previous); next.set('cms_queue_request_id', intent.body.request_id); return next; });
    const response = intent.kind === 'enqueue' ? await cmsQueueApi.enqueue(intent.body)
      : intent.kind === 'send' ? await cmsQueueApi.send(intent.body) : await cmsQueueApi.archive(intent.body);
    if (!receiptValid(response.data, intent.body.request_id, intent.kind)) throw new Error('invalid receipt');
    if (current()) { setReceipt(response.data); setConfirmed(true); await load(current); }
    // HTTP error status alone cannot prove that no claim or provider effect exists.
  });
  const readOriginal = () => run(async current => {
    const original = submitted.current?.body.request_id ?? recoverId;
    if (!uuid(original)) throw new Error('invalid UUID');
    const value = (await cmsQueueApi.receipt(original)).data;
    if (!receiptValid(value, original, submitted.current?.kind)) throw new Error('invalid receipt');
    if (current()) { setReceipt(value); setConfirmed(true); await load(current); }
    // 404, timeout and untrusted 2xx do not unlock an unknown write.
  });
  const newIntent = () => { if (confirmed && !running.current) { submitted.current = undefined; setPending(undefined); setConfirmed(false); } };
  const recover = (id: string) => run(async current => {
    if (submitted.current) return;
    await cmsQueueApi.recover(id); if (current()) await load(current);
  });
  return { queue, receipt, pending, recoverId, setRecoverId, confirmed, busy, error, refresh, write, readOriginal, newIntent, recover };
}
