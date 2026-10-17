import { useEffect, useRef, useState } from 'react';
import { useAuthStore } from '@/stores/authStore';
import { newRequestId } from '@/utils/requestId';
import { multiTargetApi, type MultiExecute, type MultiPreview, type MultiProfile, type MultiRun, type MultiSelection, type MultiRecent } from '@/api/redteamMultiTarget';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export function useMultiTarget() {
  const [agents, setAgents] = useState<MultiProfile[]>([]); const [mcps, setMcps] = useState<MultiProfile[]>([]);
  const [preview, setPreview] = useState<MultiPreview | null>(null); const [receipt, setReceipt] = useState<MultiRun | null>(null);
  const [requestId, setRequestId] = useState(''); const [attempted, setAttempted] = useState(false);
  const [recent, setRecent] = useState<MultiRecent | null>(null); const recentRank = useRef(0);
  const [busy, setBusy] = useState(false); const [readBusy, setReadBusy] = useState(false); const [localBusy, setLocalBusy] = useState(false); const [error, setError] = useState('');
  const life = useRef({ live: true, epoch: 0, active: false, localActive: false, readRank: 0, controllers: new Set<AbortController>() });
  const prepared = useRef<MultiSelection[] | null>(null);
  const held = useRef<{ body: MultiExecute; epoch: number; terminal: boolean } | null>(null);
  const [heldView, setHeldView] = useState<{ id: string; epoch: number; terminal: boolean } | null>(null);
  const [scopeEpoch, setScopeEpoch] = useState(0);
  useEffect(() => {
    const state = life.current; state.live = true;
    const unsubscribe = useAuthStore.subscribe((next, previous) => {
      if (next.tenant?.id !== previous.tenant?.id || next.tenant?.slug !== previous.tenant?.slug || next.sessionGeneration !== previous.sessionGeneration) {
        state.epoch++; setScopeEpoch(state.epoch); for (const controller of state.controllers) controller.abort();
      }
    });
    const controller = new AbortController(); state.controllers.add(controller); const epoch = state.epoch;
    void Promise.all([multiTargetApi.profiles('agent', controller.signal), multiTargetApi.profiles('mcp', controller.signal)]).then(([a, m]) => {
      if (state.live && state.epoch === epoch && !controller.signal.aborted) { setAgents(a.items); setMcps(m.items); }
    }).catch(() => { if (state.live && state.epoch === epoch && !controller.signal.aborted) setError('Target inventory unavailable / 目标库存不可用'); });
    return () => { state.live = false; unsubscribe(); for (const value of state.controllers) value.abort(); state.controllers.clear(); };
  }, []);
  async function run(operation: (signal: AbortSignal, current: () => boolean) => Promise<void>, lane: 'main' | 'read' | 'local' = 'main') {
    const state = life.current; if (lane === 'main' && state.active || lane === 'local' && state.localActive) return;
    if (lane === 'main') { state.active = true; setBusy(true); } else if (lane === 'local') { state.localActive = true; setLocalBusy(true); } else setReadBusy(true);
    const epoch = state.epoch; const controller = new AbortController(); state.controllers.add(controller);
    const current = () => state.live && state.epoch === epoch && !controller.signal.aborted;
    setError('');
    try { await operation(controller.signal, current); }
    catch { if (current()) setError('Request unresolved or rejected. Read the original UUID; do not resend. / 请求未确认或被拒绝，请读取原 UUID，不要重发。'); }
    finally { state.controllers.delete(controller); if (lane === 'main') state.active = false; if (lane === 'local') state.localActive = false; if (current()) { if (lane === 'read') setReadBusy(false); else if (lane === 'local') setLocalBusy(false); else setBusy(false); } }
  }
  const resetPreview = () => { if (!held.current) { prepared.current = null; setPreview(null); } };
  function acceptReceipt(result: MultiRun, requestedId: string, current: () => boolean, rank: number) {
    if (!current() || life.current.readRank !== rank) return;
    if (result.requestId !== requestedId) throw new Error('Receipt identity mismatch');
    const pending = held.current;
    if (pending?.body.request_id === requestedId && pending.epoch === life.current.epoch) {
      pending.terminal = result.completionState === 'complete';
      setHeldView({ id: pending.body.request_id, epoch: pending.epoch, terminal: pending.terminal });
    }
    setReceipt(result);
  }
  const review = (targets: MultiSelection[]) => run(async (signal, current) => {
    if (held.current) return;
    const result = await multiTargetApi.preview(targets, signal);
    if (current()) { prepared.current = targets.map(row => ({ ...row })); setPreview(result); }
  });
  const execute = (confirmLive: boolean) => run(async (signal, current) => {
    if (held.current || !preview || !prepared.current) return;
    const id = newRequestId(); const body: MultiExecute = { request_id: id, targets: prepared.current, reviewed_topology_sha256: preview.topologySha256, confirm_registered_targets: true, confirm_live: confirmLive };
    held.current = { body, epoch: life.current.epoch, terminal: false };
    setHeldView({ id, epoch: life.current.epoch, terminal: false });
    setRequestId(id); setAttempted(true); setReceipt(null); const rank = ++life.current.readRank;
    const result = await multiTargetApi.execute(body, signal);
    acceptReceipt(result, id, current, rank);
  });
  const readOriginal = (requestedId: string) => run(async (signal, current) => {
    const id = requestedId.trim(); if (!uuid.test(id)) { if (current()) setError('Enter a canonical UUID / 请输入规范 UUID'); return; }
    setRequestId(id);
    const rank = ++life.current.readRank; const result = await multiTargetApi.get(id, signal);
    acceptReceipt(result, id, current, rank);
  }, 'read');
  const read = () => readOriginal(requestId);
  const recentRuns = (offset = 0) => run(async (signal, current) => {
    const rank = ++recentRank.current; const result = await multiTargetApi.recent(offset, signal);
    if (current() && rank === recentRank.current) setRecent(result);
  }, 'read');
  const archive = (reviewed: MultiRun) => run(async (signal, current) => {
    if (reviewed.requestId !== requestId.trim() || reviewed.completionState !== 'complete'
      || reviewed.status === 'archived' || !Number.isSafeInteger(reviewed.generation) || reviewed.generation < 1) return;
    const id = reviewed.requestId; const rank = ++life.current.readRank;
    const result = await multiTargetApi.archive(id, reviewed.generation, signal);
    acceptReceipt(result, id, current, rank);
  }, 'local');
  const local = (action: 'cancel' | 'recover') => run(async (signal, current) => {
    const id = requestId.trim(); if (!uuid.test(id)) return; const rank = ++life.current.readRank;
    const result = await multiTargetApi.local(id, action, signal); acceptReceipt(result, id, current, rank);
  }, 'local');
  const canNewIntent = receipt?.completionState === 'complete' && !busy && !readBusy && !localBusy
    && (!heldView || heldView.terminal && heldView.epoch === scopeEpoch && receipt.requestId === heldView.id);
  const newIntent = () => {
    if (!canNewIntent || life.current.active || life.current.localActive) return;
    const pending = held.current;
    if (pending && (!pending.terminal || pending.epoch !== life.current.epoch || receipt?.requestId !== pending.body.request_id)) return;
    held.current = null; setHeldView(null); prepared.current = null; setAttempted(false); setPreview(null); setReceipt(null); setRequestId('');
  };
  return { agents, mcps, preview, receipt, requestId, setRequestId, attempted, busy, readBusy, localBusy, error, canNewIntent, resetPreview, review, execute, read, local, newIntent, recent, recentRuns, readOriginal, archive };
}
