import { useCallback, useEffect, useRef, useState } from 'react';
import { schedulerManagedJobsApi as api } from '@/api/schedulerManagedJobs';
import { schedulerNativeApi as native } from '@/api/schedulerNative';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { useAuthStore } from '@/stores/authStore';
import { newRequestId } from '@/utils/requestId';
import type { ObservationReceipt, SchedulerState } from '../scheduler-native/types';
import type { ApplyInput, Intent, ManagedState, Operation, Preview, PreviewInput } from './types';
import { digest, positiveInt64, previewRejected, safeFailure, uuid } from './text';

const invalid = () => new Error('Acknowledgement identity invalid / 返回身份不匹配');
export function useManagedJobs(canRead: boolean, canManage: boolean) {
  const scope = useOperationScope(), reads = useRef(new Set<AbortController>()), latest = useRef(0), receiptSequence = useRef(0);
  const listRead = useRef<AbortController | null>(null), originalRead = useRef<AbortController | null>(null);
  const held = useRef<Intent | null>(null), attempted = useRef(new Set<string>()), observing = useRef(false);
  const [data, setData] = useState<ManagedState | null>(null), [nativeState, setNative] = useState<SchedulerState | null>(null);
  const [observation, setObservation] = useState<ObservationReceipt | null>(null), [preview, setPreview] = useState<Preview | null>(null);
  const [operation, setOperation] = useState<Operation | null>(null), [intent, setIntent] = useState<Intent | null>(null);
  const [attemptedId, setAttemptedId] = useState<string | null>(null);
  const [observationRequestId, setObservationRequestId] = useState('');
  const [requestId, setRequestId] = useState(''), [purpose, setPurpose] = useState<'apply' | 'preview'>('apply');
  const [busy, setBusy] = useState(false), [reading, setReading] = useState(false), [loading, setLoading] = useState(canRead), [error, setError] = useState('');
  useEffect(() => { const active = reads.current; return () => active.forEach(controller => controller.abort()); }, []);
  const load = useCallback(async (rank: number, controller: AbortController) => {
    reads.current.add(controller);
    try {
      const [state, other] = await Promise.all([api.state(controller.signal), native.state(controller.signal)]);
      if (!controller.signal.aborted && scope.current() && rank === latest.current) {
        const tenant = useAuthStore.getState().tenant?.id;
        if ((state.data.target && state.data.target.tenant !== tenant) || other.data.tenantId !== tenant) throw invalid();
        setData(state.data); setNative(other.data);
      }
    } catch (cause) { if (!controller.signal.aborted && scope.current() && rank === latest.current) setError(safeFailure(cause)); }
    finally { reads.current.delete(controller); if (!controller.signal.aborted && scope.current() && rank === latest.current) setLoading(false); }
  }, [scope]);
  const refresh = useCallback(async () => {
    if (!canRead || !scope.current()) return; listRead.current?.abort();
    const controller = new AbortController(); listRead.current = controller; setLoading(true); await load(++latest.current, controller);
  }, [canRead, scope, load]);
  useEffect(() => { if (!canRead) return; const controller = new AbortController(); listRead.current = controller; void load(++latest.current, controller); return () => controller.abort(); }, [canRead, load]);
  function hold(value: Intent, select = true) { held.current = value; setIntent(value); if (select) { setPurpose(value.purpose); setRequestId(value.id); } }
  function publishOperation(row: Operation, expected: string) {
    if (row.requestId !== expected || !digest(row.inputHash) || !row.target || row.target.tenant !== useAuthStore.getState().tenant?.id || !digest(row.target.fingerprint)
      || !Number.isSafeInteger(row.configurationVersion) || row.configurationVersion <= 0 || row.configurationVersion !== row.target.configurationVersion
      || !['running', 'pending_audit', 'complete'].includes(row.completionState) || !Array.isArray(row.allowedActions)
      || typeof row.archived !== 'boolean' || typeof row.archivable !== 'boolean') throw invalid();
    setOperation(row);
    if (held.current?.purpose === 'apply' && held.current.id === expected && row.completionState === 'complete') hold({ ...held.current, state: 'known' });
  }
  function publishPreview(row: Preview, expected: string) {
    if (row.id !== expected || !digest(row.fingerprint) || !row.target || row.target.tenant !== useAuthStore.getState().tenant?.id || !digest(row.target.fingerprint)
      || !Number.isSafeInteger(row.configurationVersion) || row.configurationVersion <= 0 || row.configurationVersion !== row.target.configurationVersion
      || typeof row.archived !== 'boolean' || typeof row.canApply !== 'boolean' || typeof row.archivable !== 'boolean'
      || (!row.archived && (!positiveInt64(row.desired?.id) || !Number.isFinite(Date.parse(row.expiresAt ?? ''))))) throw invalid();
    setPreview(row);
    if (held.current?.purpose === 'preview' && held.current.id === expected) hold({ ...held.current, state: 'known' });
  }
  const locked = () => held.current && held.current.state !== 'known' && held.current.state !== 'rejected';
  const readOriginal = async (id = requestId, type = purpose) => {
    if (!canRead || !uuid(id) || !scope.current()) return;
    originalRead.current?.abort(); const rank = ++receiptSequence.current, controller = new AbortController(); originalRead.current = controller; reads.current.add(controller); setReading(true); setError('');
    setRequestId(id); setPurpose(type);
    try {
      if (type === 'preview') { const reply = await api.readPreview(id, controller.signal);
        if (!controller.signal.aborted && scope.current() && rank === receiptSequence.current) publishPreview(reply.data, id); }
      else { const reply = await api.receipt(id, controller.signal);
        if (!controller.signal.aborted && scope.current() && rank === receiptSequence.current) publishOperation(reply.data, id); }
    } catch (cause) { if (!controller.signal.aborted && scope.current() && rank === receiptSequence.current) setError(safeFailure(cause)); }
    finally { reads.current.delete(controller); if (!controller.signal.aborted && scope.current() && rank === receiptSequence.current) setReading(false); }
  };
  const changeRequest = (id: string, type = purpose) => {
    if (!scope.current()) return; originalRead.current?.abort(); receiptSequence.current++; setRequestId(id); setPurpose(type); setReading(false);
  };
  const prepare = async (body: Omit<PreviewInput, 'request_id'>) => {
    if (!canManage || !data?.canPrepare || locked() || !scope.current()) return;
    const generation = scope.begin(); if (generation === undefined) return;
    const id = newRequestId(), input: PreviewInput = { ...body, request_id: id }; const rank = ++receiptSequence.current;
    hold({ purpose: 'preview', id, body: input, state: 'waiting' }); setBusy(true); setError(''); setPreview(null);
    try { const reply = await api.preview(input); if (scope.current(generation) && rank === receiptSequence.current) publishPreview(reply.data, id); }
    catch (cause) { if (scope.current(generation) && held.current?.id === id && held.current.state !== 'known') { hold({ purpose: 'preview', id, body: input, state: previewRejected(cause) ? 'rejected' : 'unknown' }, rank === receiptSequence.current); if (rank === receiptSequence.current) setError(safeFailure(cause)); } }
    finally { if (scope.finish(generation)) setBusy(false); }
  };
  const apply = async (confirmed: { noCas: boolean; callback: boolean; live: boolean; unknown: boolean }) => {
    if (!canManage || !data?.canManage || !preview?.canApply || preview.archived || locked() || attempted.current.has(preview.id)
      || !confirmed.noCas || !confirmed.callback || (preview.target.transportMode === 'live' && !confirmed.live)) return;
    const generation = scope.begin(); if (generation === undefined) return;
    const id = newRequestId(), input: ApplyInput = { preview_id: preview.id, preview_fingerprint: preview.fingerprint,
      confirm_no_cloud_cas: true, confirm_callback_unknown: true, confirm_live: confirmed.live, confirm_unknown_overlap: confirmed.unknown };
    attempted.current.add(preview.id); setAttemptedId(preview.id); const rank = ++receiptSequence.current;
    hold({ purpose: 'apply', id, body: input, state: 'waiting' }); setBusy(true); setError(''); setOperation(null);
    try { const reply = await api.apply(id, input); if (scope.current(generation) && rank === receiptSequence.current) publishOperation(reply.data, id); }
    catch (cause) { if (scope.current(generation) && held.current?.id === id && held.current.state !== 'known') {
      hold({ purpose: 'apply', id, body: input, state: 'unknown' }, rank === receiptSequence.current); if (rank === receiptSequence.current) setError(safeFailure(cause)); } }
    finally { if (scope.finish(generation)) { setBusy(false); await refresh(); } }
  };
  const release = () => {
    if (!scope.current() || busy || locked()) return false;
    held.current = null; setIntent(null); setPreview(null); setOperation(null); setError(''); return true;
  };
  const observe = async (live: boolean, initialize: boolean) => {
    const target = nativeState?.sourceTarget;
    if (!canRead || !nativeState?.canObserve || !target || observing.current || nativeState.busy
      || (target.transportMode === 'live' && !live) || (initialize && (!canManage || !nativeState.canInitMock))) return;
    observing.current = true; const generation = scope.begin(); if (generation === undefined) { observing.current = false; return; }
    setBusy(true); setError('');
    try { const id = newRequestId(); setObservationRequestId(id); const reply = await native.observe({ request_id: id, configuration_version: target.configurationVersion,
      confirm_live: live, initialize_mock_fixture: initialize });
      if (scope.current(generation)) { if (reply.data.requestId !== id) throw invalid(); setObservation(reply.data); await refresh(); } }
    catch (cause) { if (scope.current(generation)) setError(safeFailure(cause)); }
    finally { observing.current = false; if (scope.finish(generation)) setBusy(false); }
  };
  const readObservation = async (id: string, page = 1) => {
    if (!canRead || !uuid(id) || !scope.current() || !Number.isSafeInteger(page) || page < 1) return;
    originalRead.current?.abort(); const rank = ++receiptSequence.current, controller = new AbortController(); originalRead.current = controller; reads.current.add(controller); setReading(true);
    try { const reply = await native.receipt(id, page, controller.signal, 50);
      if (!controller.signal.aborted && scope.current() && rank === receiptSequence.current && reply.data.requestId === id) setObservation(reply.data); }
    catch (cause) { if (!controller.signal.aborted && scope.current() && rank === receiptSequence.current) setError(safeFailure(cause)); }
    finally { reads.current.delete(controller); if (!controller.signal.aborted && scope.current() && rank === receiptSequence.current) setReading(false); }
  };
  const localAction = async (action: 'recover_local' | 'observe') => {
    if (!canManage || !operation?.allowedActions.includes(action)) return;
    const generation = scope.begin(); if (generation === undefined) return; const id = operation.requestId, rank = ++receiptSequence.current;
    setBusy(true); setError('');
    try { const reply = await (action === 'recover_local' ? api.recover(id) : api.observeOriginal(id));
      if (scope.current(generation) && rank === receiptSequence.current) publishOperation(reply.data, id); }
    catch (cause) { if (scope.current(generation) && rank === receiptSequence.current) setError(safeFailure(cause)); }
    finally { if (scope.finish(generation)) { setBusy(false); await refresh(); } }
  };
  const archive = async (ids: string[], generation: number) => {
    if (!canManage || !data?.canManage || !ids.length || ids.length > Math.min(48, data.limits.maxArchive)
      || new Set(ids).size !== ids.length || ids.some(id => !uuid(id))) return;
    const eligible = new Set([...data.operations, ...(operation ? [operation] : [])].filter(row => row.archivable).map(row => row.requestId));
    data.previews.filter(row => row.archivable).forEach(row => eligible.add(row.id)); if (ids.some(id => !eligible.has(id))) return;
    const lane = scope.begin(); if (lane === undefined) return; setBusy(true); setError('');
    try { await api.archive([...ids].sort(), generation); if (scope.current(lane)) { await refresh(); if (operation && ids.includes(operation.requestId)) await readOriginal(operation.requestId, 'apply'); } }
    catch (cause) { if (scope.current(lane)) setError(safeFailure(cause)); }
    finally { if (scope.finish(lane)) setBusy(false); }
  };
  return { data, nativeState, observation, observationRequestId, preview, operation, intent, requestId, purpose, busy, reading, loading, error,
    intentLocked: !!intent && intent.state !== 'known' && intent.state !== 'rejected', attempted: !!preview && attemptedId === preview.id,
    refresh, readOriginal, changeRequest, prepare, apply, release, observe, readObservation, localAction, archive };
}
export type ManagedController = ReturnType<typeof useManagedJobs>;
