import { useCallback, useEffect, useRef, useState } from 'react';
import { agentteamsOrchestrationApi as api } from '@/api/agentteamsOrchestration';
import { ApiRequestError } from '@/api/transport';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { choose, immutable, input, matching, matchingPreview } from './definition';
import { failure, uuid } from './text';
import type { Draft, Pending, Prepared, Receipt, State, Target } from './types';

export function useOrchestration(canRead: boolean, canWrite: boolean) {
  const scope = useOperationScope(), listSequence = useRef(0), receiptSequence = useRef(0), previewSequence = useRef(0);
  const controllers = useRef(new Set<AbortController>()), listRead = useRef<AbortController | null>(null), receiptRead = useRef<AbortController | null>(null);
  const pending = useRef<Pending | null>(null), preparedRef = useRef<Prepared | null>(null);
  const [data, setData] = useState<State | null>(null), [draft, setDraft] = useState<Draft | null>(null), [prepared, setPrepared] = useState<Prepared | null>(null);
  const [receipt, setReceipt] = useState<Receipt | null>(null), [requestId, setRequestId] = useState(''), [recovery, setRecovery] = useState<Pending | null>(null);
  const [loading, setLoading] = useState(canRead), [busy, setBusy] = useState(false), [reading, setReading] = useState(false), [error, setError] = useState('');
  useEffect(() => { const owned = controllers.current; return () => owned.forEach(controller => controller.abort()); }, []);
  const readState = useCallback(async (controller: AbortController, sequence: number) => {
    controllers.current.add(controller);
    try { const response = await api.state(controller.signal); if (!controller.signal.aborted && scope.current() && sequence === listSequence.current) { setData(response.data); return response.data; } }
    catch (cause) { if (!controller.signal.aborted && scope.current() && sequence === listSequence.current) setError(failure(cause)); }
    finally { controllers.current.delete(controller); if (!controller.signal.aborted && scope.current() && sequence === listSequence.current) setLoading(false); }
    return null;
  }, [scope]);
  const refresh = useCallback(async () => {
    if (!canRead || !scope.current()) return null;
    const controller = new AbortController(); listRead.current?.abort(); listRead.current = controller; setLoading(true);
    return readState(controller, ++listSequence.current);
  }, [canRead, readState, scope]);
  useEffect(() => { if (!canRead) return; const controller = new AbortController(); listRead.current = controller; void readState(controller, ++listSequence.current); return () => controller.abort(); }, [canRead, readState]);
  const updateDraft = (value: Draft | null) => { if (!scope.current() || busy || pending.current) return; previewSequence.current++; preparedRef.current = null; setPrepared(null); setDraft(value); };
  const select = (target: Target) => updateDraft(choose(target));
  const prepare = async () => {
    if (!draft || !canWrite || !data?.canManage || pending.current || busy || !scope.current()) return;
    const generation = scope.begin(); if (generation === undefined) return;
    const sequence = ++previewSequence.current, controller = new AbortController(); controllers.current.add(controller); setBusy(true); setError('');
    try { const body = input(draft); const response = await api.preview(draft.target.teamName, body, controller.signal);
      if (!controller.signal.aborted && scope.current(generation) && sequence === previewSequence.current) {
        if (!matchingPreview(response.data, draft.target.teamName, body)) throw new Error('Invalid preview / 预览无法核验');
        preparedRef.current = { team: draft.target.teamName, body: immutable(body), preview: response.data }; setPrepared(preparedRef.current);
      } }
    catch (cause) { if (!controller.signal.aborted && scope.current(generation)) setError(failure(cause)); }
    finally { controllers.current.delete(controller); if (scope.finish(generation)) setBusy(false); }
  };
  const outcome = (phase: Pending['phase']) => { if (scope.current() && pending.current && pending.current.phase !== 'committed') { pending.current = { ...pending.current, phase }; setRecovery(pending.current); } };
  const apply = async () => {
    const candidate = preparedRef.current;
    if (!candidate || pending.current || !canWrite || !data?.canManage || !candidate.body.confirm_application_owned || (candidate.body.change.action === 'sync' && !candidate.body.confirm_mock_sync)) return;
    const generation = scope.begin(); if (generation === undefined) return;
    pending.current = { ...candidate, phase: 'in_flight' }; setRecovery(pending.current); setRequestId(candidate.body.request_id);
    const sequence = ++receiptSequence.current, controller = new AbortController(); controllers.current.add(controller); setBusy(true); setError(''); setReceipt(null);
    try { const response = await api.apply(candidate.team, candidate.body, controller.signal);
      if (controller.signal.aborted || !scope.current(generation)) return;
      if (!matching(response.data, candidate, candidate.body.request_id)) throw new Error('Invalid original receipt / 原回执无法核验');
      if (sequence === receiptSequence.current) { setReceipt(response.data); pending.current = null; setRecovery(null); preparedRef.current = null; setPrepared(null);
        setDraft(old => old ? { ...old, expectedVersion: response.data.version, text: JSON.stringify(candidate.preview.result.local ?? old.target.template, null, 2), confirmed: false, mockConfirmed: false } : old); }
      else outcome('committed');
      await refresh();
    } catch (cause) { if (!controller.signal.aborted && scope.current(generation)) { outcome(cause instanceof ApiRequestError && cause.status >= 400 && cause.status < 500 && cause.status !== 408 ? 'rejected' : 'unknown'); setError(failure(cause)); } }
    finally { controllers.current.delete(controller); if (scope.finish(generation)) setBusy(false); }
  };
  const readReceipt = async () => {
    const id = pending.current?.body.request_id ?? requestId;
    if (!canRead || !uuid(id) || !scope.current()) return;
    const sequence = ++receiptSequence.current, controller = new AbortController(); receiptRead.current?.abort(); receiptRead.current = controller; controllers.current.add(controller); setReading(true); setError('');
    try { const response = await api.receipt(id, controller.signal); if (controller.signal.aborted || !scope.current() || sequence !== receiptSequence.current) return;
      if (!matching(response.data, pending.current ?? undefined, id)) throw new Error('Invalid original receipt / 原回执无法核验'); setReceipt(response.data); outcome('committed'); }
    catch (cause) { if (!controller.signal.aborted && scope.current() && sequence === receiptSequence.current) setError(failure(cause)); }
    finally { controllers.current.delete(controller); if (!controller.signal.aborted && scope.current() && sequence === receiptSequence.current) setReading(false); }
  };
  const changeRequest = (value: string) => { if (pending.current || !scope.current()) return; receiptRead.current?.abort(); receiptSequence.current++; setRequestId(value); setReceipt(null); setReading(false); };
  const beginNew = () => { if (busy || reading || !scope.current() || !pending.current || !['committed', 'rejected'].includes(pending.current.phase)) return;
    pending.current = null; setRecovery(null); preparedRef.current = null; setPrepared(null); setDraft(old => old ? { ...old, confirmed: false, mockConfirmed: false, sourceConfirmed: false } : old); };
  return { data, draft, prepared, receipt, requestId, recovery, writeLocked: recovery !== null, loading, busy, reading, error,
    refresh, updateDraft, select, prepare, apply, readReceipt, changeRequest, beginNew, reportError: setError };
}
export type OrchestrationFlow = ReturnType<typeof useOrchestration>;
