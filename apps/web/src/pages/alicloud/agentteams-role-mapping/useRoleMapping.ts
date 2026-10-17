import { useCallback, useEffect, useRef, useState } from 'react';
import { agentteamsRoleMappingApi as api } from '@/api/agentteamsRoleMapping';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { newRequestId } from '@/utils/requestId';
import type { Change, MappingDraft, MappingInput, MappingIntent, MappingState } from './types';
import { failure, uuid } from './text';
import { captureWrite, matchingIntent, rejectedBeforeCommit, type PendingRoleWrite } from './recovery';

export function useRoleMapping(canRead: boolean, canWrite: boolean) {
  const scope = useOperationScope(), listSequence = useRef(0), receiptSequence = useRef(0);
  const activeReads = useRef(new Set<AbortController>()), listRead = useRef<AbortController | null>(null), receiptRead = useRef<AbortController | null>(null);
  const [data, setData] = useState<MappingState | null>(null), [receipt, setReceipt] = useState<MappingIntent | null>(null);
  const [draft, setDraft] = useState<MappingDraft | null>(null), [intent, setIntent] = useState({ asset: '', request: '' });
  const [loading, setLoading] = useState(canRead), [reading, setReading] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState('');
  const pendingWrite = useRef<PendingRoleWrite | null>(null), [recovery, setRecovery] = useState<PendingRoleWrite | null>(null);
  const markOutcome = (request: string, phase: PendingRoleWrite['phase']) => {
    const pending = pendingWrite.current;
    if (!pending || pending.body.request_id !== request || !scope.current() || pending.phase === 'committed') return;
    pendingWrite.current = { ...pending, phase }; setRecovery(pendingWrite.current);
  };
  useEffect(() => { const controllers = activeReads.current; return () => controllers.forEach(controller => controller.abort()); }, []);
  const readState = useCallback(async (sequence: number, controller: AbortController) => {
    activeReads.current.add(controller);
    try {
      const response = await api.state(controller.signal);
      if (controller.signal.aborted || !scope.current() || sequence !== listSequence.current) return null;
      setData(response.data); return response.data;
    } catch (cause) { if (!controller.signal.aborted && scope.current() && sequence === listSequence.current) setError(failure(cause)); return null; }
    finally { activeReads.current.delete(controller); if (!controller.signal.aborted && scope.current() && sequence === listSequence.current) setLoading(false); }
  }, [scope]);
  const refresh = useCallback(async () => {
    if (!canRead || !scope.current()) return null;
    const controller = new AbortController(); listRead.current?.abort(); listRead.current = controller;
    setLoading(true); return readState(++listSequence.current, controller);
  }, [canRead, scope, readState]);
  useEffect(() => {
    if (!canRead || !scope.current()) return;
    const controller = new AbortController(); listRead.current = controller; void readState(++listSequence.current, controller);
    return () => controller.abort();
  }, [canRead, scope, readState]);
  const changeDraft = (value: MappingDraft | null) => { if (!busy && !pendingWrite.current && scope.current()) setDraft(value); };
  const changeIntent = (patch: Partial<typeof intent>) => {
    if (!scope.current() || pendingWrite.current) return;
    receiptSequence.current++; receiptRead.current?.abort(); setReceipt(null); setReading(false); setIntent(old => ({ ...old, ...patch }));
  };
  const readReceipt = async () => {
    const asset = pendingWrite.current?.asset ?? intent.asset, request = pendingWrite.current?.body.request_id ?? intent.request;
    if (!canRead || !uuid(asset) || !uuid(request) || !scope.current()) return;
    const sequence = ++receiptSequence.current, controller = new AbortController(); receiptRead.current?.abort(); receiptRead.current = controller;
    activeReads.current.add(controller); setReading(true); setError('');
    try {
      const response = await api.receipt(asset, request, controller.signal);
      if (controller.signal.aborted || !scope.current() || sequence !== receiptSequence.current) return;
      if (!matchingIntent(response.data, asset, request)) throw new Error('Invalid Role intent receipt / 角色意图回执无法核验');
      setReceipt(response.data); markOutcome(request, 'committed');
    } catch (cause) { if (!controller.signal.aborted && scope.current() && sequence === receiptSequence.current) setError(failure(cause)); }
    finally { activeReads.current.delete(controller); if (!controller.signal.aborted && scope.current() && sequence === receiptSequence.current) setReading(false); }
  };
  const save = async (asset: string, expectedVersion: number, change: Change) => {
    if (!canWrite || !data?.canManage || pendingWrite.current || !uuid(asset) || !Number.isSafeInteger(expectedVersion) || expectedVersion < 0) return;
    const generation = scope.begin(); if (generation === undefined) return;
    const request = newRequestId(), sequence = ++receiptSequence.current, controller = new AbortController();
    activeReads.current.add(controller); setBusy(true); setError(''); setIntent({ asset, request }); setReceipt(null);
    const body: MappingInput = { request_id: request, expected_version: expectedVersion, confirm_local_constraint: true, change: { ...change } };
    pendingWrite.current = captureWrite(asset, body); setRecovery(pendingWrite.current);
    try {
      if (!scope.current(generation)) return;
      const response = await api.save(asset, pendingWrite.current.body, controller.signal);
      if (controller.signal.aborted || !scope.current(generation)) return;
      if (!matchingIntent(response.data, asset, request)) throw new Error('Invalid Role intent receipt / 角色意图回执无法核验');
      if (sequence === receiptSequence.current) {
        setReceipt(response.data); setDraft(old => old?.worker.assetId === asset ? { ...old, expectedVersion: response.data.original.version, confirmed: false } : old);
        pendingWrite.current = null; setRecovery(null);
      } else {
        markOutcome(request, 'committed');
      }
      await refresh();
    } catch (cause) { if (!controller.signal.aborted && scope.current(generation)) {
      markOutcome(request, rejectedBeforeCommit(cause) ? 'rejected' : 'unknown'); setError(failure(cause));
    } }
    finally { activeReads.current.delete(controller); if (scope.finish(generation)) setBusy(false); }
  };
  const beginNewAction = () => {
    const pending = pendingWrite.current;
    if (!canWrite || busy || reading || !scope.current() || !pending || !['committed', 'rejected'].includes(pending.phase)) return;
    pendingWrite.current = null; setRecovery(null); setError(''); setDraft(old => old ? { ...old, confirmed: false } : old);
  };
  return { data, draft, intent, receipt, loading, reading, busy, recovery, writeLocked: recovery !== null, error,
    refresh, changeDraft, changeIntent, readReceipt, save, beginNewAction };
}
export type RoleFlow = ReturnType<typeof useRoleMapping>;
