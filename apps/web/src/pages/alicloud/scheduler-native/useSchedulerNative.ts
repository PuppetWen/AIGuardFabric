import { useCallback, useEffect, useRef, useState } from 'react';
import { schedulerNativeApi as api } from '@/api/schedulerNative';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { newRequestId } from '@/utils/requestId';
import type { Assignment, ObservationReceipt, SchedulerState } from './types';
import { adoptable, failure, uuid } from './text';

export function useSchedulerNative(canRead: boolean, canWrite: boolean) {
  const scope = useOperationScope(), listSequence = useRef(0), receiptSequence = useRef(0);
  const reads = useRef(new Set<AbortController>()), receiptRead = useRef<AbortController | null>(null);
  const [data, setData] = useState<SchedulerState | null>(null), [receipt, setReceipt] = useState<ObservationReceipt | null>(null);
  const [requestId, setRequestId] = useState(''), [intentId, setIntentId] = useState('');
  const [busy, setBusy] = useState(false), [reading, setReading] = useState(false), [loading, setLoading] = useState(canRead), [error, setError] = useState('');
  useEffect(() => { const active = reads.current; return () => active.forEach(controller => controller.abort()); }, []);
  const readState = useCallback(async (sequence: number, controller: AbortController) => {
    reads.current.add(controller);
    try {
      const response = await api.state(controller.signal);
      if (controller.signal.aborted || !scope.current() || sequence !== listSequence.current) return null;
      setData(response.data); return response.data;
    } catch (cause) {
      if (!controller.signal.aborted && scope.current() && sequence === listSequence.current) setError(failure(cause));
      return null;
    } finally {
      reads.current.delete(controller);
      if (!controller.signal.aborted && scope.current() && sequence === listSequence.current) setLoading(false);
    }
  }, [scope]);
  const refresh = useCallback(async () => {
    if (!canRead || !scope.current()) return null;
    setLoading(true); return readState(++listSequence.current, new AbortController());
  }, [canRead, scope, readState]);
  useEffect(() => {
    if (!canRead || !scope.current()) return;
    const controller = new AbortController(); void readState(++listSequence.current, controller);
    return () => controller.abort();
  }, [canRead, scope, readState]);
  async function run(work: (generation: number) => Promise<void>) {
    const generation = scope.begin(); if (generation === undefined) return;
    setBusy(true); setError('');
    try { await work(generation); }
    catch (cause) { if (scope.current(generation)) setError(failure(cause)); }
    finally { if (scope.finish(generation)) setBusy(false); }
  }
  const readReceipt = async (id = requestId, page = 1) => {
    if (!canRead || !uuid(id) || !scope.current() || !Number.isSafeInteger(page) || page < 1) return;
    const sequence = ++receiptSequence.current, controller = new AbortController();
    receiptRead.current?.abort(); receiptRead.current = controller; reads.current.add(controller);
    setRequestId(id); setReading(true); setError('');
    try {
      const pageSize = receipt?.requestId === id ? receipt.observation?.pageSize ?? 50 : 50;
      const response = await api.receipt(id, page, controller.signal, pageSize);
      if (!controller.signal.aborted && scope.current() && sequence === receiptSequence.current && response.data.requestId === id) setReceipt(response.data);
    } catch (cause) {
      if (!controller.signal.aborted && scope.current() && sequence === receiptSequence.current) setError(failure(cause));
    } finally {
      reads.current.delete(controller);
      if (!controller.signal.aborted && scope.current() && sequence === receiptSequence.current) setReading(false);
    }
  };
  const changeRequest = (id: string) => {
    if (!scope.current()) return;
    receiptSequence.current++; receiptRead.current?.abort(); setRequestId(id); setReceipt(null); setReading(false);
  };
  const observe = async (live: boolean, initialize: boolean) => {
    if (!canRead || !data?.canObserve || !data.sourceTarget || data.busy || busy
      || (data.sourceTarget.transportMode === 'live' && !live) || (initialize && (!canWrite || !data.canInitMock))) return;
    const id = newRequestId(), body = { request_id: id, configuration_version: data.sourceTarget.configurationVersion,
      confirm_live: live, initialize_mock_fixture: initialize };
    await run(async generation => {
      setRequestId(id); setReceipt(null); const sequence = ++receiptSequence.current;
      const response = await api.observe(body);
      if (scope.current(generation) && sequence === receiptSequence.current && response.data.requestId === id) setReceipt(response.data);
      if (scope.current(generation)) await refresh();
    });
  };
  const replace = async (bindings: Assignment[], expectedVersion: number, observation: ObservationReceipt) => {
    if (!canWrite || !data?.canBind || busy || !adoptable(data, observation) || bindings.length > 6
      || new Set(bindings.map(row => row.job_id)).size !== bindings.length) return;
    const id = newRequestId(), body = { action: 'replace' as const, request_id: id, expected_version: expectedVersion,
      configuration_version: observation.originalTarget!.configurationVersion, observation_id: observation.requestId,
      bindings: bindings.map(row => ({ ...row })), confirm_local_only: true as const };
    await run(async generation => { setIntentId(id); await api.bind(body); if (scope.current(generation)) await refresh(); });
  };
  const disable = async (expectedVersion: number) => {
    if (!canWrite || busy || !data) return;
    const id = newRequestId();
    await run(async generation => {
      setIntentId(id); await api.bind({ action: 'disable', request_id: id, expected_version: expectedVersion });
      if (scope.current(generation)) await refresh();
    });
  };
  const archive = async (ids: string[], expectedGeneration: number) => {
    if (!canWrite || busy || !data || !ids.length || ids.length > Math.min(100, data.limits.maxArchive) || new Set(ids).size !== ids.length) return;
    const eligible = new Map(data.recentObservations.map(row => [row.requestId, row])); if (receipt) eligible.set(receipt.requestId, receipt);
    if (ids.some(id => !eligible.get(id)?.archivable || !eligible.get(id)?.allowedActions.includes('archive'))) return;
    const body = { expected_generation: expectedGeneration, request_ids: [...ids].sort() };
    await run(async generation => {
      await api.archive(body);
      if (scope.current(generation)) { await refresh(); if (receipt && ids.includes(receipt.requestId)) await readReceipt(receipt.requestId); }
    });
  };
  return { data, receipt, requestId, intentId, busy, reading, loading, error, refresh, readReceipt, changeRequest, observe, replace, disable, archive };
}
export type SchedulerController = ReturnType<typeof useSchedulerNative>;
