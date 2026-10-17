import { useCallback, useEffect, useRef, useState } from 'react';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { newRequestId } from '@/utils/requestId';
import { publicationApi } from './api';
import { applicable, matchingObservation, originalObservable, unknownAcknowledgementReady } from './eligibility';
import { failure, usePublicationText, uuid } from './text';
import { initialRequest, rememberRequest, watchRequestScope } from './requestScope';
import type { ApplyInput, Change, Observation, Operation, Preview, PublicationState } from './types';

export interface Baseline { observation: Observation; stateVersion: number }
export function usePublication(canRead: boolean, canWrite: boolean) {
  const scope = useOperationScope(), text = usePublicationText();
  const listSequence = useRef(0), receiptSequence = useRef(0);
  const [data, setData] = useState<PublicationState | null>(null);
  const [baseline, setBaseline] = useState<Baseline | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [operation, setOperation] = useState<Operation | null>(null);
  const [attempted, setAttempted] = useState<string | null>(null);
  const [requestId, setRequestId] = useState(initialRequest);
  const [busy, setBusy] = useState(false), [loading, setLoading] = useState(canRead), [reading, setReading] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => watchRequestScope(() => {
    receiptSequence.current++; setRequestId(''); setOperation(null); setReading(false);
  }), []);

  const readState = useCallback(async (sequence: number, signal?: AbortSignal) => {
    try {
      const response = await publicationApi.state(signal);
      if (signal?.aborted || !scope.current() || sequence !== listSequence.current) return null;
      setData(response.data); return response.data;
    } catch (cause) {
      if (!signal?.aborted && scope.current() && sequence === listSequence.current) setError(failure(cause, text));
      return null;
    } finally { if (!signal?.aborted && scope.current() && sequence === listSequence.current) setLoading(false); }
  }, [scope, text]);
  const refresh = useCallback(async (signal?: AbortSignal) => {
    if (!canRead || !scope.current()) return null;
    const sequence = ++listSequence.current; setLoading(true);
    return readState(sequence, signal);
  }, [canRead, scope, readState]);
  useEffect(() => {
    if (!canRead || !scope.current()) return;
    const controller = new AbortController(); void readState(++listSequence.current, controller.signal);
    return () => controller.abort();
  }, [canRead, readState, scope]);

  async function run(work: (generation: number) => Promise<void>) {
    const generation = scope.begin();
    if (generation === undefined) return;
    setBusy(true); setError('');
    try { await work(generation); }
    catch (cause) { if (scope.current(generation)) setError(failure(cause, text)); }
    finally { if (scope.finish(generation)) setBusy(false); }
  }
  const adopt = () => {
    if (busy || !data || !scope.current() || !matchingObservation(data, data.observation)) return;
    setBaseline({ observation: data.observation!, stateVersion: data.stateVersion }); setPreview(null);
  };
  const observe = async (confirmLive: boolean) => {
    if (!canRead || !data?.canObserve || !data.binding || busy || data.busy
      || (data.binding.transportMode === 'live' && !confirmLive)) return;
    const target = data.binding;
    await run(async generation => {
      setPreview(null);
      if (baseline) setBaseline({ ...baseline, observation: { ...baseline.observation, usable: false } });
      const response = await publicationApi.observe({ request_id: newRequestId(), configuration_version: target.configurationVersion, confirm_live: confirmLive });
      if (!scope.current(generation)) return;
      const latest = await refresh();
      if (scope.current(generation) && latest && matchingObservation(latest, response.data))
        setBaseline({ observation: response.data, stateVersion: latest.stateVersion });
    });
  };
  const prepare = async (change: Change, acknowledge: boolean) => {
    if (!canWrite || !data?.canPrepare || !baseline || busy || data.busy
      || !matchingObservation(data, baseline.observation)) return;
    const unresolved = operation?.requestId === data.unresolvedOperationId ? operation
      : data.operations.find(row => row.requestId === data.unresolvedOperationId) ?? null;
    if (data.unresolvedOperationId && (!acknowledge || !unknownAcknowledgementReady(data, baseline.observation, unresolved))) return;
    const captured = { request_id: newRequestId(), configuration_version: baseline.observation.target.configurationVersion,
      observation_id: baseline.observation.id, expected_state_version: baseline.stateVersion, change,
      ...(data.unresolvedOperationId ? { acknowledge_unknown_operation_id: data.unresolvedOperationId } : {}) };
    await run(async generation => {
      setPreview(null);
      const response = await publicationApi.preview(captured);
      if (scope.current(generation)) { setPreview(response.data); await refresh(); }
    });
  };
  const apply = async (confirm: Pick<ApplyInput, 'confirm_apply' | 'confirm_upsert' | 'confirm_live' | 'confirm_unknown_overlap'>) => {
    if (!canWrite || !data || busy || !applicable(data, preview, attempted)
      || !confirm.confirm_apply || !confirm.confirm_upsert || !preview
      || (preview.target.transportMode === 'live' && !confirm.confirm_live)
      || (preview.unknownOverlapWarning && !confirm.confirm_unknown_overlap)) return;
    const id = newRequestId(), captured = { request_id: id, preview_id: preview.id, expected_state_version: preview.stateVersion, ...confirm };
    await run(async generation => {
      // A failed/aborted HTTP response cannot prove that the server did not consume this preview.
      setAttempted(preview.id); setRequestId(id); rememberRequest(id); setOperation(null);
      const sequence = ++receiptSequence.current;
      const response = await publicationApi.apply(captured);
      if (scope.current(generation) && sequence === receiptSequence.current && response.data.requestId === id) setOperation(response.data);
      if (scope.current(generation)) await refresh();
    });
  };
  const readReceipt = async (id = requestId) => {
    if (!canRead || !uuid(id) || !scope.current()) return;
    const sequence = ++receiptSequence.current; setRequestId(id); rememberRequest(id); setReading(true); setError('');
    try {
      const response = await publicationApi.receipt(id);
      if (scope.current() && sequence === receiptSequence.current && response.data.requestId === id) setOperation(response.data);
    } catch (cause) { if (scope.current() && sequence === receiptSequence.current) setError(failure(cause, text)); }
    finally { if (scope.current() && sequence === receiptSequence.current) setReading(false); }
  };
  const changeRequest = (id: string) => {
    if (!scope.current() || busy) return;
    receiptSequence.current++; setRequestId(id); setOperation(null); setReading(false);
  };
  const invalidatePreview = () => { if (!busy && scope.current()) setPreview(null); };
  const observeOriginal = async (confirmLive: boolean) => {
    if (!canRead || !operation || busy || !originalObservable(data, operation)
      || (data?.binding?.transportMode === 'live' && !confirmLive)) return;
    const captured = operation;
    await run(async generation => {
      setPreview(null);
      if (baseline) setBaseline({ ...baseline, observation: { ...baseline.observation, usable: false } });
      const response = await publicationApi.observeOriginal(captured.requestId, { request_id: newRequestId(),
        configuration_version: captured.recoveryConfigurationVersion!, confirm_live: confirmLive });
      if (scope.current(generation)) {
        // An observation is separate evidence; it never turns an unknown write into accepted.
        const latest = await refresh();
        if (scope.current(generation) && latest && matchingObservation(latest, response.data))
          setBaseline({ observation: response.data, stateVersion: latest.stateVersion });
        await readReceipt(captured.requestId);
      }
    });
  };
  const recover = async () => {
    if (!canWrite || !operation?.allowedActions.includes('recover_local') || busy) return;
    const id = operation.requestId;
    await run(async generation => {
      const sequence = ++receiptSequence.current;
      const response = await publicationApi.recover(id);
      if (scope.current(generation) && sequence === receiptSequence.current && response.data.requestId === id) setOperation(response.data);
      if (scope.current(generation)) await refresh();
    });
  };
  const archive = async (ids: string[], expectedGeneration: number) => {
    if (!canWrite || !data || busy || ids.length === 0 || ids.length > data.limits.maxArchive) return;
    const eligible = new Map(data.operations.map(row => [row.requestId, row]));
    if (ids.some(id => !eligible.get(id)?.archivable || !eligible.get(id)?.allowedActions.includes('archive'))) return;
    const captured = { expected_generation: expectedGeneration, request_ids: [...new Set(ids)].sort() };
    await run(async generation => {
      await publicationApi.archive(captured);
      if (scope.current(generation)) { await refresh(); if (operation && ids.includes(operation.requestId)) await readReceipt(operation.requestId); }
    });
  };
  return { data, baseline, preview, operation, attempted, requestId, busy, loading, reading, error,
    refresh, adopt, observe, prepare, apply, readReceipt, changeRequest, invalidatePreview, observeOriginal, recover, archive };
}
