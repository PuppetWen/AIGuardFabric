import { useCallback, useEffect, useRef, useState } from 'react';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { newRequestId } from '@/utils/requestId';
import { apigPublicationApi as api } from '@/api/apigPolicyPublication';
import type { ApigChange, ApigObservation, ApigOperation, ApigPreview, ApigPublicationState, ApplyConfirmations } from '@/types/apigPolicyPublication';
import { applicable, matchingObservation, originalObservable, unknownReady } from './eligibility';
import { failure, uuid } from './text';
import { initialRequest, rememberRequest, watchRequestScope } from './requestScope';

export interface Baseline { observation: ApigObservation; stateVersion: number }
export function useApigPublication(canRead: boolean, canWrite: boolean) {
  const scope = useOperationScope(), listSequence = useRef(0), receiptSequence = useRef(0);
  const reads = useRef(new Set<AbortController>()), receiptRead = useRef<AbortController | null>(null);
  const [data, setData] = useState<ApigPublicationState | null>(null), [baseline, setBaseline] = useState<Baseline | null>(null);
  const [preview, setPreview] = useState<ApigPreview | null>(null), [operation, setOperation] = useState<ApigOperation | null>(null);
  const [attempted, setAttempted] = useState<string | null>(null), [requestId, setRequestId] = useState(initialRequest);
  const [busy, setBusy] = useState(false), [reading, setReading] = useState(false), [loading, setLoading] = useState(canRead), [error, setError] = useState('');
  const [sourcePage, setSourcePage] = useState(1), [eligibleOnly, setEligibleOnly] = useState(false);
  useEffect(() => {
    const active = reads.current;
    return () => { active.forEach(controller => controller.abort()); };
  }, []);
  useEffect(() => watchRequestScope(() => {
    receiptSequence.current++; receiptRead.current?.abort(); setRequestId(''); setOperation(null); setReading(false);
  }), []);
  const readState = useCallback(async (sequence: number, controller: AbortController) => {
    reads.current.add(controller);
    try {
      const response = await api.state({ source_page: sourcePage, source_page_size: 20, source_eligible_only: eligibleOnly }, controller.signal);
      if (controller.signal.aborted || !scope.current() || sequence !== listSequence.current) return null;
      setData(response.data); return response.data;
    } catch (cause) {
      if (!controller.signal.aborted && scope.current() && sequence === listSequence.current) setError(failure(cause));
      return null;
    } finally {
      reads.current.delete(controller);
      if (!controller.signal.aborted && scope.current() && sequence === listSequence.current) setLoading(false);
    }
  }, [scope, sourcePage, eligibleOnly]);
  const refresh = useCallback(async () => {
    if (!canRead || !scope.current()) return null;
    setLoading(true); return readState(++listSequence.current, new AbortController());
  }, [canRead, scope, readState]);
  useEffect(() => {
    if (!canRead || !scope.current()) return;
    const controller = new AbortController(); void readState(++listSequence.current, controller);
    return () => controller.abort();
  }, [canRead, readState, scope]);
  async function run(work: (generation: number) => Promise<void>) {
    const generation = scope.begin(); if (generation === undefined) return;
    setBusy(true); setError('');
    try { await work(generation); }
    catch (cause) { if (scope.current(generation)) setError(failure(cause)); }
    finally { if (scope.finish(generation)) setBusy(false); }
  }
  const adopt = () => {
    if (busy || !data || !scope.current() || !matchingObservation(data, data.observation)) return;
    setBaseline({ observation: data.observation!, stateVersion: data.stateVersion }); setPreview(null);
  };
  const observe = async (live: boolean, initialize: boolean) => {
    if (!canRead || !data?.canObserve || !data.binding || busy || data.busy
      || (data.binding.transportMode === 'live' && !live) || (initialize && (!canWrite || !data.canInitializeMockFixture))) return;
    const target = data.binding;
    await run(async generation => {
      setPreview(null); if (baseline) setBaseline({ ...baseline, observation: { ...baseline.observation, usable: false } });
      const response = await api.observe({ request_id: newRequestId(), configuration_version: target.configurationVersion,
        confirm_live: live, initialize_mock_fixture: initialize });
      if (!scope.current(generation)) return;
      const latest = await refresh();
      if (scope.current(generation) && latest && matchingObservation(latest, response.data)) setBaseline({ observation: response.data, stateVersion: latest.stateVersion });
    });
  };
  const prepare = async (change: ApigChange, acknowledge: boolean) => {
    if (!canWrite || !data?.canPrepare || !baseline || busy || data.busy || !matchingObservation(data, baseline.observation)) return;
    const unresolved = operation?.requestId === data.unresolvedOperationId ? operation : data.operations.find(row => row.requestId === data.unresolvedOperationId) ?? null;
    if (data.unresolvedOperationId && (!acknowledge || !unknownReady(data, baseline.observation, unresolved))) return;
    const captured = { request_id: newRequestId(), configuration_version: baseline.observation.target.configurationVersion,
      observation_id: baseline.observation.id, expected_state_version: baseline.stateVersion, change,
      ...(data.unresolvedOperationId ? { acknowledge_unknown_operation_id: data.unresolvedOperationId } : {}) };
    await run(async generation => {
      setPreview(null); const response = await api.preview(captured);
      if (scope.current(generation)) { setPreview(response.data); await refresh(); }
    });
  };
  const apply = async (confirm: ApplyConfirmations) => {
    if (!canWrite || !data || busy || !preview || !applicable(data, preview, attempted)
      || !confirm.confirm_apply || !confirm.confirm_scope_difference || !confirm.confirm_shared_policy_impact || !confirm.confirm_no_cloud_cas
      || (preview.target.transportMode === 'live' && !confirm.confirm_live) || (preview.unknownOverlapWarning && !confirm.confirm_unknown_overlap)) return;
    const id = newRequestId(), captured = { request_id: id, preview_id: preview.id, expected_state_version: preview.stateVersion, ...confirm };
    await run(async generation => {
      setAttempted(preview.id); setRequestId(id); rememberRequest(id); setOperation(null);
      const sequence = ++receiptSequence.current, response = await api.apply(captured);
      if (scope.current(generation) && sequence === receiptSequence.current && response.data.requestId === id) setOperation(response.data);
      if (scope.current(generation)) await refresh();
    });
  };
  const readReceipt = async (id = requestId) => {
    if (!canRead || !uuid(id) || !scope.current()) return;
    const sequence = ++receiptSequence.current, controller = new AbortController(); receiptRead.current?.abort(); receiptRead.current = controller;
    reads.current.add(controller); setRequestId(id); rememberRequest(id); setReading(true); setError('');
    try {
      const response = await api.receipt(id, controller.signal);
      if (!controller.signal.aborted && scope.current() && sequence === receiptSequence.current && response.data.requestId === id) setOperation(response.data);
    } catch (cause) { if (!controller.signal.aborted && scope.current() && sequence === receiptSequence.current) setError(failure(cause)); }
    finally { reads.current.delete(controller); if (!controller.signal.aborted && scope.current() && sequence === receiptSequence.current) setReading(false); }
  };
  const changeRequest = (id: string) => {
    if (!scope.current() || busy) return;
    receiptSequence.current++; receiptRead.current?.abort(); setRequestId(id); setOperation(null); setReading(false);
  };
  const invalidatePreview = () => { if (!busy && scope.current()) setPreview(null); };
  const changeSources = (page: number, onlyEligible: boolean) => {
    if (busy || !scope.current() || !Number.isSafeInteger(page) || page < 1 || (page === sourcePage && onlyEligible === eligibleOnly)) return;
    setLoading(true); setSourcePage(page); setEligibleOnly(onlyEligible);
  };
  const observeOriginal = async (live: boolean) => {
    if (!canRead || !operation || busy || !originalObservable(data, operation) || (data?.binding?.transportMode === 'live' && !live)) return;
    const captured = operation;
    await run(async generation => {
      setPreview(null); const response = await api.observeOriginal(captured.requestId, { request_id: newRequestId(),
        configuration_version: captured.recoveryConfigurationVersion!, confirm_live: live });
      if (!scope.current(generation)) return;
      const latest = await refresh();
      if (scope.current(generation) && latest && matchingObservation(latest, response.data)) setBaseline({ observation: response.data, stateVersion: latest.stateVersion });
      await readReceipt(captured.requestId);
    });
  };
  const recover = async () => {
    if (!canWrite || !operation?.allowedActions.includes('recover_local') || busy) return;
    const id = operation.requestId;
    await run(async generation => {
      const sequence = ++receiptSequence.current, response = await api.recover(id);
      if (scope.current(generation) && sequence === receiptSequence.current && response.data.requestId === id) setOperation(response.data);
      if (scope.current(generation)) await refresh();
    });
  };
  const archive = async (ids: string[], expectedGeneration: number) => {
    if (!canWrite || !data || busy || ids.length === 0 || ids.length > data.limits.maxArchive) return;
    const eligible = new Map(data.operations.map(row => [row.requestId, row]));
    if (operation) eligible.set(operation.requestId, operation);
    if (ids.some(id => !eligible.get(id)?.archivable || !eligible.get(id)?.allowedActions.includes('archive'))) return;
    const captured = { expected_generation: expectedGeneration, request_ids: [...new Set(ids)].sort() };
    await run(async generation => {
      await api.archive(captured);
      if (scope.current(generation)) { await refresh(); if (operation && ids.includes(operation.requestId)) await readReceipt(operation.requestId); }
    });
  };
  return { data, baseline, preview, operation, attempted, requestId, busy, loading, reading, error, refresh, adopt, observe,
    prepare, apply, readReceipt, changeRequest, invalidatePreview, observeOriginal, recover, archive, eligibleOnly, changeSources };
}
