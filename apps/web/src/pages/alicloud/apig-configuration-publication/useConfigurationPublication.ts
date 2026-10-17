import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiRequestError } from '@/api/transport';
import { apigConfigurationApi as api } from '@/api/apigConfigurationPublication';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { newRequestId } from '@/utils/requestId';
import type { ApplyConfirmations, ApplyInput, ConfigurationChange, ConfigurationObservation, ConfigurationOperation, ConfigurationPreview, ConfigurationState } from '@/types/apigConfigurationPublication';
import { matching, observable, safeRevision, unknownReady } from './eligibility';
import { failure, uuid } from './text';
import { initialRequest, rememberRequest, watchRequestScope } from './requestScope';

interface Held { id: string; body: Readonly<ApplyInput>; terminal: boolean; rejected: boolean }
export function useConfigurationPublication(canRead: boolean, canWrite: boolean) {
  const scope = useOperationScope(), listSequence = useRef(0), receiptSequence = useRef(0), held = useRef<Held | null>(null);
  const reads = useRef(new Set<AbortController>()), latestRead = useRef<AbortController | null>(null);
  const [data, setData] = useState<ConfigurationState | null>(null), [baseline, setBaseline] = useState<ConfigurationObservation | null>(null);
  const [preview, setPreview] = useState<ConfigurationPreview | null>(null), [operation, setOperation] = useState<ConfigurationOperation | null>(null);
  const [requestId, setRequestId] = useState(initialRequest), [busy, setBusy] = useState(false), [reading, setReading] = useState(false);
  const [loading, setLoading] = useState(canRead), [error, setError] = useState('');
  const [heldView, setHeldView] = useState<Pick<Held, 'id' | 'terminal' | 'rejected'> | null>(null);
  useEffect(() => { const active = reads.current; return () => { active.forEach(c => c.abort()); }; }, []);
  useEffect(() => watchRequestScope(() => {
    held.current = null; setHeldView(null); receiptSequence.current++; latestRead.current?.abort(); setOperation(null); setRequestId(''); setReading(false);
  }), []);
  const readState = useCallback(async (sequence: number, controller: AbortController) => {
    reads.current.add(controller);
    try {
      const response = await api.state(controller.signal);
      if (controller.signal.aborted || !scope.current() || sequence !== listSequence.current) return null;
      setData(response.data); return response.data;
    } catch (cause) { if (!controller.signal.aborted && scope.current() && sequence === listSequence.current) setError(failure(cause)); return null; }
    finally { reads.current.delete(controller); if (!controller.signal.aborted && scope.current() && sequence === listSequence.current) setLoading(false); }
  }, [scope]);
  const refresh = useCallback(async () => {
    if (!canRead || !scope.current()) return null;
    setLoading(true); return readState(++listSequence.current, new AbortController());
  }, [canRead, readState, scope]);
  useEffect(() => {
    if (!canRead) return;
    const controller = new AbortController(); void readState(++listSequence.current, controller); return () => controller.abort();
  }, [canRead, readState]);
  async function run(work: (generation: number) => Promise<void>) {
    const generation = scope.begin(); if (generation === undefined) return;
    setBusy(true); setError('');
    try { await work(generation); } catch (cause) { if (scope.current(generation)) setError(failure(cause)); }
    finally { if (scope.finish(generation)) setBusy(false); }
  }
  const accept = (row: ConfigurationOperation, id: string) => {
    if (!row || row.requestId !== id || !row.target || !row.cloudWrite || !row.readback || !row.localPublication || !Array.isArray(row.allowedActions))
      throw new Error('回执不完整或不是原编号；保持原意图锁 / Invalid original receipt; keep the original intent locked');
    const original = held.current;
    if (original?.id === id && row.previewId === original.body.preview_id
      && row.completionState === 'complete' && row.localPublication.status === 'published') {
      original.terminal = true;
      setHeldView({ id: original.id, terminal: true, rejected: original.rejected });
    }
    setOperation(row);
  };
  const observe = async (live: boolean, initialize: boolean) => {
    if (!canRead || !data?.binding || !data.canObserve || busy || (initialize && (!canWrite || !data.canInitializeMockFixture))
      || (data.binding.transportMode === 'live' && !live)) return;
    const target = data.binding;
    await run(async generation => {
      const response = await api.observe({ request_id: newRequestId(), configuration_version: target.configurationVersion,
        confirm_live: live, initialize_mock_fixture: initialize });
      if (scope.current(generation)) await refresh(); // A new observation is compared before explicit adoption.
      if (scope.current(generation) && response.data.target.targetScopeId !== target.targetScopeId) throw new Error('Observation target changed');
    });
  };
  const adopt = () => {
    if (!busy && scope.current() && matching(data, data?.observation ?? null)) { setBaseline(data!.observation); setPreview(null); }
  };
  const prepare = async (change: ConfigurationChange, acknowledge: boolean) => {
    if (!canWrite || !data?.canPrepare || busy || held.current || !matching(data, baseline)) return;
    const unresolved = operation?.requestId === data.unresolvedOperationId ? operation : data.operations.find(r => r.requestId === data.unresolvedOperationId) ?? null;
    if (data.unresolvedOperationId && (!acknowledge || !unknownReady(data, baseline, unresolved))) return;
    const body = { request_id: newRequestId(), configuration_version: baseline.target.configurationVersion, observation_id: baseline.id,
      expected_state_version: data.stateVersion, change, ...(data.unresolvedOperationId ? { acknowledge_unknown_operation_id: data.unresolvedOperationId } : {}) };
    await run(async generation => { const response = await api.preview(body); if (scope.current(generation)) { setPreview(response.data); await refresh(); } });
  };
  const apply = async (confirm: ApplyConfirmations) => {
    if (!canWrite || busy || held.current || !data?.canApply || !data.binding || !preview?.previewUsable || !preview.allowedActions.includes('apply')
      || !(Date.parse(preview.expiresAt) > Date.now())
      || !safeRevision(preview.stateVersion) || preview.stateVersion !== data.stateVersion
      || preview.target.targetScopeId !== data.binding?.targetScopeId || preview.target.configurationVersion !== data.binding.configurationVersion
      || !confirm.confirm_apply || !confirm.confirm_preserved_private_configuration || !confirm.confirm_streaming_or_shared_impact || !confirm.confirm_no_cloud_cas
      || (preview.target.transportMode === 'live' && !confirm.confirm_live) || (preview.unknownOverlapWarning && !confirm.confirm_unknown_overlap)) return;
    await run(async generation => {
      const id = newRequestId(), body = Object.freeze({ request_id: id, preview_id: preview.id, expected_state_version: preview.stateVersion, ...confirm });
      held.current = { id, body, terminal: false, rejected: false };
      setHeldView({ id, terminal: false, rejected: false }); setRequestId(id); rememberRequest(id); setOperation(null);
      const sequence = ++receiptSequence.current;
      try {
        const response = await api.apply(body);
        if (scope.current(generation) && sequence === receiptSequence.current) accept(response.data, id);
      } catch (cause) {
        if (scope.current(generation) && held.current?.id === id && cause instanceof ApiRequestError
          && [400, 409, 412].includes(cause.status)) {
          held.current.rejected = true;
          setHeldView({ id, terminal: held.current.terminal, rejected: true });
        }
        throw cause;
      } finally { if (scope.current(generation)) await refresh(); }
    });
  };
  const readReceipt = async (id = requestId) => {
    if (!canRead || !uuid(id) || !scope.current()) return;
    const sequence = ++receiptSequence.current, controller = new AbortController(); latestRead.current?.abort(); latestRead.current = controller;
    reads.current.add(controller); setRequestId(id); rememberRequest(id); setReading(true); setError('');
    try { const response = await api.receipt(id, controller.signal); if (!controller.signal.aborted && scope.current() && sequence === receiptSequence.current) accept(response.data, id); }
    catch (cause) { if (!controller.signal.aborted && scope.current() && sequence === receiptSequence.current) setError(failure(cause)); }
    finally { reads.current.delete(controller); if (!controller.signal.aborted && scope.current() && sequence === receiptSequence.current) setReading(false); }
  };
  const changeRequest = (id: string) => { if (scope.current()) { receiptSequence.current++; latestRead.current?.abort(); setRequestId(id); setOperation(null); setReading(false); } };
  const invalidatePreview = () => { if (!busy && scope.current()) setPreview(null); };
  const newIntent = () => {
    if (busy || !scope.current() || !held.current || !(held.current.terminal || held.current.rejected)) return;
    held.current = null; setHeldView(null); setPreview(null); setError('');
  };
  const observeOriginal = async (live: boolean) => {
    if (!operation || busy || !canRead || !observable(data, operation) || (data?.binding?.transportMode === 'live' && !live)) return;
    const original = operation;
    await run(async generation => {
      await api.observeOriginal(original.requestId, { request_id: newRequestId(), configuration_version: original.recoveryConfigurationVersion!, confirm_live: live });
      if (scope.current(generation)) { await refresh(); await readReceipt(original.requestId); }
    });
  };
  const recover = async () => {
    if (!canWrite || busy || !operation?.allowedActions.includes('recover_local')) return;
    const id = operation.requestId;
    await run(async generation => {
      const sequence = ++receiptSequence.current, response = await api.recover(id);
      if (scope.current(generation) && sequence === receiptSequence.current) accept(response.data, id);
      if (scope.current(generation)) await refresh();
    });
  };
  const archive = async (ids: string[], generation: number) => {
    if (!canWrite || busy || !data || !safeRevision(generation) || ids.length === 0 || ids.length > data.limits.maxArchive || new Set(ids).size !== ids.length) return;
    const known = new Map(data.operations.map(row => [row.requestId, row])); if (operation) known.set(operation.requestId, operation);
    if (ids.some(id => !known.get(id)?.archivable || !known.get(id)?.allowedActions.includes('archive'))) return;
    const body = { expected_generation: generation, request_ids: [...ids].sort() };
    await run(async epoch => { await api.archive(body); if (scope.current(epoch)) { await refresh(); if (operation && ids.includes(operation.requestId)) await readReceipt(operation.requestId); } });
  };
  return { data, baseline, preview, operation, requestId, busy, reading, loading, error, refresh, observe, adopt, prepare, apply,
    readReceipt, changeRequest, invalidatePreview, newIntent, observeOriginal, recover, archive,
    heldId: heldView?.id ?? null, canNewIntent: !busy && !!heldView && (heldView.terminal || heldView.rejected) };
}
