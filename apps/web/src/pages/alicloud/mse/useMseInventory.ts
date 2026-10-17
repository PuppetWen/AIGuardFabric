import { useEffect, useRef, useState } from 'react';
import { ApiRequestError } from '@/api/transport';
import { mseInventoryApi } from '@/api/mseInventory';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { newRequestId } from '@/utils/requestId';
import type { MseInventory, MseOperation } from '@/types/mseInventory';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function useMseInventory(canRead: boolean, canWrite: boolean) {
  const scope = useOperationScope();
  const [data, setData] = useState<MseInventory>();
  const [loading, setLoading] = useState(false);
  const [syncBusy, setSyncBusy] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);
  const [receiptBusy, setReceiptBusy] = useState(false);
  const [error, setError] = useState('');
  const [requestId, setRequestId] = useState('');
  const [operation, setOperation] = useState<MseOperation>();
  const [missing, setMissing] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);
  const listSequence = useRef(0), receiptSequence = useRef(0);
  const dispatching = useRef(false), acting = useRef(false);
  const controllers = useRef(new Set<AbortController>());
  useEffect(() => {
    const owned = controllers.current;
    return () => { for (const controller of owned) controller.abort(); };
  }, []);

  const refresh = async (clearError = false) => {
    if (!canRead || !scope.current()) return;
    const sequence = ++listSequence.current;
    const controller = new AbortController(); controllers.current.add(controller);
    setLoading(true);
    try {
      const response = await mseInventoryApi.list(controller.signal);
      if (scope.current() && sequence === listSequence.current) {
        setData(response.data); setSelected([]); if (clearError) setError('');
      }
    } catch (cause) {
      if (scope.current() && sequence === listSequence.current) setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      controllers.current.delete(controller);
      if (scope.current() && sequence === listSequence.current) setLoading(false);
    }
  };
  useEffect(() => {
    if (!canRead) return;
    const controller = new AbortController(); controllers.current.add(controller);
    const sequence = ++listSequence.current;
    void mseInventoryApi.list(controller.signal).then(response => {
      if (scope.current() && sequence === listSequence.current) setData(response.data);
    }).catch(cause => {
      if (scope.current() && sequence === listSequence.current) setError(cause instanceof Error ? cause.message : String(cause));
    }).finally(() => controllers.current.delete(controller));
    return () => { controller.abort(); };
  }, [canRead, scope]);

  const read = async (id = requestId) => {
    if (!canRead || !uuid.test(id) || !scope.current()) return;
    const sequence = ++receiptSequence.current;
    setRequestId(id); setReceiptBusy(true); setError('');
    setOperation(previous => previous?.requestId === id ? previous : undefined);
    try {
      const response = await mseInventoryApi.receipt(id);
      if (!scope.current() || sequence !== receiptSequence.current) return;
      if (response.data.requestId !== id) throw new Error('Receipt request identity mismatch / 回执请求编号不匹配');
      setOperation(response.data); setMissing(false);
    } catch (cause) {
      if (scope.current() && sequence === receiptSequence.current) {
        setMissing(cause instanceof ApiRequestError && cause.status === 404);
        setError(cause instanceof Error ? cause.message : String(cause));
      }
    } finally { if (scope.current() && sequence === receiptSequence.current) setReceiptBusy(false); }
  };
  const changeRequest = (id: string) => {
    if (dispatching.current || acting.current || !scope.current()) return;
    receiptSequence.current++; setReceiptBusy(false); setRequestId(id); setOperation(undefined); setMissing(false); setError('');
  };
  const canPrepare = !syncBusy && !actionBusy && (!!operation && !operation.canCancel && operation.status !== 'running' || missing);
  const prepare = () => {
    if (!canPrepare || !scope.current()) return;
    changeRequest(''); setConfirmed(false);
  };
  const active = data?.operations.some(run => run.current && run.canCancel) === true;
  const canSync = canWrite && data?.configured === true && data.configurationVersion !== null && !active && !requestId &&
    !syncBusy && !actionBusy && (data.mocked === true || confirmed);
  const sync = async () => {
    if (!canSync || !data || data.configurationVersion === null || dispatching.current || acting.current || !scope.current()) return;
    const id = newRequestId(), sequence = ++receiptSequence.current;
    dispatching.current = true; setSyncBusy(true); setReceiptBusy(false); setRequestId(id); setOperation(undefined); setMissing(false); setError('');
    try {
      const response = await mseInventoryApi.sync({ request_id: id, configuration_version: data.configurationVersion, confirm_live: confirmed });
      if (!scope.current() || sequence !== receiptSequence.current) return;
      if (response.data.requestId !== id) throw new Error('Receipt request identity mismatch / 回执请求编号不匹配');
      setOperation(response.data);
    } catch (cause) {
      if (scope.current() && sequence === receiptSequence.current) setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      dispatching.current = false;
      if (scope.current()) { setSyncBusy(false); await refresh(); }
    }
  };
  const cancel = async () => {
    if (!canWrite || !operation?.canCancel || acting.current || !scope.current()) return;
    const id = operation.requestId, sequence = ++receiptSequence.current;
    acting.current = true; setActionBusy(true); setReceiptBusy(false); setError('');
    try {
      const response = await mseInventoryApi.cancel(id);
      if (!scope.current() || sequence !== receiptSequence.current) return;
      if (response.data.requestId !== id) throw new Error('Receipt request identity mismatch / 回执请求编号不匹配');
      setOperation(response.data); await refresh();
    } catch (cause) {
      if (scope.current() && sequence === receiptSequence.current) setError(cause instanceof Error ? cause.message : String(cause));
    } finally { acting.current = false; if (scope.current()) setActionBusy(false); }
  };
  const archive = async () => {
    const ids = selected.filter(id => data?.operations.some(run => run.requestId === id && run.archivable && !run.archived));
    if (!canWrite || !data || ids.length === 0 || ids.length > 100 || acting.current || dispatching.current || !scope.current()) return;
    acting.current = true; setActionBusy(true); setError('');
    try {
      await mseInventoryApi.archive({ expected_generation: data.generation, request_ids: ids });
      if (!scope.current()) return;
      await refresh();
      if (operation && ids.includes(operation.requestId)) await read(operation.requestId);
    } catch (cause) { if (scope.current()) setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { acting.current = false; if (scope.current()) setActionBusy(false); }
  };
  return { data, loading, syncBusy, actionBusy, receiptBusy, error, requestId, operation, confirmed, setConfirmed,
    selected, setSelected, canSync, canPrepare, canReadReceipt: uuid.test(requestId), refresh, read, changeRequest, sync, cancel, archive, prepare };
}
