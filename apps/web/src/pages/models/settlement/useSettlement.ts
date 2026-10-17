import { useEffect, useRef, useState } from 'react';
import { gatewaySettlementApi as api, type SettlementReceipt } from '@/api/gatewaySettlement';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { validAttempt, validReceipt } from './validation';

export function useSettlement(canRead: boolean, canWrite: boolean) {
  const scope = useOperationScope(), readSequence = useRef(0);
  const controllers = useRef(new Set<AbortController>()), activeRead = useRef<AbortController | null>(null);
  const pending = useRef<string | null>(null);
  const [attempt, setAttempt] = useState(''), [receipt, setReceipt] = useState<SettlementReceipt | null>(null);
  const [busy, setBusy] = useState(false), [reading, setReading] = useState(false);
  const [unknown, setUnknown] = useState(false), [error, setError] = useState('');
  useEffect(() => { const requests = controllers.current; return () => requests.forEach(request => request.abort()); }, []);
  const changeAttempt = (value: string) => {
    if (pending.current || !scope.current()) return;
    readSequence.current++; activeRead.current?.abort(); setReading(false);
    setAttempt(value.trim().toLowerCase()); setReceipt(null); setError('');
  };
  const read = async () => {
    const id = pending.current ?? attempt;
    if (!canRead || !validAttempt(id) || !scope.current()) return;
    const sequence = ++readSequence.current, controller = new AbortController();
    activeRead.current?.abort(); activeRead.current = controller; controllers.current.add(controller);
    setReading(true); setError('');
    try {
      const response = await api.read(id, controller.signal);
      if (controller.signal.aborted || !scope.current() || sequence !== readSequence.current) return;
      if (!validReceipt(response.data, id)) throw new Error('Invalid settlement receipt / 无法核验结算回执');
      setReceipt(response.data);
      if (!busy) { pending.current = null; setUnknown(false); }
    } catch (cause) {
      if (!controller.signal.aborted && scope.current() && sequence === readSequence.current) setError(String(cause));
    } finally {
      controllers.current.delete(controller);
      if (!controller.signal.aborted && scope.current() && sequence === readSequence.current) setReading(false);
    }
  };
  const recover = async () => {
    if (!canRead || !canWrite || pending.current || !receipt?.recoveryAvailable || receipt.attemptId !== attempt) return;
    const generation = scope.begin(); if (generation === undefined) return;
    const id = attempt, sequence = ++readSequence.current, controller = new AbortController();
    pending.current = id; controllers.current.add(controller); setBusy(true); setUnknown(true); setError('');
    try {
      const response = await api.recover(id, controller.signal);
      if (controller.signal.aborted || !scope.current(generation)) return;
      if (!validReceipt(response.data, id) || response.data.state !== 'settled') throw new Error('Unconfirmed settlement / 结算结果尚未确认');
      if (sequence === readSequence.current) setReceipt(response.data);
      pending.current = null; setUnknown(false);
    } catch (cause) {
      if (!controller.signal.aborted && scope.current(generation)) setError(String(cause));
    } finally {
      controllers.current.delete(controller);
      if (scope.finish(generation)) setBusy(false);
    }
  };
  return { attempt, receipt, busy, reading, unknown, error, changeAttempt, read, recover,
    canRecover: canRead && canWrite && !busy && !unknown && receipt?.recoveryAvailable === true && receipt.attemptId === attempt };
}
