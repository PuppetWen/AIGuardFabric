import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { taskHandlingApi } from '@/api/agentTeamsTaskHandling';
import { ApiRequestError } from '@/api/client';
import { useAuthStore } from '@/stores/authStore';
import type { ArchiveInput, HandlingDecision, HandlingEvent, HandlingPage, HandlingReceipt, HandlingWindow, ResolutionInput } from '@/types/agentTeamsTaskHandling';

type Pending = { id: string; eventId: string; kind: 'resolve'; body: ResolutionInput }
  | { id: string; eventId: string; kind: 'archive'; body: ArchiveInput };
export function safeVersion(value: unknown, positive = false): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= (positive ? 1 : 0);
}

export function useTaskHandling() {
  const [params, setParams] = useSearchParams();
  const [page, setPage] = useState<HandlingPage>();
  const [previous, setPrevious] = useState<HandlingPage[]>([]);
  const [window, setWindow] = useState<HandlingWindow>();
  const [event, setEvent] = useState<HandlingEvent>();
  const [decision, setDecision] = useState<HandlingDecision>('acknowledged');
  const [pending, setPending] = useState<Pending>();
  const [receipt, setReceipt] = useState<HandlingReceipt>();
  const [rejected, setRejected] = useState(false);
  const [recoveryId, setRecoveryId] = useState(params.get('task_request_id') ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const alive = useRef(true);
  const locked = useRef(false);
  const submitted = useRef<Pending | undefined>(undefined);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const run = async (work: (current: () => boolean) => Promise<void>) => {
    if (locked.current) return;
    locked.current = true; setBusy(true); setError(undefined);
    const before = useAuthStore.getState();
    const current = () => alive.current && useAuthStore.getState().tenant?.id === before.tenant?.id
      && useAuthStore.getState().sessionGeneration === before.sessionGeneration;
    try { await work(current); }
    catch (cause) { if (current()) setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { locked.current = false; if (current()) setBusy(false); }
  };
  const readPage = (cursor?: string, range?: HandlingWindow) => range
    ? taskHandlingApi.list(cursor, range) : taskHandlingApi.list(cursor);
  const load = (next = false, selectedWindow?: HandlingWindow) => run(async current => {
    const range = next ? window : selectedWindow;
    if (range) {
      const seconds = (Date.parse(range.until) - Date.parse(range.from)) / 1000;
      if (!Number.isFinite(seconds) || seconds <= 0 || seconds > 30 * 86400) {
        throw new Error('请选择不超过30天的时间窗 / Select a window of up to 30 days');
      }
    }
    const result = await readPage(next ? page?.nextCursor ?? undefined : undefined, range);
    if (!current()) return;
    setWindow(range);
    setPrevious(next && page ? old => [...old, page] : []); setPage(result.data);
    // A list refresh never changes the user's selected draft or old submitted body.
  });
  const select = (id: string) => run(async current => {
    if (pending && !receipt) throw new Error('先读取原请求编号 / Read the original request before changing the draft');
    const result = await taskHandlingApi.event(id);
    if (!current()) return;
    setEvent(result.data); setDecision(result.data.handling?.decision ?? 'acknowledged');
    submitted.current = undefined; setPending(undefined); setReceipt(undefined); setRejected(false);
  });
  const refreshDetail = () => run(async current => {
    if (!event) return;
    const result = await taskHandlingApi.event(event.id);
    if (current()) setEvent(result.data); // Never change a previously submitted payload.
  });
  const submit = (kind: 'resolve' | 'archive') => run(async current => {
    if (!event || submitted.current) return;
    const source = event.currentSource;
    const version = event.handling?.version ?? 0;
    if (!safeVersion(version) || !safeVersion(page?.generation)) throw new Error('请读取当前记录 / Read the current record');
    if (!source.sourceGone && (!source.fingerprint || !safeVersion(source.cloudConfigurationVersion, true))) {
      throw new Error('请重新读取来源证明 / Refresh the source evidence');
    }
    if (kind === 'resolve' && source.sourceGone) throw new Error('来源已删除，仅可归档 / Source removed; archive only');
    const id = crypto.randomUUID();
    const operation: Pending = kind === 'resolve'
      ? { id, eventId: event.id, kind, body: { request_id: id, expected_version: version,
        expected_cloud_configuration_version: source.cloudConfigurationVersion!, expected_source_fingerprint: source.fingerprint!, decision } }
      : { id, eventId: event.id, kind, body: { request_id: id, expected_generation: page!.generation,
        event_ids: [event.id], sources: [{ source_id: event.sourceId, fingerprint: source.sourceGone ? null : source.fingerprint }],
        expected_cloud_configuration_version: source.sourceGone ? null : source.cloudConfigurationVersion } };
    submitted.current = operation;
    setPending(operation); setReceipt(undefined); setRejected(false); setRecoveryId(id);
    setParams(old => { const next = new URLSearchParams(old); next.set('task_request_id', id); return next; }, { replace: true });
    try {
      const result = operation.kind === 'resolve' ? await taskHandlingApi.resolve(operation.eventId, operation.body)
        : await taskHandlingApi.archive(operation.body);
      if (current()) setReceipt(result.data);
    } catch (cause) {
      // A completed validation/conflict rejection differs from an unknown transport outcome.
      if (current() && cause instanceof ApiRequestError && cause.status >= 400 && cause.status < 500 && cause.status !== 408) {
        setRejected(true);
      }
      throw cause;
    }
  });
  const recover = () => run(async current => {
    const result = await taskHandlingApi.request(recoveryId.trim());
    if (current()) setReceipt(result.data);
  });
  const newAction = () => run(async current => {
    if (!event || (!receipt && !rejected)) return;
    const [freshPage, freshEvent] = await Promise.all([readPage(undefined, window), taskHandlingApi.event(event.id)]);
    if (!current()) return;
    setPage(freshPage.data); setEvent(freshEvent.data); setPrevious([]);
    submitted.current = undefined; setPending(undefined); setReceipt(undefined); setRejected(false);
  });
  const back = () => {
    if (busy || previous.length === 0) return;
    setPage(previous[previous.length - 1]); setPrevious(previous.slice(0, -1));
  };
  return { page, previous, event, decision, setDecision, pending, receipt, recoveryId, setRecoveryId,
    busy, error, canStartNew: Boolean(receipt || rejected), load, select, refreshDetail, submit, recover, newAction, back };
}
