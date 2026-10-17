import { useEffect, useRef, useState } from 'react';
import { agentTeamsTraceApi } from '@/api/agentTeamsTrace';
import { ApiRequestError } from '@/api/client';
import { useAuthStore } from '@/stores/authStore';
import type { AgentTeamsTrace, TraceDraft, TraceQuery } from '@/types/agentTeamsTrace';
import { currentTraceQuery, initialTraceDraft } from './traceState';

function sameQuery(left: TraceQuery, right: TraceQuery) {
  return left.traceId === right.traceId && left.from === right.from && left.until === right.until && left.limit === right.limit;
}

export function useAgentTeamsTrace(traceId = '') {
  const [draft, setDraft] = useState(() => initialTraceDraft(traceId));
  const [data, setData] = useState<AgentTeamsTrace>();
  const [submitted, setSubmitted] = useState<TraceQuery>();
  const [cursor, setCursor] = useState<string>();
  const [previous, setPrevious] = useState<(string | undefined)[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();
  const [conflict, setConflict] = useState(false);
  const sequence = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const alive = useRef(true);
  const first = useRef<{ query: TraceQuery; data: AgentTeamsTrace } | undefined>(undefined);
  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; sequence.current += 1; controller.current?.abort(); };
  }, []);
  const edit = (patch: Partial<TraceDraft>) => {
    sequence.current += 1; controller.current?.abort();
    setDraft(value => ({ ...value, ...patch }));
    first.current = undefined;
    setData(undefined); setSubmitted(undefined); setCursor(undefined); setPrevious([]);
    setError(undefined); setConflict(false); setLoading(false);
  };
  const load = async (query: TraceQuery, next?: string, history: (string | undefined)[] = []) => {
    const starting = useAuthStore.getState();
    const request = ++sequence.current;
    controller.current?.abort();
    const abort = new AbortController(); controller.current = abort;
    const current = () => alive.current && request === sequence.current && !abort.signal.aborted
      && useAuthStore.getState().tenant?.id === starting.tenant?.id
      && useAuthStore.getState().tenant?.slug === starting.tenant?.slug
      && useAuthStore.getState().sessionGeneration === starting.sessionGeneration;
    setLoading(true); setError(undefined); setConflict(false);
    try {
      const response = await agentTeamsTraceApi.get(query, next, abort.signal);
      if (!current()) return;
      // Replace one page; never concatenate responses from different SQL snapshots.
      if (next === undefined) first.current = { query, data: response.data };
      setData(response.data); setSubmitted(query); setCursor(next); setPrevious(history);
    } catch (cause) {
      if (!current()) return;
      setError(cause instanceof Error ? cause.message : String(cause));
      setConflict(cause instanceof ApiRequestError && cause.status === 409);
    } finally { if (current()) setLoading(false); }
  };
  const query = () => {
    try { void load(currentTraceQuery(draft)); }
    catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
  };
  const refresh = () => { if (submitted) void load(submitted); else query(); };
  const next = () => { if (!loading && !conflict && submitted && data?.nextCursor) void load(submitted, data.nextCursor, [...previous, cursor]); };
  const back = () => {
    if (loading || error || conflict || !submitted || previous.length === 0) return;
    const target = previous[previous.length - 1];
    if (target !== undefined) { void load(submitted, target, previous.slice(0, -1)); return; }
    // No first-page cursor exists. Restore this query's original page instead of silently taking a new snapshot.
    const saved = first.current;
    if (!saved || !sameQuery(saved.query, submitted)) {
      setError('The saved first page is unavailable. Refresh explicitly / 保存的第一页不可用，请显式刷新');
      setConflict(true); return;
    }
    sequence.current += 1; controller.current?.abort();
    setData(saved.data); setSubmitted(saved.query); setCursor(undefined); setPrevious(previous.slice(0, -1));
    setLoading(false); setError(undefined); setConflict(false);
  };
  return { draft, edit, data, loading, error, conflict, query, refresh, next, back,
    canBack: previous.length > 0 && !loading && !error && !conflict,
    canNext: !!data?.nextCursor && !loading && !error && !conflict,
    page: previous.length + 1 };
}
