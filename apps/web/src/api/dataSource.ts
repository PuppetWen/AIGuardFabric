import { FORCE_DEMO } from './config';

/* ------------------------------------------------------------------ */
/* Demo-mode flag (observable from React)                              */
/* ------------------------------------------------------------------ */

export type DataSource = 'live' | 'demo';

export interface ApiError {
  status: number;
  code: string;
  message: string;
  /** `true` when the failure triggered the demo fallback. */
  fallback: boolean;
}

export interface ResponseMeta {
  source: DataSource;
  /** Milliseconds spent on the attempt. */
  elapsedMs: number;
  /** Present when `source === 'demo'`. */
  reason?: string;
  at: number;
}

export interface ApiResult<T> {
  data: T;
  meta: ResponseMeta;
}

let dataSource: DataSource = FORCE_DEMO ? 'demo' : 'live';
let lastReason: string | undefined = FORCE_DEMO ? 'VITE_FORCE_DEMO=true' : undefined;
let lastSyncAt: number | null = FORCE_DEMO ? Date.now() : null;
const listeners = new Set<() => void>();

function notify(): void {
  for (const listener of listeners) {
    listener();
  }
}

/** Snapshot used by `useSyncExternalStore`. */
export interface DataSourceSnapshot {
  source: DataSource;
  reason?: string;
  lastSyncAt: number | null;
}

let snapshot: DataSourceSnapshot = {
  source: dataSource,
  reason: lastReason,
  lastSyncAt,
};

function setSource(next: DataSource, reason?: string): void {
  const changed =
    next !== dataSource || reason !== lastReason || lastSyncAt !== snapshot.lastSyncAt;
  dataSource = next;
  lastReason = reason;
  if (next === 'demo') {
    lastSyncAt = Date.now();
  }
  snapshot = { source: next, reason, lastSyncAt };
  if (changed) {
    notify();
  }
}

export function subscribeDataSource(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getDataSourceSnapshot(): DataSourceSnapshot {
  return snapshot;
}

/** Imperative read for non-React callers (e.g. the WS client). */
export function isDemoMode(): boolean {
  return dataSource === 'demo';
}

/** Imperative read of the current source for sibling modules in this folder. */
export function currentSource(): DataSource {
  return dataSource;
}

/** Test/lab hook: reset the module back to the live-source assumption. */
export function __resetDataSource(): void {
  setSource(FORCE_DEMO ? 'demo' : 'live', FORCE_DEMO ? 'VITE_FORCE_DEMO=true' : undefined);
}

export function markLive(): void {
  lastSyncAt = Date.now();
  setSource('live', undefined);
}

export function markDemo(reason: string): void {
  setSource('demo', reason);
}
