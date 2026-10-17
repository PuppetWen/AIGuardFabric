import type { ApiResult } from '@/api/dataSource';
import type { Item, QueueState, Receipt, Source } from './types';
export const requestId = '10000000-0000-4000-8000-000000000001';
export const itemId = '20000000-0000-4000-8000-000000000001';
export const source: Source = { configurationId: '30000000-0000-4000-8000-000000000001', configurationVersion: 1,
  groupId: 'agf-cms-demo', region: 'cn-hangzhou', transportMode: 'mock', mocked: true };
export function result<T>(data: T): ApiResult<T> { return { data, meta: { source: 'live', elapsedMs: 1, at: Date.now() } }; }
export function item(overrides: Partial<Item> = {}): Item {
  return { id: itemId, enqueueRequestId: requestId, name: 'actual-owned-event', action: 'PutCustomEvent', payloadHash: 'a'.repeat(64),
    payloadBytes: 32, queuedAt: new Date().toISOString(), archivedAt: null, originalSource: source, sourceCurrent: true,
    attemptCount: 0, lastAttempt: null, deadLetter: false, canSend: true, canRecoverLocal: false, canArchive: true, ...overrides };
}
export function state(overrides: Partial<QueueState> = {}): QueueState {
  return { generation: 1, storedContentBytes: 32, permanentFactCount: 2, page: 1, pageSize: 20, total: 1, items: [item()], source,
    limits: { detailedItems: 128, permanentFacts: 4096, attemptsPerItem: 5, enqueueBatch: 20, sendBatch: 20, archiveBatch: 32, contentBytes: 2 * 1024 * 1024 },
    automaticRetry: false, exactlyOnce: false, consumerApplied: 'unknown', ...overrides };
}
export function receipt(id = requestId, purpose: Receipt['purpose'] = 'enqueue'): Receipt {
  return { id, purpose, inputHash: 'b'.repeat(64), submittedAt: new Date().toISOString(), generation: 2, changedCount: 1,
    itemIds: [itemId], attemptIds: [], items: [item()], originalAttempts: [], immutableIntent: true, automaticRetry: false };
}
export function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(accept => { resolve = accept; }); return { promise, resolve }; }
