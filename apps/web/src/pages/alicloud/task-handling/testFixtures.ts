import type { ApiResult } from '@/api/dataSource';
import type { HandlingEvent, HandlingPage, HandlingReceipt } from '@/types/agentTeamsTaskHandling';

export const eventId = 'b19e7a10-52c1-4a20-8820-1da728df0481';
export const requestId = '026580f1-e8d9-4263-9264-11d4b4a8c906';
export function result<T>(data: T): ApiResult<T> {
  return { data, meta: { source: 'live', elapsedMs: 1, at: Date.now() } };
}
export function event(overrides: Partial<HandlingEvent> = {}): HandlingEvent {
  return { id: eventId, category: 'collector_reported_error', originalStatus: 'error', externalEventId: 'worker-error-17',
    sourceId: 'source-one', scopeId: 'scope-one', bindingId: 'binding-one', eventTime: '2026-10-02T01:01:00Z',
    receivedAt: '2026-10-02T01:02:00Z', taskId: 'job-17', traceId: null, mocked: false,
    evidenceIdentityHash: 'evidence', messagePreview: 'Worker reported a task error', fromTeam: 'team-one', fromWorker: 'worker-one',
    handling: null, currentSource: { sourceExists: true, sourceGone: false, sourceEnabled: true, sourceName: 'Worker audit',
      cloudConfigurationVersion: 7, cloudEnabled: true, fingerprint: 'opaque-source-proof', annotationAllowedWhenDisabled: true,
      businessReplay: false }, allowedActions: ['read', 'annotate', 'archive'], cloudExecutionConfirmed: false,
    businessReplayImplemented: false, ...overrides };
}
export function page(overrides: Partial<HandlingPage> = {}): HandlingPage {
  return { items: [event()], total: 1, nextCursor: null, truncated: false, windowFrom: '2026-09-02T01:00:00Z',
    windowTo: '2026-10-02T01:00:00Z', asOfReceivedAt: '2026-10-02T01:00:00Z', evidenceLimit: 2000,
    consistency: 'statement', complete: false, category: 'collector_reported_error', generation: 12,
    activeHandledCount: 0, archivedCount: 0, businessReplayImplemented: false, ...overrides };
}
export function receipt(overrides: Partial<HandlingReceipt> = {}): HandlingReceipt {
  return { purpose: 'operator-resolution', requestId, eventId, version: 1, decision: 'acknowledged',
    cloudExecutionConfirmed: false, businessReplay: false, ...overrides };
}
export function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(value => { resolve = value; });
  return { promise, resolve };
}
