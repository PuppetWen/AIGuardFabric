import type { MseInventory, MseOperation, MseService } from '@/types/mseInventory';
export const mseMeta = { source: 'live' as const, at: Date.now(), elapsedMs: 1 };
export const mseResult = <T,>(data: T) => ({ data, meta: mseMeta });
export const mseRequest = '00000000-0000-4000-8000-000000000041';
export function mseOperation(overrides: Partial<MseOperation> = {}): MseOperation {
  return { requestId: mseRequest, scopeId: '00000000-0000-4000-8000-000000000042', configurationVersion: 4,
    mocked: true, region: 'cn-hangzhou', instanceId: 'instance-owned', namespaceId: '', sourceIdentity: 'configured-digest',
    identityEvidence: 'configured_source_digest', status: 'failed', startedAt: '2026-09-30T00:00:00Z',
    finishedAt: '2026-09-30T00:00:01Z', leaseExpiresAt: '2026-09-30T00:02:00Z', pagesRead: 1,
    servicesObserved: 1, published: false, current: true, canCancel: false, canRedispatch: false, note: 'Owned receipt',
    archived: false, archivable: true, archivedAt: null, originalStatus: null, ...overrides };
}
export function mseInventory(overrides: Partial<MseInventory> = {}): MseInventory {
  return { configured: true, scopeId: '00000000-0000-4000-8000-000000000042', configurationVersion: 4,
    mocked: true, region: 'cn-hangzhou', instanceId: 'instance-owned', namespaceId: '', sourceIdentity: 'configured-digest',
    identityEvidence: 'configured_source_digest', inventoryAvailable: false, totalServices: null, checkedAt: null,
    pagesRead: null, listingComplete: false, coverage: 'observed_pages', consistency: 'not_strong_snapshot', items: [],
    operations: [], generation: 7, archivedCount: 0, unavailableReason: 'inventory_not_observed',
    limits: { maxServices: 2000, maxPages: 20, pageSize: 100, maxSeconds: 110, maxRuns: 512, maxRecordBytes: 4194304 }, ...overrides };
}
export function mseService(index: number): MseService {
  return { key: `service-${index}`, name: `service-${index}`, groupName: 'owned-group',
    assetId: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`, instanceCount: 0,
    healthyInstanceCount: null, clusterCount: null, source: null, endpoint: null, protocol: null, runtime: null,
    networkZone: null, metadata: null, evidence: 'ListAnsServices' };
}
