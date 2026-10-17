import type { PrivateLinkEndpoint, PrivateLinkGraphData, PrivateLinkInventory, PrivateLinkOperation } from '@/types/privatelinkInventory';
export const privatelinkResult = <T,>(data: T) => ({ data, meta: { source: 'live' as const, at: Date.now(), elapsedMs: 1 } });
export const privatelinkRequest = '00000000-0000-4000-8000-000000000041';
export function privatelinkOperation(overrides: Partial<PrivateLinkOperation> = {}): PrivateLinkOperation {
  return { requestId: privatelinkRequest, scopeId: '00000000-0000-4000-8000-000000000042', configurationVersion: 4,
    mocked: true, region: 'cn-hangzhou', endpointId: 'ep-owned', sourceIdentity: 'configured-digest',
    identityEvidence: 'configured_source_digest', status: 'failed', startedAt: '2026-10-01T00:00:00Z',
    finishedAt: '2026-10-01T00:00:01Z', leaseExpiresAt: '2026-10-01T00:02:00Z', pagesRead: 2,
    endpointsObserved: 1, zonesObserved: 0, securityGroupsObserved: 0, published: false, current: true,
    canCancel: false, canRedispatch: false, note: 'Owned receipt', archived: false, archivable: true,
    archivedAt: null, originalStatus: null, ...overrides };
}
export function privatelinkInventory(overrides: Partial<PrivateLinkInventory> = {}): PrivateLinkInventory {
  return { configured: true, scopeId: '00000000-0000-4000-8000-000000000042', configurationVersion: 4,
    mocked: true, region: 'cn-hangzhou', endpointId: 'ep-owned', sourceIdentity: 'configured-digest',
    identityEvidence: 'configured_source_digest', topologyAvailable: false, checkedAt: null, pagesRead: null, listingComplete: false,
    coverage: 'selected_endpoint', consistency: 'not_strong_snapshot', networkReachability: null, authorizationAllowed: null,
    endpoint: null, graph: { nodes: [], edges: [] }, operations: [], generation: 7, archivedCount: 0,
    unavailableReason: 'inventory_not_observed', limits: { maxPages: 40, maxPagesPerList: 20, pageSize: 50,
      maxChildRecords: 2000, maxSeconds: 110, maxRuns: 512, maxRecordBytes: 4194304 }, ...overrides };
}
export function privatelinkEndpoint(overrides: Partial<PrivateLinkEndpoint> = {}): PrivateLinkEndpoint {
  return { assetId: '00000000-0000-4000-8000-000000000043', endpointId: 'ep-owned', name: null, region: 'cn-hangzhou',
    vpcId: 'vpc-owned', serviceId: 'eps-owned', serviceRegionId: 'cn-shanghai', domain: null,
    endpointType: null, endpointStatus: 'Active', connectionStatus: 'Connected', businessStatus: null,
    zonesAvailable: true, securityGroupsAvailable: false, zones: [], securityGroups: [], ...overrides };
}
export function privatelinkGraph(): PrivateLinkGraphData {
  return { nodes: [
    { id: 'endpoint:ep-owned', kind: 'endpoint', cloudId: 'ep-owned', region: 'cn-hangzhou', assetId: privatelinkEndpoint().assetId, referenceOnly: false },
    { id: 'service:eps-owned', kind: 'service', cloudId: 'eps-owned', region: 'cn-shanghai', assetId: null, referenceOnly: true },
    { id: 'sg:sg-owned', kind: 'security_group', cloudId: 'sg-owned', region: null, assetId: null, referenceOnly: true },
  ], edges: [
    { from: 'endpoint:ep-owned', to: 'service:eps-owned', relation: 'references_service', evidenceAction: 'GetVpcEndpointAttribute', observedAt: '2026-10-01T00:01:00Z' },
    { from: 'endpoint:ep-owned', to: 'sg:sg-owned', relation: 'has_security_group', evidenceAction: 'ListVpcEndpointSecurityGroups', observedAt: '2026-10-01T00:01:00Z' },
  ] };
}
