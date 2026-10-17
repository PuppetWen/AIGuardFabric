export type PrivateLinkRunStatus = 'running' | 'succeeded' | 'failed' | 'cancelled' | 'interrupted' | 'superseded' | 'archived';
export interface PrivateLinkZone {
  zoneId: string; region: string | null; status: string | null; eniId: string | null;
  vSwitchId: string | null; eniIp: string | null; ipv6: string | null; domain: string | null;
}
export interface PrivateLinkSecurityGroup { securityGroupId: string; status: string | null }
export interface PrivateLinkEndpoint {
  assetId: string | null; endpointId: string; name: string | null; region: string | null;
  vpcId: string | null; serviceId: string | null; serviceRegionId: string | null; domain: string | null;
  endpointType: string | null; endpointStatus: string | null; connectionStatus: string | null; businessStatus: string | null;
  zonesAvailable: boolean; securityGroupsAvailable: boolean; zones: PrivateLinkZone[]; securityGroups: PrivateLinkSecurityGroup[];
}
export type PrivateLinkNodeKind = 'endpoint' | 'zone' | 'security_group' | 'eni' | 'vswitch' | 'vpc' | 'service';
export interface PrivateLinkNode {
  id: string; kind: PrivateLinkNodeKind; cloudId: string; region: string | null; assetId: string | null; referenceOnly: boolean;
}
export interface PrivateLinkEdge {
  from: string; to: string; relation: 'has_zone' | 'has_security_group' | 'in_vpc' | 'references_service' | 'zone_eni' | 'zone_vswitch';
  evidenceAction: 'GetVpcEndpointAttribute' | 'ListVpcEndpointZones' | 'ListVpcEndpointSecurityGroups'; observedAt: string;
}
export interface PrivateLinkGraphData { nodes: PrivateLinkNode[]; edges: PrivateLinkEdge[] }
export interface PrivateLinkOperation {
  requestId: string; scopeId: string; configurationVersion: number; mocked: boolean;
  region: string; endpointId: string; sourceIdentity: string; identityEvidence: 'configured_source_digest'; status: PrivateLinkRunStatus;
  startedAt: string; finishedAt: string | null; leaseExpiresAt: string; pagesRead: number;
  endpointsObserved: number; zonesObserved: number; securityGroupsObserved: number; published: boolean; current: boolean;
  canCancel: boolean; canRedispatch: false; note: string;
  archived: boolean; archivable: boolean; archivedAt: string | null; originalStatus: PrivateLinkRunStatus | null;
}
export interface PrivateLinkInventory {
  configured: boolean; scopeId: string | null; configurationVersion: number | null; sourceIdentity: string | null;
  identityEvidence: 'configured_source_digest'; region: string | null; endpointId: string | null; mocked: boolean | null;
  topologyAvailable: boolean; checkedAt: string | null; pagesRead: number | null; listingComplete: boolean;
  coverage: 'selected_endpoint'; consistency: 'not_strong_snapshot';
  networkReachability: null; authorizationAllowed: null; unavailableReason: string | null;
  generation: number; archivedCount: number; operations: PrivateLinkOperation[];
  endpoint: PrivateLinkEndpoint | null; graph: PrivateLinkGraphData;
  limits: { maxPages: number; maxPagesPerList: number; pageSize: number; maxChildRecords: number; maxSeconds: number; maxRuns: number; maxRecordBytes: number };
}
export interface PrivateLinkSyncInput { request_id: string; configuration_version: number; confirm_live: boolean }
export interface PrivateLinkArchiveInput { expected_generation: number; request_ids: string[] }
export interface PrivateLinkArchiveResult { generation: number; archivedCount: number; archivedRequestIds: string[] }
