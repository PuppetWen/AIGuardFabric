export type MseRunStatus = 'running' | 'succeeded' | 'failed' | 'cancelled' | 'interrupted' | 'superseded' | 'archived';
export interface MseService {
  key: string; name: string; groupName: string; assetId: string | null;
  instanceCount: number | null; healthyInstanceCount: number | null; clusterCount: number | null;
  source: string | null; endpoint: null; protocol: null; runtime: null; networkZone: null; metadata: null;
  evidence: 'ListAnsServices';
}
export interface MseOperation {
  requestId: string; scopeId: string; configurationVersion: number; mocked: boolean;
  region: string; instanceId: string; namespaceId: string; sourceIdentity: string;
  identityEvidence: 'configured_source_digest'; status: MseRunStatus;
  startedAt: string; finishedAt: string | null; leaseExpiresAt: string;
  pagesRead: number; servicesObserved: number; published: boolean; current: boolean;
  canCancel: boolean; canRedispatch: false; note: string;
  archived: boolean; archivable: boolean; archivedAt: string | null; originalStatus: MseRunStatus | null;
}
export interface MseInventory {
  configured: boolean; scopeId: string | null; configurationVersion: number | null; mocked: boolean | null;
  region: string | null; instanceId: string | null; namespaceId: string | null; sourceIdentity: string | null;
  identityEvidence: 'configured_source_digest'; inventoryAvailable: boolean; totalServices: number | null;
  checkedAt: string | null; pagesRead: number | null; listingComplete: boolean;
  coverage: 'observed_pages'; consistency: 'not_strong_snapshot'; items: MseService[]; operations: MseOperation[];
  generation: number; archivedCount: number; unavailableReason: string | null;
  limits: { maxServices: number; maxPages: number; pageSize: number; maxSeconds: number; maxRuns: number; maxRecordBytes: number };
}
export interface MseSyncInput { request_id: string; configuration_version: number; confirm_live: boolean }
export interface MseArchiveInput { expected_generation: number; request_ids: string[] }
export interface MseArchiveResult { generation: number; archivedCount: number; archivedRequestIds: string[] }
