export interface PolicyRevision { policyId: string; version: number }
export interface Target {
  targetScopeId: string; configurationId: string; configurationVersion: number;
  sourceLabel: string; region: string; instanceId: string; engineOrigin: string;
  namespaceId: string; group: string; dataId: string; dialect: 'nacos-http-v2-cas';
  mocked: boolean; transportMode: 'mock' | 'live' | 'loopback-test';
}
export interface Observation {
  id: string; requestId: string; target: Target; startedAt: string; observedAt: string;
  contentMd5: string; contentHash: string; contentBytes: number; contentEmpty: boolean;
  usable: boolean; reason: string | null;
}
export type TerminalStatus = 'verified' | 'conflict' | 'failed' | 'uncertain' | 'superseded';
export interface Operation {
  requestId: string; previewId: string; target: Target; action: 'publish' | 'rollback';
  sourcePublicationId: string | null; startedAt: string; submittedAt: string;
  finishedAt: string | null; leaseExpiresAt: string;
  status: 'started' | TerminalStatus | 'archived'; originalStatus: TerminalStatus | null;
  archived: boolean; archivedAt: string | null; archivable: boolean;
  cloudWrite: { status: 'not_attempted' | 'attempting' | 'accepted' | 'conflict' | 'rejected' | 'unknown' };
  readback: { status: 'not_attempted' | 'matched' | 'different' | 'unavailable'; observedAt: string | null; currentHash: string | null };
  localPublication: { status: 'not_staged' | 'pending_audit' | 'published' };
  completionState: 'running' | 'pending_audit' | 'complete'; safeReason: string | null;
  consumerApplied: null; supersededBy: string | null; sourceCurrent: boolean | null;
  currentPolicyVersions: PolicyRevision[] | null; recoveryScopeId: string | null;
  recoveryConfigurationVersion: number | null;
  allowedActions: ('read_receipt' | 'observe' | 'recover_local' | 'archive')[];
}
export interface Preview {
  id: string; requestId: string; target: Target; stateVersion: number; action: 'publish' | 'rollback';
  sourcePublicationId: string | null; observationId: string; baselineObservedAt: string;
  baselineMd5: string; baselineHash: string; baselineBytes: number; desiredHash: string; desiredBytes: number;
  sourcePolicyVersions: PolicyRevision[]; currentPolicyVersions: PolicyRevision[]; expiresAt: string;
  previewUsable: boolean; reason: string | null; consumedBy: string | null;
  casSemantics: 'content-md5-upsert'; consumerApplied: null;
  acknowledgeUnknownOperationId: string | null; unknownOverlapWarning: boolean;
  allowedActions: ('apply' | 'read_receipt')[];
}
export interface PublicationHistory {
  publicationId: string; target: Target; verifiedAt: string; contentHash: string; contentBytes: number;
  sourcePolicyVersions: PolicyRevision[]; rollbackAvailable: boolean; reason: string | null;
}
export interface Limits {
  maxPolicies: number; maxContentBytes: number; maxRecordBytes: number; maxMainBytes: number;
  maxAggregateAgentIds: number; maxStoredContentBytes: number; maxDetailedRuns: number;
  maxPreviews: number; maxObservations: number; maxArchive: number; maxDriverSeconds: number;
  maxOperationSeconds: number; leaseSeconds: number; previewSeconds: number; observationSeconds: number;
}
export interface PublicationState {
  configured: boolean; enabled: boolean | null; binding: Target | null; stateVersion: number; generation: number;
  canObserve: boolean; canPrepare: boolean; canApply: boolean; bindingReason: string | null;
  busy: boolean; leaseExpiresAt: string | null; unresolvedOperationId: string | null;
  observation: Observation | null; operations: Operation[]; history: PublicationHistory[];
  detailedRunCount: number; archivedCount: number; storedContentBytes: number; limits: Limits; consumerApplied: null;
}
export interface ObserveInput { request_id: string; configuration_version: number; confirm_live: boolean }
export type Change = { action: 'publish'; policies: { policy_id: string; version: number }[] }
  | { action: 'rollback'; publication_id: string };
export interface PreviewInput {
  request_id: string; configuration_version: number; observation_id: string; expected_state_version: number;
  change: Change; acknowledge_unknown_operation_id?: string;
}
export interface ApplyInput {
  request_id: string; preview_id: string; expected_state_version: number;
  confirm_apply: boolean; confirm_upsert: boolean; confirm_live: boolean; confirm_unknown_overlap: boolean;
}
export interface ArchiveInput { expected_generation: number; request_ids: string[] }
export interface ArchiveResult { generation: number; archivedCount: number; archivedRequestIds: string[]; unchanged: boolean }
