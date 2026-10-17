export type ManagedLimit = 'RequestPerMinute' | 'TokenPerMinute';
export interface PolicyRevision { policyId: string; version: number }
export interface ApigTarget {
  targetScopeId: string; writeResourceId: string; configurationId: string; configurationVersion: number;
  sourceLabel: string; region: string; endpoint: string; mocked: boolean; transportMode: 'mock' | 'live' | 'loopback-test';
  binding: { httpApiId: string; gatewayId: string; environmentId: string; policyId: string; attachmentId: string };
}
export interface SourceLimit {
  policyId: string; policyVersion: number; quotaId: string; quotaVersion: number; quotaFingerprint: string;
  managedLimit: ManagedLimit; limit: number;
}
export interface EligibleSource { policyId: string; version: number; name: string; eligible: boolean; source: SourceLimit | null; reason: string | null }
export interface ApigObservation {
  id: string; requestId: string; target: ApigTarget; startedAt: string; observedAt: string;
  fingerprint: string; configHash: string; contentHash: string; contentBytes: number; usable: boolean; reason: string | null;
  slots: { managedLimit: ManagedLimit; currentLimit: number | null; supported: boolean; reason: string | null }[];
}
export interface ApigPreview {
  id: string; requestId: string; target: ApigTarget; stateVersion: number; action: 'publish' | 'rollback';
  sourcePublicationId: string | null; observationId: string; baselineObservedAt: string; baselineFingerprint: string; baselineConfigHash: string;
  managedLimit: ManagedLimit; previousLimit: number; desiredLimit: number; desiredHash: string; desiredBytes: number;
  sourcePolicyVersions: PolicyRevision[]; currentPolicyVersions: PolicyRevision[]; expiresAt: string;
  previewUsable: boolean; reason: string | null; consumedBy: string | null; casSemantics: 'none'; noCloudCas: true;
  sharedPolicyImpact: null; consumerApplied: null; acknowledgeUnknownOperationId: string | null;
  unknownOverlapWarning: boolean; allowedActions: string[];
}
export interface ApigOperation {
  requestId: string; previewId: string; target: ApigTarget; action: 'publish' | 'rollback'; sourcePublicationId: string | null;
  startedAt: string; submittedAt: string; finishedAt: string | null; leaseExpiresAt: string;
  status: 'started' | 'verified' | 'conflict' | 'failed' | 'uncertain' | 'superseded' | 'archived'; originalStatus: string | null;
  archived: boolean; archivedAt: string | null; archivable: boolean;
  cloudWrite: { status: 'not_attempted' | 'attempting' | 'accepted' | 'unknown'; providerRequestId: string | null };
  readback: { status: 'not_attempted' | 'matched' | 'different' | 'unavailable'; observedAt: string | null; currentHash: string | null };
  localPublication: { status: 'not_staged' | 'pending_audit' | 'published' }; completionState: 'complete' | 'pending_audit' | 'running';
  safeReason: string | null; consumerApplied: null; supersededBy: string | null; sourceCurrent: boolean | null;
  sourcePolicyVersions: PolicyRevision[]; currentPolicyVersions: PolicyRevision[] | null;
  recoveryScopeId: string | null; recoveryConfigurationVersion: number | null; allowedActions: string[];
}
export interface ApigHistory {
  publicationId: string; target: ApigTarget; verifiedAt: string; contentHash: string; contentBytes: number;
  sourcePolicyVersions: PolicyRevision[]; rollbackAvailable: boolean; reason: string | null;
}
export interface ApigPublicationState {
  configured: boolean; enabled: boolean | null; binding: ApigTarget | null; stateVersion: number; generation: number;
  canInitializeMockFixture: boolean; canObserve: boolean; canPrepare: boolean; canApply: boolean; bindingReason: string | null;
  busy: boolean; leaseExpiresAt: string | null; unresolvedOperationId: string | null; observation: ApigObservation | null;
  sources: { items: EligibleSource[]; page: number; pageSize: number; total: number; policyCount: number; eligibleCount: number; totalPages: number; truncated: boolean; reason: string | null };
  operations: ApigOperation[]; history: ApigHistory[]; detailedRunCount: number; archivedCount: number; storedContentBytes: number;
  consumerApplied: null; sharedPolicyImpact: null; noCloudCas: true;
  limits: { maxPolicies: number; maxContentBytes: number; maxProviderConfigBytes: number; maxRecordBytes: number; maxMainBytes: number;
    maxAggregateAgentIds: number; maxStoredContentBytes: number; maxDetailedRuns: number; maxPreviews: number; maxObservations: number;
    maxArchive: number; maxDriverSeconds: number; maxOperationSeconds: number; leaseSeconds: number; previewSeconds: number; observationSeconds: number };
}
export interface ObserveInput { request_id: string; configuration_version: number; confirm_live: boolean; initialize_mock_fixture?: boolean }
export type ApigChange = { action: 'publish'; policies: { policy_id: string; version: number }[] } | { action: 'rollback'; publication_id: string };
export interface PreviewInput { request_id: string; configuration_version: number; observation_id: string; expected_state_version: number;
  change: ApigChange; acknowledge_unknown_operation_id?: string }
export interface ApplyInput { request_id: string; preview_id: string; expected_state_version: number; confirm_apply: boolean;
  confirm_scope_difference: boolean; confirm_shared_policy_impact: boolean; confirm_no_cloud_cas: boolean;
  confirm_live: boolean; confirm_unknown_overlap: boolean }
export type ApplyConfirmations = Omit<ApplyInput, 'request_id' | 'preview_id' | 'expected_state_version'>;
export interface SourceQuery { source_page?: number; source_page_size?: number; source_eligible_only?: boolean }
